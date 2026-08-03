<#
.SYNOPSIS
    Verifies that the daemon's named pipe rejects a DIFFERENT OS user.

.DESCRIPTION
    THIS SCRIPT WAS NEVER RUN BY THE AGENT THAT WROTE IT.

    Everything about the Windows peer check that ONE unelevated user on ONE
    machine can establish is covered by automated tests and was executed:

      crates/ssk-winhost/src/pipe.rs           (mod windows_tests, 14 tests)
      crates/ssk-winhost/tests/named_pipe_auth.rs (4 tests)

    Those cover same-user acceptance end to end through the real FFI, the two
    fail-open traps (a SECURITY_ANONYMOUS client, and a client with no
    security-QoS flags), the revert-impersonation post-condition, the DACL and
    mandatory integrity label read back off the live pipe handle, and the
    anti-squat refusal.

    They do NOT establish that the label would actually block a below-Medium
    integrity client: spawning one needs token manipulation that also requires
    elevation. Only that the label is present on the object.

    The ONE property they cannot establish is the headline one: that a process
    owned by a *genuinely different* user is refused. Creating a second user
    account requires elevation, and the implementing session ran unelevated on
    the user's real primary machine under a hard no-system-changes rule. This is
    the same limitation the Unix twin discloses at crates/ssk-ipc/src/auth.rs
    (`scripts/manual_peer_cred_test.sh`); it is discharged the same way, by a
    scripted operator check rather than by an #[ignore]d test that would read as
    coverage in a test report.

    Run this on a DISPOSABLE Windows VM. It creates a local user account. It
    does NOT touch the firewall, any service, or the registry.

.PARAMETER SecondUser
    Name of a second local account to run the hostile client as. Created if it
    does not exist (requires elevation).

.PARAMETER SecondUserPassword
    Password for that account, as a SecureString. Prompted for if omitted.

.EXAMPLE
    # From an ELEVATED PowerShell on a disposable VM:
    .\verify-pipe-peer-auth.ps1 -SecondUser ssk-probe

.NOTES
    Expected result on success:
      [PASS] same-user client was served
      [PASS] foreign-user client was refused

    A '[FAIL] foreign-user client was SERVED' means roadmap SEC-3 is still open:
    the impersonation check is not comparing SIDs, or is comparing them wrongly.

    A '[PASS] foreign-user client could not even open the pipe' is ALSO a pass,
    and is the stronger outcome: it means the explicit DACL
    (crates/ssk-winhost/src/pipe.rs, `sddl_for_user_owned_pipe`) refused the
    open before the peer check was ever consulted. Both layers are supposed to
    hold; the script reports which one did.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SecondUser,

    [System.Security.SecureString]$SecondUserPassword
)

$ErrorActionPreference = 'Stop'

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Elevated)) {
    Write-Error "This script must run ELEVATED: it creates a local user account."
}

if (-not $SecondUserPassword) {
    $SecondUserPassword = Read-Host -AsSecureString `
        "Password for the throwaway account '$SecondUser'"
}

# --- 0. Locate the test binary -------------------------------------------
# The probe reuses the crate's own integration test, which already contains a
# real server built from WindowsPipeFactory + WindowsPeerAuthenticator. Build it
# first:
#
#     cargo test -p ssk-winhost --test named_pipe_auth --no-run
#
# and note the produced named_pipe_auth-*.exe path. The manual leg below drives
# a pipe served by that binary.
Write-Host @"
--- BUILD STEP (run as the FIRST user, unelevated) ---
    cargo test -p ssk-winhost --test named_pipe_auth --no-run

Then start a long-lived server on a KNOWN pipe name. The simplest way is a tiny
scratch binary in the crate that calls:

    ssk_ipc::server::serve_named_pipe(
        r"\\.\pipe\ssk-peer-auth-probe",
        handler,
        Arc::new(ssk_winhost::WindowsPipeFactory::for_current_user()?),
        Arc::new(ssk_winhost::WindowsPeerAuthenticator::new()?),
        ssk_ipc::ServeLimits::default(),
    )

(sskd itself will do once its Windows composition root is wired; until then the
scratch binary is the honest way to run this leg.)
"@

$PipeName = '\\.\pipe\ssk-peer-auth-probe'

# --- 1. Create the second user -------------------------------------------
if (-not (Get-LocalUser -Name $SecondUser -ErrorAction SilentlyContinue)) {
    Write-Host "Creating local user '$SecondUser'"
    New-LocalUser -Name $SecondUser -Password $SecondUserPassword `
        -AccountNeverExpires -PasswordNeverExpires | Out-Null
    Add-LocalGroupMember -Group 'Users' -Member $SecondUser
} else {
    Write-Host "Local user '$SecondUser' already exists; reusing it."
}

# --- 2. Leg 1: same user must be SERVED ----------------------------------
# Run as the user that owns the pipe. Opening and writing a CBOR frame is what
# the crate's own tests already do; here we only need "did the server keep the
# connection open".
$sameUserProbe = {
    param($Pipe)
    try {
        $c = New-Object System.IO.Pipes.NamedPipeClientStream(
            '.', ($Pipe -replace '^\\\\\.\\pipe\\', ''),
            [System.IO.Pipes.PipeDirection]::InOut,
            [System.IO.Pipes.PipeOptions]::None,
            [System.Security.Principal.TokenImpersonationLevel]::Identification)
        $c.Connect(5000)
        # The server authenticates BEFORE reading, and hangs up on refusal.
        # Staying connected for a moment is the observable difference.
        Start-Sleep -Milliseconds 300
        $connected = $c.IsConnected
        $c.Dispose()
        if ($connected) { 'SERVED' } else { 'REFUSED' }
    } catch {
        "OPEN-DENIED: $($_.Exception.Message)"
    }
}

$sameUser = & $sameUserProbe $PipeName
if ($sameUser -eq 'SERVED') {
    Write-Host "[PASS] same-user client was served" -ForegroundColor Green
} else {
    Write-Host "[FAIL] same-user client was not served ($sameUser)" -ForegroundColor Red
    Write-Host "       The check is refusing legitimate callers; do not read the" -ForegroundColor Red
    Write-Host "       foreign-user leg below as a pass until this is fixed." -ForegroundColor Red
}

# --- 3. Leg 2: the foreign user must be REFUSED --------------------------
# THE leg this whole script exists for. It must run under the SECOND user's
# token, which is why a second account is required.
Write-Host @"

--- MANUAL LEG (the one that actually proves the control) ---
Open a NEW PowerShell window AS '$SecondUser':

    runas /user:$SecondUser powershell.exe

...and in that window run:

    `$c = New-Object System.IO.Pipes.NamedPipeClientStream(
        '.', 'ssk-peer-auth-probe',
        [System.IO.Pipes.PipeDirection]::InOut,
        [System.IO.Pipes.PipeOptions]::None,
        [System.Security.Principal.TokenImpersonationLevel]::Identification)
    `$c.Connect(5000)
    Start-Sleep -Milliseconds 300
    "IsConnected = `$(`$c.IsConnected)"

EXPECTED, either of:
  [PASS] Connect() throws UnauthorizedAccessException
         -> the explicit DACL refused the open. The peer check was never
            reached, which is the stronger of the two outcomes.
  [PASS] Connect() succeeds but IsConnected is False after the sleep
         -> the peer SID check refused and the server hung up.

  [FAIL] IsConnected = True
         -> roadmap SEC-3 is STILL OPEN. A foreign user is holding a live
            connection to the daemon's control pipe.

Also worth recording while you are here (P2 exit criterion):

    `$sd = (Get-Acl -Path '\\.\pipe\ssk-peer-auth-probe').Sddl

EXPECTED: an owner ACE for the FIRST user, plus SY and BA, and NO ACE for
WD (Everyone) or AN (ANONYMOUS LOGON). The automated test
`the_pipe_carries_the_explicit_dacl_and_not_the_default` asserts exactly this
from inside the process; this is the same fact observed from outside it.

And the leg the automated tests genuinely cannot reach — the mandatory
integrity label's ENFORCEMENT. From a below-Medium-integrity process (e.g.
launched with `icacls`-set Low IL, or from a sandboxed host), opening the pipe
for WRITE must fail. The label is asserted PRESENT by the automated test; only
its effect is unverified.

Cleanup (elevated): Remove-LocalUser -Name '$SecondUser'

===============================================================================
P3 LEGS -- the privileged broker's pipe. NONE of these have ever been executed.
===============================================================================

Everything above is about the UNPRIVILEGED sskd pipe, which is same-user and
whose descriptor is sddl_for_user_owned_pipe. P3 added a SECOND pipe with a
DIFFERENT authentication contract: \\.\pipe\kaleidoscorp-sskbroker-1, created
by ssk-svc.exe running as LocalSystem, carrying
sddl_for_system_owned_pipe(&[<allow-listed SIDs>]).

The automated tests in crates/ssk-winhost/tests/privileged_pipe.rs drive a REAL
broker over a REAL pipe end to end, unelevated -- engage, release, lease
lifetime, an unlisted peer refused, the accept loop stopping. What they cannot
reach is everything that depends on WHO the two ends are. Those are the legs
below. Each states what must be observed, and what a failure means.

  P3-1  The pipe is owned by SYSTEM.
        With the service RUNNING, from any account:
            (Get-Acl '\\.\pipe\kaleidoscorp-sskbroker-1').Sddl
        EXPECTED: starts O:SY, and the DACL is
            (A;;FA;;;SY) + one (A;;0x12019b;;;<sid>) per allow-listed SID
            + (A;;0x12019b;;;BA), plus S:(ML;;NW;;;ME).
        A GA on anything but SY means instance creation was handed to a client
        and same-user squatting is NOT closed.
        FAILURE MEANING: require_pipe_owner on the client side will refuse
        every connection, and the product is unusable rather than unsafe. The
        client-side check itself is asserted by the automated test
        a_client_refuses_an_endpoint_that_is_not_owned_by_the_expected_principal.

  P3-2  An allow-listed user CAN engage and release; a non-allow-listed user
        CANNOT.
        Write %ProgramData%\ScorpioSync\state\authz.json (elevated) naming ONLY
        the first user:
            { "scheme": 1,
              "grants": [ { "sid": "<first user SID>",
                            "verbs": ["read_status","engage_kill_switch",
                                      "release_kill_switch"] } ] }
        Then, as the second account, drive an engage.
        EXPECTED: refused with PEER_NOT_GRANTED, and
        `netsh advfirewall firewall show rule name=all` shows NO new
        SSK-KillSwitch rule.
        EXPECTED, same account: GetStatus still ANSWERS. Tier R is open on
        purpose -- a severed machine must stay diagnosable.
        FAILURE MEANING: the allow-list is not on the served path. This is the
        headline P3 property and nothing on a one-account box can establish it.

  P3-3  The DACL denies instance creation ACROSS principals.
        As the first (non-SYSTEM) user, attempt to create a second instance of
        \\.\pipe\kaleidoscorp-sskbroker-1.
        EXPECTED: ERROR_ACCESS_DENIED (5).
        The MASK's refusal is proven same-user by the automated tests in
        pipe.rs; the PRINCIPAL SPLIT is what this leg adds, and only this leg.

  P3-4  Squatting the well-known name refuses the service, visibly.
        Before starting the service, create \\.\pipe\kaleidoscorp-sskbroker-1
        from an unprivileged process and leave it open. Then sc start.
        EXPECTED: the service fails to start (FILE_FLAG_FIRST_PIPE_INSTANCE
        refuses) and the reason is in the rotated log under
        %ProgramData%\ScorpioSync\state\logs.
        EXPECTED, second half: a client pointed at the squatter is REFUSED by
        the owner check rather than being fed a forged status.
        FAILURE MEANING: a squatter can answer Ok(Status) claiming Engaged
        while egress flows.

  P3-5  Tier O is reachable at all.
        From an ELEVATED console, confirm CheckTokenMembership(S-1-5-32-544)
        returns TRUE for that caller -- i.e. that an elevated administrator can
        recover a machine whose authz.json is unreadable. Nothing on an
        unelevated box can produce an elevated token, so the entire Override
        tier is unexercised.
        FAILURE MEANING: there is no recovery path from a broken allow-list
        other than editing the file by hand.

  P3-6  Startup reconciliation actually reconciles.
        With the service STOPPED, plant an SSK kill-switch rule by hand
        (elevated). Start the service.
        EXPECTED: the rotated log records "startup reconciliation complete"
        with action=swept, and the planted rule is gone.
        FAILURE MEANING: a crash that strands a severed machine stays stranded
        across a restart -- the failure this phase exists to remove.

  P3-7  The state directory works as LocalSystem.
        EXPECTED: on first start, %ProgramData%\ScorpioSync\state is created
        granting ONLY NT AUTHORITY\SYSTEM and BUILTIN\Administrators, and the
        service can then write killswitch.cbor through it.
        This has NEVER been executed on any machine, elevated or not (P1
        residual, unchanged).

  P3-8  The SCM lifecycle.
        EXPECTED: sc start returns before the start timeout even though
        reconciliation runs first (the host reports StartPending with a wait
        hint, then Running); sc stop returns and every listener thread is
        joined; sc query reports STOPPED with exit code 0.
        A start failure reports service-specific exit code 0x53534B01, which
        means "the privileged control plane could not be built" -- the reason
        is in the rotated log and nowhere else (there is no Event Log source).
"@
