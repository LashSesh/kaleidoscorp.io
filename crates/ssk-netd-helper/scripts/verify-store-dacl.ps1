<#
.SYNOPSIS
    Verifies that the ProgramData store DACL actually denies an unelevated writer.

.DESCRIPTION
    THIS SCRIPT WAS NEVER RUN BY THE AGENT THAT WROTE IT.

    The property it checks -- "after `provision`, an elevated process can write
    the store and an unelevated one cannot" -- requires elevation to establish
    and a second, unelevated logon to falsify. The implementing session ran
    unelevated on the user's real primary machine under a hard no-system-changes
    rule, so it verified the *argv* (crates/ssk-netd-helper/src/store.rs, mod
    tests) and left the *effect* to this script.

    Run it on a DISPOSABLE Windows VM. It creates a directory, takes ownership
    of it for BUILTIN\Administrators, and replaces its DACL. It does not touch
    the firewall, any service, or the registry.

.PARAMETER Root
    Scratch directory to provision. Defaults to a fresh temp path. Do NOT point
    this at a directory you care about: its DACL is replaced.

.EXAMPLE
    # From an ELEVATED PowerShell on a disposable VM:
    .\verify-store-dacl.ps1

.NOTES
    Expected result on success:
      [PASS] elevated write succeeded
      [PASS] unelevated write was denied
    A '[FAIL] unelevated write SUCCEEDED' means the DACL is not protecting the
    store and roadmap SEC-1 is still open at the storage layer.
#>
[CmdletBinding()]
param(
    [string]$Root = (Join-Path $env:TEMP ("ssk-dacl-check-" + [guid]::NewGuid().ToString('N')))
)

$ErrorActionPreference = 'Stop'

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Elevated)) {
    Write-Error "This script must be run from an ELEVATED shell. Half of it is the elevated leg."
}

$icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'

# These two argv lists must stay identical to setowner_args()/lockdown_args()
# in crates/ssk-netd-helper/src/store.rs. If they drift, this script stops
# testing the shipped behaviour.
$setownerArgs = @($Root, '/setowner', '*S-1-5-32-544', '/T')
$lockdownArgs = @($Root, '/inheritance:r',
                  '/grant:r', '*S-1-5-18:(OI)(CI)F',
                  '/grant:r', '*S-1-5-32-544:(OI)(CI)F',
                  '/T')

Write-Host "Provisioning $Root"
New-Item -ItemType Directory -Path $Root -Force | Out-Null

& $icacls @setownerArgs
if ($LASTEXITCODE -ne 0) { Write-Error "setowner failed with exit $LASTEXITCODE" }
& $icacls @lockdownArgs
if ($LASTEXITCODE -ne 0) { Write-Error "lockdown failed with exit $LASTEXITCODE" }

Write-Host "`n--- resulting DACL ---"
& $icacls $Root

# Leg 1: the elevated process must still be able to write. (The pre-P1 bug was
# that even this failed, because the caller was a UAC-FILTERED admin token, for
# which the Administrators ACE grants nothing.)
$probe = Join-Path $Root 'killswitch.cbor'
try {
    Set-Content -Path $probe -Value 'elevated-probe' -Encoding utf8 -ErrorAction Stop
    Write-Host "[PASS] elevated write succeeded" -ForegroundColor Green
} catch {
    Write-Host "[FAIL] elevated write was denied: $($_.Exception.Message)" -ForegroundColor Red
}

# Leg 2: an unelevated process must be denied. This cannot be spawned from an
# elevated shell (a child inherits the elevated token), so it is a MANUAL step.
Write-Host @"

--- MANUAL LEG (the one that actually proves the control) ---
Open a SEPARATE, UNELEVATED PowerShell window as the same user and run:

    Set-Content -Path '$probe' -Value 'unelevated-probe' -Encoding utf8

EXPECTED: 'Access to the path ... is denied' (UnauthorizedAccessException).
  [PASS] if it is denied.
  [FAIL] if it succeeds -- the store is writable by an unprivileged process
         owned by the same user, which is the %TEMP% hole (SEC-1) relocated,
         not closed.

Also confirm the read side:

    Get-Content '$probe'

EXPECTED: denied as well. The store has no Users ACE at all by design: both the
writer (engage) and the reader (release) are elevated, so nothing unprivileged
needs access.

Cleanup (elevated): Remove-Item -Recurse -Force '$Root'
"@
