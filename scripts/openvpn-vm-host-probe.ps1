<#
.SYNOPSIS
Read-only Windows host inventory for planning a disposable OpenVPN acceptance VM.
.DESCRIPTION
No installation, VM start, feature change, registry write, network mutation or
external executable invocation. Output is planning evidence, never VM acceptance.
Unknown facts remain null and block the local resource plan. Requirements below
are project planning margins, not Microsoft's minimum system requirements.
#>
[CmdletBinding()]
param([ValidatePattern('^[A-Za-z]:$')][string]$StorageDrive = $env:SystemDrive)

function Get-OpenVpnHostAssessment {
    param([System.Collections.IDictionary]$Facts)
    $blockers = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $Facts.total_memory_bytes -or $Facts.total_memory_bytes -lt 12GB) { $blockers.Add('host_memory_below_project_plan_or_unknown') }
    if ($null -eq $Facts.free_memory_bytes -or $Facts.free_memory_bytes -lt 6GB) { $blockers.Add('free_memory_below_project_plan_or_unknown') }
    if ($null -eq $Facts.storage_free_bytes -or $Facts.storage_free_bytes -lt 96GB) { $blockers.Add('storage_below_project_plan_or_unknown') }
    if (@($Facts.management_tools | Where-Object { $_ -is [string] -and -not [string]::IsNullOrWhiteSpace($_) }).Count -eq 0) { $blockers.Add('vm_management_unavailable_or_unknown') }
    if (@($Facts.query_failures).Count -gt 0) { $blockers.Add('inventory_incomplete') }
    [ordered]@{
        schema = 1
        collected_unix_ms = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        facts = $Facts
        project_plan = [ordered]@{ host_memory_bytes = 12GB; free_memory_bytes = 6GB; storage_free_bytes = 96GB; concurrent_guests = 1 }
        host_resources_sufficient = ($blockers.Count -eq 0)
        vm_ready = $false
        release_ready = $false
        blockers = @($blockers.ToArray())
        remaining_checks = @('disposable_vm_and_snapshot', 'console_access', 'isolated_test_network', 'approved_distribution_and_driver', 'test_credentials_and_principals', 'actual_guest_requirements_and_vm_cases')
    }
}

function Get-OpenVpnHostFacts {
    param([string]$Drive)
    $failures = [System.Collections.Generic.List[string]]::new()
    $facts = [ordered]@{
        os_caption = $null; os_build = $null; hypervisor_present = $null
        total_memory_bytes = $null; free_memory_bytes = $null
        storage_drive = $Drive; storage_free_bytes = $null
        elevated = ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        management_tools = @(); services = @(); query_failures = @()
    }
    try {
        $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $facts.hypervisor_present = [bool]$computer.HypervisorPresent
        $facts.total_memory_bytes = [long]$computer.TotalPhysicalMemory
    } catch { $failures.Add('computer_inventory_unavailable') }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $facts.os_caption = [string]$os.Caption; $facts.os_build = [string]$os.BuildNumber
        $facts.free_memory_bytes = [long]$os.FreePhysicalMemory * 1KB
    } catch { $failures.Add('os_inventory_unavailable') }
    try {
        $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$Drive'" -ErrorAction Stop
        if ($null -eq $disk -or $disk.DriveType -ne 3) { $failures.Add('local_fixed_storage_unavailable') }
        else { $facts.storage_free_bytes = [long]$disk.FreeSpace }
    } catch { $failures.Add('storage_inventory_unavailable') }
    $facts.management_tools = @(Get-Command -Name Get-VM,VBoxManage,vmrun,qemu-system-x86_64 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
    $candidates = @()
    if ($env:ProgramFiles) { $candidates += @{Name='VBoxManage.exe';Path=(Join-Path $env:ProgramFiles 'Oracle\VirtualBox\VBoxManage.exe')} }
    if (${env:ProgramFiles(x86)}) { $candidates += @{Name='vmrun.exe';Path=(Join-Path ${env:ProgramFiles(x86)} 'VMware\VMware Workstation\vmrun.exe')} }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate.Path -PathType Leaf) { $facts.management_tools += $candidate.Name }
    }
    $facts.management_tools = @($facts.management_tools | Sort-Object -Unique)
    $facts.services = @(Get-Service -Name vmms,vmcompute,VMAuthdService,VMwareHostd -ErrorAction SilentlyContinue | ForEach-Object { @{name=$_.Name;status=$_.Status.ToString()} })
    $facts.query_failures = @($failures.ToArray())
    $facts
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($env:OS -ne 'Windows_NT') { throw 'This read-only host probe requires Windows.' }
    Get-OpenVpnHostAssessment -Facts (Get-OpenVpnHostFacts -Drive $StorageDrive) | ConvertTo-Json -Depth 6
}
