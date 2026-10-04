# Pure fixture checks. Dot-sourcing does not query CIM or change the host.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\openvpn-vm-host-probe.ps1')
function Assert-Probe([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
$facts = [ordered]@{ total_memory_bytes=16GB; free_memory_bytes=8GB; storage_free_bytes=120GB; management_tools=@('Get-VM'); query_failures=@() }
$result = Get-OpenVpnHostAssessment -Facts $facts
Assert-Probe $result.host_resources_sufficient 'sufficient fixture resources refused'
Assert-Probe (-not $result.vm_ready -and -not $result.release_ready) 'resources cannot authorize a VM or release'
foreach ($field in @('total_memory_bytes','free_memory_bytes','storage_free_bytes')) {
    $copy = [ordered]@{}; foreach ($key in $facts.Keys) { $copy[$key]=$facts[$key] }; $copy[$field]=$null
    Assert-Probe (-not (Get-OpenVpnHostAssessment -Facts $copy).host_resources_sufficient) 'unknown resource accepted'
    $copy[$field]=1
    Assert-Probe (-not (Get-OpenVpnHostAssessment -Facts $copy).host_resources_sufficient) 'insufficient resource accepted'
}
$facts.management_tools=@(); Assert-Probe (-not (Get-OpenVpnHostAssessment -Facts $facts).host_resources_sufficient) 'missing VM tools accepted'
$facts.management_tools=$null; Assert-Probe (-not (Get-OpenVpnHostAssessment -Facts $facts).host_resources_sufficient) 'unknown VM tools accepted'
$facts.management_tools=@('VBoxManage'); $facts.query_failures=@('denied')
Assert-Probe (-not (Get-OpenVpnHostAssessment -Facts $facts).host_resources_sufficient) 'partial inventory accepted'
Write-Output 'Host probe fixture checks passed (11 assertions); no host inventory collected.'
