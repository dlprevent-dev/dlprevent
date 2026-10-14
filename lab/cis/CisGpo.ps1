# Shared by the Set-Cis*Baseline.ps1 scripts: build GPOs by writing their files straight into
# SYSVOL (GptTmpl.inf, audit.csv, Registry.pol) and registering them on the GPO object.
Import-Module GroupPolicy, ActiveDirectory

$domain = Get-ADDomain
$sysvol = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies"

# CSE pairs for gPCMachineExtensionNames, already sorted by GUID as AD wants them.
$ExtRegistry = '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]'
$ExtSecurity = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
$ExtAudit    = '[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]'

function Get-CisGpo([string]$Name) {
    $g = Get-GPO -Name $Name -ErrorAction SilentlyContinue
    if (-not $g) { $g = New-GPO -Name $Name -Comment "CIS baseline - lab/cis/$(Split-Path $MyInvocation.PSCommandPath -Leaf)" }
    $g
}

function Write-GpoFile($Gpo, [string]$RelPath, [string]$Text, [string]$Encoding) {
    $path = Join-Path "$sysvol\{$($Gpo.Id)}\Machine" $RelPath
    New-Item -ItemType Directory -Force -Path (Split-Path $path) | Out-Null
    Set-Content -Path $path -Value $Text -Encoding $Encoding
}

function Write-SecTemplate($Gpo, [string]$Body) {
    $inf = "[Unicode]`r`nUnicode=yes`r`n$($Body -replace "`r?`n", "`r`n")`r`n[Version]`r`nsignature=`"`$CHICAGO`$`"`r`nRevision=1"
    Write-GpoFile $Gpo 'Microsoft\Windows NT\SecEdit\GptTmpl.inf' $inf Unicode
}

# Registry.pol in one write. Set-GPRegistryValue rewrites the file once per value and trips over
# its own Registry.tmp when something (Defender, DFSR) holds it. Format: "PReg", version 1, then
# [key;value;type;size;data] with UTF-16LE text.
function Write-RegistryPol($Gpo, [string]$Lines) {
    $u = [Text.Encoding]::Unicode
    $ms = New-Object IO.MemoryStream
    $w = New-Object IO.BinaryWriter $ms
    $w.Write([byte[]](0x50, 0x52, 0x65, 0x67)); $w.Write([uint32]1)
    foreach ($line in $Lines -split "`r?`n" | Where-Object { $_ }) {
        $key, $name, $type, $data = $line -split '\|', 4
        if ($type -eq 'D') { $t = 4; $bytes = [BitConverter]::GetBytes([uint32]$data) }
        else { $t = 1; $bytes = $u.GetBytes("$data`0") }
        $w.Write($u.GetBytes("[$key`0;$name`0;")); $w.Write([uint32]$t)
        $w.Write($u.GetBytes(';')); $w.Write([uint32]$bytes.Length)
        $w.Write($u.GetBytes(';')); $w.Write($bytes); $w.Write($u.GetBytes(']'))
    }
    $dir = "$sysvol\{$($Gpo.Id)}\Machine"
    Remove-Item "$dir\Registry.tmp" -ErrorAction SilentlyContinue
    [IO.File]::WriteAllBytes("$dir\Registry.pol", $ms.ToArray())
}

# Files written straight into SYSVOL are only picked up when the CSE is registered on the GPO
# object and the version moves, in AD and in GPT.INI alike.
function Publish-Gpo($Gpo, [string]$ExtensionNames) {
    $dn = "CN={$($Gpo.Id)},CN=Policies,CN=System,$($domain.DistinguishedName)"
    $v = (Get-ADObject $dn -Properties versionNumber).versionNumber + 1
    Set-ADObject $dn -Replace @{ versionNumber = $v; gPCMachineExtensionNames = $ExtensionNames }
    Set-Content -Path "$sysvol\{$($Gpo.Id)}\GPT.INI" -Value "[General]`r`nVersion=$v" -Encoding ASCII
}

function Set-FirstLink($Gpo, [string]$Target) {
    $linked = (Get-GPInheritance -Target $Target).GpoLinks | Where-Object GpoId -eq $Gpo.Id
    if ($linked) { Set-GPLink -Guid $Gpo.Id -Target $Target -LinkEnabled Yes -Order 1 | Out-Null }
    else { New-GPLink -Guid $Gpo.Id -Target $Target -LinkEnabled Yes -Order 1 | Out-Null }
}

# Advanced audit policy. Lines "Subcategory|{GUID}|n", n: 1 = Success, 2 = Failure, 3 = both.
function Write-AuditCsv($Gpo, [string]$Lines) {
    $names = @{ 1 = 'Success'; 2 = 'Failure'; 3 = 'Success and Failure' }
    $csv = @('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value')
    foreach ($line in $Lines -split "`r?`n" | Where-Object { $_ }) {
        $sub, $guid, $val = $line -split '\|'
        $csv += ",System,Audit $sub,$guid,$($names[[int]$val]),,$val"
    }
    Write-GpoFile $Gpo 'Microsoft\Windows NT\Audit\audit.csv' ($csv -join "`r`n") ASCII
}
