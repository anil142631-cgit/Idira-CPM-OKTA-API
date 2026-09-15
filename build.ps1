<#
    Script  : build.ps1
    Purpose : Builds OktaApiTokenPlugin.dll with the .NET Framework C# compiler (csc.exe) on the CPM server - no Visual Studio required
    Author  : Anilkumar Dadi | Anilkumar.Dadi@cyderes.com | Cyderes
    Version : 1.0
    Date    : 15-Sep-2026
#>
<#
.SYNOPSIS
  Builds OktaApiTokenPlugin.dll with the C# compiler that ships with .NET Framework 4.x (csc.exe).
  No Visual Studio needed. Run on the CPM server, from the folder that contains src\.

.EXAMPLE
  cd C:\OktaPlugin
  .\build.ps1
  Copy-Item .\OktaApiTokenPlugin.dll "C:\Program Files (x86)\CyberArk\Password Manager\bin\"
#>
param(
    [string] $CpmBin = "C:\Program Files (x86)\CyberArk\Password Manager\bin",
    [string] $Out = (Join-Path $PSScriptRoot 'OktaApiTokenPlugin.dll')
)
$ErrorActionPreference = 'Stop'

# ---- compiler ---------------------------------------------------------------------------------------
$csc = Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { $csc = Join-Path $env:windir 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
if (-not (Test-Path $csc)) { throw 'csc.exe not found - .NET Framework 4.x must be installed' }
$fw = Split-Path $csc
Write-Host "Compiler: $csc"

# ---- reference assemblies ---------------------------------------------------------------------------
function Resolve-Ref([string] $name) {
    $candidates = @(
        (Join-Path $fw "$name.dll"),
        "C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.8\$name.dll",
        "C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.7.2\$name.dll"
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    $gac = Get-ChildItem (Join-Path $env:windir "Microsoft.NET\assembly\GAC_MSIL\$name") -Recurse -Filter "$name.dll" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($gac) { return $gac.FullName }
    throw "Reference assembly $name.dll not found"
}
$frameworkRefs = 'System', 'System.Core', 'System.Net.Http', 'System.Web', 'System.Web.Extensions', 'System.Security', 'System.Xml' | ForEach-Object { Resolve-Ref $_ }

# ---- CyberArk SDK assemblies straight from the CPM bin folder ---------------------------------------
# CANetPluginInvoker.exe loads plugin dependencies from bin\_common and shares the account objects
# (MarshalByRefObject) across the plugin AppDomain. The plugin MUST be compiled against the SAME assembly
# identities the invoker loads, or the SecureString password fails to marshal across and arrives null.
# Reference _common first, then fall back to bin.
$sdkNames = 'CyberArk.Extensions.Plugins.Models', 'CyberArk.Extensions.Utilties', 'CyberArk.Extensions.Contracts', 'CyberArk.Extensions.Infra.Common'
$common = Join-Path $CpmBin '_common'
$sdkRefs = @()
foreach ($n in $sdkNames) {
    $c = Join-Path $common "$n.dll"; $b = Join-Path $CpmBin "$n.dll"
    if     (Test-Path $c) { $sdkRefs += $c }
    elseif (Test-Path $b) { $sdkRefs += $b }
}
if ($sdkRefs.Count -lt 2) { throw "CyberArk SDK assemblies not found in $common or $CpmBin" }
Write-Host "SDK references:"; $sdkRefs | ForEach-Object { Write-Host "  $_" }

# ---- compile ----------------------------------------------------------------------------------------
$sources = Get-ChildItem (Join-Path $PSScriptRoot 'src') -Filter *.cs | ForEach-Object { $_.FullName }
if (-not $sources) { throw "No .cs files under $PSScriptRoot\src" }

$args = @('/nologo', '/target:library', '/platform:anycpu', '/optimize+', "/out:$Out") +
        (($frameworkRefs + $sdkRefs) | ForEach-Object { "/r:$_" }) + $sources

& $csc @args
if ($LASTEXITCODE -ne 0) { throw "csc.exe failed with exit code $LASTEXITCODE" }

$dll = Get-Item $Out
Write-Host ""
Write-Host "Built $($dll.FullName)  ($($dll.Length) bytes)"
Write-Host "Next: Copy-Item `"$($dll.FullName)`" `"$CpmBin\`""
