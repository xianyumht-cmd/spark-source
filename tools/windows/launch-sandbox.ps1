Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$exePath = Join-Path $repoRoot 'Spark1.5.2F.exe'
if (-not (Test-Path $exePath)) {
    throw "Place Spark1.5.2F.exe at the repository root first: $exePath"
}

$outputPath = Join-Path $repoRoot 'unpack-output'
New-Item -ItemType Directory -Force -Path $outputPath | Out-Null

$inputXml = [System.Security.SecurityElement]::Escape($repoRoot)
$outputXml = [System.Security.SecurityElement]::Escape($outputPath)
$wsbPath = Join-Path $env:TEMP ('spark-unpack-' + [Guid]::NewGuid().ToString('N') + '.wsb')

$command = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "New-Item -ItemType Directory -Force C:\work | Out-Null; Copy-Item C:\input\Spark1.5.2F.exe C:\work\Spark1.5.2F.exe; & C:\input\tools\windows\collect-unpacked.ps1 -ExePath C:\work\Spark1.5.2F.exe -OutDir C:\output"'
$commandXml = [System.Security.SecurityElement]::Escape($command)

$xml = @"
<Configuration>
  <Networking>Disable</Networking>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <PrinterRedirection>Disable</PrinterRedirection>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <ProtectedClient>Enable</ProtectedClient>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$inputXml</HostFolder>
      <SandboxFolder>C:\input</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>$outputXml</HostFolder>
      <SandboxFolder>C:\output</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>$commandXml</Command>
  </LogonCommand>
</Configuration>
"@

Set-Content -LiteralPath $wsbPath -Value $xml -Encoding UTF8
Start-Process -FilePath $wsbPath
Write-Host "Windows Sandbox launched. Output will be written to: $outputPath"
