param(
    [ValidateSet('Detect','Stop','Start')][string]$Action = 'Detect',
    [string]$Executable = ''
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
if ($Action -eq 'Detect') {
    $candidates = @()
    if ($env:CLASH_VERGE_EXE) { $candidates += $env:CLASH_VERGE_EXE }
    $keys = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*')
    foreach ($entry in (Get-ItemProperty $keys -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -eq 'Clash Verge'})) {
        if ($entry.InstallLocation) { $candidates += Join-Path ($entry.InstallLocation.Trim('"')) 'clash-verge.exe' }
    }
    $candidates += @( (Join-Path $env:LOCALAPPDATA 'Clash Verge\clash-verge.exe'), (Join-Path $env:ProgramFiles 'Clash Verge\clash-verge.exe') )
    $found = $candidates | Where-Object {Test-Path -LiteralPath $_ -PathType Leaf} | Select-Object -First 1
    @{executable=$found} | ConvertTo-Json -Compress
    exit 0
}
if (-not (Test-Path -LiteralPath $Executable -PathType Leaf) -or [IO.Path]::GetFileName($Executable) -ne 'clash-verge.exe') {
    throw 'Invalid Clash Verge executable.'
}
if ($Action -eq 'Stop') {
    Get-Process -Name 'clash-verge' -ErrorAction SilentlyContinue | Where-Object {$_.Path -eq $Executable} | Stop-Process
    Start-Sleep -Milliseconds 500
}
if ($Action -eq 'Start') {
    $null = Start-Process -FilePath $Executable -WindowStyle Hidden -PassThru
}
Write-Output '{}'
