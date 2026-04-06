$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

$venvPython = Join-Path $projectRoot "venv\\Scripts\\python.exe"

if (Test-Path $venvPython) {
    & $venvPython application.py
    exit $LASTEXITCODE
}

python application.py
exit $LASTEXITCODE
