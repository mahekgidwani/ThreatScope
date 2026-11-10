<#
.SYNOPSIS
  Loads the fictional demo data (backend/demo) into the running ThreatScope stack.
.DESCRIPTION
  Run from the repo root:  .\backend\demo\load-demo.ps1
  Sends events to the DEVELOPMENT database. Use -DryRun to only print them.
  Never stops, restarts or deletes anything.
#>
param([switch]$DryRun)
$ErrorActionPreference = 'Stop'

$running = docker compose ps --status running --services
if ($LASTEXITCODE -ne 0 -or $running -notcontains 'backend') {
    throw "The backend container is not running. Start it first with: docker compose up -d"
}

$extra = @()
if ($DryRun) { $extra = @('--dry-run') }
$run = @('compose', 'run', '--rm', '-e', 'THREATSCOPE_API_URL=http://backend:8000', 'backend', 'python', '-m')

function Invoke-Adapter([string[]]$AdapterArgs) {
    $ErrorActionPreference = 'Continue'   # docker prints progress on stderr, which 'Stop' would treat as a failure
    & docker @run @AdapterArgs @extra
    if ($LASTEXITCODE -ne 0) { throw "Adapter failed (exit $LASTEXITCODE): $($AdapterArgs[0])" }
}

Write-Host "1/3 look-alike domains"
Invoke-Adapter @('integrations.opensquat_adapter', '--keywords', 'demo/brands.txt', '--domains', 'demo/domains.txt')
Write-Host "2/3 honeypot (ModSecurity) log"
Invoke-Adapter @('integrations.modsec_adapter', 'demo/modsec_audit.log')
Write-Host "3/3 file analysis"
Invoke-Adapter @('integrations.analyse_file', 'demo/note.txt')

if ($DryRun) { Write-Host "Dry run: nothing was stored." }
else { Write-Host "Done. Re-running is safe: events already stored are reported as 'already recorded'." }
