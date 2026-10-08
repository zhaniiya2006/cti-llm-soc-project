# Collect four harmless launches and their genuine Windows PowerShell Event 400 records.
[CmdletBinding()]
param([string]$OutputDirectory, [string]$PrivateDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false)
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $PSScriptRoot 'data' }
if (-not $PrivateDirectory) { $PrivateDirectory = Join-Path (Split-Path -Parent $repoRoot) 'week5-private' }
$publicPath = [IO.Path]::GetFullPath($OutputDirectory)
$privatePath = [IO.Path]::GetFullPath($PrivateDirectory)
$repoPath = [IO.Path]::GetFullPath($repoRoot).TrimEnd('\')
if ($privatePath.StartsWith($repoPath + '\', [StringComparison]::OrdinalIgnoreCase) -or $privatePath -eq $repoPath) {
    throw 'Private originals must remain outside the repository.'
}
foreach ($name in @('windows-events.xml', 'powershell-events.jsonl', 'collection-manifest.json')) {
    if (Test-Path -LiteralPath (Join-Path $publicPath $name)) { throw "Existing collection protected: $name. Select another output directory." }
}
$null = Get-WinEvent -ListLog 'Windows PowerShell'
$runId = [guid]::NewGuid().ToString('N')
$runPrivatePath = Join-Path $privatePath $runId
$null = New-Item -ItemType Directory -Path $runPrivatePath -Force
$executable = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$definitions = @(
    @{ id = 'plain'; encoded = $false; hidden = $false },
    @{ id = 'encoded'; encoded = $true; hidden = $false },
    @{ id = 'hidden'; encoded = $false; hidden = $true },
    @{ id = 'encoded_hidden'; encoded = $true; hidden = $true }
)
$cases = New-Object 'System.Collections.Generic.List[object]'
$started = [datetime]::UtcNow
foreach ($definition in $definitions) {
    $marker = "CTIW5-$runId-$($definition.id)"
    $payload = "Write-Output '$marker'"
    $arguments = '-NoProfile -NonInteractive'
    if ($definition.hidden) { $arguments += ' -WindowStyle Hidden' }
    if ($definition.encoded) {
        $arguments += ' -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
    } else { $arguments += ' -Command "' + $payload + '"' }
    $stdoutPath = Join-Path $runPrivatePath ($definition.id + '.stdout.txt')
    $stderrPath = Join-Path $runPrivatePath ($definition.id + '.stderr.txt')
    $child = Start-Process -FilePath $executable -ArgumentList $arguments -WindowStyle Hidden -PassThru -Wait -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    $child.WaitForExit()
    $child.Refresh()
    $stdout = (Get-Content -LiteralPath $stdoutPath -Raw).TrimEnd([char[]]"`r`n")
    if ($child.ExitCode -ne 0 -or $stdout -cne $marker) { throw "Unverified case $($definition.id)" }
    $stderr = Get-Content -LiteralPath $stderrPath -Raw
    $stderrKind = 'empty'
    if (-not [string]::IsNullOrWhiteSpace($stderr)) {
        if (-not $stderr.StartsWith('#< CLIXML')) { throw 'Unexpected child stderr; inspect private output.' }
        [xml]$progressXml = $stderr -replace '^#< CLIXML\s*', ''
        $nodes = @($progressXml.SelectNodes("/*[local-name()='Objs']/*"))
        if ($nodes.Count -eq 0 -or @($nodes | Where-Object { $_.LocalName -ne 'Obj' -or $_.GetAttribute('S') -ne 'progress' }).Count -gt 0) {
            throw 'Child stderr contained a non-progress stream.'
        }
        $stderrKind = 'powershell_progress_only'
    }
    $cases.Add([ordered]@{ case_id = $definition.id; pid = [int]$child.Id; exit_code = [int]$child.ExitCode; payload = $payload; stdout = $stdout; stderr = $stderrKind; ground_truth = 'benign' })
}
$finished = [datetime]::UtcNow
[IO.File]::WriteAllText((Join-Path $runPrivatePath 'execution.json'), (@{ run_id = $runId; started_utc = $started.ToString('o'); finished_utc = $finished.ToString('o'); cases = @($cases.ToArray()) } | ConvertTo-Json -Depth 7), $utf8)
$selected = @{}
for ($attempt = 0; $attempt -lt 10; $attempt++) {
    # Expand the provider filter by one second; enforce the exact interval below.
    # This avoids a boundary event being lost by provider time rounding.
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Windows PowerShell'; Id = 400; StartTime = $started.AddSeconds(-1).ToLocalTime(); EndTime = $finished.AddSeconds(1).ToLocalTime() } -ErrorAction SilentlyContinue)
    foreach ($case in $cases) {
        $matches = @($events | Where-Object { [int]$_.ProcessId -eq $case.pid -and $_.TimeCreated.ToUniversalTime() -ge $started -and $_.TimeCreated.ToUniversalTime() -le $finished })
        if ($matches.Count -gt 1) { throw 'Ambiguous native event selection.' }
        if ($matches.Count -eq 1) { $selected[$case.case_id] = $matches[0] }
    }
    if ($selected.Count -eq 4) { break }
    Start-Sleep -Milliseconds 500
}
if ($selected.Count -ne 4) { throw 'All four native Event 400 records were not found; no public dataset produced.' }
$publicXml = New-Object System.Xml.XmlDocument
$null = $publicXml.AppendChild($publicXml.CreateElement('Events'))
$jsonLines = New-Object 'System.Collections.Generic.List[string]'
foreach ($case in $cases) {
    $record = $selected[$case.case_id]
    $original = $record.ToXml()
    $originalPath = Join-Path $runPrivatePath ($case.case_id + '.original.xml')
    [IO.File]::WriteAllText($originalPath, $original, $utf8)
    [xml]$eventXml = $original
    $context = ($eventXml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']") | ForEach-Object { $_.InnerText }) -join "`n"
    $commandMatches = [regex]::Matches($context, '(?m)^[ \t]*HostApplication=([^\r\n]*)')
    if ($commandMatches.Count -ne 1) { throw 'Missing or ambiguous HostApplication.' }
    $commandLine = $commandMatches[0].Groups[1].Value
    if ($commandLine -match '-EncodedCommand\s+(\S+)') {
        $decoded = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Matches[1]))
        if ($decoded -cne $case.payload) { throw 'Event encoded payload differs from executed case.' }
    } elseif (-not $commandLine.Contains($case.payload)) { throw 'Event does not contain executed payload.' }
    $case.record_id = [long]$record.RecordId
    $case.timestamp_utc = $record.TimeCreated.ToUniversalTime().ToString('o')
    $case.command_line = $commandLine
    $case.original_xml_sha256 = (Get-FileHash -LiteralPath $originalPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $computer = $eventXml.SelectSingleNode("/*[local-name()='Event']/*[local-name()='System']/*[local-name()='Computer']")
    $computer.InnerText = 'CTI-LAB-HOST'
    $security = $eventXml.SelectSingleNode("/*[local-name()='Event']/*[local-name()='System']/*[local-name()='Security']")
    if ($null -ne $security -and $security.HasAttribute('UserID')) { $security.SetAttribute('UserID', 'S-1-0-0') }
    $null = $publicXml.DocumentElement.AppendChild($publicXml.ImportNode($eventXml.DocumentElement, $true))
    $document = [ordered]@{
        '@timestamp' = $case.timestamp_utc
        event = @{ code = '400'; provider = 'PowerShell'; action = 'engine-start' }
        winlog = @{ channel = 'Windows PowerShell'; record_id = $case.record_id }
        host = @{ name = 'CTI-LAB-HOST' }
        process = @{ name = 'powershell.exe'; pid = $case.pid; command_line = $commandLine }
        lab = @{ run_id = $runId; case_id = $case.case_id; ground_truth = 'benign' }
    }
    $jsonLines.Add(($document | ConvertTo-Json -Depth 7 -Compress))
}
$null = New-Item -ItemType Directory -Path $publicPath -Force
$settings = New-Object System.Xml.XmlWriterSettings
$settings.Encoding = $utf8
$settings.Indent = $true
$writer = [Xml.XmlWriter]::Create((Join-Path $publicPath 'windows-events.xml'), $settings)
try { $publicXml.Save($writer) } finally { $writer.Dispose() }
[IO.File]::WriteAllText((Join-Path $publicPath 'powershell-events.jsonl'), ($jsonLines -join "`n") + "`n", $utf8)
$manifest = [ordered]@{
    run_id = $runId; started_utc = $started.ToString('o'); finished_utc = $finished.ToString('o'); collected_utc = [datetime]::UtcNow.ToString('o')
    event_count = 4; collector_version = $PSVersionTable.PSVersion.ToString(); executable = $executable
    collector_sha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
    cases = @($cases.ToArray())
    redactions = @('Event/System/Computer replaced with CTI-LAB-HOST', 'Event/System/Security/@UserID replaced with S-1-0-0 when present')
    scope = 'Genuine native events from four controlled benign launches; launch flags alone do not establish malware.'
    raw_originals = 'PrivateDirectory/<run_id>/*.original.xml outside repository'
    artifacts = @('windows-events.xml', 'powershell-events.jsonl') | ForEach-Object { @{ path = $_; sha256 = (Get-FileHash -LiteralPath (Join-Path $publicPath $_) -Algorithm SHA256).Hash.ToLowerInvariant() } }
}
[IO.File]::WriteAllText((Join-Path $publicPath 'collection-manifest.json'), ($manifest | ConvertTo-Json -Depth 9) + "`n", $utf8)
@{ run_id = $runId; native_event_count = $selected.Count; public_directory = $publicPath } | ConvertTo-Json
