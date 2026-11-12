# Capture only our controlled child processes. No audit policy or system setting is changed.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('car','atomic')][string]$Mode,
    [Parameter(Mandatory)][string]$OutputDirectory
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$utf8 = [Text.UTF8Encoding]::new($false)
$out = [IO.Path]::GetFullPath($OutputDirectory)
if ((Test-Path -LiteralPath $out) -and @(Get-ChildItem -LiteralPath $out -Force).Count) { throw 'Use a new or empty output directory; completed evidence is protected.' }
$null = New-Item -ItemType Directory -Path $out -Force
$runId = [guid]::NewGuid().ToString('N')
$started = [datetime]::UtcNow
$psExe = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$cmdExe = 'C:\Windows\System32\cmd.exe'
$rows = [Collections.Generic.List[object]]::new()
$checks = [Collections.Generic.List[object]]::new()
function Save-Json($Path, $Object) { [IO.File]::WriteAllText($Path, ($Object | ConvertTo-Json -Depth 14) + "`n", $utf8) }
function Capture-Child([string]$CaseId,[string]$Executable,[string]$Arguments,[string]$ExpectedOutput,[string]$Technique,[bool]$ViaCommandPrompt=$false) {
    $stdout = Join-Path $out ($CaseId + '.stdout.txt')
    $stderr = Join-Path $out ($CaseId + '.stderr.txt')
    $before = [datetime]::UtcNow
    $wrapper = $null
    if ($ViaCommandPrompt) {
        $wrapper = Start-Process -FilePath $cmdExe -ArgumentList ('/d /c powershell.exe ' + $Arguments) -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        $native = $null
        for ($attempt=0; $attempt -lt 15 -and -not $native; $attempt++) {
            $native = Get-CimInstance Win32_Process -Filter "ParentProcessId=$($wrapper.Id) AND Name='powershell.exe'"
            if (-not $native) { Start-Sleep -Milliseconds 100 }
        }
        if (-not $native) { throw 'Atomic command-prompt child was not observed.' }
        $child = [Diagnostics.Process]::GetProcessById([int]$native.ProcessId)
    } else {
        $child = Start-Process -FilePath $Executable -ArgumentList $Arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        $native = Get-CimInstance Win32_Process -Filter "ProcessId=$($child.Id)"
    }
    if (-not $native) { throw "Process exited before its native snapshot: $CaseId" }
    $sampled = [datetime]::UtcNow
    $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($native.ParentProcessId)"
    if (-not $parent -or $parent.CreationDate -gt $native.CreationDate) { throw 'Parent unavailable or PID reuse detected.' }
    $child.WaitForExit(); $child.Refresh()
    if ($wrapper) { $wrapper.WaitForExit(); $wrapper.Refresh(); if ($wrapper.ExitCode -ne 0) { throw 'Atomic command prompt failed.' } }
    $executionExit = if ($wrapper) { $wrapper.ExitCode } else { $child.ExitCode }
    $text = [IO.File]::ReadAllText($stdout).Trim()
    if ($executionExit -ne 0 -or $text -cne $ExpectedOutput) { throw "Execution/output verification failed: $CaseId; executor_exit=$executionExit; stdout=$text" }
    $errorText = Get-Content -LiteralPath $stderr -Raw -Encoding oem
    if ($errorText) {
        if (-not $errorText.StartsWith('#< CLIXML')) { throw 'Unexpected stderr; inspect locally before publication.' }
        [xml]$streamXml = $errorText -replace '^#< CLIXML\s*',''
        foreach ($stream in $streamXml.DocumentElement.ChildNodes) {
            if ($stream.GetAttribute('S') -notin @('progress','information')) { throw 'Unexpected error stream.' }
        }
        foreach ($identity in $streamXml.SelectNodes('//*[@N="User"]')) { $identity.InnerText='CTI-LAB-USER' }
        foreach ($identity in $streamXml.SelectNodes('//*[@N="Computer"]')) { $identity.InnerText='CTI-LAB-HOST' }
        $errorText = "#< CLIXML`n" + $streamXml.OuterXml
        [IO.File]::WriteAllText($stderr,$errorText,$utf8)
    }
    # Publish selected fields only; no user identity, actual hostname or unrelated processes.
    $command = $native.CommandLine.Replace($out, '<LAB_WORKDIR>')
    $row = [ordered]@{
        '@timestamp' = $native.CreationDate.ToUniversalTime().ToString('o')
        event = @{ kind='event'; category=@('process'); type=@('start'); action='controlled-process-observed'; provider='Win32_Process CIM snapshot' }
        host = @{ name='CTI-LAB-HOST' }
        process = @{ name=$native.Name.ToLowerInvariant(); pid=[int]$native.ProcessId; command_line=$command; parent=@{ name=$parent.Name.ToLowerInvariant(); pid=[int]$parent.ProcessId } }
        observation = @{ sampled_at_utc=$sampled.ToString('o'); parent_created_utc=$parent.CreationDate.ToUniversalTime().ToString('o'); source='Get-CimInstance Win32_Process'; limitation='Live process snapshot after controlled launch, not Sysmon/4688 or a fleet-wide process-create stream' }
        lab = @{ run_id=$runId; case_id=$CaseId; ground_truth='benign'; technique=$Technique }
    }
    $rows.Add($row)
    $checks.Add(@{case_id=$CaseId; pid=[int]$child.Id; started_utc=$before.ToString('o'); finished_utc=[datetime]::UtcNow.ToString('o'); exit_code=[int]$executionExit; exit_code_source=$(if ($wrapper) {'command_prompt executor, which propagates last child exit status'} else {'launched child'}); checked_stdout=$text; stderr=$errorText; source='actual child execution'})
}
if ($Mode -eq 'car') {
    Capture-Child 'plain' $psExe '-NoProfile -NonInteractive -Command "Write-Output CTI-CAR-PLAIN; Start-Sleep -Seconds 4"' 'CTI-CAR-PLAIN' 'T1059.001'
    $code = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output 'CTI-CAR-ENCODED'; Start-Sleep -Seconds 4"))
    Capture-Child 'encoded' $psExe ('-NoProfile -NonInteractive -EncodedCommand ' + $code) 'CTI-CAR-ENCODED' 'T1059.001'
    Capture-Child 'cmd_control' $cmdExe '/d /c "echo CTI-CAR-CMD-CONTROL & ping.exe -n 5 127.0.0.1 > nul"' 'CTI-CAR-CMD-CONTROL' 'T1059.003'
} else {
    # ART a538de64: original executor is powershell.exe -e #{obfuscated_code}.
    # Parameter override is disclosed: default harmless greeting + a four-second observation delay.
    $original = 'JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcAIAAtAGYAIAAnAHgAJwApACkAIAAoACIAVwByACIAKwAiAGkAdAAiACsAIgBlAC0ASAAiACsAIgBvAHMAdAAgACcASAAiACsAIgBlAGwAIgArACIAbABvACwAIABmAHIAIgArACIAbwBtACAAUAAiACsAIgBvAHcAIgArACIAZQByAFMAIgArACIAaAAiACsAIgBlAGwAbAAhACcAIgApAA=='
    $reviewed = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($original))
    $inputCode = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($reviewed + '; Start-Sleep -Seconds 4'))
    Capture-Child 'art_powershell' $psExe ('-e ' + $inputCode) 'Hello, from PowerShell!' 'T1059.001' $true
    # ART 9e8894c0: parameterized batch creation and original Start-Process executor.
    $batch = Join-Path $out 'T1059.003_script.bat'
    [IO.File]::WriteAllText($batch, "@echo off`r`necho CTI-ATOMIC-BATCH`r`nping.exe -n 5 127.0.0.1 > nul`r`n", [Text.Encoding]::ASCII)
    $before = [datetime]::UtcNow
    $child = Start-Process $batch -WindowStyle Hidden -PassThru
    $native = Get-CimInstance Win32_Process -Filter "ProcessId=$($child.Id)"
    if (-not $native -or $native.Name -ine 'cmd.exe') { throw 'ART batch executor process was not captured.' }
    $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($native.ParentProcessId)"
    if (-not $parent -or $parent.CreationDate -gt $native.CreationDate) { throw 'Unverified batch parent.' }
    $sampled = [datetime]::UtcNow
    $child.WaitForExit(); $child.Refresh()
    if ($child.ExitCode -ne 0) { throw 'ART batch failed.' }
    $rows.Add([ordered]@{
        '@timestamp'=$native.CreationDate.ToUniversalTime().ToString('o')
        event=@{kind='event';category=@('process');type=@('start');action='controlled-process-observed';provider='Win32_Process CIM snapshot'}
        host=@{name='CTI-LAB-HOST'}
        process=@{name=$native.Name.ToLowerInvariant();pid=[int]$native.ProcessId;command_line=$native.CommandLine.Replace($out,'<LAB_WORKDIR>');parent=@{name=$parent.Name.ToLowerInvariant();pid=[int]$parent.ProcessId}}
        observation=@{sampled_at_utc=$sampled.ToString('o');parent_created_utc=$parent.CreationDate.ToUniversalTime().ToString('o');source='Get-CimInstance Win32_Process';limitation='Live snapshot; not a Sysmon/4688 event'}
        lab=@{run_id=$runId;case_id='art_batch';ground_truth='benign';technique='T1059.003'}
    })
    $checks.Add(@{case_id='art_batch';pid=[int]$child.Id;started_utc=$before.ToString('o');finished_utc=[datetime]::UtcNow.ToString('o');exit_code=[int]$child.ExitCode;checked_stdout='not captured for shell-association Start-Process executor';batch_sha256=(Get-FileHash -LiteralPath $batch -Algorithm SHA256).Hash.ToLowerInvariant()})
    # Delete only the exact file just created in this run, after checking its parent.
    if ((Split-Path -Parent ([IO.Path]::GetFullPath($batch))) -cne $out) { throw 'Cleanup path escaped run directory.' }
    Remove-Item -LiteralPath $batch
    Save-Json (Join-Path $out 'atomic-selection.json') @{
        source_commit='59ea87397c5faf8cad1e6ebe36fd625d0063e894'
        tests=@(
            @{guid='a538de64-1c74-46ed-aa60-b995ed302598';technique='T1059.001';executor='powershell.exe -e #{obfuscated_code}';decoded_default=$reviewed;input_change='Appended ; Start-Sleep -Seconds 4 before UTF-16LE encoding to allow native snapshot';actual_encoded_input=$inputCode;cleanup='No persistent payload artifact'}
            @{guid='9e8894c0-50bd-4525-a96c-d4ac78ece388';technique='T1059.003';executor='Start-Process "#{script_path}"';input_change='command_to_execute prints CTI-ATOMIC-BATCH then sends five ICMP requests to 127.0.0.1 for observation delay; script_path is isolated run directory';cleanup_verified=(-not (Test-Path -LiteralPath $batch))}
        )
        method='Reviewed, parameterized official atomic commands executed directly; Invoke-AtomicRedTeam module was not installed or invoked'
    }
}
[IO.File]::WriteAllText((Join-Path $out 'process-observations.jsonl'), (($rows | ForEach-Object { $_ | ConvertTo-Json -Depth 12 -Compress }) -join "`n") + "`n", $utf8)
# Corroborate only our PowerShell PIDs using genuine Event 400 XML. Event 400 is not the parent source.
$nativeXml = [Xml.XmlDocument]::new(); $null=$nativeXml.AppendChild($nativeXml.CreateElement('Events'))
foreach ($row in $rows) {
    if ($row.process.name -ne 'powershell.exe') { continue }
    $events = @(Get-WinEvent -FilterHashtable @{LogName='Windows PowerShell';Id=400;StartTime=$started.AddSeconds(-1).ToLocalTime()} -ErrorAction SilentlyContinue | Where-Object { $_.ProcessId -eq $row.process.pid -and $_.TimeCreated.ToUniversalTime() -ge $started })
    if ($events.Count -ne 1) { throw "Missing/ambiguous Event 400 for $($row.lab.case_id): $($events.Count)" }
    [xml]$xml=$events[0].ToXml()
    $xml.SelectSingleNode("//*[local-name()='Computer']").InnerText='CTI-LAB-HOST'
    $security=$xml.SelectSingleNode("//*[local-name()='Security']")
    if ($security -and $security.HasAttribute('UserID')) { $security.SetAttribute('UserID','S-1-0-0') }
    $null=$nativeXml.DocumentElement.AppendChild($nativeXml.ImportNode($xml.DocumentElement,$true))
}
$nativeXml.Save((Join-Path $out 'powershell-event400.xml'))
$artifacts = @(Get-ChildItem -LiteralPath $out -File | ForEach-Object { @{path=$_.Name;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()} })
Save-Json (Join-Path $out 'collection-manifest.json') @{
    run_id=$runId;mode=$Mode;started_utc=$started.ToString('o');finished_utc=[datetime]::UtcNow.ToString('o');count=$rows.Count;collector_sha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();cases=@($checks.ToArray());artifacts=$artifacts
    provenance='Actual controlled launches + native Win32_Process snapshots; PowerShell Event 400 corroboration. No Sysmon/4688/4104 claim.'
    redactions=@('Actual hostname replaced by CTI-LAB-HOST','Event400 user SID replaced by S-1-0-0','Run directory in batch command line replaced by <LAB_WORKDIR>','CLIXML stderr decoded from OEM to UTF-8; User and Computer fields replaced by CTI-LAB-USER and CTI-LAB-HOST')
    limitation='All cases are benign; snapshot collection is scoped to launched PIDs and is not continuous endpoint monitoring.'
}
@{mode=$Mode;run_id=$runId;process_observations=$rows.Count;event400_records=$nativeXml.DocumentElement.ChildNodes.Count} | ConvertTo-Json
