param([Parameter(Mandatory=$true)][string]$Tool,[Parameter(Mandatory=$true)][string]$Fixture,[Parameter(Mandatory=$true)][string]$Dependency,[string]$X86Dependency)
$ErrorActionPreference='Stop'
$Tool=(Resolve-Path $Tool).Path
$root=Join-Path $PSScriptRoot ('../validation-artifacts/integration/'+[Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Force -Path $root | Out-Null
$root=(Resolve-Path $root).Path
function Check($condition,$message) { if (!$condition) { throw $message } }
function Inspect($path) {
 $output=& $Tool --json $path
 Check ($LASTEXITCODE -eq 0) "Inspection failed: $output"
 Check ($output | Test-Json -SchemaFile (Join-Path $PSScriptRoot '../docs/schema.json')) 'JSON schema validation failed'
 return ($output | ConvertFrom-Json)
}
$unicode=Join-Path $root '診断 café'
New-Item -ItemType Directory -Force -Path $unicode | Out-Null
$target=Join-Path $unicode 'target.exe'
Copy-Item -LiteralPath $Fixture -Destination $target -Force
$data=Inspect $target
Check ($data.target.path -eq $target) 'Unicode JSON path lost'
$delay=@($data.delay_imports | Where-Object name -eq 'fixture-dependency.dll')
Check ($delay.Count -eq 1) 'Delay import missing'
Check ($delay[0].resolution -eq 'missing_under_model') 'Missing fixture not detected'
Copy-Item -LiteralPath $Dependency -Destination (Join-Path $unicode 'fixture-dependency.dll') -Force
$data=Inspect $target
Check (($data.delay_imports | Where-Object name -eq 'fixture-dependency.dll').resolution -eq 'candidate_under_model') 'Local candidate missing'
if ($X86Dependency) {
 Copy-Item -LiteralPath $X86Dependency -Destination (Join-Path $unicode 'fixture-dependency.dll') -Force
 $data=Inspect $target
 Check ((($data.delay_imports | Where-Object name -eq 'fixture-dependency.dll').candidates | Where-Object architecture_check -eq 'machine_mismatch').Count -eq 1) 'Architecture mismatch missed'
}
# Patch a controlled import string, never execute fixture code.
$bytes=[IO.File]::ReadAllBytes($target)
$needle=[Text.Encoding]::ASCII.GetBytes('fixture-dependency.dll')
$offset=-1
for($i=0;$i -le $bytes.Length-$needle.Length;$i++) {
 $equal=$true
 for($j=0;$j -lt $needle.Length;$j++) { if($bytes[$i+$j] -ne $needle[$j]) {$equal=$false;break} }
 if($equal) {$offset=$i;break}
}
Check ($offset -ge 0) 'Fixture import string absent'
$api=[Text.Encoding]::ASCII.GetBytes('api-ms-test.dll'+[char]0)
[Array]::Copy($api,0,$bytes,$offset,$api.Length)
$apiPath=Join-Path $unicode 'api.exe'
[IO.File]::WriteAllBytes($apiPath,$bytes)
$data=Inspect $apiPath
Check (($data.delay_imports | Where-Object name -eq 'api-ms-test.dll').classification -eq 'api_set_contract') 'API-set pattern missed'
$bad=Join-Path $unicode 'bad.exe'
[IO.File]::WriteAllBytes($bad,[byte[]](1,2,3))
$errorJson=(& $Tool --json $bad | ConvertFrom-Json)
Check ($LASTEXITCODE -eq 1 -and $errorJson.error) 'Malformed input not controlled'
$remote=(& $Tool --json '\\never-contact.invalid\share\target.exe' | ConvertFrom-Json)
Check ($LASTEXITCODE -eq 1 -and $remote.error -match 'rejected') 'Remote target not rejected'
foreach($path in @('//never-contact.invalid/share/target.exe','\\?\UNC\never-contact.invalid\share\target.exe','\\.\pipe\test')) {
 $reject=(& $Tool --json $path | ConvertFrom-Json)
 Check ($LASTEXITCODE -eq 1 -and $reject.error -match 'rejected') 'Remote/device spelling not rejected'
}
$junction=Join-Path $root 'junction'
New-Item -ItemType Junction -Path $junction -Target $unicode | Out-Null
$reject=(& $Tool --json (Join-Path $junction 'target.exe') | ConvertFrom-Json)
Check ($LASTEXITCODE -eq 1 -and $reject.error -match 'reparse') 'Reparse ancestor not rejected'
# Duplicate candidates: an app-local copy of a system import is never executed.
$kernel=Join-Path $unicode 'KERNEL32.dll'
Copy-Item -LiteralPath "$env:WINDIR\System32\kernel32.dll" -Destination $kernel -Force
$data=Inspect $target
Check ((($data.imports | Where-Object name -eq 'KERNEL32.dll').candidates | Where-Object status -eq 'present').Count -ge 2) 'Duplicate candidates missing'
$manifest=$target+'.manifest'
[IO.File]::WriteAllText($manifest,'<assembly/>')
Check ((Inspect $target).target.external_manifest) 'External manifest missed'
foreach($path in @("$env:WINDIR\System32\notepad.exe","$env:WINDIR\System32\kernel32.dll","$env:WINDIR\System32\ntdll.dll","$env:WINDIR\SysWOW64\kernel32.dll")) {
 $data=Inspect $path
 Write-Output "$path : $($data.target.architecture), $($data.imports.Count) normal, $($data.delay_imports.Count) delay"
}
Write-Output 'Integration and independent JSON parsing passed.'
