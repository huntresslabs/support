# clears all exclusions within Defender except for Huntress exclusions
$exclude = "*Huntress*"

$pathExclusions = Get-MpPreference | select ExclusionPath 
foreach ($exclusion in $pathExclusions) {
     if (($exclusion.ExclusionPath -ne $null) -AND !($exclusion.ExclusionPath -like $exclude)) {
          Remove-MpPreference -ExclusionPath $exclusion.ExclusionPath
     }
}

$extensionExclusion = Get-MpPreference | select ExclusionExtension 
foreach ($exclusion in $extensionExclusion) {
    if ($exclusion.ExclusionExtension -ne $null) -AND !($exclusion.ExclusionPath -like $exclude)) {
        Remove-MpPreference -ExclusionExtension $exclusion.ExclusionExtension
    }
}

$processExclusions = Get-MpPreference | select ExclusionProcess
foreach ($exclusion in $processExclusions) {
    if ($exclusion.ExclusionProcess -ne $null) -AND !($exclusion.ExclusionPath -like $exclude)) {
        Remove-MpPreference -ExclusionProcess $exclusion.ExclusionProcess
    }
}
