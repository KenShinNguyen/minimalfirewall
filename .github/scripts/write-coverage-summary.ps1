$ErrorActionPreference = "Stop"

$coverageFiles = @(
    Get-ChildItem -LiteralPath "TestResults" -Filter "coverage.cobertura.xml" -File -Recurse -ErrorAction SilentlyContinue
)

if ($coverageFiles.Count -ne 1) {
    throw "Expected exactly one Cobertura report under TestResults; found $($coverageFiles.Count)."
}

[xml]$coverageDocument = Get-Content -LiteralPath $coverageFiles[0].FullName -Raw
$coverage = $coverageDocument.DocumentElement

if ($null -eq $coverage -or $coverage.LocalName -ne "coverage") {
    throw "The generated coverage report is not a valid Cobertura document."
}

$culture = [System.Globalization.CultureInfo]::InvariantCulture
$lineRateText = $coverage.GetAttribute("line-rate")
$branchRateText = $coverage.GetAttribute("branch-rate")

if ([string]::IsNullOrWhiteSpace($lineRateText) -or [string]::IsNullOrWhiteSpace($branchRateText)) {
    throw "Cobertura report is missing line-rate or branch-rate metadata."
}

$lineCoverage = [double]::Parse($lineRateText, $culture) * 100
$branchCoverage = [double]::Parse($branchRateText, $culture) * 100
$lineCoverageText = $lineCoverage.ToString("0.00", $culture) + "%"
$branchCoverageText = $branchCoverage.ToString("0.00", $culture) + "%"

$lineCounts = "{0} / {1}" -f $coverage.GetAttribute("lines-covered"), $coverage.GetAttribute("lines-valid")
$branchCounts = "{0} / {1}" -f $coverage.GetAttribute("branches-covered"), $coverage.GetAttribute("branches-valid")

$summaryLines = @(
    "## Code coverage",
    "",
    "| Metric | Covered / valid | Coverage |",
    "|---|---:|---:|",
    "| Lines | $lineCounts | $lineCoverageText |",
    "| Branches | $branchCounts | $branchCoverageText |",
    "",
    "Measurement excludes *.Designer.cs source files and the test assembly."
)

$minimumLineRaw = $env:MIN_LINE_COVERAGE
$minimumBranchRaw = $env:MIN_BRANCH_COVERAGE
$thresholdConfigured = -not [string]::IsNullOrWhiteSpace($minimumLineRaw) -or -not [string]::IsNullOrWhiteSpace($minimumBranchRaw)

if ($thresholdConfigured) {
    if ([string]::IsNullOrWhiteSpace($minimumLineRaw) -or [string]::IsNullOrWhiteSpace($minimumBranchRaw)) {
        throw "Both MIN_LINE_COVERAGE and MIN_BRANCH_COVERAGE must be configured together."
    }

    $minimumLine = [double]::Parse($minimumLineRaw, $culture)
    $minimumBranch = [double]::Parse($minimumBranchRaw, $culture)

    if ($minimumLine -lt 0 -or $minimumLine -gt 100 -or $minimumBranch -lt 0 -or $minimumBranch -gt 100) {
        throw "Coverage thresholds must be between 0 and 100."
    }

    $lineResult = if ($lineCoverage -ge $minimumLine) { "PASS" } else { "FAIL" }
    $branchResult = if ($branchCoverage -ge $minimumBranch) { "PASS" } else { "FAIL" }

    $summaryLines += @(
        "",
        "| Floor | Required | Result |",
        "|---|---:|---:|",
        "| Lines | $($minimumLine.ToString('0.00', $culture))% | $lineResult |",
        "| Branches | $($minimumBranch.ToString('0.00', $culture))% | $branchResult |"
    )

    if ($lineCoverage -lt $minimumLine -or $branchCoverage -lt $minimumBranch) {
        throw "Coverage is below the configured floor. Lines: $lineCoverageText (minimum $minimumLineRaw%); branches: $branchCoverageText (minimum $minimumBranchRaw%)."
    }
}
else {
    $summaryLines += @(
        "",
        "Coverage floor: not enforced in this baseline-measurement commit. The numeric floor will be added after reviewing this run's measured baseline."
    )
}

if ([string]::IsNullOrWhiteSpace($env:GITHUB_STEP_SUMMARY)) {
    throw "GITHUB_STEP_SUMMARY is not available."
}

Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value ($summaryLines -join [Environment]::NewLine) -Encoding utf8

Write-Host "Line coverage: $lineCoverageText ($lineCounts)"
Write-Host "Branch coverage: $branchCoverageText ($branchCounts)"
