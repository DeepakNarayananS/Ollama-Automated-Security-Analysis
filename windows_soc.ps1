$ErrorActionPreference = "SilentlyContinue"

Write-Host ""
Write-Host "=============================================="
Write-Host "       Local Windows Security AI"
Write-Host "       Foundation-Sec-8B-Reasoning"
Write-Host "=============================================="
Write-Host ""

# --------------------------------------------------
# Project paths
# --------------------------------------------------

$ProjectRoot = Split-Path -Parent $PSScriptRoot

$ConfigFile = Join-Path `
    $ProjectRoot `
    "config\config.json"

$ReportsDirectory = Join-Path `
    $PSScriptRoot `
    "reports"

# Create reports directory if required
New-Item `
    -ItemType Directory `
    -Path $ReportsDirectory `
    -Force | Out-Null


# --------------------------------------------------
# Load configuration
# --------------------------------------------------

$config = Get-Content `
    $ConfigFile `
    -Raw |
    ConvertFrom-Json

$ollamaUrl = $config.ollama.url
$model = $config.ollama.model


# --------------------------------------------------
# Collect Windows Security events
# --------------------------------------------------

Write-Host "[1/3] Collecting Windows Security events..."
Write-Host ""

$events = Get-WinEvent -FilterHashtable @{
    LogName = "Security"
    Id      = 4624,4625,4688
} -MaxEvents 150 -ErrorAction SilentlyContinue


$count = if ($events) {
    $events.Count
}
else {
    0
}

Write-Host "Collected $count events."


# --------------------------------------------------
# Prepare evidence
# --------------------------------------------------

$data = @(
    $events |
    Select-Object `
        TimeCreated,
        Id,
        ProviderName,
        Message
) | ConvertTo-Json -Depth 5


# --------------------------------------------------
# Security analysis prompt
# --------------------------------------------------

$prompt = @"
You are a defensive Windows SOC analyst.

Defensively analyze these Windows Security events for suspicious activity,
attack patterns, and security risks.

Provide:

## Executive Summary

## Overall Risk
LOW / MEDIUM / HIGH / CRITICAL

## Suspicious Activity

Identify suspicious events and explain why.

## Evidence

Only cite evidence actually present in the logs.

## Impact

Explain the potential security impact.

## Investigation

Give concrete next steps for a Windows administrator.

## Recommended Remediation

Give defensive actions.

## False Positives

Explain legitimate reasons the activity may occur.

IMPORTANT:

- Only report findings supported by the supplied logs.
- Do not invent missing events.
- Do not assume missing information.
- Do not hallucinate usernames, IP addresses, processes,
  commands, or attack techniques.
- Distinguish confirmed evidence from potential risks.
- A suspicious event does not automatically prove compromise.

WINDOWS SECURITY EVENTS:

$data
"@


# --------------------------------------------------
# Send to Foundation-Sec
# --------------------------------------------------

Write-Host ""
Write-Host "[2/3] Sending evidence to local Foundation-Sec..."
Write-Host ""

$body = @{
    model  = $model
    prompt = $prompt
    stream = $false
    options = @{
        temperature = 0.1
    }
} | ConvertTo-Json -Depth 10


try {

    $response = Invoke-RestMethod `
        -Uri $ollamaUrl `
        -Method Post `
        -ContentType "application/json" `
        -Body $body `
        -TimeoutSec 600

}
catch {

    Write-Host ""
    Write-Host "ERROR: Could not connect to Ollama."
    Write-Host ""
    Write-Host $_.Exception.Message

    exit 1
}


# --------------------------------------------------
# Display report
# --------------------------------------------------

Write-Host ""
Write-Host "[3/3] Analysis complete."
Write-Host ""

Write-Host "=============================================="
Write-Host "          WINDOWS SOC ASSESSMENT"
Write-Host "=============================================="
Write-Host ""

$report = $response.response

Write-Host $report


# --------------------------------------------------
# Save report
# --------------------------------------------------

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$reportFile = Join-Path `
    $ReportsDirectory `
    "windows_soc_$timestamp.md"

$report | Out-File `
    -FilePath $reportFile `
    -Encoding UTF8

Write-Host ""
Write-Host "=============================================="
Write-Host "Report saved:"
Write-Host $reportFile
Write-Host "=============================================="
Write-Host ""