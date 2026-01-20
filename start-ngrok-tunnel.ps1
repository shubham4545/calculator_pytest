# ============================================================================
# NGrok Tunnel Auto-Start Script with Logging
# Purpose: Start ngrok tunnel on Jenkins port (8080) with comprehensive logging
# ============================================================================

param(
    [string]$Port = 8080,
    [string]$LogDir = "$PSScriptRoot\ngrok-logs",
    [switch]$ShowURL
)

# Create log directory if it doesn't exist
if (!(Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir | Out-Null
}

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$logFile = "$LogDir\ngrok-$timestamp.log"
$urlFile = "$LogDir\ngrok-tunnel-url.txt"

# Function to log messages
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage
    Add-Content -Path $logFile -Value $logMessage
}

Write-Log "Starting ngrok tunnel auto-start script..."
Write-Log "Port: $Port"
Write-Log "Log Directory: $LogDir"

# Check if ngrok is installed
Write-Log "Checking ngrok installation..."
try {
    $ngrokVersion = ngrok --version 2>&1
    Write-Log "ngrok found: $ngrokVersion"
} catch {
    Write-Log "ERROR: ngrok not found! Please install ngrok first." "ERROR"
    Write-Log "Download from: https://ngrok.com/download" "ERROR"
    exit 1
}

# Check if Jenkins is accessible
Write-Log "Checking Jenkins on localhost:$Port..."
try {
    $jenkinsCheck = Invoke-WebRequest -Uri "http://localhost:$Port" -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
    Write-Log "Jenkins is accessible (Status: $($jenkinsCheck.StatusCode))"
} catch {
    if ($_.Exception.Response.StatusCode -eq 403) {
        Write-Log "Jenkins is running but requires authentication (403 Forbidden) - OK"
    } else {
        Write-Log "WARNING: Jenkins may not be running on port $Port" "WARN"
        Write-Log "Exception: $_" "WARN"
    }
}

# Start ngrok tunnel
Write-Log "Starting ngrok tunnel on port $Port..."
$ngrokStartTime = Get-Date

# Start ngrok in background process
$ngrokProcess = Start-Process ngrok -ArgumentList "http $Port" -NoNewWindow -PassThru

if ($ngrokProcess) {
    Write-Log "ngrok process started (PID: $($ngrokProcess.Id))"
} else {
    Write-Log "ERROR: Failed to start ngrok process" "ERROR"
    exit 1
}

# Wait for ngrok API to be ready
Write-Log "Waiting for ngrok API to be ready..."
$maxRetries = 10
$retryCount = 0
$apiReady = $false

while ($retryCount -lt $maxRetries -and -not $apiReady) {
    Start-Sleep -Seconds 2
    try {
        $apiResponse = Invoke-WebRequest -Uri "http://127.0.0.1:4040/api/tunnels" -UseBasicParsing -ErrorAction Stop
        if ($apiResponse.StatusCode -eq 200) {
            $apiReady = $true
            Write-Log "ngrok API is ready!"
        }
    } catch {
        $retryCount++
        Write-Log "Waiting for ngrok API... (attempt $retryCount/$maxRetries)"
    }
}

if (-not $apiReady) {
    Write-Log "ERROR: ngrok API failed to start within timeout" "ERROR"
    $ngrokProcess | Stop-Process -Force
    exit 1
}

# Get tunnel URL
try {
    $tunnelData = Invoke-WebRequest -Uri "http://127.0.0.1:4040/api/tunnels" -UseBasicParsing | ConvertFrom-Json
    $publicUrl = $tunnelData.tunnels[0].public_url
    
    Write-Log "================================"
    Write-Log "✓ NGROK TUNNEL ACTIVE"
    Write-Log "================================"
    Write-Log "Public URL: $publicUrl"
    Write-Log "Local URL: http://localhost:$Port"
    Write-Log "ngrok Web UI: http://127.0.0.1:4040"
    Write-Log "Process ID: $($ngrokProcess.Id)"
    Write-Log "Started: $ngrokStartTime"
    Write-Log "================================"
    
    # Save URL to file for reference
    @"
Public URL: $publicUrl
Local URL: http://localhost:$Port
Web UI: http://127.0.0.1:4040
Process ID: $($ngrokProcess.Id)
Started: $ngrokStartTime
"@ | Set-Content -Path $urlFile
    
    Write-Log "Tunnel URL saved to: $urlFile"
    
    if ($ShowURL) {
        Write-Host $publicUrl
    }
} catch {
    Write-Log "ERROR: Failed to retrieve tunnel URL" "ERROR"
    Write-Log "Exception: $_" "ERROR"
    $ngrokProcess | Stop-Process -Force
    exit 1
}

# Keep ngrok running
Write-Log "ngrok tunnel is running. Press Ctrl+C to stop..."
Write-Log "Log file: $logFile"

# Monitor ngrok process
while ($ngrokProcess -and -not $ngrokProcess.HasExited) {
    Start-Sleep -Seconds 5
    
    # Every 30 seconds, verify tunnel is still active
    if ([math]::Floor((Get-Date - $ngrokStartTime).TotalSeconds) % 30 -eq 0) {
        try {
            $tunnelData = Invoke-WebRequest -Uri "http://127.0.0.1:4040/api/tunnels" -UseBasicParsing | ConvertFrom-Json
            $status = $tunnelData.tunnels[0].public_url
            Write-Log "Tunnel status check: Active ($status)"
        } catch {
            Write-Log "WARNING: Could not verify tunnel status" "WARN"
        }
    }
}

Write-Log "ngrok tunnel stopped."
