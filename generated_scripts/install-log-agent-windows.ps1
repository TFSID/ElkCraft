# Log Forwarding Agent Installation Script for Windows
# Generated on: 2025-06-25 16:23:33
# Ingestion Server: localhost:5044

# Requires PowerShell 5.0+ and Administrator privileges

param(
    [switch]$Force
)

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

Write-Host "=== Log Forwarding Agent Installation ===" -ForegroundColor Green
Write-Host "Target OS: Windows" -ForegroundColor Yellow
Write-Host "Ingestion Server: localhost:5044" -ForegroundColor Yellow
Write-Host ""

# Global variables
$FilebeatVersion = "8.11.0"
$FilebeatUrl = "https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.11.0-windows-x86_64.zip"
$InstallPath = "C:\Program Files\Filebeat"
$ConfigPath = "$InstallPath\filebeat.yml"
$LogAgentPath = "C:\ProgramData\LogAgent"
$FilebeatLogPath = "$LogAgentPath\logs" # Filebeat internal logs path

# Create directories
function Create-Directories {
    Write-Host "Creating directories..." -ForegroundColor Blue
    
    $directories = @(
        $InstallPath,
        $LogAgentPath,
        $FilebeatLogPath,
        "$LogAgentPath\config"
    )
    
    foreach ($dir in $directories) {
        if (!(Test-Path -Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Host "Created directory: $dir" -ForegroundColor Green
        }
    }
}

# Download and install Filebeat
function Install-Filebeat {
    Write-Host "Downloading and installing Filebeat..." -ForegroundColor Blue
    
    $tempFile = "$env:TEMP\filebeat.zip"
    $tempExtract = "$env:TEMP\filebeat-extract"
    
    try {
        # Download Filebeat
        Write-Host "Downloading Filebeat from $FilebeatUrl..."
        Invoke-WebRequest -Uri $FilebeatUrl -OutFile $tempFile -UseBasicParsing
        
        # Extract
        Write-Host "Extracting Filebeat..."
        Expand-Archive -Path $tempFile -DestinationPath $tempExtract -Force
        
        # Copy files to installation directory
        $extractedPath = Get-ChildItem -Path $tempExtract -Directory | Select-Object -First 1
        Copy-Item -Path "$($extractedPath.FullName)\*" -Destination $InstallPath -Recurse -Force
        
        Write-Host "Filebeat installed to $InstallPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to download or install Filebeat: $($_.Exception.Message)"
        exit 1
    }
    finally {
        # Cleanup
        if (Test-Path $tempFile) { Remove-Item $tempFile -Force }
        if (Test-Path $tempExtract) { Remove-Item $tempExtract -Force -Recurse }
    }
}

# Configure Filebeat
function Configure-Filebeat {
    Write-Host "Configuring Filebeat..." -ForegroundColor Blue
    
    # Backup original config if exists
    if (Test-Path $ConfigPath) {
        Copy-Item $ConfigPath "$ConfigPath.backup" -Force
    }
    
    # Create Filebeat configuration
    $config = @"
filebeat.inputs:
# IIS Logs
- type: log
  enabled: true
  paths:
    - C:\inetpub\logs\LogFiles\W3SVC*\*.log
    - C:\Windows\System32\LogFiles\W3SVC*\*.log
  fields:
    log_type: iis_access
  fields_under_root: true

# IIS Error Logs
- type: log
  enabled: true
  paths:
    - C:\inetpub\logs\FailedReqLogFiles\*.log
  fields:
    log_type: iis_error
  fields_under_root: true

# Windows Event Logs
- type: winlogbeat
  enabled: true
  event_logs:
    - name: Application
      level: error, warning, info
    - name: Security
    - name: System
  fields:
    log_type: windows_event
  fields_under_root: true

# Apache Logs (if installed)
- type: log
  enabled: true
  paths:
    - C:\Apache*\logs\access.log
    - C:\Apache*\logs\error.log
    - C:\xampp\apache\logs\*.log
  fields:
    log_type: apache
  fields_under_root: true

# Application Logs (standard locations)
- type: log
  enabled: true
  paths:
    - C:\ProgramData\*\logs\*.log
    - C:\Program Files\*\logs\*.log
    - C:\logs\*.log
  fields:
    log_type: application
  fields_under_root: true
  exclude_files: ['\\.gz$$', '\\.zip$$', '\\.7z$$']

# Output configuration
output.logstash:
  hosts: ["localhost:5044"]

# Logging configuration for Filebeat's internal logs
logging.level: info
logging.to_files: true
logging.files:
  path: $FilebeatLogPath
  name: filebeat
  keepfiles: 7
  permissions: 0644

# Processors
processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_process_metadata:
      match_pids: [system.process.ppid]
      target: system.process.parent
"@

    $config | Out-File -FilePath $ConfigPath -Encoding UTF8
    Write-Host "Filebeat configuration created at $ConfigPath" -ForegroundColor Green
}

# Install Filebeat as Windows Service
function Install-FilebeatService {
    Write-Host "Installing Filebeat as Windows Service..." -ForegroundColor Blue
    
    $serviceName = "filebeat"
    $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    
    if ($existingService) {
        Write-Host "Stopping existing Filebeat service..."
        Stop-Service -Name $serviceName -Force
        & "$InstallPath\filebeat.exe" remove
    }
    
    # Install service
    Set-Location $InstallPath
    & ".\filebeat.exe" install
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Filebeat service installed successfully" -ForegroundColor Green
        
        # Start service
        Start-Service -Name $serviceName
        Set-Service -Name $serviceName -StartupType Automatic
        
        Write-Host "Filebeat service started and set to automatic startup" -ForegroundColor Green
    } else {
        Write-Error "Failed to install Filebeat service"
        exit 1
    }
}

# Configure Windows Event Forwarding (Note: This typically refers to WEF/WEC, not directly controlled by agent install)
function Configure-WindowsEventForwarding {
    Write-Host "Note: Filebeat collects Windows Event Logs directly. This function placeholder for WinRM setup for other scenarios." -ForegroundColor Yellow
    # This section would typically enable WinRM if needed for *remote* event collection,
    # but Filebeat itself collects local event logs.
    try {
        # Check if WinRM is enabled (for general remote management, not strictly for Filebeat)
        $winrmStatus = Get-Service -Name WinRM -ErrorAction SilentlyContinue
        if ($null -eq $winrmStatus -or $winrmStatus.Status -ne 'Running') {
            Write-Host "Attempting to enable WinRM for potential remote management (if needed)..."
            winrm quickconfig -force | Out-Null
            Write-Host "WinRM configured for event forwarding" -ForegroundColor Green
        } else {
            Write-Host "WinRM service is already running." -ForegroundColor Green
        }
    }
    catch {
        Write-Warning "Could not configure WinRM automatically: $($_.Exception.Message)"
    }
}

# Create monitoring script
function Create-MonitoringScript {
    Write-Host "Creating monitoring script..." -ForegroundColor Blue
    
    $monitorScript = @"
# Log Agent Monitoring Script for Windows
# Usage: powershell -ExecutionPolicy Bypass -File "$LogAgentPath\monitor-log-agent.ps1"

Write-Host "=== Log Agent Status ===" -ForegroundColor Green
Write-Host "Timestamp: $$(Get-Date)" -ForegroundColor Yellow
Write-Host ""

# Check Filebeat service
Write-Host "Filebeat Service Status:" -ForegroundColor Blue
Get-Service -Name filebeat | Format-Table -AutoSize

# Check recent Filebeat logs
Write-Host "Recent Filebeat Logs:" -ForegroundColor Blue
if (Test-Path "$FilebeatLogPath\filebeat") {
    Get-Content "$FilebeatLogPath\filebeat" -Tail 20
} else {
    Write-Host "No Filebeat logs found at $FilebeatLogPath\filebeat" -ForegroundColor Yellow
}

# Test connectivity
Write-Host "Connectivity Test:" -ForegroundColor Blue
try {
    Test-NetConnection -ComputerName "localhost" -Port 5044 -InformationLevel Quiet
    if ($$?) {
        Write-Host "Connection to localhost:5044 - SUCCESS" -ForegroundColor Green
    } else {
        Write-Host "Connection to localhost:5044 - FAILED" -ForegroundColor Red
    }
} catch {
    Write-Host "Connection test failed: $$($_.Exception.Message)" -ForegroundColor Red
}

# Show disk usage
Write-Host "Log Directory Disk Usage:" -ForegroundColor Blue
if (Test-Path "$LogAgentPath") {
    Get-ChildItem "$LogAgentPath" -Recurse | Measure-Object -Property Length -Sum | Select-Object @{Name="Size (MB)"; Expression={[math]::Round($_.Sum/1MB,2)}}
}
"@

    $monitorScript | Out-File -FilePath "$LogAgentPath\monitor-log-agent.ps1" -Encoding UTF8
    Write-Host "Monitoring script created at $LogAgentPath\monitor-log-agent.ps1" -ForegroundColor Green
}

# Create uninstall script
function Create-UninstallScript {
    Write-Host "Creating uninstall script..." -ForegroundColor Blue
    
    $uninstallScript = @"
# Uninstall Log Agent
# Usage: powershell -ExecutionPolicy Bypass -File "$LogAgentPath\uninstall-log-agent.ps1"

Write-Host "Uninstalling Log Agent..." -ForegroundColor Yellow

# Define paths from where the agent was installed
$$InstallPath = "C:\Program Files\Filebeat"
$$LogAgentPath = "C:\ProgramData\LogAgent"

# Stop and remove Filebeat service
try {
    Stop-Service -Name filebeat -Force -ErrorAction SilentlyContinue
    & "$$InstallPath\filebeat.exe" remove
    Write-Host "Filebeat service removed" -ForegroundColor Green
} catch {
    Write-Warning "Could not remove Filebeat service: $$($_.Exception.Message)"
}

# Remove installation directory
if (Test-Path "$$InstallPath") {
    Remove-Item "$$InstallPath" -Recurse -Force
    Write-Host "Installation directory removed" -ForegroundColor Green
}

# Remove log agent data (optional)
Write-Host "Log data and scripts are located at $$LogAgentPath"
$$confirmRemoval = Read-Host "Do you want to remove the log data directory (Y/N)? This will delete all logs and monitoring scripts."
if ($$confirmRemoval -eq "Y") {
    if (Test-Path "$$LogAgentPath") {
        Remove-Item "$$LogAgentPath" -Recurse -Force
        Write-Host "Log agent data removed" -ForegroundColor Green
    }
} else {
    Write-Host "Log data directory retained." -ForegroundColor Yellow
}

Write-Host "Uninstallation complete" -ForegroundColor Green
"@

    $uninstallScript | Out-File -FilePath "$LogAgentPath\uninstall-log-agent.ps1" -Encoding UTF8
    Write-Host "Uninstall script created at $LogAgentPath\uninstall-log-agent.ps1" -ForegroundColor Green
}

# Main installation function
function Main {
    Write-Host "Starting log agent installation..." -ForegroundColor Green
    
    try {
        Create-Directories
        Install-Filebeat
        Configure-Filebeat
        Install-FilebeatService
        Configure-WindowsEventForwarding
        Create-MonitoringScript
        Create-UninstallScript
        
        Write-Host ""
        Write-Host "=== Installation Complete ===" -ForegroundColor Green
        Write-Host "Log forwarding agent has been installed and configured." -ForegroundColor White
        Write-Host "Logs will be forwarded to: localhost:5044" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Management Commands:" -ForegroundColor Blue
        Write-Host "   - Monitor agent: powershell -ExecutionPolicy Bypass -File '$LogAgentPath\monitor-log-agent.ps1'" -ForegroundColor White
        Write-Host "   - Restart service: Restart-Service filebeat" -ForegroundColor White
        Write-Host "   - Check service: Get-Service filebeat" -ForegroundColor White
        Write-Host "   - Test config: & '$InstallPath\filebeat.exe' test config" -ForegroundColor White
        Write-Host "   - Test output: & '$InstallPath\filebeat.exe' test output" -ForegroundColor White
        Write-Host "   - Uninstall: powershell -ExecutionPolicy Bypass -File '$LogAgentPath\uninstall-log-agent.ps1'" -ForegroundColor White
        Write-Host ""
    }
    catch {
        Write-Error "Installation failed: $($_.Exception.Message)"
        exit 1
    }
}

# Run main function
Main
