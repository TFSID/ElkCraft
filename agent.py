#!/usr/bin/env python3
"""
Log Agent Installer Generator
Generates installation scripts for log forwarding agents on Linux and Windows
"""

import os
import json
from datetime import datetime

class LogAgentGenerator:
    def __init__(self):
        self.config = {
            "ingestion_server": "your-log-server.com",
            "ingestion_port": "5044",
            "agent_name": "log-forwarder",
            "version": "1.0.0"
        }
    
    def set_config(self, ingestion_server, port="5044", agent_name="log-forwarder"):
        """Set configuration for the agent"""
        self.config["ingestion_server"] = ingestion_server
        self.config["ingestion_port"] = port
        self.config["agent_name"] = agent_name
    
    def generate_linux_script(self):
        """Generate Linux installation script"""
        script = f'''#!/bin/bash
# Log Forwarding Agent Installation Script for Linux
# Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
# Ingestion Server: {self.config["ingestion_server"]}:{self.config["ingestion_port"]}

set -e

echo "=== Log Forwarding Agent Installation ==="
echo "Target OS: Linux (All Distributions)"
echo "Ingestion Server: {self.config['ingestion_server']}:{self.config['ingestion_port']}"
echo

# Detect Linux distribution
detect_distro() {{
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
    else
        DISTRO="unknown"
    fi
    echo "Detected distribution: $DISTRO"
}}

# Install dependencies based on distribution
install_dependencies() {{
    echo "Installing dependencies..."
    case $DISTRO in
        ubuntu|debian)
            apt-get update
            apt-get install -y curl wget gnupg software-properties-common rsyslog
            ;;
        centos|rhel|fedora)
            if command -v dnf &> /dev/null; then
                dnf install -y curl wget gnupg2 rsyslog
            else
                yum install -y curl wget gnupg2 rsyslog
            fi
            ;;
        arch)
            pacman -Sy --noconfirm curl wget gnupg rsyslog
            ;;
        *)
            echo "Unsupported distribution. Please install curl, wget, gnupg, and rsyslog manually."
            ;;
    esac
}}

# Install Filebeat (Elastic Beat Agent)
install_filebeat() {{
    echo "Installing Filebeat..."
    case $DISTRO in
        ubuntu|debian)
            wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
            echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | tee -a /etc/apt/sources.list.d/elastic-8.x.list
            apt-get update
            apt-get install -y filebeat
            ;;
        centos|rhel|fedora)
            rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
            cat > /etc/yum.repos.d/elastic.repo << 'EOF'
[elastic-8.x]
name=Elastic repository for 8.x packages
baseurl=https://artifacts.elastic.co/packages/8.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF
            if command -v dnf &> /dev/null; then
                dnf install -y filebeat
            else
                yum install -y filebeat
            fi
            ;;
        *)
            echo "Manual Filebeat installation required for this distribution"
            ;;
    esac
}}

# Configure Filebeat
configure_filebeat() {{
    echo "Configuring Filebeat..."
    
    # Backup original config
    cp /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.backup
    
    # Create new configuration
    cat > /etc/filebeat/filebeat.yml << 'EOF'
filebeat.inputs:
# Apache Access Logs
- type: log
  enabled: true
  paths:
    - /var/log/apache2/access.log
    - /var/log/httpd/access_log
    - /var/log/apache2/access*.log
    - /var/log/httpd/access*.log
  fields:
    log_type: apache_access
  fields_under_root: true

# Apache Error Logs  
- type: log
  enabled: true
  paths:
    - /var/log/apache2/error.log
    - /var/log/httpd/error_log
    - /var/log/apache2/error*.log
    - /var/log/httpd/error*.log
  fields:
    log_type: apache_error
  fields_under_root: true

# Nginx Logs
- type: log
  enabled: true
  paths:
    - /var/log/nginx/access.log
    - /var/log/nginx/error.log
    - /var/log/nginx/*.log
  fields:
    log_type: nginx
  fields_under_root: true

# System Logs
- type: log
  enabled: true
  paths:
    - /var/log/syslog
    - /var/log/messages
    - /var/log/secure
    - /var/log/auth.log
  fields:
    log_type: system
  fields_under_root: true

# Application Logs
- type: log
  enabled: true
  paths:
    - /var/log/*.log
    - /opt/*/logs/*.log
    - /home/*/logs/*.log
  fields:
    log_type: application
  fields_under_root: true
  exclude_files: ['\.gz$', '\.zip$']

# Output configuration
output.logstash:
  hosts: ["{self.config['ingestion_server']}:{self.config['ingestion_port']}"]

# Logging configuration
logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644

# Processor for adding metadata
processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_docker_metadata: ~
  - add_kubernetes_metadata: ~
EOF
}}

# Configure system logs forwarding
configure_rsyslog() {{
    echo "Configuring rsyslog for centralized logging..."
    
    # Backup original rsyslog config
    cp /etc/rsyslog.conf /etc/rsyslog.conf.backup
    
    # Add forwarding rule to rsyslog
    cat >> /etc/rsyslog.conf << 'EOF'

# Forward logs to ingestion server
*.* @@{self.config['ingestion_server']}:514
EOF
    
    # Create custom rsyslog config for application logs
    cat > /etc/rsyslog.d/50-default.conf << 'EOF'
# Forward all logs to remote server
$ActionQueueFileName fwdRule1 # unique name prefix for spool files
$ActionQueueMaxDiskSpace 1g   # 1gb space limit (use as much as possible)
$ActionQueueSaveOnShutdown on # save messages to disk on shutdown
$ActionQueueType LinkedList   # run asynchronously
$ActionResumeRetryCount -1    # infinite retries if host is down
*.* @@{self.config['ingestion_server']}:514
EOF
}}

# Start and enable services
enable_services() {{
    echo "Starting and enabling services..."
    
    # Enable and start rsyslog
    systemctl enable rsyslog
    systemctl restart rsyslog
    
    # Enable and start filebeat
    systemctl enable filebeat
    systemctl start filebeat
    
    echo "Services status:"
    systemctl status rsyslog --no-pager -l
    systemctl status filebeat --no-pager -l
}}

# Create monitoring script
create_monitoring_script() {{
    echo "Creating monitoring script..."
    
    cat > /usr/local/bin/log-agent-monitor.sh << 'EOF'
#!/bin/bash
# Log Agent Monitoring Script

echo "=== Log Agent Status ==="
echo "Timestamp: $(date)"
echo

echo "Filebeat Status:"
systemctl status filebeat --no-pager -l
echo

echo "Rsyslog Status:"
systemctl status rsyslog --no-pager -l
echo

echo "Recent Filebeat Logs:"
tail -20 /var/log/filebeat/filebeat
echo

echo "Connectivity Test:"
nc -zv {self.config['ingestion_server']} {self.config['ingestion_port']}
nc -zv {self.config['ingestion_server']} 514
EOF

    chmod +x /usr/local/bin/log-agent-monitor.sh
    echo "Monitoring script created at /usr/local/bin/log-agent-monitor.sh"
}}

# Main installation function
main() {{
    echo "Starting log agent installation..."
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        echo "Please run as root or with sudo"
        exit 1
    fi
    
    detect_distro
    install_dependencies
    install_filebeat
    configure_filebeat
    configure_rsyslog
    enable_services
    create_monitoring_script
    
    echo
    echo "=== Installation Complete ==="
    echo "Log forwarding agent has been installed and configured."
    echo "Logs will be forwarded to: {self.config['ingestion_server']}:{self.config['ingestion_port']}"
    echo
    echo "To monitor the agent, run: /usr/local/bin/log-agent-monitor.sh"
    echo "To test connectivity: filebeat test output"
    echo
    echo "Service management:"
    echo "  - Restart filebeat: systemctl restart filebeat"
    echo "  - Restart rsyslog: systemctl restart rsyslog"
    echo "  - Check logs: journalctl -u filebeat -f"
}}

# Run main function
main "$@"
'''
        return script
    
    def generate_windows_script(self):
        """Generate Windows installation script (PowerShell)"""
        script = f'''# Log Forwarding Agent Installation Script for Windows
# Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
# Ingestion Server: {self.config["ingestion_server"]}:{self.config["ingestion_port"]}

# Requires PowerShell 5.0+ and Administrator privileges

param(
    [switch]$Force,
    [string]$LogPath = "C:\\ProgramData\\LogAgent\\logs"
)

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {{
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}}

Write-Host "=== Log Forwarding Agent Installation ===" -ForegroundColor Green
Write-Host "Target OS: Windows" -ForegroundColor Yellow
Write-Host "Ingestion Server: {self.config['ingestion_server']}:{self.config['ingestion_port']}" -ForegroundColor Yellow
Write-Host ""

# Global variables
$FilebeatVersion = "8.11.0"
$FilebeatUrl = "https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-$FilebeatVersion-windows-x86_64.zip"
$InstallPath = "C:\\Program Files\\Filebeat"
$ConfigPath = "$InstallPath\\filebeat.yml"
$LogAgentPath = "C:\\ProgramData\\LogAgent"

# Create directories
function Create-Directories {{
    Write-Host "Creating directories..." -ForegroundColor Blue
    
    $directories = @(
        $InstallPath,
        $LogAgentPath,
        "$LogAgentPath\\logs",
        "$LogAgentPath\\config"
    )
    
    foreach ($dir in $directories) {{
        if (!(Test-Path -Path $dir)) {{
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Host "Created directory: $dir" -ForegroundColor Green
        }}
    }}
}}

# Download and install Filebeat
function Install-Filebeat {{
    Write-Host "Downloading and installing Filebeat..." -ForegroundColor Blue
    
    $tempFile = "$env:TEMP\\filebeat.zip"
    $tempExtract = "$env:TEMP\\filebeat-extract"
    
    try {{
        # Download Filebeat
        Write-Host "Downloading Filebeat from $FilebeatUrl..."
        Invoke-WebRequest -Uri $FilebeatUrl -OutFile $tempFile -UseBasicParsing
        
        # Extract
        Write-Host "Extracting Filebeat..."
        Expand-Archive -Path $tempFile -DestinationPath $tempExtract -Force
        
        # Copy files to installation directory
        $extractedPath = Get-ChildItem -Path $tempExtract -Directory | Select-Object -First 1
        Copy-Item -Path "$($extractedPath.FullName)\\*" -Destination $InstallPath -Recurse -Force
        
        Write-Host "Filebeat installed to $InstallPath" -ForegroundColor Green
    }}
    catch {{
        Write-Error "Failed to download or install Filebeat: $($_.Exception.Message)"
        exit 1
    }}
    finally {{
        # Cleanup
        if (Test-Path $tempFile) {{ Remove-Item $tempFile -Force }}
        if (Test-Path $tempExtract) {{ Remove-Item $tempExtract -Force -Recurse }}
    }}
}}

# Configure Filebeat
function Configure-Filebeat {{
    Write-Host "Configuring Filebeat..." -ForegroundColor Blue
    
    # Backup original config if exists
    if (Test-Path $ConfigPath) {{
        Copy-Item $ConfigPath "$ConfigPath.backup" -Force
    }}
    
    # Create Filebeat configuration
    $config = @"
filebeat.inputs:
# IIS Logs
- type: log
  enabled: true
  paths:
    - C:\\inetpub\\logs\\LogFiles\\W3SVC*\\*.log
    - C:\\Windows\\System32\\LogFiles\\W3SVC*\\*.log
  fields:
    log_type: iis_access
  fields_under_root: true

# IIS Error Logs
- type: log
  enabled: true
  paths:
    - C:\\inetpub\\logs\\FailedReqLogFiles\\*.log
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
    - C:\\Apache*\\logs\\access.log
    - C:\\Apache*\\logs\\error.log
    - C:\\xampp\\apache\\logs\\*.log
  fields:
    log_type: apache
  fields_under_root: true

# Application Logs
- type: log
  enabled: true
  paths:
    - C:\\ProgramData\\*\\logs\\*.log
    - C:\\Program Files\\*\\logs\\*.log
    - C:\\logs\\*.log
    - $LogPath\\*.log
  fields:
    log_type: application
  fields_under_root: true
  exclude_files: ['\.gz$$', '\.zip$$', '\.7z$$']

# Custom Application Logs
- type: log
  enabled: true
  paths:
    - C:\\temp\\*.log
    - C:\\var\\log\\*.log
  fields:
    log_type: custom
  fields_under_root: true

# Output configuration
output.logstash:
  hosts: ["{self.config['ingestion_server']}:{self.config['ingestion_port']}"]

# Logging configuration
logging.level: info
logging.to_files: true
logging.files:
  path: $LogAgentPath\\logs
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
}}

# Install Filebeat as Windows Service
function Install-FilebeatService {{
    Write-Host "Installing Filebeat as Windows Service..." -ForegroundColor Blue
    
    $serviceName = "filebeat"
    $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    
    if ($existingService) {{
        Write-Host "Stopping existing Filebeat service..."
        Stop-Service -Name $serviceName -Force
        & "$InstallPath\\filebeat.exe" remove
    }}
    
    # Install service
    Set-Location $InstallPath
    & ".\\filebeat.exe" install
    
    if ($LASTEXITCODE -eq 0) {{
        Write-Host "Filebeat service installed successfully" -ForegroundColor Green
        
        # Start service
        Start-Service -Name $serviceName
        Set-Service -Name $serviceName -StartupType Automatic
        
        Write-Host "Filebeat service started and set to automatic startup" -ForegroundColor Green
    }} else {{
        Write-Error "Failed to install Filebeat service"
        exit 1
    }}
}}

# Configure Windows Event Forwarding
function Configure-WindowsEventForwarding {{
    Write-Host "Configuring Windows Event Forwarding..." -ForegroundColor Blue
    
    # Enable WinRM if needed
    try {{
        winrm quickconfig -force | Out-Null
        Write-Host "WinRM configured for event forwarding" -ForegroundColor Green
    }}
    catch {{
        Write-Warning "Could not configure WinRM automatically"
    }}
}}

# Create monitoring script
function Create-MonitoringScript {{
    Write-Host "Creating monitoring script..." -ForegroundColor Blue
    
    $monitorScript = @"
# Log Agent Monitoring Script for Windows
# Usage: powershell -ExecutionPolicy Bypass -File monitor-log-agent.ps1

Write-Host "=== Log Agent Status ===" -ForegroundColor Green
Write-Host "Timestamp: $$(Get-Date)" -ForegroundColor Yellow
Write-Host ""

# Check Filebeat service
Write-Host "Filebeat Service Status:" -ForegroundColor Blue
Get-Service -Name filebeat | Format-Table -AutoSize

# Check recent Filebeat logs
Write-Host "Recent Filebeat Logs:" -ForegroundColor Blue
if (Test-Path "$LogAgentPath\\logs\\filebeat") {{
    Get-Content "$LogAgentPath\\logs\\filebeat" -Tail 20
}} else {{
    Write-Host "No Filebeat logs found" -ForegroundColor Yellow
}}

# Test connectivity
Write-Host "Connectivity Test:" -ForegroundColor Blue
try {{
    Test-NetConnection -ComputerName "{self.config['ingestion_server']}" -Port {self.config['ingestion_port']} -InformationLevel Quiet
    if ($$?) {{
        Write-Host "Connection to {self.config['ingestion_server']}:{self.config['ingestion_port']} - SUCCESS" -ForegroundColor Green
    }} else {{
        Write-Host "Connection to {self.config['ingestion_server']}:{self.config['ingestion_port']} - FAILED" -ForegroundColor Red
    }}
}} catch {{
    Write-Host "Connection test failed: $$($_.Exception.Message)" -ForegroundColor Red
}}

# Show disk usage
Write-Host "Log Directory Disk Usage:" -ForegroundColor Blue
if (Test-Path $LogAgentPath) {{
    Get-ChildItem $LogAgentPath -Recurse | Measure-Object -Property Length -Sum | Select-Object @{{Name="Size (MB)"; Expression={{[math]::Round($_.Sum/1MB,2)}}}}
}}
"@

    $monitorScript | Out-File -FilePath "$LogAgentPath\\monitor-log-agent.ps1" -Encoding UTF8
    Write-Host "Monitoring script created at $LogAgentPath\\monitor-log-agent.ps1" -ForegroundColor Green
}}

# Create uninstall script
function Create-UninstallScript {{
    Write-Host "Creating uninstall script..." -ForegroundColor Blue
    
    $uninstallScript = @"
# Uninstall Log Agent
Write-Host "Uninstalling Log Agent..." -ForegroundColor Yellow

# Stop and remove Filebeat service
try {{
    Stop-Service -Name filebeat -Force -ErrorAction SilentlyContinue
    & "$InstallPath\\filebeat.exe" remove
    Write-Host "Filebeat service removed" -ForegroundColor Green
}} catch {{
    Write-Warning "Could not remove Filebeat service: $$($_.Exception.Message)"
}}

# Remove installation directory
if (Test-Path "$InstallPath") {{
    Remove-Item "$InstallPath" -Force -Recurse
    Write-Host "Installation directory removed" -ForegroundColor Green
}}

# Remove log agent data (optional)
Read-Host "Press Enter to also remove log data directory ($LogAgentPath), or Ctrl+C to cancel"
if (Test-Path "$LogAgentPath") {{
    Remove-Item "$LogAgentPath" -Force -Recurse
    Write-Host "Log agent data removed" -ForegroundColor Green
}}

Write-Host "Uninstallation complete" -ForegroundColor Green
"@

    $uninstallScript | Out-File -FilePath "$LogAgentPath\\uninstall-log-agent.ps1" -Encoding UTF8
    Write-Host "Uninstall script created at $LogAgentPath\\uninstall-log-agent.ps1" -ForegroundColor Green
}}

# Main installation function
function Main {{
    Write-Host "Starting log agent installation..." -ForegroundColor Green
    
    try {{
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
        Write-Host "Logs will be forwarded to: {self.config['ingestion_server']}:{self.config['ingestion_port']}" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Management Commands:" -ForegroundColor Blue
        Write-Host "  - Monitor agent: powershell $LogAgentPath\\monitor-log-agent.ps1" -ForegroundColor White
        Write-Host "  - Restart service: Restart-Service filebeat" -ForegroundColor White
        Write-Host "  - Check service: Get-Service filebeat" -ForegroundColor White
        Write-Host "  - Test config: & '$InstallPath\\filebeat.exe' test config" -ForegroundColor White
        Write-Host "  - Test output: & '$InstallPath\\filebeat.exe' test output" -ForegroundColor White
        Write-Host "  - Uninstall: powershell $LogAgentPath\\uninstall-log-agent.ps1" -ForegroundColor White
        Write-Host ""
    }}
    catch {{
        Write-Error "Installation failed: $($_.Exception.Message)"
        exit 1
    }}
}}

# Run main function
Main
'''
        return script
    
    def save_scripts(self, output_dir="./generated_scripts"):
        """Save generated scripts to files"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Generate and save Linux script
        linux_script = self.generate_linux_script()
        linux_file = os.path.join(output_dir, "install-log-agent-linux.sh")
        with open(linux_file, 'w', encoding='utf-8') as f:
            f.write(linux_script)
        os.chmod(linux_file, 0o755)  # Make executable
        
        # Generate and save Windows script
        windows_script = self.generate_windows_script()
        windows_file = os.path.join(output_dir, "install-log-agent-windows.ps1")
        with open(windows_file, 'w', encoding='utf-8') as f:
            f.write(windows_script)
        
        # Create configuration file
        config_file = os.path.join(output_dir, "agent-config.json")
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(self.config, f, indent=2)
        
        return {
            "linux_script": linux_file,
            "windows_script": windows_file,
            "config_file": config_file,
            "output_directory": output_dir
        }

def main():
    """Main function to demonstrate usage"""
    print("Log Agent Installer Generator")
    print("=" * 40)
    
    # Create generator instance
    generator = LogAgentGenerator()
    
    # Get user input for configuration
    print("\\nConfiguration Setup:")
    ingestion_server = input("Enter ingestion server address (default: your-log-server.com): ").strip()
    if not ingestion_server:
        ingestion_server = "your-log-server.com"
    
    port = input("Enter ingestion server port (default: 5044): ").strip()
    if not port:
        port = "5044"
    
    agent_name = input("Enter agent name (default: log-forwarder): ").strip()
    if not agent_name:
        agent_name = "log-forwarder"
    
    # Set configuration
    generator.set_config(ingestion_server, port, agent_name)
    
    # Generate and save scripts
    print("\\nGenerating installation scripts...")
    result = generator.save_scripts()
    
    print("\\nGeneration Complete!")
    print(f"Linux script: {result['linux_script']}")
    print(f"Windows script: {result['windows_script']}")
    print(f"Configuration: {result['config_file']}")
    print(f"Output directory: {result['output_directory']}")
    
    print("\\nUsage Instructions:")
    print("For Linux:")
    print(f"  sudo bash {result['linux_script']}")
    print("\\nFor Windows:")
    print(f"  powershell -ExecutionPolicy Bypass -File {result['windows_script']}")

if __name__ == "__main__":
    main()