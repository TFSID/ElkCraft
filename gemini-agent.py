#!/usr/bin/env python3
"""
Enhanced Log Agent Installer Generator
Generates installation scripts for log forwarding agents on Linux and Windows
with improved menu system and configuration options
"""

import os
import json
from datetime import datetime

class LogAgentGenerator:
    def __init__(self):
        # Initialize default configuration parameters
        # These defaults are aligned with common ELK stack configurations
        self.config = {
            "ingestion_server": "your-log-server.com", # Placeholder for the Logstash server address
            "ingestion_port": "5044", # Standard Logstash Beats input port
            "agent_name": "log-forwarder",
            "version": "1.0.0", # Internal version of the generator script
            
            # Linux specific configurations
            "linux_rsyslog_port": "514", # Standard syslog port for rsyslog forwarding
            "linux_filebeat_log_path": "/var/log/filebeat", # Default internal log path for Filebeat on Linux
            "linux_custom_log_paths": [], # List of custom log paths for Linux Filebeat (empty by default)

            # Windows specific configurations
            "windows_filebeat_version": "8.11.0", # Recommended Filebeat version for Windows
            "windows_filebeat_install_path": "C:\\Program Files\\Filebeat", # Default Filebeat installation directory on Windows
            "windows_log_agent_data_path": "C:\\ProgramData\\LogAgent", # Base path for agent data (logs, scripts) on Windows
            "windows_custom_log_paths": [], # List of custom log paths for Windows Filebeat (empty by default)

            # Common configurations
            "filebeat_log_keepfiles": 7, # Number of Filebeat internal log files to keep
        }
    
    def set_config(self, ingestion_server, port="5044", agent_name="log-forwarder",
                   linux_rsyslog_port="514",
                   linux_filebeat_log_path="/var/log/filebeat",
                   filebeat_log_keepfiles=7,
                   windows_filebeat_version="8.11.0",
                   windows_filebeat_install_path="C:\\Program Files\\Filebeat",
                   windows_log_agent_data_path="C:\\ProgramData\\LogAgent",
                   linux_custom_log_paths=None, # Use None for mutable defaults
                   windows_custom_log_paths=None):
        """
        Set configuration for the agent.
        
        Args:
            ingestion_server (str): The address of the log ingestion server.
            port (str, optional): The port of the log ingestion server. Defaults to "5044" (Logstash Beats port).
            agent_name (str, optional): The name of the log forwarding agent. Defaults to "log-forwarder".
            linux_rsyslog_port (str, optional): Port for rsyslog forwarding on Linux. Defaults to "514" (standard syslog).
            linux_filebeat_log_path (str, optional): Filebeat's internal log path on Linux. Defaults to "/var/log/filebeat".
            filebeat_log_keepfiles (int, optional): Number of Filebeat log files to keep. Defaults to 7.
            windows_filebeat_version (str, optional): Filebeat version for Windows. Defaults to "8.11.0".
            windows_filebeat_install_path (str, optional): Filebeat installation directory on Windows. Defaults to "C:\\Program Files\\Filebeat".
            windows_log_agent_data_path (str, optional): Base path for agent data (logs, scripts) on Windows. Defaults to "C:\\ProgramData\\LogAgent".
            linux_custom_log_paths (list, optional): List of custom log paths for Linux Filebeat. Defaults to [].
            windows_custom_log_paths (list, optional): List of custom log paths for Windows Filebeat. Defaults to [].
        """
        self.config["ingestion_server"] = ingestion_server
        self.config["ingestion_port"] = port
        self.config["agent_name"] = agent_name
        self.config["linux_rsyslog_port"] = linux_rsyslog_port
        self.config["linux_filebeat_log_path"] = linux_filebeat_log_path
        self.config["filebeat_log_keepfiles"] = filebeat_log_keepfiles
        self.config["windows_filebeat_version"] = windows_filebeat_version
        self.config["windows_filebeat_install_path"] = windows_filebeat_install_path
        self.config["windows_log_agent_data_path"] = windows_log_agent_data_path
        
        if linux_custom_log_paths is not None:
            self.config["linux_custom_log_paths"] = linux_custom_log_paths
        if windows_custom_log_paths is not None:
            self.config["windows_custom_log_paths"] = windows_custom_log_paths

    def display_menu(self):
        """Display the main menu and handle user selection"""
        while True:
            print("\n" + "="*60)
            print("         LOG AGENT INSTALLER GENERATOR")
            print("="*60)
            print("1. Quick Setup (Default Values)")
            print("2. Custom Configuration")
            print("3. View Current Configuration")
            print("4. Generate Scripts")
            print("5. Load Configuration from File")
            print("6. Save Configuration to File")
            print("7. Exit")
            print("="*60)
            
            choice = input("Select an option (1-7): ").strip()
            
            if choice == "1":
                self.quick_setup()
            elif choice == "2":
                self.custom_configuration()
            elif choice == "3":
                self.view_configuration()
            elif choice == "4":
                self.generate_and_save_scripts()
            elif choice == "5":
                self.load_configuration()
            elif choice == "6":
                self.save_configuration()
            elif choice == "7":
                print("Goodbye!")
                break
            else:
                print("Invalid option. Please select 1-7.")

    def quick_setup(self):
        """Quick setup with default values, only requiring ingestion server"""
        print("\n" + "-"*50)
        print("         QUICK SETUP")
        print("-"*50)
        print("This will use default values for all settings.")
        print("You only need to specify the ingestion server address.")
        print()
        
        # Only ask for ingestion server (required)
        while True:
            ingestion_server = input("Enter ingestion server address: ").strip()
            if ingestion_server:
                break
            print("Ingestion server address is required!")
        
        # Ask if user wants to change the port (optional)
        port_input = input(f"Enter ingestion server port (default: {self.config['ingestion_port']}): ").strip()
        port = port_input if port_input else self.config['ingestion_port']
        
        # Set configuration with defaults
        self.set_config(ingestion_server=ingestion_server, port=port)
        
        print(f"\n✓ Quick setup complete!")
        print(f"  Ingestion Server: {ingestion_server}:{port}")
        print(f"  All other settings use default values.")
        print(f"  Use option 3 to view full configuration.")

    def custom_configuration(self):
        """Full custom configuration setup"""
        print("\n" + "-"*50)
        print("         CUSTOM CONFIGURATION")
        print("-"*50)
        
        # Required: Ingestion server
        while True:
            ingestion_server = input("Enter ingestion server address: ").strip()
            if ingestion_server:
                break
            print("Ingestion server address is required!")
        
        # Common configuration
        print("\n--- Common Settings ---")
        port = input(f"Enter ingestion server port (default: {self.config['ingestion_port']}): ").strip() or self.config['ingestion_port']
        agent_name = input(f"Enter agent name (default: {self.config['agent_name']}): ").strip() or self.config['agent_name']
        filebeat_log_keepfiles = int(input(f"Enter number of Filebeat log files to keep (default: {self.config['filebeat_log_keepfiles']}): ") or str(self.config['filebeat_log_keepfiles']))

        # Linux specific configuration
        print("\n--- Linux Specific Settings ---")
        linux_rsyslog_port = input(f"Enter rsyslog forwarding port (default: {self.config['linux_rsyslog_port']}): ").strip() or self.config['linux_rsyslog_port']
        linux_filebeat_log_path = input(f"Enter Filebeat's internal log path on Linux (default: {self.config['linux_filebeat_log_path']}): ").strip() or self.config['linux_filebeat_log_path']
        
        linux_custom_logs_input = input("Enter comma-separated custom log paths for Linux Filebeat (optional): ").strip()
        linux_custom_log_paths = [p.strip() for p in linux_custom_logs_input.split(',') if p.strip()] if linux_custom_logs_input else []

        # Windows specific configuration
        print("\n--- Windows Specific Settings ---")
        windows_filebeat_version = input(f"Enter Filebeat version for Windows (default: {self.config['windows_filebeat_version']}): ").strip() or self.config['windows_filebeat_version']
        windows_filebeat_install_path = input(f"Enter Filebeat installation path on Windows (default: {self.config['windows_filebeat_install_path']}): ").strip() or self.config['windows_filebeat_install_path']
        windows_log_agent_data_path = input(f"Enter base data path for Windows agent (default: {self.config['windows_log_agent_data_path']}): ").strip() or self.config['windows_log_agent_data_path']
        
        windows_custom_logs_input = input("Enter comma-separated custom log paths for Windows Filebeat (optional): ").strip()
        windows_custom_log_paths = [p.strip() for p in windows_custom_logs_input.split(',') if p.strip()] if windows_custom_logs_input else []
        
        # Set configuration
        self.set_config(
            ingestion_server=ingestion_server,
            port=port,
            agent_name=agent_name,
            linux_rsyslog_port=linux_rsyslog_port,
            linux_filebeat_log_path=linux_filebeat_log_path,
            filebeat_log_keepfiles=filebeat_log_keepfiles,
            windows_filebeat_version=windows_filebeat_version,
            windows_filebeat_install_path=windows_filebeat_install_path,
            windows_log_agent_data_path=windows_log_agent_data_path,
            linux_custom_log_paths=linux_custom_log_paths,
            windows_custom_log_paths=windows_custom_log_paths
        )
        
        print(f"\n✓ Custom configuration complete!")

    def view_configuration(self):
        """Display current configuration"""
        print("\n" + "-"*50)
        print("         CURRENT CONFIGURATION")
        print("-"*50)
        
        print("Common Settings:")
        print(f"  Ingestion Server: {self.config['ingestion_server']}")
        print(f"  Ingestion Port: {self.config['ingestion_port']}")
        print(f"  Agent Name: {self.config['agent_name']}")
        print(f"  Filebeat Log Keep Files: {self.config['filebeat_log_keepfiles']}")
        
        print("\nLinux Settings:")
        print(f"  Rsyslog Port: {self.config['linux_rsyslog_port']}")
        print(f"  Filebeat Log Path: {self.config['linux_filebeat_log_path']}")
        print(f"  Custom Log Paths: {self.config['linux_custom_log_paths'] or 'None'}")
        
        print("\nWindows Settings:")
        print(f"  Filebeat Version: {self.config['windows_filebeat_version']}")
        print(f"  Install Path: {self.config['windows_filebeat_install_path']}")
        print(f"  Data Path: {self.config['windows_log_agent_data_path']}")
        print(f"  Custom Log Paths: {self.config['windows_custom_log_paths'] or 'None'}")

    def load_configuration(self):
        """Load configuration from a JSON file"""
        config_file = input("Enter configuration file path (default: ./agent-config.json): ").strip() or "./agent-config.json"
        
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                loaded_config = json.load(f)
                self.config.update(loaded_config)
            print(f"✓ Configuration loaded from {config_file}")
        except FileNotFoundError:
            print(f"✗ Configuration file not found: {config_file}")
        except json.JSONDecodeError:
            print(f"✗ Invalid JSON in configuration file: {config_file}")
        except Exception as e:
            print(f"✗ Error loading configuration: {e}")

    def save_configuration(self):
        """Save current configuration to a JSON file"""
        config_file = input("Enter configuration file path (default: ./agent-config.json): ").strip() or "./agent-config.json"
        
        try:
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2)
            print(f"✓ Configuration saved to {config_file}")
        except Exception as e:
            print(f"✗ Error saving configuration: {e}")

    def generate_and_save_scripts(self):
        """Generate and save installation scripts"""
        if self.config['ingestion_server'] == "your-log-server.com":
            print("✗ Please configure the ingestion server address first!")
            return
        
        output_dir = input("Enter output directory (default: ./generated_scripts): ").strip() or "./generated_scripts"
        
        try:
            result = self.save_scripts(output_dir)
            print(f"\n✓ Scripts generated successfully!")
            print(f"  Linux script: {result['linux_script']}")
            print(f"  Windows script: {result['windows_script']}")
            print(f"  Configuration: {result['config_file']}")
            print(f"  Output directory: {result['output_directory']}")
            
            print(f"\nUsage Instructions:")
            print(f"For Linux:")
            print(f"   sudo bash {result['linux_script']}")
            print(f"\nFor Windows:")
            print(f"   powershell -ExecutionPolicy Bypass -File {result['windows_script']}")
            
        except Exception as e:
            print(f"✗ Error generating scripts: {e}")
    
    def generate_linux_script(self):
        """Generate Linux installation script"""
        
        # Prepare custom log paths for insertion into the YAML config
        custom_linux_log_paths_str = ""
        if self.config['linux_custom_log_paths']:
            custom_linux_log_paths_str = "\n# Custom Application Logs (user defined)\n- type: log\n  enabled: true\n  paths:\n"
            for path in self.config['linux_custom_log_paths']:
                custom_linux_log_paths_str += f"    - {path}\n"
            custom_linux_log_paths_str += "  fields:\n    log_type: custom_application\n  fields_under_root: true\n  exclude_files: ['\\\\.gz$', '\\\\.zip$']\n"


        script = f'''#!/bin/bash
# Log Forwarding Agent Installation Script for Linux
# Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
# Ingestion Server: {self.config["ingestion_server"]}:{self.config["ingestion_port"]}

set -e

echo "=== Log Forwarding Agent Installation ==="
echo "Target OS: Linux (All Distributions)"
echo "Ingestion Server: {self.config['ingestion_server']}:{self.config['ingestion_port']}"
echo "Rsyslog Forwarding Port: {self.config['linux_rsyslog_port']}"
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

# Application Logs (standard locations)
- type: log
  enabled: true
  paths:
    - /var/log/*.log
    - /opt/*/logs/*.log
    - /home/*/logs/*.log
  fields:
    log_type: application
  fields_under_root: true
  exclude_files: ['\\.gz$', '\\.zip$']
{custom_linux_log_paths_str}
# Output configuration
output.logstash:
  hosts: ["{self.config['ingestion_server']}:{self.config['ingestion_port']}"]

# Logging configuration for Filebeat's internal logs
logging.level: info
logging.to_files: true
logging.files:
  path: {self.config['linux_filebeat_log_path']}
  name: filebeat
  keepfiles: {self.config['filebeat_log_keepfiles']}
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
*.* @@{self.config['ingestion_server']}:{self.config['linux_rsyslog_port']}
EOF
    
    # Create custom rsyslog config for application logs
    cat > /etc/rsyslog.d/50-default.conf << 'EOF'
# Forward all logs to remote server
$ActionQueueFileName fwdRule1 # unique name prefix for spool files
$ActionQueueMaxDiskSpace 1g   # 1gb space limit (use as much as possible)
$ActionQueueSaveOnShutdown on # save messages to disk on shutdown
$ActionQueueType LinkedList   # run asynchronously
$ActionResumeRetryCount -1    # infinite retries if host is down
*.* @@{self.config['ingestion_server']}:{self.config['linux_rsyslog_port']}
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
tail -20 {self.config['linux_filebeat_log_path']}/filebeat
echo

echo "Connectivity Test:"
nc -zv {self.config['ingestion_server']} {self.config['ingestion_port']}
nc -zv {self.config['ingestion_server']} {self.config['linux_rsyslog_port']}
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
    echo "   - Restart filebeat: systemctl restart filebeat"
    echo "   - Restart rsyslog: systemctl restart rsyslog"
    echo "   - Check logs: journalctl -u filebeat -f"
}}

# Run main function
main "$@"
'''
        return script
    
    def generate_windows_script(self):
        """Generate Windows installation script (PowerShell)"""
        
        # Determine Filebeat download URL based on version
        filebeat_url = f"https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-{self.config['windows_filebeat_version']}-windows-x86_64.zip"

        # Prepare custom log paths for insertion into the YAML config
        custom_windows_log_paths_str = ""
        if self.config['windows_custom_log_paths']:
            custom_windows_log_paths_str = "\n# Custom Application Logs (user defined)\n- type: log\n  enabled: true\n  paths:\n"
            for path in self.config['windows_custom_log_paths']:
                # Escape backslashes for PowerShell string
                escaped_path = path.replace('\\', '\\\\') 
                custom_windows_log_paths_str += f"    - {escaped_path}\n"
            custom_windows_log_paths_str += "  fields:\n    log_type: custom\n  fields_under_root: true\n"


        script = f'''# Log Forwarding Agent Installation Script for Windows
# Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
# Ingestion Server: {self.config["ingestion_server"]}:{self.config["ingestion_port"]}

# Requires PowerShell 5.0+ and Administrator privileges

param(
    [switch]$Force
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
$FilebeatVersion = "{self.config['windows_filebeat_version']}"
$FilebeatUrl = "{filebeat_url}"
$InstallPath = "{self.config['windows_filebeat_install_path']}"
$ConfigPath = "$InstallPath\\filebeat.yml"
$LogAgentPath = "{self.config['windows_log_agent_data_path']}"
$FilebeatLogPath = "$LogAgentPath\\logs" # Filebeat internal logs path

# Create directories
function Create-Directories {{
    Write-Host "Creating directories..." -ForegroundColor Blue
    
    $directories = @(
        $InstallPath,
        $LogAgentPath,
        $FilebeatLogPath,
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

# Application Logs (standard locations)
- type: log
  enabled: true
  paths:
    - C:\\ProgramData\\*\\logs\\*.log
    - C:\\Program Files\\*\\logs\\*.log
    - C:\\logs\\*.log
  fields:
    log_type: application
  fields_under_root: true
  exclude_files: ['\\\\.gz$$', '\\\\.zip$$', '\\\\.7z$$']
{custom_windows_log_paths_str}
# Output configuration
output.logstash:
  hosts: ["{self.config['ingestion_server']}:{self.config['ingestion_port']}"]

# Logging configuration for Filebeat's internal logs
logging.level: info
logging.to_files: true
logging.files:
  path: $FilebeatLogPath
  name: filebeat
  keepfiles: {self.config['filebeat_log_keepfiles']}
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

# Configure Windows Event Forwarding (Note: This typically refers to WEF/WEC, not directly controlled by agent install)
function Configure-WindowsEventForwarding {{
    Write-Host "Note: Filebeat collects Windows Event Logs directly. This function placeholder for WinRM setup for other scenarios." -ForegroundColor Yellow
    # This section would typically enable WinRM if needed for *remote* event collection,
    # but Filebeat itself collects local event logs.
    try {{
        # Check if WinRM is enabled (for general remote management, not strictly for Filebeat)
        $winrmStatus = Get-Service -Name WinRM -ErrorAction SilentlyContinue
        if ($null -eq $winrmStatus -or $winrmStatus.Status -ne 'Running') {{
            Write-Host "Attempting to enable WinRM for potential remote management (if needed)..."
            winrm quickconfig -force | Out-Null
            Write-Host "WinRM configured for event forwarding" -ForegroundColor Green
        }} else {{
            Write-Host "WinRM service is already running." -ForegroundColor Green
        }}
    }}
    catch {{
        Write-Warning "Could not configure WinRM automatically: $($_.Exception.Message)"
    }}
}}

# Create monitoring script
function Create-MonitoringScript {{
    Write-Host "Creating monitoring script..." -ForegroundColor Blue
    
    $monitorScript = @"
# Log Agent Monitoring Script for Windows
# Usage: powershell -ExecutionPolicy Bypass -File "$LogAgentPath\\monitor-log-agent.ps1"

Write-Host "=== Log Agent Status ===" -ForegroundColor Green
Write-Host "Timestamp: $$(Get-Date)" -ForegroundColor Yellow
Write-Host ""

# Check Filebeat service
Write-Host "Filebeat Service Status:" -ForegroundColor Blue
Get-Service -Name filebeat | Format-Table -AutoSize

# Check recent Filebeat logs
Write-Host "Recent Filebeat Logs:" -ForegroundColor Blue
if (Test-Path "$FilebeatLogPath\\filebeat") {{
    Get-Content "$FilebeatLogPath\\filebeat" -Tail 20
}} else {{
    Write-Host "No Filebeat logs found at $FilebeatLogPath\\filebeat" -ForegroundColor Yellow
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
if (Test-Path "$LogAgentPath") {{
    Get-ChildItem "$LogAgentPath" -Recurse | Measure-Object -Property Length -Sum | Select-Object @{{Name="Size (MB)"; Expression={{[math]::Round($_.Sum/1MB,2)}}}}
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
# Usage: powershell -ExecutionPolicy Bypass -File "$LogAgentPath\\uninstall-log-agent.ps1"

Write-Host "Uninstalling Log Agent..." -ForegroundColor Yellow

# Define paths from where the agent was installed
$$InstallPath = "{self.config['windows_filebeat_install_path']}"
$$LogAgentPath = "{self.config['windows_log_agent_data_path']}"

# Stop and remove Filebeat service
try {{
    Stop-Service -Name filebeat -Force -ErrorAction SilentlyContinue
    & "$$InstallPath\\filebeat.exe" remove
    Write-Host "Filebeat service removed" -ForegroundColor Green
}} catch {{
    Write-Warning "Could not remove Filebeat service: $$($_.Exception.Message)"
}}

# Remove installation directory
if (Test-Path "$$InstallPath") {{
    Remove-Item "$$InstallPath" -Recurse -Force
    Write-Host "Installation directory removed" -ForegroundColor Green
}}

# Remove log agent data (optional)
Write-Host "Log data and scripts are located at $$LogAgentPath"
$$confirmRemoval = Read-Host "Do you want to remove the log data directory (Y/N)? This will delete all logs and monitoring scripts."
if ($$confirmRemoval -eq "Y") {{
    if (Test-Path "$$LogAgentPath") {{
        Remove-Item "$$LogAgentPath" -Recurse -Force
        Write-Host "Log agent data removed" -ForegroundColor Green
    }}
}} else {{
    Write-Host "Log data directory retained." -ForegroundColor Yellow
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
        Write-Host "   - Monitor agent: powershell -ExecutionPolicy Bypass -File '$LogAgentPath\\monitor-log-agent.ps1'" -ForegroundColor White
        Write-Host "   - Restart service: Restart-Service filebeat" -ForegroundColor White
        Write-Host "   - Check service: Get-Service filebeat" -ForegroundColor White
        Write-Host "   - Test config: & '$InstallPath\\filebeat.exe' test config" -ForegroundColor White
        Write-Host "   - Test output: & '$InstallPath\\filebeat.exe' test output" -ForegroundColor White
        Write-Host "   - Uninstall: powershell -ExecutionPolicy Bypass -File '$LogAgentPath\\uninstall-log-agent.ps1'" -ForegroundColor White
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
    """Main function with enhanced menu system"""
    print("Enhanced Log Agent Installer Generator")
    print("=" * 60)
    
    # Create generator instance
    generator = LogAgentGenerator()
    
    # Start the menu system
    generator.display_menu()

if __name__ == "__main__":
    main()
