#!/usr/bin/env python3
"""
Log Ingestion Server Script Generator
Generates installation scripts for Log Ingestion Server that can receive, format, 
and filter logs from various sources (SNORT, OSSEC, Suricata, Apache, etc.)
for forwarding to ELK Stack.
"""

import os
import json
from datetime import datetime

class LogIngestionGenerator:
    def __init__(self):
        self.config = {
            'elk_host': '127.0.0.1',
            'elk_port': '9200',
            'logstash_port': '5044',
            'syslog_port': '514',
            'rsyslog_port': '10514',
            'fluentd_port': '24224'
        }
        
    def generate_linux_script(self):
        """Generate Linux installation script"""
        script = f"""#!/bin/bash
# Log Ingestion Server Installation Script for Linux
# Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# Supports: Ubuntu, CentOS, RHEL, Debian, Fedora

set -e

# Colors for output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m' # No Color

echo -e "${{GREEN}}=== Log Ingestion Server Installation ===${{NC}}"

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    echo -e "${{RED}}Cannot detect OS. Exiting.${{NC}}"
    exit 1
fi

echo -e "${{YELLOW}}Detected OS: $OS $VER${{NC}}"

# Function to install packages based on OS
install_packages() {{
    case $OS in
        ubuntu|debian)
            apt-get update
            apt-get install -y curl wget gnupg2 software-properties-common apt-transport-https
            apt-get install -y rsyslog rsyslog-relp syslog-ng
            apt-get install -y python3 python3-pip
            apt-get install -y logrotate
            ;;
        centos|rhel|fedora)
            if command -v dnf &> /dev/null; then
                dnf update -y
                dnf install -y curl wget gnupg2
                dnf install -y rsyslog syslog-ng
                dnf install -y python3 python3-pip
                dnf install -y logrotate
            else
                yum update -y
                yum install -y curl wget gnupg2
                yum install -y rsyslog syslog-ng
                yum install -y python3 python3-pip
                yum install -y logrotate
            fi
            ;;
        *)
            echo -e "${{RED}}Unsupported OS: $OS${{NC}}"
            exit 1
            ;;
    esac
}}

# Install Elastic Stack Repository
install_elastic_repo() {{
    echo -e "${{YELLOW}}Installing Elastic Stack Repository...${{NC}}"
    
    case $OS in
        ubuntu|debian)
            wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
            echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-8.x.list
            apt-get update
            ;;
        centos|rhel|fedora)
            rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
            cat > /etc/yum.repos.d/elasticsearch.repo << EOF
[elasticsearch]
name=Elasticsearch repository for 8.x packages
baseurl=https://artifacts.elastic.co/packages/8.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=0
autorefresh=1
type=rpm-md
EOF
            ;;
    esac
}}

# Install Logstash
install_logstash() {{
    echo -e "${{YELLOW}}Installing Logstash...${{NC}}"
    
    case $OS in
        ubuntu|debian)
            apt-get install -y logstash
            ;;
        centos|rhel|fedora)
            if command -v dnf &> /dev/null; then
                dnf install -y --enablerepo=elasticsearch logstash
            else
                yum install -y --enablerepo=elasticsearch logstash
            fi
            ;;
    esac
}}

# Install Fluentd
install_fluentd() {{
    echo -e "${{YELLOW}}Installing Fluentd...${{NC}}"
    
    curl -L https://toolbelt.treasuredata.com/sh/install-redhat-td-agent4.sh | sh
    
    # Install plugins
    /opt/td-agent/bin/fluent-gem install fluent-plugin-elasticsearch
    /opt/td-agent/bin/fluent-gem install fluent-plugin-rewrite-tag-filter
    /opt/td-agent/bin/fluent-gem install fluent-plugin-parser
}}

# Configure Rsyslog
configure_rsyslog() {{
    echo -e "${{YELLOW}}Configuring Rsyslog...${{NC}}"
    
    cat > /etc/rsyslog.d/50-log-ingestion.conf << 'EOF'
# Log Ingestion Server Configuration

# Enable UDP and TCP reception
module(load="imudp")
input(type="imudp" port="{self.config['syslog_port']}")

module(load="imtcp")
input(type="imtcp" port="{self.config['rsyslog_port']}")

# Template for structured logging
template(name="JSONFormat" type="list") {{
    constant(value="{{\\"timestamp\\":\\"")
    property(name="timereported" dateFormat="rfc3339")
    constant(value="\\",\\"host\\":\\"")
    property(name="hostname")
    constant(value="\\",\\"severity\\":\\"")
    property(name="syslogseverity-text")
    constant(value="\\",\\"facility\\":\\"")
    property(name="syslogfacility-text")
    constant(value="\\",\\"tag\\":\\"")
    property(name="syslogtag")
    constant(value="\\",\\"message\\":\\"")
    property(name="msg" format="json")
    constant(value="\\"}}")
    constant(value="\\n")
}}

# Filtering rules for different log sources
# SNORT logs
if $programname == 'snort' then {{
    action(type="omfile" file="/var/log/ingestion/snort.log" template="JSONFormat")
    stop
}}

# OSSEC logs
if $programname == 'ossec' then {{
    action(type="omfile" file="/var/log/ingestion/ossec.log" template="JSONFormat")
    stop
}}

# Suricata logs
if $programname == 'suricata' then {{
    action(type="omfile" file="/var/log/ingestion/suricata.log" template="JSONFormat")
    stop
}}

# Apache logs
if $programname == 'apache2' or $programname == 'httpd' then {{
    action(type="omfile" file="/var/log/ingestion/apache.log" template="JSONFormat")
    stop
}}

# Nginx logs
if $programname == 'nginx' then {{
    action(type="omfile" file="/var/log/ingestion/nginx.log" template="JSONFormat")
    stop
}}

# SSH logs
if $programname == 'sshd' then {{
    action(type="omfile" file="/var/log/ingestion/ssh.log" template="JSONFormat")
    stop
}}

# Firewall logs
if $programname == 'iptables' or $programname == 'ufw' then {{
    action(type="omfile" file="/var/log/ingestion/firewall.log" template="JSONFormat")
    stop
}}

# Default catch-all
*.* action(type="omfile" file="/var/log/ingestion/general.log" template="JSONFormat")
EOF

    # Create log directories
    mkdir -p /var/log/ingestion
    chown syslog:syslog /var/log/ingestion
    chmod 755 /var/log/ingestion
}}

# Configure Logstash
configure_logstash() {{
    echo -e "${{YELLOW}}Configuring Logstash...${{NC}}"
    
    # Main pipeline configuration
    cat > /etc/logstash/conf.d/log-ingestion.conf << 'EOF'
input {{
    # Syslog input
    syslog {{
        port => {self.config['syslog_port']}
        type => "syslog"
    }}
    
    # File inputs for different log types
    file {{
        path => "/var/log/ingestion/snort.log"
        start_position => "beginning"
        type => "snort"
        codec => "json"
    }}
    
    file {{
        path => "/var/log/ingestion/ossec.log"
        start_position => "beginning"
        type => "ossec"
        codec => "json"
    }}
    
    file {{
        path => "/var/log/ingestion/suricata.log"
        start_position => "beginning"
        type => "suricata"
        codec => "json"
    }}
    
    file {{
        path => "/var/log/ingestion/apache.log"
        start_position => "beginning"
        type => "apache"
        codec => "json"
    }}
    
    file {{
        path => "/var/log/ingestion/nginx.log"
        start_position => "beginning"
        type => "nginx"
        codec => "json"
    }}
    
    file {{
        path => "/var/log/ingestion/ssh.log"
        start_position => "beginning"
        type => "ssh"
        codec => "json"
    }}
    
    file {{
        path => "/var/log/ingestion/firewall.log"
        start_position => "beginning"
        type => "firewall"
        codec => "json"
    }}
}}

filter {{
    # Common timestamp parsing
    date {{
        match => [ "timestamp", "ISO8601" ]
    }}
    
    # SNORT log processing
    if [type] == "snort" {{
        grok {{
            match => {{ "message" => "%{{GREEDYDATA:snort_message}}" }}
        }}
        
        # Extract priority and classification
        if [snort_message] =~ /Priority: (\d+)/ {{
            mutate {{
                add_field => {{ "priority" => "%{{[snort_message][1]}}" }}
            }}
        }}
        
        # Add threat level
        if [priority] {{
            if [priority] == "1" {{
                mutate {{ add_field => {{ "threat_level" => "high" }} }}
            }} else if [priority] == "2" {{
                mutate {{ add_field => {{ "threat_level" => "medium" }} }}
            }} else {{
                mutate {{ add_field => {{ "threat_level" => "low" }} }}
            }}
        }}
    }}
    
    # OSSEC log processing
    if [type] == "ossec" {{
        grok {{
            match => {{ "message" => "%{{GREEDYDATA:ossec_message}}" }}
        }}
        
        # Extract rule ID and level
        if [ossec_message] =~ /Rule: (\d+)/ {{
            mutate {{
                add_field => {{ "rule_id" => "%{{[ossec_message][1]}}" }}
            }}
        }}
        
        if [ossec_message] =~ /Level: (\d+)/ {{
            mutate {{
                add_field => {{ "alert_level" => "%{{[ossec_message][1]}}" }}
            }}
        }}
    }}
    
    # Suricata log processing
    if [type] == "suricata" {{
        # Parse Suricata EVE JSON format
        if [message] =~ /^\{{/ {{
            json {{
                source => "message"
            }}
        }}
        
        # Add alert category
        if [alert] {{
            mutate {{
                add_field => {{ "event_category" => "alert" }}
            }}
        }}
    }}
    
    # Apache log processing
    if [type] == "apache" {{
        grok {{
            match => {{ "message" => "%{{COMBINEDAPACHELOG}}" }}
        }}
        
        # Convert response code to number
        mutate {{
            convert => {{ "response" => "integer" }}
        }}
        
        # Add threat indicators
        if [response] >= 400 {{
            mutate {{
                add_field => {{ "is_error" => "true" }}
            }}
        }}
        
        # Detect potential attacks
        if [request] =~ /(sql|script|exec|union|select|drop|insert|update|delete)/i {{
            mutate {{
                add_field => {{ "potential_attack" => "true" }}
                add_field => {{ "attack_type" => "sql_injection" }}
            }}
        }}
        
        if [request] =~ /(javascript|vbscript|onload|onerror|eval)/i {{
            mutate {{
                add_field => {{ "potential_attack" => "true" }}
                add_field => {{ "attack_type" => "xss" }}
            }}
        }}
    }}
    
    # SSH log processing
    if [type] == "ssh" {{
        # Failed login attempts
        if [message] =~ /Failed password/ {{
            mutate {{
                add_field => {{ "event_type" => "failed_login" }}
                add_field => {{ "severity" => "warning" }}
            }}
        }}
        
        # Successful logins
        if [message] =~ /Accepted/ {{
            mutate {{
                add_field => {{ "event_type" => "successful_login" }}
                add_field => {{ "severity" => "info" }}
            }}
        }}
        
        # Extract IP addresses
        grok {{
            match => {{ "message" => "%{{IPV4:src_ip}}" }}
        }}
    }}
    
    # Firewall log processing
    if [type] == "firewall" {{
        # Extract common firewall fields
        grok {{
            match => {{ "message" => "%{{WORD:action}}.*SRC=%{{IPV4:src_ip}}.*DST=%{{IPV4:dst_ip}}.*PROTO=%{{WORD:protocol}}.*DPT=%{{INT:dst_port}}" }}
        }}
        
        # Add threat indicators
        if [action] == "DROP" or [action] == "REJECT" {{
            mutate {{
                add_field => {{ "is_blocked" => "true" }}
            }}
        }}
    }}
    
    # Add processing metadata
    mutate {{
        add_field => {{ "processed_by" => "log-ingestion-server" }}
        add_field => {{ "processed_at" => "%{{@timestamp}}" }}
    }}
}}

output {{
    # Send to Elasticsearch
    elasticsearch {{
        hosts => ["{self.config['elk_host']}:{self.config['elk_port']}"]
        index => "logs-%{{type}}-%{{+YYYY.MM.dd}}"
    }}
    
    # Debug output (optional)
    stdout {{
        codec => rubydebug
    }}
}}
EOF

    # Set proper permissions
    chown logstash:logstash /etc/logstash/conf.d/log-ingestion.conf
    chmod 644 /etc/logstash/conf.d/log-ingestion.conf
}}

# Configure Fluentd
configure_fluentd() {{
    echo -e "${{YELLOW}}Configuring Fluentd...${{NC}}"
    
    cat > /etc/td-agent/td-agent.conf << 'EOF'
# Log Ingestion Server - Fluentd Configuration

<source>
  @type forward
  port {self.config['fluentd_port']}
  bind 0.0.0.0
</source>

<source>
  @type tail
  path /var/log/ingestion/*.log
  pos_file /var/log/td-agent/ingestion.log.pos
  tag ingestion.*
  format json
  time_key timestamp
  time_format %Y-%m-%dT%H:%M:%S.%NZ
</source>

# SNORT log processing
<filter ingestion.snort>
  @type record_transformer
  <record>
    log_type snort
    security_tool snort
  </record>
</filter>

# OSSEC log processing
<filter ingestion.ossec>
  @type record_transformer
  <record>
    log_type ossec
    security_tool ossec
  </record>
</filter>

# Suricata log processing
<filter ingestion.suricata>
  @type record_transformer
  <record>
    log_type suricata
    security_tool suricata
  </record>
</filter>

# Apache log processing
<filter ingestion.apache>
  @type record_transformer
  <record>
    log_type apache
    service_type web_server
  </record>
</filter>

# Common enrichment
<filter ingestion.**>
  @type record_transformer
  <record>
    ingestion_server ${{ENV['HOSTNAME']}}
    ingestion_time ${{Time.now.iso8601}}
  </record>
</filter>

# Output to Elasticsearch
<match ingestion.**>
  @type elasticsearch
  host {self.config['elk_host']}
  port {self.config['elk_port']}
  index_name logs-%{{tag}}-%Y%m%d
  type_name _doc
  include_tag_key true
  tag_key @log_name
  flush_interval 10s
  <buffer>
    @type file
    path /var/log/td-agent/buffer/elasticsearch
    flush_mode interval
    retry_type exponential_backoff
    flush_thread_count 2
    flush_interval 5s
    retry_forever
    retry_max_interval 30
    chunk_limit_size 2M
    queue_limit_length 8
    overflow_action block
  </buffer>
</match>
EOF
}}

# Configure log rotation
configure_logrotate() {{
    echo -e "${{YELLOW}}Configuring Log Rotation...${{NC}}"
    
    cat > /etc/logrotate.d/log-ingestion << 'EOF'
/var/log/ingestion/*.log {{
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 syslog syslog
    postrotate
        systemctl reload rsyslog
    endscript
}}
EOF
}}

# Configure firewall
configure_firewall() {{
    echo -e "${{YELLOW}}Configuring Firewall...${{NC}}"
    
    if command -v ufw &> /dev/null; then
        ufw allow {self.config['syslog_port']}/udp
        ufw allow {self.config['rsyslog_port']}/tcp
        ufw allow {self.config['fluentd_port']}/tcp
        ufw allow {self.config['logstash_port']}/tcp
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port={self.config['syslog_port']}/udp
        firewall-cmd --permanent --add-port={self.config['rsyslog_port']}/tcp
        firewall-cmd --permanent --add-port={self.config['fluentd_port']}/tcp
        firewall-cmd --permanent --add-port={self.config['logstash_port']}/tcp
        firewall-cmd --reload
    fi
}}

# Start and enable services
start_services() {{
    echo -e "${{YELLOW}}Starting Services...${{NC}}"
    
    systemctl enable rsyslog
    systemctl restart rsyslog
    
    systemctl enable logstash
    systemctl restart logstash
    
    systemctl enable td-agent
    systemctl restart td-agent
    
    echo -e "${{GREEN}}All services started successfully!${{NC}}"
}}

# Main installation process
main() {{
    echo -e "${{YELLOW}}Starting Log Ingestion Server installation...${{NC}}"
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${{RED}}This script must be run as root${{NC}}"
        exit 1
    fi
    
    install_packages
    install_elastic_repo
    install_logstash
    install_fluentd
    configure_rsyslog
    configure_logstash
    configure_fluentd
    configure_logrotate
    configure_firewall
    start_services
    
    echo -e "${{GREEN}}=== Installation Complete ===${{NC}}"
    echo -e "${{YELLOW}}Log Ingestion Server is now running!${{NC}}"
    echo -e "${{YELLOW}}Listening on:${{NC}}"
    echo -e "  - Syslog UDP: {self.config['syslog_port']}"
    echo -e "  - Rsyslog TCP: {self.config['rsyslog_port']}"
    echo -e "  - Fluentd: {self.config['fluentd_port']}"
    echo -e "  - Logstash: {self.config['logstash_port']}"
    echo -e "${{YELLOW}}Logs are stored in: /var/log/ingestion/${{NC}}"
    echo -e "${{YELLOW}}Configure your endpoints to send logs to this server.${{NC}}"
}}

# Run main function
main "$@"
"""
        return script

    def generate_windows_script(self):
        """Generate Windows PowerShell installation script"""
        script = f"""# Log Ingestion Server Installation Script for Windows
# Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# Supports: Windows Server 2016+, Windows 10+

# Requires Administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {{
    Write-Host "This script requires Administrator privileges. Please run as Administrator." -ForegroundColor Red
    exit 1
}}

# Set execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force

Write-Host "=== Log Ingestion Server Installation ===" -ForegroundColor Green

# Configuration
$Config = @{{
    InstallPath = "C:\\LogIngestion"
    DataPath = "C:\\LogIngestion\\Data"
    LogPath = "C:\\LogIngestion\\Logs"
    ConfigPath = "C:\\LogIngestion\\Config"
    ElkHost = "{self.config['elk_host']}"
    ElkPort = "{self.config['elk_port']}"
    LogstashPort = "{self.config['logstash_port']}"
    SyslogPort = "{self.config['syslog_port']}"
    FluentdPort = "{self.config['fluentd_port']}"
}}

# Create directories
function Create-Directories {{
    Write-Host "Creating directories..." -ForegroundColor Yellow
    
    $dirs = @($Config.InstallPath, $Config.DataPath, $Config.LogPath, $Config.ConfigPath)
    foreach ($dir in $dirs) {{
        if (!(Test-Path $dir)) {{
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Host "Created: $dir" -ForegroundColor Green
        }}
    }}
}}

# Install Chocolatey
function Install-Chocolatey {{
    Write-Host "Installing Chocolatey..." -ForegroundColor Yellow
    
    if (!(Get-Command choco -ErrorAction SilentlyContinue)) {{
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        
        # Refresh environment
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    }}
}}

# Install required software
function Install-Software {{
    Write-Host "Installing required software..." -ForegroundColor Yellow
    
    # Install Java (required for Logstash)
    choco install openjdk11 -y
    
    # Install Ruby (required for Fluentd)
    choco install ruby -y
    
    # Install NSSM (for running services)
    choco install nssm -y
    
    # Install 7zip (for extracting archives)
    choco install 7zip -y
    
    # Refresh environment
    refreshenv
}}

# Install Logstash
function Install-Logstash {{
    Write-Host "Installing Logstash..." -ForegroundColor Yellow
    
    $logstashUrl = "https://artifacts.elastic.co/downloads/logstash/logstash-8.11.0-windows-x86_64.zip"
    $logstashZip = "$($Config.InstallPath)\\logstash.zip"
    $logstashPath = "$($Config.InstallPath)\\logstash"
    
    # Download Logstash
    Invoke-WebRequest -Uri $logstashUrl -OutFile $logstashZip
    
    # Extract Logstash
    & "C:\\Program Files\\7-Zip\\7z.exe" x $logstashZip -o"$($Config.InstallPath)" -y
    
    # Rename directory
    $extractedDir = Get-ChildItem -Path $Config.InstallPath -Directory | Where-Object {{ $_.Name -like "logstash-*" }}
    if ($extractedDir) {{
        Rename-Item -Path $extractedDir.FullName -NewName "logstash"
    }}
    
    # Cleanup
    Remove-Item $logstashZip -Force
}}

# Install Fluentd
function Install-Fluentd {{
    Write-Host "Installing Fluentd..." -ForegroundColor Yellow
    
    # Install Fluentd gem
    gem install fluentd --no-document
    gem install fluent-plugin-elasticsearch --no-document
    gem install fluent-plugin-rewrite-tag-filter --no-document
    gem install fluent-plugin-parser --no-document
    gem install fluent-plugin-windows-eventlog --no-document
}}

# Configure Logstash
function Configure-Logstash {{
    Write-Host "Configuring Logstash..." -ForegroundColor Yellow
    
    $logstashConfig = @"
input {{
    # Windows Event Log
    eventlog {{
        logfile => ["System", "Security", "Application"]
        type => "wineventlog"
    }}
    
    # File inputs for different log types
    file {{
        path => "$($Config.LogPath.Replace('\\', '/'))/**/*.log"
        start_position => "beginning"
        type => "file"
    }}
    
    # Syslog input
    syslog {{
        port => $($Config.SyslogPort)
        type => "syslog"
    }}
    
    # TCP input for remote logs
    tcp {{
        port => $($Config.LogstashPort)
        type => "tcp"
        codec => json
    }}
}}

filter {{
    # Common timestamp parsing
    if [type] == "wineventlog" {{
        date {{
            match => [ "TimeCreated", "yyyy-MM-dd HH:mm:ss" ]
        }}
        
        # Add Windows-specific fields
        mutate {{
            add_field => {{ "log_type" => "firewall" }}
            add_field => {{ "security_tool" => "windows_firewall" }}
        }}
        
        # Add threat indicators
        if [action] == "DROP" or [action] == "BLOCK" {{
            mutate {{
                add_field => {{ "is_blocked" => "true" }}
            }}
        }}
    }}
    
    # Add processing metadata
    mutate {{
        add_field => {{ "processed_by" => "log-ingestion-server-windows" }}
        add_field => {{ "processed_at" => "%{{@timestamp}}" }}
        add_field => {{ "os_type" => "windows" }}
    }}
}}

output {{
    # Send to Elasticsearch
    elasticsearch {{
        hosts => ["$($Config.ElkHost):$($Config.ElkPort)"]
        index => "logs-windows-%{{type}}-%{{+YYYY.MM.dd}}"
    }}
    
    # Debug output (optional)
    stdout {{
        codec => rubydebug
    }}
}}
"@

    # Write Logstash configuration
    $logstashConfigPath = "$($Config.ConfigPath)\\logstash.conf"
    $logstashConfig | Out-File -FilePath $logstashConfigPath -Encoding UTF8
    
    Write-Host "Logstash configuration written to: $logstashConfigPath" -ForegroundColor Green
}}

# Configure Fluentd
function Configure-Fluentd {{
    Write-Host "Configuring Fluentd..." -ForegroundColor Yellow
    
    $fluentdConfig = @"
# Log Ingestion Server - Fluentd Configuration for Windows

<source>
  @type forward
  port $($Config.FluentdPort)
  bind 0.0.0.0
</source>

<source>
  @type windows_eventlog
  channels application,system,security
  tag winevt.raw
  rate_limit 200
  <storage>
    @type local
    persistent true
    path $($Config.DataPath.Replace('\', '/'))\\fluentd-winevt.pos
  </storage>
</source>

<source>
  @type tail
  path $($Config.LogPath.Replace('\', '/'))/**/*.log
  pos_file $($Config.DataPath.Replace('\', '/'))\\fluentd-files.pos
  tag files.*
  format none
</source>

# Windows Event Log processing
<filter winevt.raw>
  @type record_transformer
  <record>
    log_type windows_eventlog
    os_type windows
    hostname #{Socket.gethostname}
  </record>
</filter>

# Security event filtering
<filter winevt.raw>
  @type grep
  <regexp>
    key channel
    pattern ^(Security|System)$
  </regexp>
</filter>

# IIS log processing
<filter files.iis>
  @type parser
  key_name message
  reserve_data true
  <parse>
    @type regexp
    expression /^(?<timestamp>\S+ \S+) (?<site>\S+) (?<method>\S+) (?<page>\S+) (?<querystring>\S+) (?<port>\d+) (?<username>\S+) (?<clienthost>\S+) (?<useragent>\S+) (?<referer>\S+) (?<response>\d+) (?<subresponse>\d+) (?<scstatus>\d+) (?<bytes>\d+) (?<timetaken>\d+)$/
  </parse>
</filter>

<filter files.iis>
  @type record_transformer
  <record>
    log_type iis
    service_type web_server
    os_type windows
  </record>
</filter>

# Common enrichment for all logs
<filter **>
  @type record_transformer
  <record>
    ingestion_server #{Socket.gethostname}
    ingestion_time #{Time.now.iso8601}
    ingestion_platform windows
  </record>
</filter>

# Output to Elasticsearch
<match **>
  @type elasticsearch
  host $($Config.ElkHost)
  port $($Config.ElkPort)
  index_name logs-windows-%{tag}-%Y%m%d
  type_name _doc
  include_tag_key true
  tag_key @log_name
  flush_interval 10s
  <buffer>
    @type file
    path $($Config.DataPath.Replace('\', '/'))\\buffer\\elasticsearch
    flush_mode interval
    retry_type exponential_backoff
    flush_thread_count 2
    flush_interval 5s
    retry_forever
    retry_max_interval 30
    chunk_limit_size 2M
    queue_limit_length 8
    overflow_action block
  </buffer>
</match>
"@

    # Write Fluentd configuration
    $fluentdConfigPath = "$($Config.ConfigPath)\\fluentd.conf"
    $fluentdConfig | Out-File -FilePath $fluentdConfigPath -Encoding UTF8
    
    Write-Host "Fluentd configuration written to: $fluentdConfigPath" -ForegroundColor Green
}}

# Configure Windows Event Log forwarding
function Configure-EventLogForwarding {{
    Write-Host "Configuring Windows Event Log forwarding..." -ForegroundColor Yellow
    
    # Enable Windows Event Forwarding
    wecutil qc /q
    
    # Create custom event log subscription configuration
    $subscriptionXml = @"
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
    <SubscriptionId>LogIngestionSubscription</SubscriptionId>
    <SubscriptionType>SourceInitiated</SubscriptionType>
    <Description>Log Ingestion Server Subscription</Description>
    <Enabled>true</Enabled>
    <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
    <ConfigurationMode>Normal</ConfigurationMode>
    <Delivery Mode="Push">
        <Batching>
            <BatchErrorThreshold>10</BatchErrorThreshold>
            <BatchSize>5</BatchSize>
        </Batching>
        <PushSettings>
            <Heartbeat Interval="900000"/>
        </PushSettings>
    </Delivery>
    <Query>
        <![CDATA[
        <QueryList>
            <Query Id="0">
                <Select Path="Security">*[System[EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672]]</Select>
                <Select Path="System">*[System[Level=1 or Level=2 or Level=3]]</Select>
                <Select Path="Application">*[System[Level=1 or Level=2]]</Select>
            </Query>
        </QueryList>
        ]]>
    </Query>
    <ReadExistingEvents>false</ReadExistingEvents>
    <TransportName>HTTP</TransportName>
    <ContentFormat>Events</ContentFormat>
    <Locale Language="en-US"/>
    <LogFile>ForwardedEvents</LogFile>
    <PublisherName>Microsoft-Windows-EventCollector</PublisherName>
    <AllowedSourceNonDomainComputers></AllowedSourceNonDomainComputers>
    <AllowedSourceDomainComputers>O:NSG:NSD:(A;;GA;;;DC)(A;;GA;;;NS)</AllowedSourceDomainComputers>
</Subscription>
"@

    $subscriptionPath = "$($Config.ConfigPath)\\subscription.xml"
    $subscriptionXml | Out-File -FilePath $subscriptionPath -Encoding UTF8
    
    # Create the subscription
    try {{
        wecutil cs $subscriptionPath
        Write-Host "Event log subscription created successfully" -ForegroundColor Green
    }} catch {{
        Write-Host "Warning: Could not create event log subscription. Manual configuration may be required." -ForegroundColor Yellow
    }}
}}

# Create Windows Services
function Create-Services {{
    Write-Host "Creating Windows services..." -ForegroundColor Yellow
    
    # Create Logstash service
    $logstashBat = @"
@echo off
cd /d "$($Config.InstallPath)\\logstash\\bin"
logstash.bat -f "$($Config.ConfigPath)\\logstash.conf"
"@
    $logstashBatPath = "$($Config.InstallPath)\\start-logstash.bat"
    $logstashBat | Out-File -FilePath $logstashBatPath -Encoding ASCII
    
    nssm install LogIngestionLogstash $logstashBatPath
    nssm set LogIngestionLogstash Description "Log Ingestion Server - Logstash"
    nssm set LogIngestionLogstash Start SERVICE_AUTO_START
    
    # Create Fluentd service
    $fluentdBat = @"
@echo off
fluentd -c "$($Config.ConfigPath)\\fluentd.conf" -o "$($Config.LogPath)\\fluentd.log"
"@
    $fluentdBatPath = "$($Config.InstallPath)\\start-fluentd.bat"
    $fluentdBat | Out-File -FilePath $fluentdBatPath -Encoding ASCII
    
    nssm install LogIngestionFluentd $fluentdBatPath
    nssm set LogIngestionFluentd Description "Log Ingestion Server - Fluentd"
    nssm set LogIngestionFluentd Start SERVICE_AUTO_START
    
    Write-Host "Windows services created successfully" -ForegroundColor Green
}}

# Configure Windows Firewall
function Configure-Firewall {{
    Write-Host "Configuring Windows Firewall..." -ForegroundColor Yellow
    
    # Create firewall rules
    New-NetFirewallRule -DisplayName "Log Ingestion - Syslog UDP" -Direction Inbound -Protocol UDP -LocalPort $Config.SyslogPort -Action Allow
    New-NetFirewallRule -DisplayName "Log Ingestion - Logstash TCP" -Direction Inbound -Protocol TCP -LocalPort $Config.LogstashPort -Action Allow
    New-NetFirewallRule -DisplayName "Log Ingestion - Fluentd TCP" -Direction Inbound -Protocol TCP -LocalPort $Config.FluentdPort -Action Allow
    
    Write-Host "Firewall rules configured successfully" -ForegroundColor Green
}}

# Create log parsing PowerShell module
function Create-LogParsingModule {{
    Write-Host "Creating log parsing PowerShell module..." -ForegroundColor Yellow
    
    $moduleContent = @"
# Log Ingestion Server - PowerShell Log Parsing Module

function Parse-IISLog {{
    param(
        [string]`$LogPath,
        [string]`$OutputPath
    )
    
    Get-Content `$LogPath | ForEach-Object {{
        if (`$_ -notmatch '^#') {{
            `$fields = `$_ -split ' '
            if (`$fields.Count -ge 15) {{
                `$logEntry = [PSCustomObject]@{{
                    timestamp = "`$(`$fields[0]) `$(`$fields[1])"
                    site = `$fields[2]
                    method = `$fields[3]
                    page = `$fields[4]
                    querystring = `$fields[5]
                    port = `$fields[6]
                    username = `$fields[7]
                    clienthost = `$fields[8]
                    useragent = `$fields[9]
                    referer = `$fields[10]
                    response = `$fields[11]
                    subresponse = `$fields[12]
                    scstatus = `$fields[13]
                    bytes = `$fields[14]
                    timetaken = `$fields[15]
                    log_type = "iis"
                }}
                
                `$logEntry | ConvertTo-Json -Compress | Out-File -FilePath `$OutputPath -Append -Encoding UTF8
            }}
        }}
    }}
}}

function Parse-WindowsEventLog {{
    param(
        [string]`$LogName,
        [string]`$OutputPath,
        [int]`$MaxEvents = 1000
    )
    
    Get-WinEvent -LogName `$LogName -MaxEvents `$MaxEvents | ForEach-Object {{
        `$logEntry = [PSCustomObject]@{{
            timestamp = `$_.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            event_id = `$_.Id
            level = `$_.LevelDisplayName
            log_name = `$_.LogName
            source = `$_.ProviderName
            message = `$_.Message
            computer = `$_.MachineName
            user = `$_.UserId
            log_type = "windows_eventlog"
        }}
        
        `$logEntry | ConvertTo-Json -Compress | Out-File -FilePath `$OutputPath -Append -Encoding UTF8
    }}
}}

function Start-LogMonitoring {{
    param(
        [string]`$ConfigPath
    )
    
    `$config = Get-Content `$ConfigPath | ConvertFrom-Json
    
    # Monitor IIS logs
    if (`$config.IISLogPath) {{
        Register-ObjectEvent -InputObject (New-Object System.IO.FileSystemWatcher `$config.IISLogPath) -EventName Created -Action {{
            Parse-IISLog -LogPath `$Event.SourceEventArgs.FullPath -OutputPath "`$(`$config.OutputPath)\\iis.log"
        }}
    }}
    
    # Monitor Windows Event Logs
    Register-WmiEvent -Query "SELECT * FROM Win32_NTLogEvent WHERE LogFile='Security'" -Action {{
        Parse-WindowsEventLog -LogName "Security" -OutputPath "`$(`$config.OutputPath)\\security.log" -MaxEvents 10
    }}
}}

Export-ModuleMember -Function Parse-IISLog, Parse-WindowsEventLog, Start-LogMonitoring
"@

    $modulePath = "$($Config.InstallPath)\\LogIngestionModule.psm1"
    $moduleContent | Out-File -FilePath $modulePath -Encoding UTF8
    
    Write-Host "PowerShell module created: $modulePath" -ForegroundColor Green
}}

# Start services
function Start-Services {{
    Write-Host "Starting services..." -ForegroundColor Yellow
    
    try {{
        Start-Service LogIngestionLogstash
        Write-Host "Logstash service started" -ForegroundColor Green
    }} catch {{
        Write-Host "Warning: Could not start Logstash service" -ForegroundColor Yellow
    }}
    
    try {{
        Start-Service LogIngestionFluentd
        Write-Host "Fluentd service started" -ForegroundColor Green
    }} catch {{
        Write-Host "Warning: Could not start Fluentd service" -ForegroundColor Yellow
    }}
}}

# Main installation function
function Main {{
    Write-Host "Starting Log Ingestion Server installation for Windows..." -ForegroundColor Yellow
    
    try {{
        Create-Directories
        Install-Chocolatey
        Install-Software
        Install-Logstash
        Install-Fluentd
        Configure-Logstash
        Configure-Fluentd
        Configure-EventLogForwarding
        Create-Services
        Configure-Firewall
        Create-LogParsingModule
        Start-Services
        
        Write-Host "=== Installation Complete ===" -ForegroundColor Green
        Write-Host "Log Ingestion Server is now running on Windows!" -ForegroundColor Yellow
        Write-Host "Listening on:" -ForegroundColor Yellow
        Write-Host "  - Syslog UDP: $($Config.SyslogPort)" -ForegroundColor White
        Write-Host "  - Logstash TCP: $($Config.LogstashPort)" -ForegroundColor White
        Write-Host "  - Fluentd: $($Config.FluentdPort)" -ForegroundColor White
        Write-Host "Installation Path: $($Config.InstallPath)" -ForegroundColor Yellow
        Write-Host "Log Path: $($Config.LogPath)" -ForegroundColor Yellow
        Write-Host "Config Path: $($Config.ConfigPath)" -ForegroundColor Yellow
        Write-Host "Configure your endpoints to send logs to this server." -ForegroundColor Yellow
        
    }} catch {{
        Write-Host "Installation failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }}
}}

# Run main installation
Main
"""
        return script

    def create_config_file(self):
        """Create configuration file for the log ingestion server"""
        config = {
            "server_config": {
                "elk_host": self.config['elk_host'],
                "elk_port": self.config['elk_port'],
                "logstash_port": self.config['logstash_port'],
                "syslog_port": self.config['syslog_port'],
                "fluentd_port": self.config['fluentd_port']
            },
            "log_sources": {
                "snort": {
                    "enabled": True,
                    "port": 1514,
                    "format": "syslog",
                    "index_pattern": "logs-snort-*"
                },
                "ossec": {
                    "enabled": True,
                    "port": 1515,
                    "format": "json",
                    "index_pattern": "logs-ossec-*"
                },
                "suricata": {
                    "enabled": True,
                    "port": 1516,
                    "format": "json",
                    "index_pattern": "logs-suricata-*"
                },
                "apache": {
                    "enabled": True,
                    "log_path": "/var/log/apache2/access.log",
                    "format": "combined",
                    "index_pattern": "logs-apache-*"
                },
                "nginx": {
                    "enabled": True,
                    "log_path": "/var/log/nginx/access.log",
                    "format": "combined",
                    "index_pattern": "logs-nginx-*"
                },
                "ssh": {
                    "enabled": True,
                    "log_path": "/var/log/auth.log",
                    "format": "syslog",
                    "index_pattern": "logs-ssh-*"
                },
                "firewall": {
                    "enabled": True,
                    "log_path": "/var/log/ufw.log",
                    "format": "syslog",
                    "index_pattern": "logs-firewall-*"
                }
            },
            "filtering_rules": {
                "snort": [
                    {"field": "priority", "condition": "equals", "value": "1", "action": "alert"},
                    {"field": "message", "condition": "contains", "value": "SQL injection", "action": "alert"}
                ],
                "ossec": [
                    {"field": "rule_id", "condition": "in", "value": ["5712", "5402"], "action": "alert"}
                ],
                "apache": [
                    {"field": "response", "condition": "gte", "value": 400, "action": "log"},
                    {"field": "request", "condition": "regex", "value": "sql|script|exec", "action": "alert"}
                ]
            }
        }
        return json.dumps(config, indent=2)

    def generate_scripts(self):
        """Generate both Linux and Windows scripts"""
        print("=== Log Ingestion Server Script Generator ===")
        print("Choose your operating system:")
        print("1. Linux (All Distributions)")
        print("2. Windows (Server 2016+, Windows 10+)")
        print("3. Generate both")
        print("4. Generate configuration file only")
        
        choice = input("Enter your choice (1-4): ").strip()
        
        if choice == "1":
            script = self.generate_linux_script()
            filename = "install_log_ingestion_linux.sh"
            with open(filename, 'w') as f:
                f.write(script)
            os.chmod(filename, 0o755)
            print(f"Linux installation script generated: {filename}")
            
        elif choice == "2":
            script = self.generate_windows_script()
            filename = "install_log_ingestion_windows.ps1"
            with open(filename, 'w') as f:
                f.write(script)
            print(f"Windows installation script generated: {filename}")
            
        elif choice == "3":
            # Generate Linux script
            linux_script = self.generate_linux_script()
            linux_filename = "install_log_ingestion_linux.sh"
            with open(linux_filename, 'w') as f:
                f.write(linux_script)
            os.chmod(linux_filename, 0o755)
            
            # Generate Windows script
            windows_script = self.generate_windows_script()
            windows_filename = "install_log_ingestion_windows.ps1"
            with open(windows_filename, 'w') as f:
                f.write(windows_script)
            
            print(f"Linux installation script generated: {linux_filename}")
            print(f"Windows installation script generated: {windows_filename}")
            
        elif choice == "4":
            config = self.create_config_file()
            filename = "log_ingestion_config.json"
            with open(filename, 'w') as f:
                f.write(config)
            print(f"Configuration file generated: {filename}")
            
        else:
            print("Invalid choice. Please run the script again.")
            return
        
        # Always generate config file
        if choice != "4":
            config = self.create_config_file()
            config_filename = "log_ingestion_config.json"
            with open(config_filename, 'w') as f:
                f.write(config)
            print(f"Configuration file generated: {config_filename}")
        
        print("\n=== Installation Instructions ===")
        if choice in ["1", "3"]:
            print("For Linux:")
            print("1. Transfer the .sh file to your Linux server")
            print("2. Run: chmod +x install_log_ingestion_linux.sh")
            print("3. Run: sudo ./install_log_ingestion_linux.sh")
            
        if choice in ["2", "3"]:
            print("For Windows:")
            print("1. Transfer the .ps1 file to your Windows server")
            print("2. Run PowerShell as Administrator")
            print("3. Run: .\\install_log_ingestion_windows.ps1")
        
        print("\nNote: Make sure to configure your ELK stack endpoint in the configuration file before running the installation.")

if __name__ == "__main__":
    generator = LogIngestionGenerator()
    generator.generate_scripts()d => {{ "os_type" => "windows" }}
            add_field => {{ "log_source" => "windows_eventlog" }}
        }}
        
        # Security event processing
        if [LogName] == "Security" {{
            if [EventID] == 4624 {{
                mutate {{
                    add_field => {{ "event_category" => "successful_logon" }}
                    add_field => {{ "severity" => "info" }}
                }}
            }} else if [EventID] == 4625 {{
                mutate {{
                    add_field => {{ "event_category" => "failed_logon" }}
                    add_field => {{ "severity" => "warning" }}
                }}
            }} else if [EventID] == 4648 {{
                mutate {{
                    add_field => {{ "event_category" => "explicit_logon" }}
                    add_field => {{ "severity" => "info" }}
                }}
            }}
        }}
        
        # System event processing
        if [LogName] == "System" {{
            if [EventID] == 7034 or [EventID] == 7031 {{
                mutate {{
                    add_field => {{ "event_category" => "service_failure" }}
                    add_field => {{ "severity" => "error" }}
                }}
            }}
        }}
    }}
    
    # IIS log processing
    if [path] =~ /iis/ {{
        grok {{
            match => {{ "message" => "%{{TIMESTAMP_ISO8601:timestamp}} %{{IPORHOST:site}} %{{WORD:method}} %{{URIPATH:page}} %{{NOTSPACE:querystring}} %{{NUMBER:port}} %{{NOTSPACE:username}} %{{IPORHOST:clienthost}} %{{NOTSPACE:useragent}} %{{NOTSPACE:referer}} %{{NUMBER:response}} %{{NUMBER:subresponse}} %{{NUMBER:scstatus}} %{{NUMBER:bytes}} %{{NUMBER:timetaken}}" }}
        }}
        
        mutate {{
            add_field => {{ "log_type" => "iis" }}
            add_field => {{ "service_type" => "web_server" }}
            convert => {{ "response" => "integer" }}
            convert => {{ "bytes" => "integer" }}
            convert => {{ "timetaken" => "integer" }}
        }}
        
        # Add threat indicators
        if [response] >= 400 {{
            mutate {{
                add_field => {{ "is_error" => "true" }}
            }}
        }}
        
        # Detect potential attacks
        if [querystring] =~ /(sql|script|exec|union|select|drop|insert|update|delete)/i {{
            mutate {{
                add_field => {{ "potential_attack" => "true" }}
                add_field => {{ "attack_type" => "sql_injection" }}
            }}
        }}
    }}
    
    # Firewall log processing
    if [path] =~ /firewall/ {{
        grok {{
            match => {{ "message" => "%{{TIMESTAMP_ISO8601:timestamp}} %{{WORD:action}} %{{WORD:protocol}} %{{IP:src_ip}} %{{IP:dst_ip}} %{{INT:src_port}} %{{INT:dst_port}}" }}
        }}
        
        mutate {{
            add_fiel