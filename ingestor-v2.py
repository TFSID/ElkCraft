#!/usr/bin/env python3
"""
Enhanced Log Ingestion Server Script Generator
Generates comprehensive installation scripts for Log Ingestion Server that can receive, 
format, and filter logs from various security sources (SNORT, OSSEC, Suricata, Apache, etc.)
for forwarding to ELK Stack with advanced threat detection and correlation.
"""

import os
import json
import sys
from datetime import datetime
from pathlib import Path

class LogIngestionGenerator:
    def __init__(self):
        self.config = {
            'elk_host': '127.0.0.1',
            'elk_port': '9200',
            'kibana_port': '5601',
            'logstash_port': '5044',
            'syslog_port': '514',
            'rsyslog_port': '10514',
            'fluentd_port': '24224',
            'beats_port': '5045',
            'snort_port': '1514',
            'ossec_port': '1515',
            'suricata_port': '1516'
        }
        
        self.log_sources = {
            'snort': {'enabled': True, 'priority': 'high'},
            'ossec': {'enabled': True, 'priority': 'high'},
            'suricata': {'enabled': True, 'priority': 'high'},
            'apache': {'enabled': True, 'priority': 'medium'},
            'nginx': {'enabled': True, 'priority': 'medium'},
            'ssh': {'enabled': True, 'priority': 'high'},
            'firewall': {'enabled': True, 'priority': 'high'},
            'dns': {'enabled': True, 'priority': 'medium'},
            'dhcp': {'enabled': True, 'priority': 'low'},
            'vpn': {'enabled': True, 'priority': 'medium'},
            'windows_eventlog': {'enabled': True, 'priority': 'high'},
            'iis': {'enabled': True, 'priority': 'medium'}
        }
        
    def generate_linux_script(self):
        """Generate comprehensive Linux installation script"""
        script = f"""#!/bin/bash
# Enhanced Log Ingestion Server Installation Script for Linux
# Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# Supports: Ubuntu 18.04+, CentOS 7+, RHEL 7+, Debian 9+, Fedora 30+

set -e

# Colors for output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
BLUE='\\033[0;34m'
PURPLE='\\033[0;35m'
CYAN='\\033[0;36m'
NC='\\033[0m' # No Color

# Configuration
ELK_HOST="{self.config['elk_host']}"
ELK_PORT="{self.config['elk_port']}"
KIBANA_PORT="{self.config['kibana_port']}"
LOGSTASH_PORT="{self.config['logstash_port']}"
SYSLOG_PORT="{self.config['syslog_port']}"
RSYSLOG_PORT="{self.config['rsyslog_port']}"
FLUENTD_PORT="{self.config['fluentd_port']}"
BEATS_PORT="{self.config['beats_port']}"
SNORT_PORT="{self.config['snort_port']}"
OSSEC_PORT="{self.config['ossec_port']}"
SURICATA_PORT="{self.config['suricata_port']}"

LOG_INGESTION_DIR="/opt/log-ingestion"
LOG_DIR="/var/log/ingestion"
CONFIG_DIR="/etc/log-ingestion"
SCRIPTS_DIR="$LOG_INGESTION_DIR/scripts"
RULES_DIR="$CONFIG_DIR/rules"

echo -e "${{GREEN}}=== Enhanced Log Ingestion Server Installation ===${{NC}}"
echo -e "${{CYAN}}This will install and configure a comprehensive log ingestion server${{NC}}"
echo -e "${{CYAN}}with support for multiple security tools and advanced filtering.${{NC}}"

# Detect OS
detect_os() {{
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
        CODENAME=$VERSION_CODENAME
    else
        echo -e "${{RED}}Cannot detect OS. Exiting.${{NC}}"
        exit 1
    fi
    
    echo -e "${{YELLOW}}Detected OS: $OS $VER${{NC}}"
}}

# Check system requirements
check_requirements() {{
    echo -e "${{YELLOW}}Checking system requirements...${{NC}}"
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${{RED}}This script must be run as root${{NC}}"
        exit 1
    fi
    
    # Check available memory (minimum 4GB recommended)
    MEMORY_KB=$(grep MemTotal /proc/meminfo | awk '{{print $2}}')
    MEMORY_GB=$((MEMORY_KB / 1024 / 1024))
    
    if [ $MEMORY_GB -lt 4 ]; then
        echo -e "${{YELLOW}}Warning: Less than 4GB RAM detected. Performance may be affected.${{NC}}"
    fi
    
    # Check available disk space (minimum 20GB recommended)
    DISK_SPACE=$(df / | awk 'NR==2 {{print $4}}')
    DISK_SPACE_GB=$((DISK_SPACE / 1024 / 1024))
    
    if [ $DISK_SPACE_GB -lt 20 ]; then
        echo -e "${{YELLOW}}Warning: Less than 20GB free disk space. Consider adding more storage.${{NC}}"
    fi
    
    echo -e "${{GREEN}}System requirements check completed.${{NC}}"
}}

# Create directory structure
create_directories() {{
    echo -e "${{YELLOW}}Creating directory structure...${{NC}}"
    
    mkdir -p $LOG_INGESTION_DIR
    mkdir -p $LOG_DIR
    mkdir -p $CONFIG_DIR
    mkdir -p $SCRIPTS_DIR
    mkdir -p $RULES_DIR
    mkdir -p $LOG_DIR/{{snort,ossec,suricata,apache,nginx,ssh,firewall,dns,dhcp,vpn,general}}
    mkdir -p /var/lib/log-ingestion/{{geoip,threat-intel,patterns}}
    
    # Set proper permissions
    chown -R root:root $LOG_INGESTION_DIR
    chown -R syslog:syslog $LOG_DIR
    chmod -R 755 $LOG_INGESTION_DIR
    chmod -R 755 $LOG_DIR
    
    echo -e "${{GREEN}}Directory structure created.${{NC}}"
}}

# Install packages based on OS
install_packages() {{
    echo -e "${{YELLOW}}Installing required packages...${{NC}}"
    
    case $OS in
        ubuntu|debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update
            apt-get install -y curl wget gnupg2 software-properties-common apt-transport-https
            apt-get install -y rsyslog rsyslog-relp syslog-ng-core
            apt-get install -y python3 python3-pip python3-dev
            apt-get install -y logrotate cron
            apt-get install -y jq git unzip
            apt-get install -y build-essential
            apt-get install -y net-tools htop iotop
            apt-get install -y fail2ban ufw
            ;;
        centos|rhel|fedora|rocky|almalinux)
            if command -v dnf &> /dev/null; then
                dnf update -y
                dnf install -y curl wget gnupg2 epel-release
                dnf install -y rsyslog syslog-ng
                dnf install -y python3 python3-pip python3-devel
                dnf install -y logrotate cronie
                dnf install -y jq git unzip
                dnf install -y gcc gcc-c++ make
                dnf install -y net-tools htop iotop
                dnf install -y fail2ban firewalld
            else
                yum update -y
                yum install -y curl wget gnupg2 epel-release
                yum install -y rsyslog syslog-ng
                yum install -y python3 python3-pip python3-devel
                yum install -y logrotate cronie
                yum install -y jq git unzip
                yum install -y gcc gcc-c++ make
                yum install -y net-tools htop iotop
                yum install -y fail2ban firewalld
            fi
            ;;
        *)
            echo -e "${{RED}}Unsupported OS: $OS${{NC}}"
            exit 1
            ;;
    esac
    
    # Install Python packages
    pip3 install --upgrade pip
    pip3 install requests pyyaml elasticsearch loguru geoip2 maxminddb
    
    echo -e "${{GREEN}}Packages installed successfully.${{NC}}"
}}

# Install Elastic Stack Repository
install_elastic_repo() {{
    echo -e "${{YELLOW}}Installing Elastic Stack Repository...${{NC}}"
    
    case $OS in
        ubuntu|debian)
            wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
            echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-8.x.list
            apt-get update
            ;;
        centos|rhel|fedora|rocky|almalinux)
            rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
            cat > /etc/yum.repos.d/elasticsearch.repo << 'EOF'
[elasticsearch]
name=Elasticsearch repository for 8.x packages
baseurl=https://artifacts.elastic.co/packages/8.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF
            ;;
    esac
    
    echo -e "${{GREEN}}Elastic Stack repository configured.${{NC}}"
}}

# Install Logstash
install_logstash() {{
    echo -e "${{YELLOW}}Installing Logstash...${{NC}}"
    
    case $OS in
        ubuntu|debian)
            apt-get install -y logstash
            ;;
        centos|rhel|fedora|rocky|almalinux)
            if command -v dnf &> /dev/null; then
                dnf install -y logstash
            else
                yum install -y logstash
            fi
            ;;
    esac
    
    # Install additional Logstash plugins
    /usr/share/logstash/bin/logstash-plugin install logstash-filter-geoip
    /usr/share/logstash/bin/logstash-plugin install logstash-filter-translate
    /usr/share/logstash/bin/logstash-plugin install logstash-filter-cidr
    /usr/share/logstash/bin/logstash-plugin install logstash-filter-dns
    /usr/share/logstash/bin/logstash-plugin install logstash-output-email
    
    echo -e "${{GREEN}}Logstash installed with additional plugins.${{NC}}"
}}

# Install Filebeat
install_filebeat() {{
    echo -e "${{YELLOW}}Installing Filebeat...${{NC}}"
    
    case $OS in
        ubuntu|debian)
            apt-get install -y filebeat
            ;;
        centos|rhel|fedora|rocky|almalinux)
            if command -v dnf &> /dev/null; then
                dnf install -y filebeat
            else
                yum install -y filebeat
            fi
            ;;
    esac
    
    echo -e "${{GREEN}}Filebeat installed.${{NC}}"
}}

# Install Fluentd
install_fluentd() {{
    echo -e "${{YELLOW}}Installing Fluentd...${{NC}}"
    
    curl -L https://toolbelt.treasuredata.com/sh/install-ubuntu-focal-td-agent4.sh | sh
    
    # Install plugins
    /opt/td-agent/bin/fluent-gem install fluent-plugin-elasticsearch
    /opt/td-agent/bin/fluent-gem install fluent-plugin-rewrite-tag-filter
    /opt/td-agent/bin/fluent-gem install fluent-plugin-parser
    /opt/td-agent/bin/fluent-gem install fluent-plugin-geoip
    /opt/td-agent/bin/fluent-gem install fluent-plugin-prometheus
    
    echo -e "${{GREEN}}Fluentd installed with plugins.${{NC}}"
}}

# Download GeoIP databases
download_geoip() {{
    echo -e "${{YELLOW}}Downloading GeoIP databases...${{NC}}"
    
    GEOIP_DIR="/var/lib/log-ingestion/geoip"
    
    # Download free GeoLite2 databases
    wget -O $GEOIP_DIR/GeoLite2-City.mmdb.gz "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_LICENSE_KEY&suffix=tar.gz" || true
    wget -O $GEOIP_DIR/GeoLite2-Country.mmdb.gz "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=YOUR_LICENSE_KEY&suffix=tar.gz" || true
    
    # Extract if downloaded successfully
    if [ -f "$GEOIP_DIR/GeoLite2-City.mmdb.gz" ]; then
        gunzip $GEOIP_DIR/GeoLite2-City.mmdb.gz 2>/dev/null || true
    fi
    
    if [ -f "$GEOIP_DIR/GeoLite2-Country.mmdb.gz" ]; then
        gunzip $GEOIP_DIR/GeoLite2-Country.mmdb.gz 2>/dev/null || true
    fi
    
    echo -e "${{GREEN}}GeoIP databases setup completed.${{NC}}"
}}

# Configure enhanced Rsyslog
configure_rsyslog() {{
    echo -e "${{YELLOW}}Configuring Enhanced Rsyslog...${{NC}}"
    
    # Backup original configuration
    cp /etc/rsyslog.conf /etc/rsyslog.conf.backup
    
    cat > /etc/rsyslog.d/10-log-ingestion.conf << 'EOF'
# Enhanced Log Ingestion Server Configuration

# Load modules
module(load="imudp")
module(load="imtcp")
module(load="imrelp")
module(load="imfile")
module(load="mmjsonparse")
module(load="mmnormalize")

# Input configurations
input(type="imudp" port="514" ruleset="remote")
input(type="imtcp" port="10514" ruleset="remote")
input(type="imrelp" port="20514" ruleset="remote")

# Specific ports for security tools
input(type="imudp" port="1514" ruleset="snort")
input(type="imudp" port="1515" ruleset="ossec")
input(type="imudp" port="1516" ruleset="suricata")

# Enhanced JSON template
template(name="JSONFormat" type="list") {
    constant(value="{\\"@timestamp\\":\\"")
    property(name="timereported" dateFormat="rfc3339")
    constant(value="\\",\\"@version\\":\\"1\\",\\"host\\":\\"")
    property(name="hostname")
    constant(value="\\",\\"severity\\":\\"")
    property(name="syslogseverity-text")
    constant(value="\\",\\"facility\\":\\"")
    property(name="syslogfacility-text")
    constant(value="\\",\\"program\\":\\"")
    property(name="programname")
    constant(value="\\",\\"pid\\":\\"")
    property(name="procid")
    constant(value="\\",\\"message\\":\\"")
    property(name="msg" format="json")
    constant(value="\\",\\"tags\\":[\\"syslog\\"],\\"type\\":\\"syslog\\"}")
    constant(value="\\n")
}

# SNORT ruleset
ruleset(name="snort") {
    action(type="omfile" file="/var/log/ingestion/snort/snort.log" template="JSONFormat")
    call rsyslog_remote
}

# OSSEC ruleset  
ruleset(name="ossec") {
    action(type="omfile" file="/var/log/ingestion/ossec/ossec.log" template="JSONFormat")
    call rsyslog_remote
}

# Suricata ruleset
ruleset(name="suricata") {
    action(type="omfile" file="/var/log/ingestion/suricata/suricata.log" template="JSONFormat")
    call rsyslog_remote
}

# Remote logs ruleset
ruleset(name="remote") {
    # Filter by program name
    if $programname == 'snort' then {
        action(type="omfile" file="/var/log/ingestion/snort/snort.log" template="JSONFormat")
        stop
    }
    
    if $programname == 'ossec' then {
        action(type="omfile" file="/var/log/ingestion/ossec/ossec.log" template="JSONFormat")
        stop
    }
    
    if $programname == 'suricata' then {
        action(type="omfile" file="/var/log/ingestion/suricata/suricata.log" template="JSONFormat")
        stop
    }
    
    if $programname == 'apache2' or $programname == 'httpd' then {
        action(type="omfile" file="/var/log/ingestion/apache/apache.log" template="JSONFormat")
        stop
    }
    
    if $programname == 'nginx' then {
        action(type="omfile" file="/var/log/ingestion/nginx/nginx.log" template="JSONFormat")
        stop
    }
    
    if $programname == 'sshd' then {
        action(type="omfile" file="/var/log/ingestion/ssh/ssh.log" template="JSONFormat")
        stop
    }
    
    if $programname == 'kernel' and $msg contains 'UFW' then {
        action(type="omfile" file="/var/log/ingestion/firewall/firewall.log" template="JSONFormat")
        stop
    }
    
    if $programname == 'named' or $programname == 'dnsmasq' then {
        action(type="omfile" file="/var/log/ingestion/dns/dns.log" template="JSONFormat")
        stop
    }
    
    if $programname == 'dhcpd' then {
        action(type="omfile" file="/var/log/ingestion/dhcp/dhcp.log" template="JSONFormat")
        stop
    }
    
    if $programname == 'openvpn' or $programname == 'strongswan' then {
        action(type="omfile" file="/var/log/ingestion/vpn/vpn.log" template="JSONFormat")
        stop
    }
    
    # Default catch-all
    action(type="omfile" file="/var/log/ingestion/general/general.log" template="JSONFormat")
}

# High frequency log rate limiting
$SystemLogRateLimitInterval 2
$SystemLogRateLimitBurst 500

# Working directory
$WorkDirectory /var/spool/rsyslog

# Include all config files in /etc/rsyslog.d/
$IncludeConfig /etc/rsyslog.d/*.conf
EOF

    # Set proper permissions
    chown root:root /etc/rsyslog.d/10-log-ingestion.conf
    chmod 644 /etc/rsyslog.d/10-log-ingestion.conf
    
    echo -e "${{GREEN}}Enhanced Rsyslog configured.${{NC}}"
}}

# Configure comprehensive Logstash
configure_logstash() {{
    echo -e "${{YELLOW}}Configuring Comprehensive Logstash...${{NC}}"
    
    # Main pipeline configuration
    cat > /etc/logstash/conf.d/01-inputs.conf << 'EOF'
input {
    # Beats input
    beats {
        port => 5044
        type => "beats"
    }
    
    # Syslog inputs
    syslog {
        port => 514
        type => "syslog"
    }
    
    tcp {
        port => 10514
        type => "syslog-tcp"
    }
    
    # Security tools specific inputs
    udp {
        port => 1514
        type => "snort"
    }
    
    udp {
        port => 1515
        type => "ossec"
    }
    
    udp {
        port => 1516
        type => "suricata"
    }
    
    # File inputs for local logs
    file {
        path => "/var/log/ingestion/snort/*.log"
        start_position => "beginning"
        type => "snort"
        codec => "json"
        tags => ["snort", "ids"]
    }
    
    file {
        path => "/var/log/ingestion/ossec/*.log"
        start_position => "beginning"
        type => "ossec"
        codec => "json"
        tags => ["ossec", "hids"]
    }
    
    file {
        path => "/var/log/ingestion/suricata/*.log"
        start_position => "beginning"
        type => "suricata"
        codec => "json"
        tags => ["suricata", "ids", "ips"]
    }
    
    file {
        path => "/var/log/ingestion/apache/*.log"
        start_position => "beginning"
        type => "apache"
        codec => "json"
        tags => ["apache", "web"]
    }
    
    file {
        path => "/var/log/ingestion/nginx/*.log"
        start_position => "beginning"
        type => "nginx"
        codec => "json"
        tags => ["nginx", "web"]
    }
    
    file {
        path => "/var/log/ingestion/ssh/*.log"
        start_position => "beginning"
        type => "ssh"
        codec => "json"
        tags => ["ssh", "auth"]
    }
    
    file {
        path => "/var/log/ingestion/firewall/*.log"
        start_position => "beginning"
        type => "firewall"
        codec => "json"
        tags => ["firewall", "network"]
    }
    
    file {
        path => "/var/log/ingestion/dns/*.log"
        start_position => "beginning"
        type => "dns"
        codec => "json"
        tags => ["dns", "network"]
    }
    
    file {
        path => "/var/log/ingestion/vpn/*.log"
        start_position => "beginning"
        type => "vpn"
        codec => "json"
        tags => ["vpn", "network"]
    }
}
EOF

    cat > /etc/logstash/conf.d/02-filters.conf << 'EOF'
filter {
    # Common timestamp parsing
    if [@timestamp] {
        date {
            match => [ "@timestamp", "ISO8601" ]
        }
    } else if [timestamp] {
        date {
            match => [ "timestamp", "ISO8601", "yyyy-MM-dd HH:mm:ss", "MMM dd HH:mm:ss" ]
        }
    }
    
    # Add common fields
    mutate {
        add_field => { "ingestion_server" => "%{[host][name]}" }
        add_field => { "processed_at" => "%{@timestamp}" }
        add_field => { "log_ingestion_version" => "2.0" }
    }
    
    # SNORT log processing
    if [type] == "snort" {
        # Parse SNORT alert format
        grok {
            match => { "message" => "\[%{INT:generator_id}:%{INT:signature_id}:%{INT:signature_revision}\] %{DATA:alert_msg} \[Classification: %{DATA:classification}\] \[Priority: %{INT:priority}\] %{GREEDYDATA:snort_raw}" }
        }
        
        # Extract network information
        grok {
            match => { "snort_raw" => "%{IP:src_ip}:%{INT:src_port} -> %{IP:dst_ip}:%{INT:dst_port}" }
        }
        
        # Add threat level based on priority
        if [priority] {
            if [priority] == "1" {
                mutate { add_field => { "threat_level" => "critical" } }
            } else if [priority] == "2" {
                mutate { add_field => { "threat_level" => "high" } }
            } else if [priority] == "3" {
                mutate { add_field => { "threat_level" => "medium" } }
            } else {
                mutate { add_field => { "threat_level" => "low" } }
            }
        }
        
        # GeoIP enrichment
        if [src_ip] {
            geoip {
                source => "src_ip"
                target => "src_geoip"
                database => "/var/lib/log-ingestion/geoip/GeoLite2-City.mmdb"
            }
        }
        
        if [dst_ip] {
            geoip {
                source => "dst_ip"
                target => "dst_geoip"
                database => "/var/lib/log-ingestion/geoip/GeoLite2-City.mmdb"
            }
        }
        
        mutate {
            add_field => { "event_category" => "intrusion_detection" }
            add_field => { "security_tool" => "snort" }
        }
    }
    
    # OSSEC log processing
    if [type] == "ossec" {
        # Parse OSSEC alert format
        grok {
            match => { "message" => "\*\* Alert %{NUMBER:alert_timestamp}: %{DATA:alert_msg}" }
        }
        
        # Extract rule information
        if [message] =~ /Rule: / {
            grok {
                match => { "message" => "Rule: %{INT:rule_id} $$level %{INT:alert_level}$$ -> '%{DATA:rule_description}'" }
            }
        }
        
        # Extract source IP if present
        if [message] =~ /Src IP: / {
            grok {
                match => { "message" => "Src IP: %{IP:src_ip}" }
            }
        }
        
        # Add severity based on level
        if [alert_level] {
            if [alert_level] >= "10" {
                mutate { add_field => { "severity" => "critical" } }
            } else if [alert_level] >= "7" {
                mutate { add_field => { "severity" => "high" } }
            } else if [alert_level] >= "4" {
                mutate { add_field => { "severity" => "medium" } }
            } else {
                mutate { add_field => { "severity" => "low" } }
            }
        }
        
        # GeoIP for source IP
        if [src_ip] {
            geoip {
                source => "src_ip"
                target => "src_geoip"
                database => "/var/lib/log-ingestion/geoip/GeoLite2-City.mmdb"
            }
        }
        
        mutate {
            add_field => { "event_category" => "host_intrusion_detection" }
            add_field => { "security_tool" => "ossec" }
        }
    }
    
    # Suricata log processing
    if [type] == "suricata" {
        # Parse Suricata EVE JSON format
        if [message] =~ /^\{/ {
            json {
                source => "message"
            }
        }
        
        # Process alert events
        if [event_type] == "alert" {
            mutate {
                add_field => { "event_category" => "network_intrusion_detection" }
                add_field => { "alert_signature" => "%{[alert][signature]}" }
                add_field => { "alert_category" => "%{[alert][category]}" }
                add_field => { "alert_severity" => "%{[alert][severity]}" }
            }
            
            # Map severity
            if [alert_severity] == "1" {
                mutate { add_field => { "threat_level" => "critical" } }
            } else if [alert_severity] == "2" {
                mutate { add_field => { "threat_level" => "high" } }
            } else if [alert_severity] == "3" {
                mutate { add_field => { "threat_level" => "medium" } }
            } else {
                mutate { add_field => { "threat_level" => "low" } }
            }
        }
        
        # GeoIP enrichment
        if [src_ip] {
            geoip {
                source => "src_ip"
                target => "src_geoip"
                database => "/var/lib/log-ingestion/geoip/GeoLite2-City.mmdb"
            }
        }
        
        if [dest_ip] {
            geoip {
                source => "dest_ip"
                target => "dst_geoip"
                database => "/var/lib/log-ingestion/geoip/GeoLite2-City.mmdb"
            }
        }
        
        mutate {
            add_field => { "security_tool" => "suricata" }
        }
    }
    
    # Apache log processing
    if [type] == "apache" {
        grok {
            match => { "message" => "%{COMBINEDAPACHELOG}" }
        }
        
        # Convert response code to number
        mutate {
            convert => { "response" => "integer" }
            convert => { "bytes" => "integer" }
        }
        
        # Add error indicators
        if [response] >= 400 {
            mutate {
                add_field => { "is_error" => "true" }
                add_field => { "error_type" => "http_error" }
            }
        }
        
        # Detect potential attacks
        if [request] =~ /(sql|script|exec|union|select|drop|insert|update|delete|<script|javascript|vbscript|onload|onerror|eval)/i {
            mutate {
                add_field => { "potential_attack" => "true" }
                add_field => { "attack_indicators" => "web_attack_pattern" }
            }
            
            if [request] =~ /(sql|union|select|drop|insert|update|delete)/i {
                mutate { add_field => { "attack_type" => "sql_injection" } }
            }
            
            if [request] =~ /(<script|javascript|vbscript|onload|onerror|eval)/i {
                mutate { add_field => { "attack_type" => "xss" } }
            }
        }
        
        # GeoIP for client IP
        if [clientip] {
            geoip {
                source => "clientip"
                target => "client_geoip"
                database => "/var/lib/log-ingestion/geoip/GeoLite2-City.mmdb"
            }
        }
        
        mutate {
            add_field => { "event_category" => "web_access" }
            add_field => { "service_type" => "web_server" }
        }
    }
    
    # SSH log processing
    if [type] == "ssh" {
        # Failed login attempts
        if [message] =~ /Failed password/ {
            grok {
                match => { "message" => "Failed password for %{DATA:username} from %{IP:src_ip} port %{INT:src_port}" }
            }
            mutate {
                add_field => { "event_type" => "failed_login" }
                add_field => { "severity" => "warning" }
                add_field => { "auth_result" => "failure" }
            }
        }
        
        # Successful logins
        if [message] =~ /Accepted/ {
            grok {
                match => { "message" => "Accepted %{DATA:auth_method} for %{DATA:username} from %{IP:src_ip} port %{INT:src_port}" }
            }
            mutate {
                add_field => { "event_type" => "successful_login" }
                add_field => { "severity" => "info" }
                add_field => { "auth_result" => "success" }
            }
        }
        
        # Invalid user attempts
        if [message] =~ /Invalid user/ {
            grok {
                match => { "message" => "Invalid user %{DATA:username} from %{IP:src_ip}" }
            }
            mutate {
                add_field => { "event_type" => "invalid_user" }
                add_field => { "severity" => "warning" }
                add_field => { "auth_result" => "failure" }
            }
        }
        
        # GeoIP for source IP
        if [src_ip] {
            geoip {
                source => "src_ip"
                target => "src_geoip"
                database => "/var/lib/log-ingestion/geoip/GeoLite2-City.mmdb"
            }
        }
        
        mutate {
            add_field => { "event_category" => "authentication" }
            add_field => { "service_type" => "ssh" }
        }
    }
    
    # Firewall log processing
    if [type] == "firewall" {
        # UFW log format
        if [message] =~ /UFW/ {
            grok {
                match => { "message" => "UFW %{WORD:action}.*SRC=%{IP:src_ip}.*DST=%{IP:dst_ip}.*PROTO=%{WORD:protocol}.*DPT=%{INT:dst_port}" }
            }
        }
        
        # iptables log format
        if [message] =~ /iptables/ {
            grok {
                match => { "message" => "iptables.*SRC=%{IP:src_ip}.*DST=%{IP:dst_ip}.*PROTO=%{WORD:protocol}.*DPT=%{INT:dst_port}" }
            }
        }
        
        # Add threat indicators
        if [action] == "BLOCK" or [action] == "DROP" or [action] == "REJECT" {
            mutate {
                add_field => { "is_blocked" => "true" }
                add_field => { "security_action" => "blocked" }
            }
        }
        
        # GeoIP enrichment
        if [src_ip] {
            geoip {
                source => "src_ip"
                target => "src_geoip"
                database => "/var/lib/log-ingestion/geoip/GeoLite2-City.mmdb"
            }
        }
        
        mutate {
            add_field => { "event_category" => "network_security" }
            add_field => { "security_tool" => "firewall" }
        }
    }
    
    # DNS log processing
    if [type] == "dns" {
        # Extract DNS query information
        grok {
            match => { "message" => "client %{IP:client_ip}#%{INT:client_port}: query: %{DATA:query_name} %{WORD:query_class} %{WORD:query_type}" }
        }
        
        # Detect suspicious DNS queries
        if [query_name] =~ /(malware|botnet|phishing|suspicious|dga)/i {
            mutate {
                add_field => { "suspicious_dns" => "true" }
                add_field => { "threat_indicator" => "suspicious_domain" }
            }
        }
        
        mutate {
            add_field => { "event_category" => "dns_query" }
            add_field => { "service_type" => "dns" }
        }
    }
    
    # VPN log processing
    if [type] == "vpn" {
        # OpenVPN logs
        if [message] =~ /OpenVPN/ {
            if [message] =~ /CONNECTED/ {
                grok {
                    match => { "message" => "%{IP:client_ip}:%{INT:client_port} \\[%{DATA:username}\\] Peer Connection Initiated" }
                }
                mutate {
                    add_field => { "event_type" => "vpn_connect" }
                    add_field => { "connection_status" => "connected" }
                }
            }
            
            if [message] =~ /DISCONNECTED/ {
                mutate {
                    add_field => { "event_type" => "vpn_disconnect" }
                    add_field => { "connection_status" => "disconnected" }
                }
            }
        }
        
        mutate {
            add_field => { "event_category" => "vpn_access" }
            add_field => { "service_type" => "vpn" }
        }
    }
    
    # Remove sensitive information
    mutate {
        remove_field => [ "password", "passwd", "secret", "key", "token" ]
    }
    
    # Add final processing metadata
    mutate {
        add_field => { "processed_by" => "enhanced-log-ingestion-server" }
        add_field => { "processing_pipeline" => "logstash" }
    }
}
EOF

    cat > /etc/logstash/conf.d/03-outputs.conf << 'EOF'
output {
    # Send to Elasticsearch with dynamic indexing
    elasticsearch {
        hosts => ["127.0.0.1:9200"]
        index => "logs-%{type}-%{+YYYY.MM.dd}"
        template_name => "log-ingestion-template"
        template_pattern => "logs-*"
        template => "/etc/logstash/templates/log-ingestion-template.json"
        template_overwrite => true
    }
    
    # High priority alerts to separate index
    if [threat_level] == "critical" or [severity] == "critical" {
        elasticsearch {
            hosts => ["127.0.0.1:9200"]
            index => "alerts-critical-%{+YYYY.MM.dd}"
        }
    }
    
    # Security events to dedicated index
    if "security" in [tags] or [event_category] =~ /intrusion|security|attack/ {
        elasticsearch {
            hosts => ["127.0.0.1:9200"]
            index => "security-events-%{+YYYY.MM.dd}"
        }
    }
    
    # Debug output (can be disabled in production)
    if [loglevel] == "debug" {
        stdout {
            codec => rubydebug
        }
    }
}
EOF

    # Create Elasticsearch template
    mkdir -p /etc/logstash/templates
    cat > /etc/logstash/templates/log-ingestion-template.json << 'EOF'
{
    "index_patterns": ["logs-*"],
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "index.refresh_interval": "5s"
    },
    "mappings": {
        "properties": {
            "@timestamp": { "type": "date" },
            "@version": { "type": "keyword" },
            "host": { "type": "keyword" },
            "message": { "type": "text" },
            "type": { "type": "keyword" },
            "tags": { "type": "keyword" },
            "severity": { "type": "keyword" },
            "threat_level": { "type": "keyword" },
            "event_category": { "type": "keyword" },
            "security_tool": { "type": "keyword" },
            "src_ip": { "type": "ip" },
            "dst_ip": { "type": "ip" },
            "src_port": { "type": "integer" },
            "dst_port": { "type": "integer" },
            "src_geoip": {
                "properties": {
                    "location": { "type": "geo_point" },
                    "country_name": { "type": "keyword" },
                    "city_name": { "type": "keyword" },
                    "continent_code": { "type": "keyword" }
                }
            },
            "dst_geoip": {
                "properties": {
                    "location": { "type": "geo_point" },
                    "country_name": { "type": "keyword" },
                    "city_name": { "type": "keyword" },
                    "continent_code": { "type": "keyword" }
                }
            }
        }
    }
}
EOF

    # Set proper permissions
    chown -R logstash:logstash /etc/logstash/
    chmod -R 644 /etc/logstash/conf.d/
    chmod -R 644 /etc/logstash/templates/
    
    echo -e "${{GREEN}}Comprehensive Logstash configured.${{NC}}"
}}

# Configure Filebeat
configure_filebeat() {{
    echo -e "${{YELLOW}}Configuring Filebeat...${{NC}}"
    
    cat > /etc/filebeat/filebeat.yml << 'EOF'
# Enhanced Filebeat Configuration for Log Ingestion Server

filebeat.inputs:
# System logs
- type: log
  enabled: true
  paths:
    - /var/log/syslog
    - /var/log/messages
  fields:
    log_type: system
    service_type: system
  fields_under_root: true

# Security logs
- type: log
  enabled: true
  paths:
    - /var/log/auth.log
    - /var/log/secure
  fields:
    log_type: auth
    service_type: authentication
  fields_under_root: true

# Apache logs
- type: log
  enabled: true
  paths:
    - /var/log/apache2/access.log
    - /var/log/apache2/error.log
    - /var/log/httpd/access_log
    - /var/log/httpd/error_log
  fields:
    log_type: apache
    service_type: web_server
  fields_under_root: true

# Nginx logs
- type: log
  enabled: true
  paths:
    - /var/log/nginx/access.log
    - /var/log/nginx/error.log
  fields:
    log_type: nginx
    service_type: web_server
  fields_under_root: true

# Custom ingestion logs
- type: log
  enabled: true
  paths:
    - /var/log/ingestion/*/*.log
  fields:
    log_source: ingestion_server
  fields_under_root: true
  multiline.pattern: '^\\{'
  multiline.negate: true
  multiline.match: after

# Processors
processors:
- add_host_metadata:
    when.not.contains.tags: forwarded
- add_docker_metadata: ~
- add_kubernetes_metadata: ~

# Output to Logstash
output.logstash:
  hosts: ["localhost:5044"]
  
# Logging
logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644

# Monitoring
monitoring.enabled: true
EOF

    # Set proper permissions
    chown root:root /etc/filebeat/filebeat.yml
    chmod 600 /etc/filebeat/filebeat.yml
    
    echo -e "${{GREEN}}Filebeat configured.${{NC}}"
}}

# Configure enhanced log rotation
configure_logrotate() {{
    echo -e "${{YELLOW}}Configuring Enhanced Log Rotation...${{NC}}"
    
    cat > /etc/logrotate.d/log-ingestion << 'EOF'
# Log Ingestion Server Log Rotation

/var/log/ingestion/*/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 syslog syslog
    sharedscripts
    postrotate
        systemctl reload rsyslog
        systemctl reload filebeat
    endscript
}

/var/log/logstash/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 644 logstash logstash
    postrotate
        systemctl reload logstash
    endscript
}

/var/log/td-agent/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 644 td-agent td-agent
    postrotate
        systemctl reload td-agent
    endscript
}
EOF

    echo -e "${{GREEN}}Enhanced log rotation configured.${{NC}}"
}}

# Create monitoring and alerting scripts
create_monitoring_scripts() {{
    echo -e "${{YELLOW}}Creating monitoring and alerting scripts...${{NC}}"
    
    # Log ingestion health check script
    cat > $SCRIPTS_DIR/health_check.py << 'EOF'
#!/usr/bin/env python3
"""
Log Ingestion Server Health Check Script
Monitors the health of all log ingestion components
"""

import json
import requests
import subprocess
import sys
import time
from datetime import datetime

def check_elasticsearch():
    """Check Elasticsearch health"""
    try:
        response = requests.get('http://localhost:9200/_cluster/health', timeout=10)
        if response.status_code == 200:
            health = response.json()
            return health['status'] in ['green', 'yellow']
    except:
        pass
    return False

def check_logstash():
    """Check Logstash health"""
    try:
        response = requests.get('http://localhost:9600/_node/stats', timeout=10)
        return response.status_code == 200
    except:
        pass
    return False

def check_service(service_name):
    """Check if a systemd service is running"""
    try:
        result = subprocess.run(['systemctl', 'is-active', service_name], 
                              capture_output=True, text=True)
        return result.stdout.strip() == 'active'
    except:
        return False

def check_log_files():
    """Check if log files are being written"""
    import os
    import glob
    
    log_dirs = ['/var/log/ingestion/*/']
    recent_files = 0
    
    for log_dir in log_dirs:
        for log_file in glob.glob(log_dir + '*.log'):
            try:
                stat = os.stat(log_file)
                if time.time() - stat.st_mtime < 300:  # Modified in last 5 minutes
                    recent_files += 1
            except:
                pass
    
    return recent_files > 0

def main():
    """Main health check function"""
    checks = {
        'elasticsearch': check_elasticsearch(),
        'logstash': check_logstash(),
        'rsyslog': check_service('rsyslog'),
        'filebeat': check_service('filebeat'),
        'td-agent': check_service('td-agent'),
        'log_files_active': check_log_files()
    }
    
    all_healthy = all(checks.values())
    
    result = {
        'timestamp': datetime.now().isoformat(),
        'overall_health': 'healthy' if all_healthy else 'unhealthy',
        'checks': checks
    }
    
    print(json.dumps(result, indent=2))
    
    if not all_healthy:
        sys.exit(1)

if __name__ == '__main__':
    main()
EOF

    # Log analysis script
    cat > $SCRIPTS_DIR/log_analyzer.py << 'EOF'
#!/usr/bin/env python3
"""
Log Analysis Script
Analyzes log patterns and generates security insights
"""

import json
import re
import sys
from collections import defaultdict, Counter
from datetime import datetime, timedelta

class LogAnalyzer:
    def __init__(self):
        self.patterns = {
            'failed_login': r'Failed password|authentication failure|invalid user',
            'sql_injection': r'(union|select|insert|update|delete|drop).*from',
            'xss_attempt': r'<script|javascript:|vbscript:|onload=|onerror=',
            'directory_traversal': r'\.\./|\.\.\\\|%2e%2e%2f',
            'suspicious_user_agent': r'(sqlmap|nikto|nmap|masscan|zap)',
            'brute_force': r'multiple failed|repeated attempts|brute.?force'
        }
        
        self.threat_scores = {
            'failed_login': 2,
            'sql_injection': 8,
            'xss_attempt': 6,
            'directory_traversal': 7,
            'suspicious_user_agent': 5,
            'brute_force': 9
        }
    
    def analyze_log_file(self, file_path):
        """Analyze a single log file"""
        results = defaultdict(list)
        ip_counter = Counter()
        
        try:
            with open(file_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        if line.strip().startswith('{'):
                            log_entry = json.loads(line.strip())
                            message = log_entry.get('message', '')
                        else:
                            message = line.strip()
                            log_entry = {'message': message, 'line_number': line_num}
                        
                        # Extract IP addresses
                        ip_matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', message)
                        for ip in ip_matches:
                            ip_counter[ip] += 1
                        
                        # Check for threat patterns
                        for pattern_name, pattern in self.patterns.items():
                            if re.search(pattern, message, re.IGNORECASE):
                                results[pattern_name].append({
                                    'line_number': line_num,
                                    'message': message[:200],
                                    'timestamp': log_entry.get('@timestamp', 'unknown'),
                                    'source_ip': ip_matches[0] if ip_matches else 'unknown'
                                })
                    
                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        continue
        
        except FileNotFoundError:
            return None
        
        return {
            'file': file_path,
            'threats': dict(results),
            'top_ips': dict(ip_counter.most_common(10)),
            'analysis_time': datetime.now().isoformat()
        }
    
    def generate_report(self, analysis_results):
        """Generate security analysis report"""
        total_threats = sum(len(threats) for threats in analysis_results['threats'].values())
        threat_score = sum(
            len(threats) * self.threat_scores.get(threat_type, 1)
            for threat_type, threats in analysis_results['threats'].items()
        )
        
        report = {
            'summary': {
                'total_threats_detected': total_threats,
                'threat_score': threat_score,
                'risk_level': self.calculate_risk_level(threat_score),
                'analysis_timestamp': datetime.now().isoformat()
            },
            'threat_breakdown': {
                threat_type: len(threats)
                for threat_type, threats in analysis_results['threats'].items()
            },
            'top_source_ips': analysis_results['top_ips'],
            'detailed_threats': analysis_results['threats']
        }
        
        return report
    
    def calculate_risk_level(self, score):
        """Calculate risk level based on threat score"""
        if score >= 50:
            return 'CRITICAL'
        elif score >= 20:
            return 'HIGH'
        elif score >= 10:
            return 'MEDIUM'
        elif score > 0:
            return 'LOW'
        else:
            return 'MINIMAL'

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 log_analyzer.py <log_file_path>")
        sys.exit(1)
    
    analyzer = LogAnalyzer()
    results = analyzer.analyze_log_file(sys.argv[1])
    
    if results is None:
        print(f"Error: Could not analyze file {sys.argv[1]}")
        sys.exit(1)
    
    report = analyzer.generate_report(results)
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
EOF

    # Alert script
    cat > $SCRIPTS_DIR/alert_manager.py << 'EOF'
#!/usr/bin/env python3
"""
Alert Manager Script
Sends alerts based on log analysis results
"""

import json
import smtplib
import sys
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

class AlertManager:
    def __init__(self, config_file='/etc/log-ingestion/alert_config.json'):
        self.config = self.load_config(config_file)
    
    def load_config(self, config_file):
        """Load alert configuration"""
        default_config = {
            'email': {
                'enabled': False,
                'smtp_server': 'localhost',
                'smtp_port': 587,
                'username': '',
                'password': '',
                'from_email': 'alerts@log-ingestion.local',
                'to_emails': ['admin@example.com']
            },
            'thresholds': {
                'critical': 50,
                'high': 20,
                'medium': 10
            }
        }
        
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                # Merge with defaults
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                return config
        except FileNotFoundError:
            return default_config
    
    def should_alert(self, threat_score, risk_level):
        """Determine if an alert should be sent"""
        thresholds = self.config['thresholds']
        
        if risk_level == 'CRITICAL' and threat_score >= thresholds['critical']:
            return True
        elif risk_level == 'HIGH' and threat_score >= thresholds['high']:
            return True
        elif risk_level == 'MEDIUM' and threat_score >= thresholds['medium']:
            return True
        
        return False
    
    def send_email_alert(self, report):
        """Send email alert"""
        if not self.config['email']['enabled']:
            return False
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.config['email']['from_email']
            msg['To'] = ', '.join(self.config['email']['to_emails'])
            msg['Subject'] = f"Security Alert - {report['summary']['risk_level']} Risk Detected"
            
            body = f"""
Security Alert - Log Ingestion Server

Risk Level: {report['summary']['risk_level']}
Threat Score: {report['summary']['threat_score']}
Total Threats: {report['summary']['total_threats_detected']}
Analysis Time: {report['summary']['analysis_timestamp']}

Threat Breakdown:
{json.dumps(report['threat_breakdown'], indent=2)}

Top Source IPs:
{json.dumps(report['top_source_ips'], indent=2)}

Please review the security logs immediately.
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(self.config['email']['smtp_server'], 
                                self.config['email']['smtp_port'])
            server.starttls()
            
            if self.config['email']['username']:
                server.login(self.config['email']['username'], 
                           self.config['email']['password'])
            
            server.send_message(msg)
            server.quit()
            
            return True
            
        except Exception as e:
            print(f"Failed to send email alert: {e}")
            return False
    
    def process_alert(self, report):
        """Process and send alerts based on report"""
        summary = report['summary']
        
        if self.should_alert(summary['threat_score'], summary['risk_level']):
            print(f"Alert triggered: {summary['risk_level']} risk detected")
            
            if self.send_email_alert(report):
                print("Email alert sent successfully")
            else:
                print("Failed to send email alert")
            
            # Log alert to file
            alert_log = {
                'timestamp': datetime.now().isoformat(),
                'risk_level': summary['risk_level'],
                'threat_score': summary['threat_score'],
                'alert_sent': True
            }
            
            with open('/var/log/ingestion/alerts.log', 'a') as f:
                f.write(json.dumps(alert_log) + '\\n')
        
        else:
            print("No alert threshold reached")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 alert_manager.py <analysis_report.json>")
        sys.exit(1)
    
    try:
        with open(sys.argv[1], 'r') as f:
            report = json.load(f)
        
        alert_manager = AlertManager()
        alert_manager.process_alert(report)
        
    except Exception as e:
        print(f"Error processing alert: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
    
EOF

    # Make scripts executable
    chmod +x $SCRIPTS_DIR/*.py
    
    echo -e "${{GREEN}}Monitoring and alerting scripts created.${{NC}}"
}}

# Configure firewall
configure_firewall() {{
    echo -e "${{YELLOW}}Configuring Firewall...${{NC}}"
    
    if command -v ufw &> /dev/null; then
        # Ubuntu/Debian UFW
        ufw --force enable
        ufw allow $SYSLOG_PORT/udp comment "Syslog UDP"
        ufw allow $RSYSLOG_PORT/tcp comment "Rsyslog TCP"
        ufw allow $FLUENTD_PORT/tcp comment "Fluentd"
        ufw allow $LOGSTASH_PORT/tcp comment "Logstash Beats"
        ufw allow $BEATS_PORT/tcp comment "Beats Input"
        ufw allow $SNORT_PORT/udp comment "SNORT"
        ufw allow $OSSEC_PORT/udp comment "OSSEC"
        ufw allow $SURICATA_PORT/udp comment "Suricata"
        ufw allow 22/tcp comment "SSH"
        
    elif command -v firewall-cmd &> /dev/null; then
        # CentOS/RHEL/Fedora firewalld
        systemctl enable firewalld
        systemctl start firewalld
        
        firewall-cmd --permanent --add-port=$SYSLOG_PORT/udp
        firewall-cmd --permanent --add-port=$RSYSLOG_PORT/tcp
        firewall-cmd --permanent --add-port=$FLUENTD_PORT/tcp
        firewall-cmd --permanent --add-port=$LOGSTASH_PORT/tcp
        firewall-cmd --permanent --add-port=$BEATS_PORT/tcp
        firewall-cmd --permanent --add-port=$SNORT_PORT/udp
        firewall-cmd --permanent --add-port=$OSSEC_PORT/udp
        firewall-cmd --permanent --add-port=$SURICATA_PORT/udp
        firewall-cmd --permanent --add-service=ssh
        firewall-cmd --reload
    fi
    
    echo -e "${{GREEN}}Firewall configured.${{NC}}"
}}

# Create systemd services and timers
create_systemd_services() {{
    echo -e "${{YELLOW}}Creating systemd services and timers...${{NC}}"
    
    # Health check service
    cat > /etc/systemd/system/log-ingestion-health.service << 'EOF'
[Unit]
Description=Log Ingestion Health Check
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/log-ingestion/scripts/health_check.py
User=root
StandardOutput=journal
StandardError=journal
EOF

    # Health check timer
    cat > /etc/systemd/system/log-ingestion-health.timer << 'EOF'
[Unit]
Description=Run Log Ingestion Health Check every 5 minutes
Requires=log-ingestion-health.service

[Timer]
OnCalendar=*:0/5
Persistent=true

[Install]
WantedBy=timers.target
EOF

    # Log analysis service
    cat > /etc/systemd/system/log-analysis.service << 'EOF'
[Unit]
Description=Log Analysis and Alerting
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'for log_file in /var/log/ingestion/*/*.log; do /opt/log-ingestion/scripts/log_analyzer.py "$log_file" > /tmp/analysis_$$(basename "$log_file").json && /opt/log-ingestion/scripts/alert_manager.py /tmp/analysis_$$(basename "$log_file").json; done'
User=root
StandardOutput=journal
StandardError=journal
EOF

    # Log analysis timer
    cat > /etc/systemd/system/log-analysis.timer << 'EOF'
[Unit]
Description=Run Log Analysis every 15 minutes
Requires=log-analysis.service

[Timer]
OnCalendar=*:0/15
Persistent=true

[Install]
WantedBy=timers.target
EOF

    # Enable and start timers
    systemctl daemon-reload
    systemctl enable log-ingestion-health.timer
    systemctl enable log-analysis.timer
    systemctl start log-ingestion-health.timer
    systemctl start log-analysis.timer
    
    echo -e "${{GREEN}}Systemd services and timers created.${{NC}}"
}}

# Start and enable services
start_services() {{
    echo -e "${{YELLOW}}Starting and enabling services...${{NC}}"
    
    # Enable and start rsyslog
    systemctl enable rsyslog
    systemctl restart rsyslog
    
    # Enable and start logstash
    systemctl enable logstash
    systemctl restart logstash
    
    # Enable and start filebeat
    systemctl enable filebeat
    systemctl restart filebeat
    
    # Enable and start fluentd
    systemctl enable td-agent
    systemctl restart td-agent
    
    # Wait for services to start
    sleep 10
    
    # Check service status
    services=("rsyslog" "logstash" "filebeat" "td-agent")
    for service in "${{services[@]}}"; do
        if systemctl is-active --quiet $service; then
            echo -e "${{GREEN}}✓ $service is running${{NC}}"
        else
            echo -e "${{RED}}✗ $service failed to start${{NC}}"
        fi
    done
    
    echo -e "${{GREEN}}Services startup completed.${{NC}}"
}}

# Create configuration files
create_config_files() {{
    echo -e "${{YELLOW}}Creating configuration files...${{NC}}"
    
    # Main configuration file
    cat > $CONFIG_DIR/log-ingestion.conf << 'EOF'
# Log Ingestion Server Configuration

[server]
name = log-ingestion-server
version = 2.0
installation_date = $(date -Iseconds)

[elasticsearch]
host = 127.0.0.1
port = 9200
index_prefix = logs

[logstash]
host = 127.0.0.1
port = 5044

[ports]
syslog_udp = 514
rsyslog_tcp = 10514
fluentd = 24224
beats = 5045
snort = 1514
ossec = 1515
suricata = 1516

[logging]
level = INFO
max_file_size = 100MB
retention_days = 30

[security]
enable_geoip = true
enable_threat_detection = true
alert_threshold = 10
EOF

    # Alert configuration
    cat > $CONFIG_DIR/alert_config.json << 'EOF'
{
    "email": {
        "enabled": false,
        "smtp_server": "localhost",
        "smtp_port": 587,
        "username": "",
        "password": "",
        "from_email": "alerts@log-ingestion.local",
        "to_emails": ["admin@example.com"]
    },
    "thresholds": {
        "critical": 50,
        "high": 20,
        "medium": 10
    },
    "notification_cooldown": 300
}
EOF

    # Threat intelligence configuration
    cat > $CONFIG_DIR/threat_intel.json << 'EOF'
{
    "malicious_ips": [],
    "suspicious_domains": [],
    "attack_patterns": {
        "sql_injection": ["union", "select", "insert", "update", "delete", "drop"],
        "xss": ["<script", "javascript:", "vbscript:", "onload=", "onerror="],
        "directory_traversal": ["../", "..\\\\", "%2e%2e%2f"],
        "command_injection": [";", "|", "&", "`", "$"]
    },
    "user_agents": {
        "suspicious": ["sqlmap", "nikto", "nmap", "masscan", "zap", "burp"]
    }
}
EOF

    # Set proper permissions
    chown -R root:root $CONFIG_DIR
    chmod -R 644 $CONFIG_DIR/*
    
    echo -e "${{GREEN}}Configuration files created.${{NC}}"
}}

