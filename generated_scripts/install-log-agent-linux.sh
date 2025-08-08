#!/bin/bash
# Log Forwarding Agent Installation Script for Linux
# Generated on: 2025-06-25 16:23:33
# Ingestion Server: localhost:5044

set -e

echo "=== Log Forwarding Agent Installation ==="
echo "Target OS: Linux (All Distributions)"
echo "Ingestion Server: localhost:5044"
echo "Rsyslog Forwarding Port: 514"
echo

# Detect Linux distribution
detect_distro() {
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
}

# Install dependencies based on distribution
install_dependencies() {
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
}

# Install Filebeat (Elastic Beat Agent)
install_filebeat() {
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
}

# Configure Filebeat
configure_filebeat() {
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
  exclude_files: ['\.gz$', '\.zip$']

# Output configuration
output.logstash:
  hosts: ["localhost:5044"]

# Logging configuration for Filebeat's internal logs
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
}

# Configure system logs forwarding
configure_rsyslog() {
    echo "Configuring rsyslog for centralized logging..."
    
    # Backup original rsyslog config
    cp /etc/rsyslog.conf /etc/rsyslog.conf.backup
    
    # Add forwarding rule to rsyslog
    cat >> /etc/rsyslog.conf << 'EOF'

# Forward logs to ingestion server
*.* @@localhost:514
EOF
    
    # Create custom rsyslog config for application logs
    cat > /etc/rsyslog.d/50-default.conf << 'EOF'
# Forward all logs to remote server
$ActionQueueFileName fwdRule1 # unique name prefix for spool files
$ActionQueueMaxDiskSpace 1g   # 1gb space limit (use as much as possible)
$ActionQueueSaveOnShutdown on # save messages to disk on shutdown
$ActionQueueType LinkedList   # run asynchronously
$ActionResumeRetryCount -1    # infinite retries if host is down
*.* @@localhost:514
EOF
}

# Start and enable services
enable_services() {
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
}

# Create monitoring script
create_monitoring_script() {
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
nc -zv localhost 5044
nc -zv localhost 514
EOF

    chmod +x /usr/local/bin/log-agent-monitor.sh
    echo "Monitoring script created at /usr/local/bin/log-agent-monitor.sh"
}

# Main installation function
main() {
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
    echo "Logs will be forwarded to: localhost:5044"
    echo
    echo "To monitor the agent, run: /usr/local/bin/log-agent-monitor.sh"
    echo "To test connectivity: filebeat test output"
    echo
    echo "Service management:"
    echo "   - Restart filebeat: systemctl restart filebeat"
    echo "   - Restart rsyslog: systemctl restart rsyslog"
    echo "   - Check logs: journalctl -u filebeat -f"
}

# Run main function
main "$@"
