"""
Linux script templates for ELK Stack installation
"""

class LinuxTemplates:
    """Templates for Linux installation script components"""
    
    def get_distro_detection_function(self):
        """Get Linux distribution detection function"""
        return """# Detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    else
        print_error "Cannot detect Linux distribution"
        exit 1
    fi
    print_status "Detected distribution: $DISTRO $VERSION"
}"""
    
    def get_root_check_function(self):
        """Get root privilege check function"""
        return """# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}"""
    
    def get_java_installation_function(self, java_version):
        """Get Java installation function"""
        return f"""# Install Java
install_java() {{
    print_status "Installing Java {java_version}..."
    
    case $DISTRO in
        "ubuntu"|"debian")
            apt-get update
            apt-get install -y openjdk-{java_version}-jdk curl wget gnupg2
            ;;
        "centos"|"rhel"|"fedora"|"rocky"|"almalinux")
            if command -v dnf &> /dev/null; then
                dnf install -y java-{java_version}-openjdk java-{java_version}-openjdk-devel curl wget gnupg2
            else
                yum install -y java-{java_version}-openjdk java-{java_version}-openjdk-devel curl wget gnupg2
            fi
            ;;
        "opensuse"|"sles")
            zypper install -y java-{java_version}-openjdk java-{java_version}-openjdk-devel curl wget gnupg2
            ;;
        "arch"|"manjaro")
            pacman -Sy --noconfirm jdk{java_version}-openjdk curl wget gnupg
            ;;
        *)
            print_warning "Unsupported distribution. Please install Java {java_version} manually."
            ;;
    esac
    
    # Verify Java installation
    java_version=$(java -version 2>&1 | head -n1 | cut -d'"' -f2)
    print_status "Java version installed: $java_version"
}}"""
    
    def get_elastic_repo_function(self):
        """Get Elastic repository setup function"""
        return """# Add Elastic repository
add_elastic_repo() {
    print_status "Adding Elastic repository..."
    
    # Import Elastic GPG key
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
    
    case $DISTRO in
        "ubuntu"|"debian")
            echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" > /etc/apt/sources.list.d/elastic-8.x.list
            apt-get update
            ;;
        "centos"|"rhel"|"fedora"|"rocky"|"almalinux")
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
}"""
    
    def get_elasticsearch_installation_function(self, config):
        """Get Elasticsearch installation function"""
        return f"""# Install Elasticsearch
install_elasticsearch() {{
    print_status "Installing Elasticsearch..."
    
    case $DISTRO in
        "ubuntu"|"debian")
            apt-get install -y elasticsearch=$ELK_VERSION
            ;;
        "centos"|"rhel"|"fedora"|"rocky"|"almalinux")
            if command -v dnf &> /dev/null; then
                dnf install -y --enablerepo=elasticsearch elasticsearch-$ELK_VERSION
            else
                yum install -y --enablerepo=elasticsearch elasticsearch-$ELK_VERSION
            fi
            ;;
        *)
            # Download and install manually for other distributions
            wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-$ELK_VERSION-linux-x86_64.tar.gz
            tar -xzf elasticsearch-$ELK_VERSION-linux-x86_64.tar.gz
            mv elasticsearch-$ELK_VERSION $INSTALL_PATH/elasticsearch
            useradd -r -s /bin/false elasticsearch
            chown -R elasticsearch:elasticsearch $INSTALL_PATH/elasticsearch
            ;;
    esac
    
    # Configure Elasticsearch
    print_status "Configuring Elasticsearch..."
    
    # Calculate heap size
    calculate_heap_size
    
    # Basic configuration
    cat > /etc/elasticsearch/elasticsearch.yml << EOF
cluster.name: $CLUSTER_NAME
node.name: $NODE_NAME
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: $ELASTICSEARCH_HOST
http.port: $ELASTICSEARCH_PORT
discovery.type: single-node
xpack.security.enabled: $ENABLE_SECURITY
xpack.security.enrollment.enabled: $ENABLE_SECURITY
xpack.security.http.ssl.enabled: $ENABLE_SSL
xpack.security.transport.ssl.enabled: $ENABLE_SSL
EOF

    # Set JVM heap size
    sed -i "s/-Xms1g/-Xms$ELASTICSEARCH_HEAP/" /etc/elasticsearch/jvm.options
    sed -i "s/-Xmx1g/-Xmx$ELASTICSEARCH_HEAP/" /etc/elasticsearch/jvm.options
    
    # Enable and start Elasticsearch
    systemctl daemon-reload
    systemctl enable elasticsearch
    systemctl start elasticsearch
    
    print_status "Waiting for Elasticsearch to start..."
    sleep 30
    
    # Test Elasticsearch
    if curl -s "$ELASTICSEARCH_HOST:$ELASTICSEARCH_PORT" > /dev/null; then
        print_status "Elasticsearch is running successfully!"
    else
        print_error "Elasticsearch failed to start"
        exit 1
    fi
}}

# Calculate heap size
calculate_heap_size() {{
    if [ "$ELASTICSEARCH_HEAP" = "auto" ]; then
        total_mem=$(free -m | awk 'NR==2{{printf "%.0f", $2/1024/2}}')
        if [ $total_mem -gt 32 ]; then
            ELASTICSEARCH_HEAP="32g"
        else
            ELASTICSEARCH_HEAP="${{total_mem}}g"
        fi
        print_status "Auto-calculated Elasticsearch heap size: $ELASTICSEARCH_HEAP"
    fi
}}"""
    
    def get_logstash_installation_function(self, config):
        """Get Logstash installation function"""
        return f"""# Install Logstash
install_logstash() {{
    print_status "Installing Logstash..."
    
    case $DISTRO in
        "ubuntu"|"debian")
            apt-get install -y logstash=1:$ELK_VERSION-1
            ;;
        "centos"|"rhel"|"fedora"|"rocky"|"almalinux")
            if command -v dnf &> /dev/null; then
                dnf install -y --enablerepo=elasticsearch logstash-$ELK_VERSION
            else
                yum install -y --enablerepo=elasticsearch logstash-$ELK_VERSION
            fi
            ;;
        *)
            # Download and install manually
            wget https://artifacts.elastic.co/downloads/logstash/logstash-$ELK_VERSION-linux-x86_64.tar.gz
            tar -xzf logstash-$ELK_VERSION-linux-x86_64.tar.gz
            mv logstash-$ELK_VERSION $INSTALL_PATH/logstash
            useradd -r -s /bin/false logstash
            chown -R logstash:logstash $INSTALL_PATH/logstash
            ;;
    esac
    
    # Create basic Logstash configuration
    print_status "Configuring Logstash..."
    
    mkdir -p /etc/logstash/conf.d
    cat > /etc/logstash/conf.d/basic.conf << EOF
input {{
  beats {{
    port => $LOGSTASH_BEATS_PORT
  }}
  syslog {{
    port => $LOGSTASH_SYSLOG_PORT
  }}
}}

filter {{
  if [fields][log_type] == "syslog" {{
    grok {{
      match => {{ "message" => "%{{SYSLOGTIMESTAMP:timestamp}} %{{GREEDYDATA:message}}" }}
    }}
    date {{
      match => [ "timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }}
  }}
}}

output {{
  elasticsearch {{
    hosts => ["$ELASTICSEARCH_HOST:$ELASTICSEARCH_PORT"]
    index => "logstash-%{{+YYYY.MM.dd}}"
  }}
  stdout {{ codec => rubydebug }}
}}
EOF

    # Configure Logstash JVM
    sed -i "s/-Xms1g/-Xms$LOGSTASH_HEAP/" /etc/logstash/jvm.options
    sed -i "s/-Xmx1g/-Xmx$LOGSTASH_HEAP/" /etc/logstash/jvm.options
    
    # Enable and start Logstash
    systemctl enable logstash
    systemctl start logstash
    
    print_status "Logstash installed and started successfully!"
}}"""
    
    def get_kibana_installation_function(self, config):
        """Get Kibana installation function"""
        return f"""# Install Kibana
install_kibana() {{
    print_status "Installing Kibana..."
    
    case $DISTRO in
        "ubuntu"|"debian")
            apt-get install -y kibana=$ELK_VERSION
            ;;
        "centos"|"rhel"|"fedora"|"rocky"|"almalinux")
            if command -v dnf &> /dev/null; then
                dnf install -y --enablerepo=elasticsearch kibana-$ELK_VERSION
            else
                yum install -y --enablerepo=elasticsearch kibana-$ELK_VERSION
            fi
            ;;
        *)
            # Download and install manually
            wget https://artifacts.elastic.co/downloads/kibana/kibana-$ELK_VERSION-linux-x86_64.tar.gz
            tar -xzf kibana-$ELK_VERSION-linux-x86_64.tar.gz
            mv kibana-$ELK_VERSION $INSTALL_PATH/kibana
            useradd -r -s /bin/false kibana
            chown -R kibana:kibana $INSTALL_PATH/kibana
            ;;
    esac
    
    # Configure Kibana
    print_status "Configuring Kibana..."
    
    cat > /etc/kibana/kibana.yml << EOF
server.port: $KIBANA_PORT
server.host: "$KIBANA_HOST"
server.name: "elk-kibana"
elasticsearch.hosts: ["http://$ELASTICSEARCH_HOST:$ELASTICSEARCH_PORT"]
elasticsearch.username: ""
elasticsearch.password: ""
logging.appenders.file.type: file
logging.appenders.file.fileName: /var/log/kibana/kibana.log
logging.appenders.file.layout.type: json
logging.root.appenders: [default, file]
pid.file: /run/kibana/kibana.pid
EOF

    # Create log directory
    mkdir -p /var/log/kibana
    chown kibana:kibana /var/log/kibana
    
    # Enable and start Kibana
    systemctl enable kibana
    systemctl start kibana
    
    print_status "Waiting for Kibana to start..."
    sleep 45
    
    # Test Kibana
    if curl -s "$KIBANA_HOST:$KIBANA_PORT" > /dev/null; then
        print_status "Kibana is running successfully!"
    else
        print_warning "Kibana may still be starting. Please check manually."
    fi
}}"""
    
    def get_firewall_configuration_function(self, config):
        """Get firewall configuration function"""
        return f"""# Configure firewall
configure_firewall() {{
    print_status "Configuring firewall..."
    
    if command -v ufw &> /dev/null; then
        # Ubuntu/Debian UFW
        ufw allow $ELASTICSEARCH_PORT/tcp  # Elasticsearch
        ufw allow $KIBANA_PORT/tcp  # Kibana
        ufw allow $LOGSTASH_BEATS_PORT/tcp  # Logstash Beats
        ufw allow $LOGSTASH_SYSLOG_PORT/tcp   # Logstash Syslog
        ufw allow $LOGSTASH_SYSLOG_PORT/udp   # Logstash Syslog
    elif command -v firewall-cmd &> /dev/null; then
        # CentOS/RHEL/Fedora firewalld
        firewall-cmd --permanent --add-port=$ELASTICSEARCH_PORT/tcp
        firewall-cmd --permanent --add-port=$KIBANA_PORT/tcp
        firewall-cmd --permanent --add-port=$LOGSTASH_BEATS_PORT/tcp
        firewall-cmd --permanent --add-port=$LOGSTASH_SYSLOG_PORT/tcp
        firewall-cmd --permanent --add-port=$LOGSTASH_SYSLOG_PORT/udp
        firewall-cmd --reload
    elif command -v iptables &> /dev/null; then
        # Generic iptables
        iptables -A INPUT -p tcp --dport $ELASTICSEARCH_PORT -j ACCEPT
        iptables -A INPUT -p tcp --dport $KIBANA_PORT -j ACCEPT
        iptables -A INPUT -p tcp --dport $LOGSTASH_BEATS_PORT -j ACCEPT
        iptables -A INPUT -p tcp --dport $LOGSTASH_SYSLOG_PORT -j ACCEPT
        iptables -A INPUT -p udp --dport $LOGSTASH_SYSLOG_PORT -j ACCEPT
    fi
}}"""
    
    def get_status_script_function(self):
        """Get status checking script function"""
        return """# Create service status script
create_status_script() {
    print_status "Creating ELK status script..."
    
    cat > /usr/local/bin/elk-status << 'EOF'
#!/bin/bash
echo "========================================="
echo "ELK Stack Status"
echo "========================================="

echo -e "\\n[Elasticsearch]"
if systemctl is-active --quiet elasticsearch; then
    echo "Status: Running"
    curl -s localhost:9200/_cluster/health | jq '.'
else
    echo "Status: Stopped"
fi

echo -e "\\n[Logstash]"
if systemctl is-active --quiet logstash; then
    echo "Status: Running"
else
    echo "Status: Stopped"
fi

echo -e "\\n[Kibana]"
if systemctl is-active --quiet kibana; then
    echo "Status: Running"
    echo "URL: http://$(hostname -I | awk '{print $1}'):5601"
else
    echo "Status: Stopped"
fi

echo -e "\\n[System Resources]"
echo "Memory Usage:"
free -h
echo "Disk Usage:"
df -h | grep -E '(Filesystem|/dev/)'
EOF

    chmod +x /usr/local/bin/elk-status
}"""
