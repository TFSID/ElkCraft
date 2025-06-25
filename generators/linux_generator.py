"""
Linux script generator for ELK Stack installation
"""

from generators.base_generator import BaseScriptGenerator
from templates.linux_templates import LinuxTemplates

class LinuxScriptGenerator(BaseScriptGenerator):
    """Generator for Linux ELK Stack installation scripts"""
    
    def __init__(self, config=None):
        super().__init__()
        if config:
            self.config = config
        self.templates = LinuxTemplates()
    
    def generate_script(self):
        """Generate complete Linux installation script with configuration"""
        config = self.config.get_all()
        
        script_parts = [
            self._generate_script_header(config),
            self._generate_configuration_display(config),
            self._generate_functions(config),
            self._generate_main_function(config)
        ]
        
        return '\n'.join(script_parts)

    
    def _generate_script_header(self, config):
        """Generate script header with configuration variables"""
        return f"""#!/bin/bash
# ELK Stack Installation Script for Linux
# Generated on: {self.generated_at.strftime('%Y-%m-%d %H:%M:%S')}
# ELK Version: {config['elk_version']}
# Configuration: Custom Generated

set -e  # Exit on any error

echo "========================================="
echo "ELK Stack Installation Script for Linux"
echo "Version: {config['elk_version']}"
echo "Java Version: {config['java_version']}"
echo "========================================="

# Configuration variables
ELK_VERSION="{config['elk_version']}"
JAVA_VERSION="{config['java_version']}"
ELASTICSEARCH_PORT="{config['elasticsearch_port']}"
KIBANA_PORT="{config['kibana_port']}"
LOGSTASH_BEATS_PORT="{config['logstash_beats_port']}"
LOGSTASH_SYSLOG_PORT="{config['logstash_syslog_port']}"
INSTALL_PATH="{config['linux_install_path']}"
CLUSTER_NAME="{config['cluster_name']}"
NODE_NAME="{config['node_name']}"
ELASTICSEARCH_HEAP="{config['elasticsearch_heap']}"
LOGSTASH_HEAP="{config['logstash_heap']}"
ENABLE_SECURITY="{str(config['enable_security']).lower()}"
ENABLE_SSL="{str(config['enable_ssl']).lower()}"
KIBANA_HOST="{config['kibana_host']}"
ELASTICSEARCH_HOST="{config['elasticsearch_host']}"

# Colors for output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
BLUE='\\033[0;34m'
NC='\\033[0m' # No Color

# Function to print colored output
print_status() {{
    echo -e "${{GREEN}}[INFO]${{NC}} $1"
}}

print_warning() {{
    echo -e "${{YELLOW}}[WARNING]${{NC}} $1"
}}

print_error() {{
    echo -e "${{RED}}[ERROR]${{NC}} $1"
}}

print_config() {{
    echo -e "${{BLUE}}[CONFIG]${{NC}} $1"
}}"""

    def _generate_configuration_display(self, config):
        """Generate configuration display function"""
        return f"""
# Display configuration
display_config() {{
    echo
    echo "========================================="
    echo "Installation Configuration"
    echo "========================================="
    print_config "ELK Version: $ELK_VERSION"
    print_config "Java Version: $JAVA_VERSION"
    print_config "Install Path: $INSTALL_PATH"
    print_config "Elasticsearch Port: $ELASTICSEARCH_PORT"
    print_config "Kibana Port: $KIBANA_PORT"
    print_config "Logstash Beats Port: $LOGSTASH_BEATS_PORT"
    print_config "Logstash Syslog Port: $LOGSTASH_SYSLOG_PORT"
    print_config "Cluster Name: $CLUSTER_NAME"
    print_config "Node Name: $NODE_NAME"
    print_config "Elasticsearch Heap: $ELASTICSEARCH_HEAP"
    print_config "Logstash Heap: $LOGSTASH_HEAP"
    print_config "Security Enabled: $ENABLE_SECURITY"
    print_config "SSL Enabled: $ENABLE_SSL"
    print_config "Kibana Host: $KIBANA_HOST"
    print_config "Elasticsearch Host: $ELASTICSEARCH_HOST"
    echo "========================================="
    echo
}}"""
    
    def _generate_functions(self, config):
        """Generate all utility functions"""
        functions = [
            self.templates.get_distro_detection_function(),
            self.templates.get_root_check_function(),
            self.templates.get_java_installation_function(config['java_version']),
            self.templates.get_elastic_repo_function(),
            self.templates.get_elasticsearch_installation_function(config),
            self.templates.get_logstash_installation_function(config),
            self.templates.get_kibana_installation_function(config),
            self.templates.get_firewall_configuration_function(config),
            self.templates.get_status_script_function()
        ]
        
        return '\n\n'.join(functions)
    
    def _generate_main_function(self, config):
        """Generate main installation function with config display"""
        return f"""
# Main installation function
main() {{
    print_status "Starting ELK Stack installation..."
    
    # Display configuration
    display_config
    
    check_root
    detect_distro
    install_java
    add_elastic_repo
    install_elasticsearch
    install_logstash
    install_kibana
    configure_firewall
    create_status_script
    
    echo
    echo "========================================="
    echo -e "${{GREEN}}ELK Stack Installation Complete!${{NC}}"
    echo "========================================="
    echo "Elasticsearch: http://$ELASTICSEARCH_HOST:$ELASTICSEARCH_PORT"
    echo "Kibana: http://$(hostname -I | awk '{{print $1}}'):$KIBANA_PORT"
    echo
    echo "Use 'elk-status' command to check services status"
    echo "Use 'systemctl status elasticsearch|logstash|kibana' for individual service status"
    echo
    echo "Configured ports:"
    echo "- Elasticsearch: $ELASTICSEARCH_PORT"
    echo "- Kibana: $KIBANA_PORT"
    echo "- Logstash Beats: $LOGSTASH_BEATS_PORT"
    echo "- Logstash Syslog: $LOGSTASH_SYSLOG_PORT"
    echo
    print_warning "Please ensure these ports are accessible from your network if needed."
}}

# Run main function
main "$@"
"""
