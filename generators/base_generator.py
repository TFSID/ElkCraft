"""
Base generator class for ELK Stack installation scripts
"""

from abc import ABC, abstractmethod
from datetime import datetime

class BaseScriptGenerator(ABC):
    """Abstract base class for script generators"""
    
    def __init__(self, config=None):
        self.config = config if config else None
        self.generated_at = datetime.now()
    
    @abstractmethod
    def generate_script(self):
        """Generate installation script - must be implemented by subclasses"""
        pass
    
    def get_script_header(self, platform):
        """Generate common script header"""
        return f"""# ELK Stack Installation Script for {platform}
# Generated on: {self.generated_at.strftime('%Y-%m-%d %H:%M:%S')}
# ELK Version: {self.config.ELK_VERSION if self.config and hasattr(self.config, 'ELK_VERSION') else 'N/A'}
# Generator: Modular ELK Installation Script Generator
"""
    
    def get_system_requirements_info(self):
        """Get system requirements information"""
        if not self.config:
            return "System requirements information not available"
    
        config_dict = self.config.get_all() if hasattr(self.config, 'get_all') else {}
        return f"""
System Requirements:
- RAM: 8GB minimum (16GB recommended)
- Disk Space: 50GB free space
- CPU: 4 cores minimum (8 cores recommended)
- Java: OpenJDK {config_dict.get('java_version', '11')}+ or Oracle JDK {config_dict.get('java_version', '11')}+
"""

    def get_port_information(self):
        """Get port information"""
        if not self.config:
            return "Port information not available"
    
        config_dict = self.config.get_all() if hasattr(self.config, 'get_all') else {}
        return f"""
Default Ports:
- Elasticsearch: {config_dict.get('elasticsearch_port', 9200)}
- Kibana: {config_dict.get('kibana_port', 5601)}
- Logstash Beats: {config_dict.get('logstash_beats_port', 5044)}
- Logstash Syslog: {config_dict.get('logstash_syslog_port', 514)}
"""

    def get_config_value(self, key, default=None):
        """Get configuration value safely"""
        if hasattr(self.config, 'get'):
            return self.config.get(key, default)
        elif hasattr(self.config, key):
            return getattr(self.config, key, default)
        else:
            return default
