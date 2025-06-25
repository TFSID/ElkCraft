"""
Configuration settings for ELK Stack Installation Generator
"""

class ELKConfig:
    """Enhanced configuration class for ELK Stack settings with interactive management"""
    
    def __init__(self):
        # Default configuration
        self.config = {
            'elk_version': "8.11.0",
            'java_version': "11",
            'elasticsearch_port': 9200,
            'kibana_port': 5601,
            'logstash_beats_port': 5044,
            'logstash_syslog_port': 514,
            'linux_install_path': "/opt",
            'windows_install_path': "C:\\ELK",
            'cluster_name': "elk-cluster",
            'node_name': "elk-node-1",
            'elasticsearch_heap': "auto",  # auto, or specific like "4g"
            'logstash_heap': "2g",
            'enable_security': False,
            'enable_ssl': False,
            'kibana_host': "0.0.0.0",
            'elasticsearch_host': "localhost"
        }
        
        # Available versions
        self.available_elk_versions = [
            "8.11.0", "8.10.4", "8.9.2", "8.8.2", "8.7.1", 
            "7.17.15", "7.16.3", "7.15.2"
        ]
        
        self.java_versions = ["8", "11", "17", "21"]
    
    def get(self, key, default=None):
        """Get configuration value"""
        return self.config.get(key, default)
    
    def set(self, key, value):
        """Set configuration value"""
        if key in self.config:
            self.config[key] = value
            return True
        return False
    
    def get_all(self):
        """Get all configuration"""
        return self.config.copy()
    
    def update(self, new_config):
        """Update configuration with new values"""
        for key, value in new_config.items():
            if key in self.config:
                self.config[key] = value
