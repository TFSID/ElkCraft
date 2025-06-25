"""
Configuration manager for ELK Stack Installation Generator
Handles interactive configuration, validation, and persistence
"""

import json
import re
from datetime import datetime
from .settings import ELKConfig

class ConfigurationManager:
    """Manages ELK Stack configuration with interactive interface"""
    
    def __init__(self):
        self.config = ELKConfig()
    
    def show_current_config(self):
        """Display current configuration"""
        print(f"\n{'='*60}")
        print(f"{'Current ELK Configuration':^60}")
        print(f"{'='*60}")
        config = self.config.get_all()
        print(f"ELK Version:           {config['elk_version']}")
        print(f"Java Version:          {config['java_version']}")
        print(f"Elasticsearch Port:    {config['elasticsearch_port']}")
        print(f"Kibana Port:           {config['kibana_port']}")
        print(f"Logstash Beats Port:   {config['logstash_beats_port']}")
        print(f"Logstash Syslog Port:  {config['logstash_syslog_port']}")
        print(f"Linux Install Path:    {config['linux_install_path']}")
        print(f"Windows Install Path:  {config['windows_install_path']}")
        print(f"Cluster Name:          {config['cluster_name']}")
        print(f"Node Name:             {config['node_name']}")
        print(f"Elasticsearch Heap:    {config['elasticsearch_heap']}")
        print(f"Logstash Heap:         {config['logstash_heap']}")
        print(f"Enable Security:       {config['enable_security']}")
        print(f"Enable SSL:            {config['enable_ssl']}")
        print(f"Kibana Host:           {config['kibana_host']}")
        print(f"Elasticsearch Host:    {config['elasticsearch_host']}")

    def configure_settings(self):
        """Interactive configuration menu"""
        while True:
            print(f"\n{'='*50}")
            print(f"{'Configuration Menu':^50}")
            print(f"{'='*50}")
            print("1.  ELK Version")
            print("2.  Java Version") 
            print("3.  Elasticsearch Port")
            print("4.  Kibana Port")
            print("5.  Logstash Beats Port")
            print("6.  Logstash Syslog Port")
            print("7.  Linux Install Path")
            print("8.  Windows Install Path")
            print("9.  Cluster Configuration")
            print("10. Memory Settings")
            print("11. Security Settings")
            print("12. Network Settings")
            print("13. Load Configuration from File")
            print("14. Save Configuration to File")
            print("15. Reset to Defaults")
            print("16. Show Current Configuration")
            print("17. Back to Main Menu")
            print("-"*50)
            
            try:
                choice = input("Select option (1-17): ").strip()
                
                if choice == '1':
                    self._configure_elk_version()
                elif choice == '2':
                    self._configure_java_version()
                elif choice == '3':
                    self._configure_port('elasticsearch_port', 'Elasticsearch')
                elif choice == '4':
                    self._configure_port('kibana_port', 'Kibana')
                elif choice == '5':
                    self._configure_port('logstash_beats_port', 'Logstash Beats')
                elif choice == '6':
                    self._configure_port('logstash_syslog_port', 'Logstash Syslog')
                elif choice == '7':
                    self._configure_path('linux_install_path', 'Linux Install Path')
                elif choice == '8':
                    self._configure_path('windows_install_path', 'Windows Install Path')
                elif choice == '9':
                    self._configure_cluster()
                elif choice == '10':
                    self._configure_memory()
                elif choice == '11':
                    self._configure_security()
                elif choice == '12':
                    self._configure_network()
                elif choice == '13':
                    self._load_config_from_file()
                elif choice == '14':
                    self._save_config_to_file()
                elif choice == '15':
                    self._reset_to_defaults()
                elif choice == '16':
                    self.show_current_config()
                elif choice == '17':
                    break
                else:
                    print("❌ Invalid choice. Please select 1-17.")
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"❌ Error: {e}")
                
            if choice != '16':  # Don't pause after showing config
                input("\nPress Enter to continue...")

    def _configure_elk_version(self):
        """Configure ELK version"""
        print(f"\nAvailable ELK versions:")
        for i, version in enumerate(self.config.available_elk_versions, 1):
            current = " (current)" if version == self.config.get('elk_version') else ""
            print(f"{i}. {version}{current}")
        print(f"{len(self.config.available_elk_versions) + 1}. Custom version")
        
        try:
            choice = input(f"Select version (1-{len(self.config.available_elk_versions) + 1}): ").strip()
            
            if choice.isdigit():
                choice_num = int(choice)
                if 1 <= choice_num <= len(self.config.available_elk_versions):
                    self.config.set('elk_version', self.config.available_elk_versions[choice_num - 1])
                    print(f"✅ ELK version set to: {self.config.get('elk_version')}")
                elif choice_num == len(self.config.available_elk_versions) + 1:
                    custom_version = input("Enter custom ELK version (e.g., 8.11.0): ").strip()
                    if self._validate_version_format(custom_version):
                        self.config.set('elk_version', custom_version)
                        print(f"✅ ELK version set to: {self.config.get('elk_version')}")
                    else:
                        print("❌ Invalid version format. Use format like 8.11.0")
                else:
                    print("❌ Invalid selection")
        except ValueError:
            print("❌ Invalid input")

    def _configure_java_version(self):
        """Configure Java version"""
        print(f"\nAvailable Java versions:")
        for i, version in enumerate(self.config.java_versions, 1):
            current = " (current)" if version == self.config.get('java_version') else ""
            print(f"{i}. Java {version}{current}")
        
        try:
            choice = input(f"Select Java version (1-{len(self.config.java_versions)}): ").strip()
            if choice.isdigit():
                choice_num = int(choice)
                if 1 <= choice_num <= len(self.config.java_versions):
                    self.config.set('java_version', self.config.java_versions[choice_num - 1])
                    print(f"✅ Java version set to: {self.config.get('java_version')}")
                else:
                    print("❌ Invalid selection")
        except ValueError:
            print("❌ Invalid input")

    def _configure_port(self, port_key, service_name):
        """Configure service port"""
        current_port = self.config.get(port_key)
        print(f"\nCurrent {service_name} port: {current_port}")
        
        try:
            new_port = input(f"Enter new {service_name} port (1024-65535): ").strip()
            if new_port.isdigit():
                port_num = int(new_port)
                if 1024 <= port_num <= 65535:
                    self.config.set(port_key, port_num)
                    print(f"✅ {service_name} port set to: {port_num}")
                else:
                    print("❌ Port must be between 1024-65535")
            else:
                print("❌ Invalid port number")
        except ValueError:
            print("❌ Invalid input")

    def _configure_path(self, path_key, path_name):
        """Configure installation path"""
        current_path = self.config.get(path_key)
        print(f"\nCurrent {path_name}: {current_path}")
        
        new_path = input(f"Enter new {path_name}: ").strip()
        if new_path:
            self.config.set(path_key, new_path)
            print(f"✅ {path_name} set to: {new_path}")

    def _configure_cluster(self):
        """Configure cluster settings"""
        print(f"\n{'='*40}")
        print(f"{'Cluster Configuration':^40}")
        print(f"{'='*40}")
        
        # Cluster name
        current_cluster = self.config.get('cluster_name')
        print(f"Current cluster name: {current_cluster}")
        new_cluster = input("Enter new cluster name (or press Enter to keep current): ").strip()
        if new_cluster:
            self.config.set('cluster_name', new_cluster)
            print(f"✅ Cluster name set to: {new_cluster}")
        
        # Node name
        current_node = self.config.get('node_name')
        print(f"Current node name: {current_node}")
        new_node = input("Enter new node name (or press Enter to keep current): ").strip()
        if new_node:
            self.config.set('node_name', new_node)
            print(f"✅ Node name set to: {new_node}")

    def _configure_memory(self):
        """Configure memory settings"""
        print(f"\n{'='*40}")
        print(f"{'Memory Configuration':^40}")
        print(f"{'='*40}")
        
        # Elasticsearch heap
        current_es_heap = self.config.get('elasticsearch_heap')
        print(f"Current Elasticsearch heap: {current_es_heap}")
        print("Options: auto, 1g, 2g, 4g, 8g, 16g, 32g")
        new_es_heap = input("Enter Elasticsearch heap size: ").strip().lower()
        if new_es_heap in ['auto', '1g', '2g', '4g', '8g', '16g', '32g'] or new_es_heap.endswith('g'):
            self.config.set('elasticsearch_heap', new_es_heap)
            print(f"✅ Elasticsearch heap set to: {new_es_heap}")
        elif new_es_heap:
            print("❌ Invalid heap size format. Use 'auto' or format like '4g'")
        
        # Logstash heap
        current_ls_heap = self.config.get('logstash_heap')
        print(f"Current Logstash heap: {current_ls_heap}")
        print("Options: 1g, 2g, 4g, 8g")
        new_ls_heap = input("Enter Logstash heap size: ").strip().lower()
        if new_ls_heap in ['1g', '2g', '4g', '8g'] or new_ls_heap.endswith('g'):
            self.config.set('logstash_heap', new_ls_heap)
            print(f"✅ Logstash heap set to: {new_ls_heap}")
        elif new_ls_heap:
            print("❌ Invalid heap size format. Use format like '2g'")

    def _configure_security(self):
        """Configure security settings"""
        print(f"\n{'='*40}")
        print(f"{'Security Configuration':^40}")
        print(f"{'='*40}")
        
        # Enable security
        current_security = self.config.get('enable_security')
        print(f"Current security status: {'Enabled' if current_security else 'Disabled'}")
        security_choice = input("Enable security? (y/n): ").strip().lower()
        if security_choice in ['y', 'yes']:
            self.config.set('enable_security', True)
            print("✅ Security enabled")
        elif security_choice in ['n', 'no']:
            self.config.set('enable_security', False)
            print("✅ Security disabled")
        
        # Enable SSL
        current_ssl = self.config.get('enable_ssl')
        print(f"Current SSL status: {'Enabled' if current_ssl else 'Disabled'}")
        ssl_choice = input("Enable SSL? (y/n): ").strip().lower()
        if ssl_choice in ['y', 'yes']:
            self.config.set('enable_ssl', True)
            print("✅ SSL enabled")
        elif ssl_choice in ['n', 'no']:
            self.config.set('enable_ssl', False)
            print("✅ SSL disabled")

    def _configure_network(self):
        """Configure network settings"""
        print(f"\n{'='*40}")
        print(f"{'Network Configuration':^40}")
        print(f"{'='*40}")
        
        # Kibana host
        current_kibana_host = self.config.get('kibana_host')
        print(f"Current Kibana host: {current_kibana_host}")
        print("Options: 0.0.0.0 (all interfaces), localhost, specific IP")
        new_kibana_host = input("Enter Kibana host: ").strip()
        if new_kibana_host:
            self.config.set('kibana_host', new_kibana_host)
            print(f"✅ Kibana host set to: {new_kibana_host}")
        
        # Elasticsearch host
        current_es_host = self.config.get('elasticsearch_host')
        print(f"Current Elasticsearch host: {current_es_host}")
        new_es_host = input("Enter Elasticsearch host: ").strip()
        if new_es_host:
            self.config.set('elasticsearch_host', new_es_host)
            print(f"✅ Elasticsearch host set to: {new_es_host}")

    def _load_config_from_file(self):
        """Load configuration from JSON file"""
        filename = input("Enter configuration filename (e.g., elk_config.json): ").strip()
        if not filename:
            filename = "elk_config.json"
        
        try:
            with open(filename, 'r') as f:
                loaded_config = json.load(f)
            
            # Validate and merge configuration
            self.config.update(loaded_config)
            
            print(f"✅ Configuration loaded from {filename}")
            self.show_current_config()
            
        except FileNotFoundError:
            print(f"❌ File {filename} not found")
        except json.JSONDecodeError:
            print(f"❌ Invalid JSON format in {filename}")
        except Exception as e:
            print(f"❌ Error loading configuration: {e}")

    def _save_config_to_file(self):
        """Save configuration to JSON file"""
        filename = input("Enter configuration filename (e.g., elk_config.json): ").strip()
        if not filename:
            filename = f"elk_config_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.config.get_all(), f, indent=4)
            
            print(f"✅ Configuration saved to {filename}")
            
        except Exception as e:
            print(f"❌ Error saving configuration: {e}")

    def _reset_to_defaults(self):
        """Reset configuration to defaults"""
        confirm = input("Are you sure you want to reset to default configuration? (y/n): ").strip().lower()
        if confirm in ['y', 'yes']:
            self.config = ELKConfig()
            print("✅ Configuration reset to defaults")

    def _validate_version_format(self, version):
        """Validate version format (x.y.z)"""
        pattern = r'^\d+\.\d+\.\d+$'
        return re.match(pattern, version) is not None
    
    def get_config(self):
        """Get the configuration object"""
        return self.config
