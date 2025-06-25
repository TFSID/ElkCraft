"""
User interface for ELK Stack Installation Script Generator
"""

from generators.linux_generator import LinuxScriptGenerator
from generators.windows_generator import WindowsScriptGenerator
from utils.file_manager import FileManager
from config.config_manager import ConfigurationManager

class MenuInterface:
    """Command-line interface for the ELK generator"""
    
    def __init__(self):
        self.config_manager = ConfigurationManager()
        self.file_manager = FileManager()
        self.linux_generator = LinuxScriptGenerator()
        self.windows_generator = WindowsScriptGenerator()
        
        # Pass configuration to generators
        self.linux_generator.config = self.config_manager.get_config()
        self.windows_generator.config = self.config_manager.get_config()
    
    def display_menu(self):
        """Display the main menu"""
        print("\n" + "="*50)
        print("   ELK Stack Installation Script Generator")
        print("   (Enhanced Modular Version)")
        print("="*50)
        print("1. Generate Linux Installation Script")
        print("2. Generate Windows Installation Script")
        print("3. Generate Both Scripts")
        print("4. Configure Settings")
        print("5. Show Current Configuration")
        print("6. Show ELK Stack Information")
        print("7. Exit")
        print("-"*50)
    
    def show_elk_info(self):
        """Display ELK Stack information"""
        config = self.config_manager.get_config().get_all()
        print(f"\n{'='*60}")
        print(f"{'ELK Stack Information':^60}")
        print(f"{'='*60}")
        print(f"ELK Version: {config['elk_version']}")
        print(f"Java Version Required: {config['java_version']}+")
        print(f"\nComponents:")
        print(f"├── Elasticsearch: Search and analytics engine")
        print(f"│   ├── Default Port: {config['elasticsearch_port']}")
        print(f"│   └── Role: Data storage and search")
        print(f"├── Logstash: Data processing pipeline")
        print(f"│   ├── Beats Input Port: {config['logstash_beats_port']}")
        print(f"│   ├── Syslog Port: {config['logstash_syslog_port']}")
        print(f"│   └── Role: Data ingestion and transformation")
        print(f"└── Kibana: Visualization and management")
        print(f"    ├── Default Port: {config['kibana_port']}") 
        print(f"    └── Role: Data visualization and dashboards")
        print(f"\nMinimum System Requirements:")
        print(f"├── RAM: 8GB (16GB recommended)")
        print(f"├── Disk Space: 50GB free space")
        print(f"├── CPU: 4 cores (8 cores recommended)")
        print(f"└── Java: OpenJDK {config['java_version']}+ or Oracle JDK {config['java_version']}+")
        print(f"\nSupported Operating Systems:")
        print(f"├── Linux: Ubuntu, Debian, CentOS, RHEL, Fedora, openSUSE, Arch")
        print(f"└── Windows: Windows Server 2016+, Windows 10+")

    
    def show_configuration(self):
        """Display current configuration"""
        config = self.config_manager.get_config().get_all()
        print(f"\n{'='*50}")
        print(f"{'Current Configuration':^50}")
        print(f"{'='*50}")
        print(f"ELK Version: {config['elk_version']}")
        print(f"Java Version: {config['java_version']}")
        print(f"Linux Install Path: {config['linux_install_path']}")
        print(f"Windows Install Path: {config['windows_install_path']}")
        print(f"\nPorts:")
        print(f"├── Elasticsearch: {config['elasticsearch_port']}")
        print(f"├── Kibana: {config['kibana_port']}")
        print(f"├── Logstash Beats: {config['logstash_beats_port']}")
        print(f"└── Logstash Syslog: {config['logstash_syslog_port']}")
    
    def generate_linux_script(self):
        """Generate Linux installation script"""
        print("\n📝 Generating Linux installation script...")
        try:
            script_content = self.linux_generator.generate_script()
            filename = self.file_manager.generate_filename('linux')
            
            if self.file_manager.save_script(script_content, filename, make_executable=True):
                print(f"\n📋 Usage Instructions:")
                print(f"1. Transfer the script to your Linux server")
                print(f"2. Make it executable: chmod +x {filename}")
                print(f"3. Run as root: sudo ./{filename}")
                return True
            return False
        except Exception as e:
            print(f"❌ Error generating Linux script: {e}")
            return False
    
    def generate_windows_script(self):
        """Generate Windows installation script"""
        print("\n📝 Generating Windows installation script...")
        try:
            script_content = self.windows_generator.generate_script()
            filename = self.file_manager.generate_filename('windows')
            
            if self.file_manager.save_script(script_content, filename):
                print(f"\n📋 Usage Instructions:")
                print(f"1. Transfer the script to your Windows server")
                print(f"2. Right-click and 'Run as Administrator'")
                print(f"3. Follow the on-screen instructions")
                return True
            return False
        except Exception as e:
            print(f"❌ Error generating Windows script: {e}")
            return False
    
    def generate_both_scripts(self):
        """Generate both Linux and Windows scripts"""
        print("\n📝 Generating both Linux and Windows scripts...")
        
        linux_success = self.generate_linux_script()
        windows_success = self.generate_windows_script()
        
        if linux_success and windows_success:
            print(f"\n📋 Both scripts generated successfully!")
            return True
        else:
            print(f"\n⚠️ Some scripts failed to generate. Check the errors above.")
            return False
    
    def run(self):
        """Main application loop"""
        print("🚀 Welcome to ELK Stack Installation Script Generator!")
        print("📦 Enhanced Modular Version with Advanced Configuration")
        
        while True:
            self.display_menu()
            try:
                choice = input("Select an option (1-7): ").strip()
                
                if choice == '1':
                    self.generate_linux_script()
                    
                elif choice == '2':
                    self.generate_windows_script()
                    
                elif choice == '3':
                    self.generate_both_scripts()
                    
                elif choice == '4':
                    self.config_manager.configure_settings()
                    # Update generators with new configuration
                    self.linux_generator.config = self.config_manager.get_config()
                    self.windows_generator.config = self.config_manager.get_config()
                    
                elif choice == '5':
                    self.config_manager.show_current_config()
                    
                elif choice == '6':
                    self.show_elk_info()
                    
                elif choice == '7':
                    print("\n👋 Thank you for using ELK Stack Installation Script Generator!")
                    print("🔗 For more information, visit: https://elastic.co")
                    break
                
                else:
                    print("❌ Invalid choice. Please select 1-7.")
                    
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"❌ An error occurred: {e}")
                
            input("\nPress Enter to continue...")
