"""
Windows script generator for ELK Stack installation
"""

from generators.base_generator import BaseScriptGenerator
from templates.windows_templates import WindowsTemplates

class WindowsScriptGenerator(BaseScriptGenerator):
    """Generator for Windows ELK Stack installation scripts"""
    
    def __init__(self, config=None):
        super().__init__()
        if config:
            self.config = config
        self.templates = WindowsTemplates()
    
    def generate_script(self):
        """Generate complete Windows installation script"""
        config = self.config.get_all()
        
        script_parts = [
            self._generate_script_header(config),
            self._generate_installation_logic(config),
            self._generate_service_setup(config),
            self._generate_completion_message(config)
        ]
        
        return '\n'.join(script_parts)
    
    def _generate_script_header(self, config):
        """Generate batch file header"""
        return f"""@echo off
REM ELK Stack Installation Script for Windows
REM Generated on: {self.generated_at.strftime('%Y-%m-%d %H:%M:%S')}
REM ELK Version: {config['elk_version']}
REM Configuration: Custom Generated

setlocal enabledelayedexpansion

echo =========================================
echo ELK Stack Installation Script for Windows
echo Version: {config['elk_version']}
echo Java Version: {config['java_version']}
echo =========================================

REM Configuration variables
set "ELK_VERSION={config['elk_version']}"
set "JAVA_VERSION={config['java_version']}"
set "ELASTICSEARCH_PORT={config['elasticsearch_port']}"
set "KIBANA_PORT={config['kibana_port']}"
set "LOGSTASH_BEATS_PORT={config['logstash_beats_port']}"
set "LOGSTASH_SYSLOG_PORT={config['logstash_syslog_port']}"
set "INSTALL_DIR={config['windows_install_path']}"
set "CLUSTER_NAME={config['cluster_name']}"
set "NODE_NAME={config['node_name']}"
set "ELASTICSEARCH_HEAP={config['elasticsearch_heap']}"
set "LOGSTASH_HEAP={config['logstash_heap']}"
set "ENABLE_SECURITY={str(config['enable_security']).lower()}"
set "ENABLE_SSL={str(config['enable_ssl']).lower()}"
set "KIBANA_HOST={config['kibana_host']}"
set "ELASTICSEARCH_HOST={config['elasticsearch_host']}"
set "DOWNLOAD_DIR=%TEMP%\\elk-downloads"

REM Display configuration
echo.
echo =========================================
echo Installation Configuration
echo =========================================
echo ELK Version: %ELK_VERSION%
echo Java Version: %JAVA_VERSION%
echo Install Directory: %INSTALL_DIR%
echo Elasticsearch Port: %ELASTICSEARCH_PORT%
echo Kibana Port: %KIBANA_PORT%
echo Logstash Beats Port: %LOGSTASH_BEATS_PORT%
echo Logstash Syslog Port: %LOGSTASH_SYSLOG_PORT%
echo Cluster Name: %CLUSTER_NAME%
echo Node Name: %NODE_NAME%
echo Elasticsearch Heap: %ELASTICSEARCH_HEAP%
echo Logstash Heap: %LOGSTASH_HEAP%
echo Security Enabled: %ENABLE_SECURITY%
echo SSL Enabled: %ENABLE_SSL%
echo Kibana Host: %KIBANA_HOST%
echo Elasticsearch Host: %ELASTICSEARCH_HOST%
echo =========================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script must be run as Administrator
    echo Right-click on Command Prompt and select "Run as Administrator"
    pause
    exit /b 1
)"""
    
    def _generate_installation_logic(self, config):
        """Generate installation logic"""
        return self.templates.get_installation_template(config)
    
    def _generate_service_setup(self, config):
        """Generate Windows service setup"""
        return self.templates.get_service_setup_template(config)
    
    def _generate_completion_message(self, config):
        """Generate completion message"""
        return f"""
REM Final information
echo.
echo =========================================
echo ELK Stack Installation Complete!
echo =========================================
echo Installation Directory: %INSTALL_DIR%
echo.
echo Services:
echo - Elasticsearch: http://%ELASTICSEARCH_HOST%:%ELASTICSEARCH_PORT%
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /i "IPv4"') do set IP=%%a
set IP=%IP: =%
echo - Kibana: http://%IP%:%KIBANA_PORT%
echo.
echo Management Scripts:
echo - Start ELK: %INSTALL_DIR%\\start-elk.bat
echo - Stop ELK: %INSTALL_DIR%\\stop-elk.bat
echo - Check Status: %INSTALL_DIR%\\elk-status.bat
echo.
echo Configured Ports:
echo - Elasticsearch: %ELASTICSEARCH_PORT%
echo - Kibana: %KIBANA_PORT%
echo - Logstash Beats: %LOGSTASH_BEATS_PORT%
echo - Logstash Syslog: %LOGSTASH_SYSLOG_PORT%
echo.
echo [WARNING] Please ensure these ports are accessible from your network if needed.
echo.
if exist "%INSTALL_DIR%\\nssm.exe" (
    echo Services have been installed and started automatically.
) else (
    echo Please start services manually using the provided batch files.
)
echo.
pause
"""
