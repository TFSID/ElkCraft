"""
Windows script templates for ELK Stack installation
"""

class WindowsTemplates:
    """Templates for Windows installation script components"""
    
    def get_installation_template(self, config):
        """Get Windows installation template"""
        return f"""
REM Create directories
echo [INFO] Creating installation directories...
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "%DOWNLOAD_DIR%" mkdir "%DOWNLOAD_DIR%"

REM Check if Java is installed
echo [INFO] Checking Java installation...
java -version >nul 2>&1
if %errorLevel% neq 0 (
    echo [WARNING] Java not found. Please install Java %JAVA_VERSION% or higher manually.
    echo Download from: https://adoptium.net/
    echo Press any key to continue after installing Java...
    pause
    
    REM Check again after user confirmation
    java -version >nul 2>&1
    if !errorLevel! neq 0 (
        echo [ERROR] Java is still not found. Exiting...
        pause
        exit /b 1
    )
)

REM Function to download files
echo [INFO] Starting downloads...

REM Download Elasticsearch
echo [INFO] Downloading Elasticsearch...
powershell -Command "& {{[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-%ELK_VERSION%-windows-x86_64.zip' -OutFile '%DOWNLOAD_DIR%\\elasticsearch.zip'}}"
if %errorLevel% neq 0 (
    echo [ERROR] Failed to download Elasticsearch
    pause
    exit /b 1
)

REM Download Logstash
echo [INFO] Downloading Logstash...
powershell -Command "& {{[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://artifacts.elastic.co/downloads/logstash/logstash-%ELK_VERSION%-windows-x86_64.zip' -OutFile '%DOWNLOAD_DIR%\\logstash.zip'}}"
if %errorLevel% neq 0 (
    echo [ERROR] Failed to download Logstash
    pause
    exit /b 1
)

REM Download Kibana
echo [INFO] Downloading Kibana...
powershell -Command "& {{[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://artifacts.elastic.co/downloads/kibana/kibana-%ELK_VERSION%-windows-x86_64.zip' -OutFile '%DOWNLOAD_DIR%\\kibana.zip'}}"
if %errorLevel% neq 0 (
    echo [ERROR] Failed to download Kibana
    pause
    exit /b 1
)

REM Download NSSM (Non-Sucking Service Manager) for Windows services
echo [INFO] Downloading NSSM...
powershell -Command "& {{[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://nssm.cc/release/nssm-2.24.zip' -OutFile '%DOWNLOAD_DIR%\\nssm.zip'}}"

REM Extract files
echo [INFO] Extracting files...

REM Extract Elasticsearch
echo [INFO] Extracting Elasticsearch...
powershell -Command "Expand-Archive -Path '%DOWNLOAD_DIR%\\elasticsearch.zip' -DestinationPath '%INSTALL_DIR%' -Force"
ren "%INSTALL_DIR%\\elasticsearch-%ELK_VERSION%" "elasticsearch"

REM Extract Logstash
echo [INFO] Extracting Logstash...
powershell -Command "Expand-Archive -Path '%DOWNLOAD_DIR%\\logstash.zip' -DestinationPath '%INSTALL_DIR%' -Force"
ren "%INSTALL_DIR%\\logstash-%ELK_VERSION%" "logstash"

REM Extract Kibana
echo [INFO] Extracting Kibana...
powershell -Command "Expand-Archive -Path '%DOWNLOAD_DIR%\\kibana.zip' -DestinationPath '%INSTALL_DIR%' -Force"
ren "%INSTALL_DIR%\\kibana-%ELK_VERSION%" "kibana"

REM Extract NSSM
if exist "%DOWNLOAD_DIR%\\nssm.zip" (
    echo [INFO] Extracting NSSM...
    powershell -Command "Expand-Archive -Path '%DOWNLOAD_DIR%\\nssm.zip' -DestinationPath '%DOWNLOAD_DIR%' -Force"
    copy "%DOWNLOAD_DIR%\\nssm-2.24\\win64\\nssm.exe" "%INSTALL_DIR%\\nssm.exe"
)

REM Configure Elasticsearch
echo [INFO] Configuring Elasticsearch...
(
echo cluster.name: %CLUSTER_NAME%
echo node.name: %NODE_NAME%
echo path.data: %INSTALL_DIR%\\elasticsearch\\data
echo path.logs: %INSTALL_DIR%\\elasticsearch\\logs
echo network.host: %ELASTICSEARCH_HOST%
echo http.port: %ELASTICSEARCH_PORT%
echo discovery.type: single-node
echo xpack.security.enabled: %ENABLE_SECURITY%
echo xpack.security.enrollment.enabled: %ENABLE_SECURITY%
echo xpack.security.http.ssl.enabled: %ENABLE_SSL%
echo xpack.security.transport.ssl.enabled: %ENABLE_SSL%
) > "%INSTALL_DIR%\\elasticsearch\\config\\elasticsearch.yml"

REM Configure Elasticsearch JVM
echo [INFO] Configuring Elasticsearch JVM settings...
if "%ELASTICSEARCH_HEAP%" == "auto" (
    set "ELASTICSEARCH_HEAP=2g"
    echo [INFO] Auto-setting Elasticsearch heap to 2g for Windows
)
(
echo -Xms%ELASTICSEARCH_HEAP%
echo -Xmx%ELASTICSEARCH_HEAP%
echo -XX:+UseG1GC
echo -XX:G1ReservePercent=25
echo -XX:InitiatingHeapOccupancyPercent=30
) > "%INSTALL_DIR%\\elasticsearch\\config\\jvm.options.d\\heap.options"

REM Configure Logstash
echo [INFO] Configuring Logstash...
mkdir "%INSTALL_DIR%\\logstash\\config\\conf.d" 2>nul

(
echo input {{
echo   beats {{
echo     port =^> %LOGSTASH_BEATS_PORT%
echo   }}
echo   tcp {{
echo     port =^> %LOGSTASH_SYSLOG_PORT%
echo     type =^> "syslog"
echo   }}
echo   udp {{
echo     port =^> %LOGSTASH_SYSLOG_PORT%
echo     type =^> "syslog"
echo   }}
echo }}
echo.
echo filter {{
echo   if [type] == "syslog" {{
echo     grok {{
echo       match =^> {{ "message" =^> "%%{{SYSLOGTIMESTAMP:timestamp}} %%{{GREEDYDATA:message}}" }}
echo     }}
echo     date {{
echo       match =^> [ "timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
echo     }}
echo   }}
echo }}
echo.
echo output {{
echo   elasticsearch {{
echo     hosts =^> ["%ELASTICSEARCH_HOST%:%ELASTICSEARCH_PORT%"]
echo     index =^> "logstash-%%{{+YYYY.MM.dd}}"
echo   }}
echo   stdout {{ codec =^> rubydebug }}
echo }}
) > "%INSTALL_DIR%\\logstash\\config\\conf.d\\basic.conf"

REM Configure Kibana
echo [INFO] Configuring Kibana...
(
echo server.port: %KIBANA_PORT%
echo server.host: "%KIBANA_HOST%"
echo server.name: "elk-kibana"
echo elasticsearch.hosts: ["http://%ELASTICSEARCH_HOST%:%ELASTICSEARCH_PORT%"]
echo logging.appenders.file.type: file
echo logging.appenders.file.fileName: %INSTALL_DIR%\\kibana\\logs\\kibana.log
echo logging.appenders.file.layout.type: json
echo logging.root.appenders: [default, file]
) > "%INSTALL_DIR%\\kibana\\config\\kibana.yml"

REM Create log directories
mkdir "%INSTALL_DIR%\\elasticsearch\\logs" 2>nul
mkdir "%INSTALL_DIR%\\logstash\\logs" 2>nul
mkdir "%INSTALL_DIR%\\kibana\\logs" 2>nul
"""
    
    def get_service_setup_template(self, config):
        """Get Windows service setup template"""
        return f"""
REM Install as Windows Services using NSSM
echo [INFO] Installing Windows services...

if exist "%INSTALL_DIR%\\nssm.exe" (
    REM Install Elasticsearch service
    echo [INFO] Installing Elasticsearch service...
    "%INSTALL_DIR%\\nssm.exe" install Elasticsearch "%INSTALL_DIR%\\elasticsearch\\bin\\elasticsearch.bat"
    "%INSTALL_DIR%\\nssm.exe" set Elasticsearch DisplayName "Elasticsearch Server"
    "%INSTALL_DIR%\\nssm.exe" set Elasticsearch Description "Elasticsearch Search Engine"
    "%INSTALL_DIR%\\nssm.exe" set Elasticsearch Start SERVICE_AUTO_START
    "%INSTALL_DIR%\\nssm.exe" set Elasticsearch AppDirectory "%INSTALL_DIR%\\elasticsearch"
    
    REM Install Logstash service
    echo [INFO] Installing Logstash service...
    "%INSTALL_DIR%\\nssm.exe" install Logstash "%INSTALL_DIR%\\logstash\\bin\\logstash.bat" "-f %INSTALL_DIR%\\logstash\\config\\conf.d\\basic.conf"
    "%INSTALL_DIR%\\nssm.exe" set Logstash DisplayName "Logstash Server"
    "%INSTALL_DIR%\\nssm.exe" set Logstash Description "Logstash Data Processing Pipeline"
    "%INSTALL_DIR%\\nssm.exe" set Logstash Start SERVICE_AUTO_START
    "%INSTALL_DIR%\\nssm.exe" set Logstash AppDirectory "%INSTALL_DIR%\\logstash"
    "%INSTALL_DIR%\\nssm.exe" set Logstash DependOnService Elasticsearch
    
    REM Install Kibana service
    echo [INFO] Installing Kibana service...
    "%INSTALL_DIR%\\nssm.exe" install Kibana "%INSTALL_DIR%\\kibana\\bin\\kibana.bat"
    "%INSTALL_DIR%\\nssm.exe" set Kibana DisplayName "Kibana Server"
    "%INSTALL_DIR%\\nssm.exe" set Kibana Description "Kibana Analytics and Visualization Platform"
    "%INSTALL_DIR%\\nssm.exe" set Kibana Start SERVICE_AUTO_START
    "%INSTALL_DIR%\\nssm.exe" set Kibana AppDirectory "%INSTALL_DIR%\\kibana"
    "%INSTALL_DIR%\\nssm.exe" set Kibana DependOnService Elasticsearch
) else (
    echo [WARNING] NSSM not available. Services must be started manually.
)

REM Configure Windows Firewall
echo [INFO] Configuring Windows Firewall...
netsh advfirewall firewall add rule name="Elasticsearch" dir=in action=allow protocol=TCP localport=%ELASTICSEARCH_PORT%
netsh advfirewall firewall add rule name="Kibana" dir=in action=allow protocol=TCP localport=%KIBANA_PORT%
netsh advfirewall firewall add rule name="Logstash Beats" dir=in action=allow protocol=TCP localport=%LOGSTASH_BEATS_PORT%
netsh advfirewall firewall add rule name="Logstash Syslog TCP" dir=in action=allow protocol=TCP localport=%LOGSTASH_SYSLOG_PORT%
netsh advfirewall firewall add rule name="Logstash Syslog UDP" dir=in action=allow protocol=UDP localport=%LOGSTASH_SYSLOG_PORT%

REM Create batch files for manual service management
echo [INFO] Creating management scripts...

REM Start ELK script
(
echo @echo off
echo echo Starting ELK Stack services...
echo net start Elasticsearch
echo timeout /t 30 /nobreak
echo net start Logstash
echo net start Kibana
echo echo ELK Stack services started!
echo pause
) > "%INSTALL_DIR%\\start-elk.bat"

REM Stop ELK script
(
echo @echo off
echo echo Stopping ELK Stack services...
echo net stop Kibana
echo net stop Logstash
echo net stop Elasticsearch
echo echo ELK Stack services stopped!
echo pause
) > "%INSTALL_DIR%\\stop-elk.bat"

REM Status check script
(
echo @echo off
echo echo =========================================
echo echo ELK Stack Status
echo echo =========================================
echo echo.
echo echo [Elasticsearch]
echo sc query Elasticsearch ^| find "STATE"
echo echo.
echo echo [Logstash]
echo sc query Logstash ^| find "STATE"
echo echo.
echo echo [Kibana]
echo sc query Kibana ^| find "STATE"
echo echo.
echo echo [URLs]
echo echo Elasticsearch: http://%ELASTICSEARCH_HOST%:%ELASTICSEARCH_PORT%
echo for /f "tokens=2 delims=:" %%%%a in ('ipconfig ^| findstr /i "IPv4"') do set IP=%%%%a
echo set IP=!IP: =!
echo echo Kibana: http://!IP!:%KIBANA_PORT%
echo echo.
echo pause
) > "%INSTALL_DIR%\\elk-status.bat"

REM Start services if NSSM is available
if exist "%INSTALL_DIR%\\nssm.exe" (
    echo [INFO] Starting ELK Stack services...
    net start Elasticsearch
    echo [INFO] Waiting for Elasticsearch to start...
    timeout /t 30 /nobreak >nul
    net start Logstash
    net start Kibana
    echo [INFO] Waiting for services to initialize...
    timeout /t 45 /nobreak >nul
)

REM Cleanup
echo [INFO] Cleaning up temporary files...
rmdir /s /q "%DOWNLOAD_DIR%" 2>nul
"""
