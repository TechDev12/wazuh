param (
    [string]$WAZUH_MANAGER
)
# Check if the script is running as administrator
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Host "The script is not running as Administrator. Relaunching as Administrator..." -ForegroundColor Yellow

    # Relaunch the script as administrator
    Start-Process powershell "-File $PSCommandPath" -Verb RunAs
    Exit
}

# Proceed with Sysmon installation if running as administrator
Write-Host "Running with Administrator privileges." -ForegroundColor Green



# Ensure that the WAZUH_MANAGER parameter is provided
if (-not $WAZUH_MANAGER) {
    Write-Host "Please provide the WAZUH_MANAGER parameter." -ForegroundColor Red
    exit 1
}

# Set the path for the Wazuh agent installer
$wazuhInstallerUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0-1.msi"
$wazuhInstallerPath = "$env:TEMP\wazuh-agent.msi"

# Download the Wazuh agent installer
Write-Host "Downloading Wazuh agent installer..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $wazuhInstallerUrl -OutFile $wazuhInstallerPath

# Install the Wazuh agent with the specified WAZUH_MANAGER
Write-Host "Installing Wazuh agent..." -ForegroundColor Cyan
Start-Process msiexec.exe -ArgumentList "/i $wazuhInstallerPath /q WAZUH_MANAGER=$WAZUH_MANAGER" -Wait

Write-Host "Wazuh agent installed successfully with manager at $WAZUH_MANAGER." -ForegroundColor Green

NET START WazuhSvc
# Set the URLs for Sysmon and SwiftOnSecurity Sysmon config
$sysmonDownloadUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmonConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"

# Define file paths
$sysmonZip = "$env:TEMP\Sysmon.zip"
$sysmonDir = "$env:TEMP\Sysmon"
$sysmonConfigFile = "$env:TEMP\sysmonconfig.xml"

# Download Sysmon.zip to temporary directory
Write-Host "Downloading Sysmon..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $sysmonDownloadUrl -OutFile $sysmonZip

# Extract Sysmon.zip
Write-Host "Extracting Sysmon..." -ForegroundColor Cyan
Expand-Archive -Path $sysmonZip -DestinationPath $sysmonDir

# Download SwiftOnSecurity Sysmon configuration file
Write-Host "Downloading SwiftOnSecurity Sysmon configuration..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $sysmonConfigUrl -OutFile $sysmonConfigFile

# Install Sysmon with the configuration file
$sysmonExe = "$sysmonDir\Sysmon64.exe"

Write-Host "Installing Sysmon..." -ForegroundColor Cyan
Start-Process -FilePath $sysmonExe -ArgumentList "-accepteula -i $sysmonConfigFile" -Wait

# Cleanup: Remove temporary files
Write-Host "Cleaning up..." -ForegroundColor Cyan
Remove-Item -Path $sysmonZip -Force
Remove-Item -Path $sysmonDir -Recurse -Force
Remove-Item -Path $sysmonConfigFile -Force


# Path to the ossec.conf file
$ossecConfPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"

# Check if the file exists
if (Test-Path $ossecConfPath) {
    # Define the XML block to insert
    $xmlToAdd = @"
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
"@

    # Read the current content of ossec.conf
    $ossecConfContent = Get-Content -Path $ossecConfPath

    # Check if the XML block is already present to avoid duplicates
    if ($ossecConfContent -notcontains "<location>Microsoft-Windows-Sysmon/Operational</location>") {
        # Convert the file content to a string
        $ossecConfString = [System.IO.File]::ReadAllText($ossecConfPath)

        # Insert the new XML block before the closing </ossec_config> tag
        $newOssecConf = $ossecConfString -replace '</ossec_config>', "$xmlToAdd</ossec_config>"

        # Write the updated content back to the ossec.conf file
        [System.IO.File]::WriteAllText($ossecConfPath, $newOssecConf)

        Write-Host "Successfully inserted the Sysmon localfile section inside ossec.conf." -ForegroundColor Green
    } else {
        Write-Host "The Sysmon localfile section already exists in ossec.conf." -ForegroundColor Yellow
    }
} else {
    Write-Host "The ossec.conf file does not exist at the specified path." -ForegroundColor Red
}

NET STOP WazuhSvc
NET START WazuhSvc
Write-Host "Sysmon installation completed successfully." -ForegroundColor Green
