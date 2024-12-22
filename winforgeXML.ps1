#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Windows configuration deployment tool using XML configurations.
.DESCRIPTION
    WinforgeXML automates Windows system configuration using XML-based configuration files.
    Supports local and remote configurations with schema validation.
.PARAMETER ConfigPath
    Path to the XML configuration file (local path or URL)
.PARAMETER LogPath
    Optional custom path for log file
.EXAMPLE
    .\winforgeXML.ps1 -ConfigPath "config.xml"
.EXAMPLE
    .\winforgeXML.ps1 -ConfigPath "https://example.com/config.xml" -LogPath "C:\Logs\winforge.log"
.NOTES
    Version: 1.0
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$ConfigPath,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:TEMP\WinforgeXML.log"
)

# Script Variables
$script:logFile = $LogPath
$script:configXML = $null
$script:schemaPath = Join-Path $PSScriptRoot "config.xsd"
$script:restartRequired = $false
$script:tempFiles = @()

# Initialize Error Handling
$ErrorActionPreference = "Stop"

#region Helper Functions
function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Add-Content -Path $script:logFile -Value $logMessage
    

}

function Write-SystemMessage {
    param (
        [Parameter()]
        [string] $title = '',
  
        [Parameter()]
        [string] $msg1 = '',

        [Parameter()]
        [string] $msg2 = '',
  
        [Parameter()]
        $titleColor = 'DarkMagenta',
  
        [Parameter()]
        $msg1Color = 'Cyan',

        [Parameter()]
        $msg2color = 'White'
    )
    
    
    if ($PSBoundParameters.ContainsKey('title')) {
        Write-Host
        Write-Host " $title ".ToUpper() -ForegroundColor White -BackgroundColor $titleColor 
        Write-Host
    }
  
    if ($PSBoundParameters.ContainsKey('msg1') -and $PSBoundParameters.ContainsKey('msg2')){
        Write-Host "$msg1" -ForegroundColor $msg1Color -NoNewline; Write-Host "$msg2" -ForegroundColor $msg2color
        return
    }

    if ($PSBoundParameters.ContainsKey('msg1')) {
        Write-Host "$msg1" -ForegroundColor $msg1Color
    }

    if ($PSBoundParameters.ContainsKey('msg2')) {
        Write-Host "$msg2" -ForegroundColor $msg2color
    }

}

function Write-ErrorMessage {
    param (
      [Parameter()]
      $msg = "ERROR",
  
      [Parameter()]
      $color = 'White'
    )
  
    Write-Host
    Write-Host " $msg ".ToUpper() -ForegroundColor $color -BackgroundColor DarkRed
    Write-Host
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host
  }

function Write-SuccessMessage {
    param (
      [Parameter()]
      $msg = "SUCCESS",
  
      [Parameter()]
      $msgColor = 'Green'
    )
  
    Write-Host
    Write-Host "Success: $msg " -ForegroundColor $msgColor -BackgroundColor Black
    Write-Host
  }

function Test-AdminPrivileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-XmlSchema {
    param (
        [Parameter(Mandatory = $true)]
        [xml]$Xml
    )
    
    try {
        # Load and validate schema
        $schemaReader = New-Object System.Xml.XmlTextReader $script:schemaPath
        $schema = [System.Xml.Schema.XmlSchema]::Read($schemaReader, $null)
        $Xml.Schemas.Add($schema) | Out-Null
        
        # Validate document
        $Xml.Validate($null)
        return $true
    }
    catch {
        Write-Log "XML validation error: $($_.Exception.Message)" -Level Error
        return $false
    }
    finally {
        if ($schemaReader) { $schemaReader.Close() }
    }
}

function Get-XmlConfig {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    try {
        # Handle remote configurations
        if ($Path -match '^https?://') {
            Write-Log "Downloading configuration from: $Path"
            $tempPath = Join-Path $env:TEMP "winforge_config.xml"
            $script:tempFiles += $tempPath
            Invoke-WebRequest -Uri $Path -OutFile $tempPath
            $Path = $tempPath
        }
        
        # Load and validate XML
        Write-SystemMessage -Title "Configuration" -Message "Loading configuration file..."
        [xml]$config = Get-Content -Path $Path
        
        if (-not (Test-XmlSchema -Xml $config)) {
            throw "XML validation failed"
        }
        
        return $config.WinforgeConfig
    }
    catch {
        Write-Log "Failed to load configuration: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Remove-TempFiles {
    foreach ($file in $script:tempFiles) {
        if (Test-Path $file) {
            Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
        }
    }
}

function Set-RegistryModification {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("add", "remove")]
        [string]$Action,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter()]
        [ValidateSet("String", "ExpandString", "Binary", "DWord", "MultiString", "QWord")]
        [string]$Type = "String",

        [Parameter()]
        [object]$Value
    )
    
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        
        if ($Action -eq 'add') {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        }
        else {
            Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue
        }
        return $true
    }
    catch {
        Write-Log "Registry modification failed: $($_.Exception.Message)" -Level Error
        return $false
    }
}


function Test-ProgramInstalled {
    param(
        [string]$ProgramName
    )

    $InstalledSoftware = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" |
                         ForEach-Object { [PSCustomObject]@{ 
                            DisplayName = $_.GetValue('DisplayName')
                            DisplayVersion = $_.GetValue('DisplayVersion')
                        }}

    # Check if the partial program name exists in the filtered list
    $isProgramInstalled = $InstalledSoftware | Where-Object { $_.DisplayName -like "*$ProgramName*" }

    return $isProgramInstalled
}


function Set-SystemCheckpoint {
    $date = Get-Date -Format "dd/MM/yyyy"
    $snapshotName = "Winforge - $date"
    
    try {
        Write-Log "Creating system restore point. Snapshot Name: $snapshotName"
        Write-SystemMessage -title "Creating System Restore Point" -msg1 "Snapshot Name: " -msg2 $snapshotName
        
        Enable-ComputerRestore -Drive "$env:systemdrive"
        Checkpoint-Computer -Description $snapshotName -RestorePointType "MODIFY_SETTINGS" -Verbose
        
        Write-Log "System restore point created successfully."
        Write-SuccessMessage -msg "System restore point created successfully."
    } catch {
        Write-Log "Error creating system restore point: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Failed to create system restore point: $($_.Exception.Message)"
        Return
    }
}



#region Configuration Functions
function Set-SystemConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$SystemConfig
    )
    
    try {
        Write-SystemMessage -Title "Configuring System Settings"

        # Computer Name
        if ($SystemConfig.ComputerName) {
            Write-Log "Setting computer name to: $($SystemConfig.ComputerName)"
            Rename-Computer -NewName $SystemConfig.ComputerName -Force
            $script:restartRequired = $true
        }

        # Locale and Timezone
        if ($SystemConfig.Locale) {
            Write-Log "Setting system locale to: $($SystemConfig.Locale)"
            Write-SystemMessage -msg1 "- Setting system locale to: " -msg2 $SystemConfig.Locale
            
            try {
                # Validate locale is supported
                if (Get-WinUserLanguageList | Where-Object { $_.LanguageTag -eq $SystemConfig.Locale }) {
                    Set-WinUILanguageOverride -Language $SystemConfig.Locale
                    Set-WinSystemLocale -SystemLocale $SystemConfig.Locale
                    Set-WinUserLanguageList $SystemConfig.Locale -Force
                    Set-Culture -CultureInfo $SystemConfig.Locale
                    
                    $script:restartRequired = $true
                    Write-SuccessMessage -msg "System locale set successfully"
                } else {
                    Write-Log "Invalid or unsupported locale: $($SystemConfig.Locale)" -Level Warning
                    Write-ErrorMessage -msg "Invalid or unsupported locale: $($SystemConfig.Locale)"
                }
            } catch {
                Write-Log "Error setting system locale: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to set system locale"
            }
        }

        if ($SystemConfig.Timezone) {
            $currentTZ = (Get-TimeZone).Id
            if ($currentTZ -ne $SystemConfig.Timezone) {
                Write-Log "Setting timezone to: $($SystemConfig.Timezone)"
                Write-SystemMessage -msg1 "- Setting timezone to: " -msg2 $SystemConfig.Timezone
                try {
                    Set-TimeZone -Id $SystemConfig.Timezone
                    $newTZ = (Get-TimeZone).Id
                    if ($newTZ -eq $SystemConfig.Timezone) {
                        Write-SuccessMessage -msg "Timezone set successfully to: $($SystemConfig.Timezone)"
                    } else {
                        Write-Log "Failed to set timezone to: $($SystemConfig.Timezone)" -Level Warning
                        Write-ErrorMessage -msg "Failed to set timezone"
                    }
                } catch {
                    Write-Log "Error setting timezone: $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to set timezone"
                }
            } else {
                Write-Log "Timezone is already set to: $($SystemConfig.Timezone)"
                Write-SystemMessage -msg1 "- Timezone already set to: " -msg2 $SystemConfig.Timezone -msg1Color "Cyan"
            }
        }

        # Windows Features
        if ($SystemConfig.EnableRemoteDesktop -eq 'true') {
            Write-Log "Enabling Remote Desktop..."
            Set-RegistryModification -Action add -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
            Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
        }

        # Store, OneDrive, and Copilot
        if ($SystemConfig.DisableWindowsStore -eq 'true') {
            Write-Log "Disabling Windows Store..."
            Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -Type DWord -Value 1
        }

        if ($SystemConfig.DisableOneDrive -eq 'true') {
            Write-Log "Disabling OneDrive..."
            Write-SystemMessage -msg1 "- Disabling OneDrive."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
                Stop-Process -Name OneDrive -Force -ErrorAction SilentlyContinue
                Write-SuccessMessage -msg "OneDrive disabled."
            } catch {
                Write-Log "Error disabling OneDrive: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable OneDrive."
            }
        }

        if ($SystemConfig.DisableCopilot -eq 'true') {
            Write-Log "Disabling Windows Copilot..."
            Write-SystemMessage -msg1 "- Disabling Windows Copilot."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "CopilotEnabled" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Type DWord -Value 1
                Write-SuccessMessage -msg "Windows Copilot disabled."
            } catch {
                Write-Log "Error disabling Windows Copilot: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable Windows Copilot."
            }
        }

        # File Explorer Settings
        if ($SystemConfig.ShowFileExtensions -eq 'true') {
            Write-SystemMessage -msg1 "- Showing file extensions..."
            Write-Log "Showing file extensions..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
                Write-SuccessMessage -msg "File extensions enabled"
            } catch {
                Write-Log "Failed to show file extensions: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to show file extensions"
            }
        }

        if ($SystemConfig.ShowHiddenFiles -eq 'true') {
            Write-SystemMessage -msg1 "- Showing hidden files..."
            Write-Log "Showing hidden files..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1
                Write-SuccessMessage -msg "Hidden files enabled"
            } catch {
                Write-Log "Failed to show hidden files: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to show hidden files"
            }
        }

        Write-Log "System configuration completed successfully"
        return $true
    }
    catch {
        Write-Log "Error configuring system settings: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Set-SecurityConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$SecurityConfig
    )
    
    try {
        Write-SystemMessage -Title "Configuring Security Settings"

        # Windows Defender
        if ($SecurityConfig.DisableDefender -eq 'true') {
            Write-SystemMessage -msg1 "- Disabling Windows Defender..."
            Write-Log "Disabling Windows Defender..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
                Write-SuccessMessage -msg "Windows Defender disabled"
            } catch {
                Write-Log "Failed to disable Windows Defender: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable Windows Defender"
            }
        }

        # UAC Settings
        if ($SecurityConfig.DisableUAC -eq 'true') {
            Write-SystemMessage -msg1 "- Disabling UAC..."
            Write-Log "Disabling UAC..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Type DWord -Value 0
                Write-SuccessMessage -msg "UAC disabled"
                $script:restartRequired = $true
            } catch {
                Write-Log "Failed to disable UAC: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable UAC"
            }
        }

        # UAC Level Settings
        if ($SecurityConfig.UACLevel) {
            Write-SystemMessage -msg1 "- Setting UAC level to: " -msg2 $SecurityConfig.UACLevel
            Write-Log "Setting UAC level to: $($SecurityConfig.UACLevel)"
            try {
                $uacValue = switch ($SecurityConfig.UACLevel) {
                    "AlwaysNotify" { 2 }    # Always notify
                    "NeverNotify" { 0 }     # Never notify
                    "Default" { 5 }         # Default - Notify when apps try to make changes (no dim)
                    default {
                        Write-Log "Invalid UAC level specified: $($SecurityConfig.UACLevel). Using default." -Level Warning
                        5  # Default value
                    }
                }
                
                $promptValue = if ($uacValue -eq 2) { 1 } else { 0 }
                
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value $uacValue
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value $promptValue
                Write-SuccessMessage -msg "UAC level set successfully"
            } catch {
                Write-Log "Failed to set UAC level: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to set UAC level"
            }
        }


        # SMB1 Protocol
        if ($SecurityConfig.DisableSMB1 -eq 'true') {
            Write-SystemMessage -msg1 "- Disabling SMB1 protocol..."
            Write-Log "Disabling SMB1 protocol..."
            try {
                Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
                $script:restartRequired = $true
                Write-SuccessMessage -msg "SMB1 protocol disabled"
            } catch {
                Write-Log "Failed to disable SMB1 protocol: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable SMB1 protocol"
            }
        }

        # AutoPlay
        if ($SecurityConfig.DisableAutoPlay -eq 'true') {
            Write-SystemMessage -msg1 "- Disabling AutoPlay..."
            Write-Log "Disabling AutoPlay..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
                Write-SuccessMessage -msg "AutoPlay disabled"
            } catch {
                Write-Log "Failed to disable AutoPlay: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable AutoPlay"
            }
        }

        # BitLocker
        if ($SecurityConfig.BitLocker.Enable -eq 'true') {
            Write-SystemMessage -msg1 "- Configuring BitLocker for drive: " -msg2 $SecurityConfig.BitLocker.Target
            Write-Log "Configuring BitLocker for drive: $($SecurityConfig.BitLocker.Target)"
            try {
                Enable-BitLocker -MountPoint $SecurityConfig.BitLocker.Target -EncryptionMethod XtsAes256 -UsedSpaceOnly
                Write-SuccessMessage -msg "BitLocker configured successfully"
            } catch {
                Write-Log "Failed to configure BitLocker: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to configure BitLocker"
            }
        }

        Write-Log "Security configuration completed successfully"
        return $true
    }
    catch {
        Write-Log "Error configuring security settings: $($_.Exception.Message)" -Level Error
        Write-ErrorMessage -msg "Failed to configure security settings"
        return $false
    }
}

function Set-PrivacyConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$PrivacyConfig
    )
    
    try {
        Write-SystemMessage -Title "Configuring Privacy Settings"

        # Telemetry
        if ($PrivacyConfig.DisableTelemetry -eq 'true') {
            Write-SystemMessage -msg1 "- Disabling telemetry..."
            Write-Log "Disabling telemetry..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
                Write-SuccessMessage -msg "Telemetry disabled"
            } catch {
                Write-Log "Failed to disable telemetry: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable telemetry"
            }
        }

        # DiagTrack
        if ($PrivacyConfig.DisableDiagTrack -eq 'true') {
            Write-SystemMessage -msg1 "- Disabling diagnostic tracking..."
            Write-Log "Disabling diagnostic tracking..."
            try {
                Stop-Service "DiagTrack" -Force
                Set-Service "DiagTrack" -StartupType Disabled
                Write-SuccessMessage -msg "Diagnostic tracking disabled"
            } catch {
                Write-Log "Failed to disable diagnostic tracking: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable diagnostic tracking"
            }
        }

        # App Privacy
        if ($PrivacyConfig.DisableAppPrivacy -eq 'true') {
            Write-SystemMessage -msg1 "- Configuring app privacy settings..."
            Write-Log "Configuring app privacy settings..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" -Name "Value" -Type String -Value "Deny"
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Name "Value" -Type String -Value "Deny"
                Write-SuccessMessage -msg "App privacy settings configured"
            } catch {
                Write-Log "Failed to configure app privacy settings: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to configure app privacy settings"
            }
        }

        # Start Menu Tracking
        if ($PrivacyConfig.DisableStartMenuTracking -eq 'true') {
            Write-SystemMessage -msg1 "- Disabling Start Menu tracking..."
            Write-Log "Disabling Start Menu tracking..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Type DWord -Value 1
                Write-SuccessMessage -msg "Start Menu tracking disabled"
            } catch {
                Write-Log "Failed to disable Start Menu tracking: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable Start Menu tracking"
            }
        }

        # Activity History
        if ($PrivacyConfig.DisableActivityHistory -eq 'true') {
            Write-SystemMessage -msg1 "- Disabling Activity History..."
            Write-Log "Disabling Activity History..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
                Write-SuccessMessage -msg "Activity History disabled"
            } catch {
                Write-Log "Failed to disable Activity History: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable Activity History"
            }
        }

        # Clipboard Data Collection
        if ($PrivacyConfig.DisableClipboardDataCollection -eq 'true') {
            Write-SystemMessage -msg1 "- Disabling Clipboard data collection..."
            Write-Log "Disabling Clipboard data collection..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Type DWord -Value 0
                Write-SuccessMessage -msg "Clipboard data collection disabled"
            } catch {
                Write-Log "Failed to disable Clipboard data collection: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable Clipboard data collection"
            }
        }

        # Start Menu Suggestions
        if ($PrivacyConfig.DisableStartMenuSuggestions -eq 'true') {
            Write-SystemMessage -msg1 "- Disabling Start Menu suggestions..."
            Write-Log "Disabling Start Menu suggestions..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
                Write-SuccessMessage -msg "Start Menu suggestions disabled"
            } catch {
                Write-Log "Failed to disable Start Menu suggestions: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable Start Menu suggestions"
            }
        }

        Write-Log "Privacy configuration completed successfully"
        return $true
    }
    catch {
        Write-Log "Error configuring privacy settings: $($_.Exception.Message)" -Level Error
        Write-ErrorMessage -msg "Failed to configure privacy settings"
        return $false
    }
}

function Install-Applications {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$AppConfig
    )
    
    try {
        Write-SystemMessage -Title "Installing Applications"

        # Package Manager Selection
        $packageManager = $AppConfig.PackageManager

        # Chocolatey Apps
        if ($packageManager -eq "Chocolatey" -and $AppConfig.ChocolateyApps) {
            Write-SystemMessage -msg1 "- Checking Chocolatey is installed..."
            Write-Log "Checking Chocolatey is installed..."

            # Install Chocolatey if not present
            if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
                Write-SystemMessage -msg1 "- Installing Chocolatey package manager..."
                Write-Log "Installing Chocolatey package manager..."
                try {
                    Set-ExecutionPolicy Bypass -Scope Process -Force
                    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
                    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
                    Write-SuccessMessage -msg "Chocolatey installed successfully"
                } catch {
                    Write-Log "Failed to install Chocolatey: $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to install Chocolatey"
                    return $false
                }
            }

            # Install Chocolatey Apps
            foreach ($app in $AppConfig.ChocolateyApps.App) {
                Write-SystemMessage -msg1 "- Installing: " -msg2 $app
                Write-Log "Installing $app..."
                try {
                    if ($app.Version) {
                        choco install $app --version $app.Version -y
                    } else {
                        choco install $app -y
                    }
                    Write-SuccessMessage -msg "$app installed successfully"
                } catch {
                    Write-Log "Failed to install $app : $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to install $app"
                }
            }
        }

        # Winget Apps
        if ($packageManager -eq "Winget" -and $AppConfig.WingetApps) {
            Write-SystemMessage -msg1 "- Checking Winget installation..."
            Write-Log "Checking Winget installation..."

            # Check if Winget is available
            if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
                Write-Log "Winget is not installed" -Level Error
                Write-ErrorMessage -msg "Winget is not installed. Please install Windows App Installer"
                return $false
            }

            # Reset Winget sources and accept agreements
            Write-SystemMessage -msg1 "- Resetting Winget sources..."
            Write-Log "Resetting Winget sources..."
            try {
                winget source reset --force
                Add-AppxPackage -Path "https://cdn.winget.microsoft.com/cache/source.msix"
                Write-SuccessMessage -msg "Winget sources reset successfully"
            } catch {
                Write-Log "Failed to reset Winget sources: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to reset Winget sources"
            }

            # Install Winget Apps
            foreach ($app in $AppConfig.WingetApps.App) {
                Write-SystemMessage -msg1 "- Installing: " -msg2 $app.ID
                Write-Log "Installing $($app.ID)..."
                try {
                    if ($app.Version) {
                        winget install $app.ID --version $app.Version --accept-source-agreements --accept-package-agreements
                    } else {
                        winget install $app.ID --accept-source-agreements --accept-package-agreements
                    }
                    Write-SuccessMessage -msg "$($app.ID) installed successfully"
                } catch {
                    Write-Log "Failed to install $($app.ID): $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to install $($app.ID)"
                }
            }
        }

        Write-Log "Application installation completed successfully"
        return $true
    }
    catch {
        Write-Log "Error installing applications: $($_.Exception.Message)" -Level Error
        Write-ErrorMessage -msg "Failed to install applications"
        return $false
    }
}

function Set-EnvironmentVariables {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$EnvConfig
    )
    
    try {
        Write-SystemMessage -Title "Setting Environment Variables"
        foreach ($variable in $EnvConfig.ChildNodes) {
            [System.Environment]::SetEnvironmentVariable($variable.Name, $variable.InnerText, [System.EnvironmentVariableTarget]::Machine)
        }
        return $true
    }
    catch {
        Write-Log "Error setting environment variables: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Set-WindowsActivation {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$ActivationConfig
    )
    
    try {
        Write-SystemMessage -Title "Windows Activation"
        $productKey = $ActivationConfig.ProductKey
        $version = $ActivationConfig.Version
        
        # Install product key
        if ($productKey) {
            Write-Log "Installing product key..."
            slmgr.vbs /ipk $productKey
            Start-Sleep -Seconds 2
            slmgr.vbs /ato
        }
        return $true
    }
    catch {
        Write-Log "Error activating Windows: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Set-WindowsUpdateConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$UpdateConfig
    )
    
    try {
        Write-SystemMessage -Title "Configuring Windows Update"
        
        # Auto Update Settings
        if ($UpdateConfig.NoAutoUpdate) {
            Write-SystemMessage -msg1 "- Configuring automatic updates..."
            Write-Log "Setting automatic updates to: $($UpdateConfig.NoAutoUpdate)"
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type DWord -Value ([int]$UpdateConfig.NoAutoUpdate)
                Write-SuccessMessage -msg "Automatic updates configured"
            } catch {
                Write-Log "Failed to configure automatic updates: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to configure automatic updates"
            }
        }

        # Update Options (2=Notify, 3=Auto DL, 4=Auto DL and Install)
        if ($UpdateConfig.AUOptions) {
            Write-SystemMessage -msg1 "- Setting update behavior..."
            Write-Log "Setting update options to: $($UpdateConfig.AUOptions)"
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value $UpdateConfig.AUOptions
                Write-SuccessMessage -msg "Update behavior configured"
            } catch {
                Write-Log "Failed to set update options: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to set update options"
            }
        }

        # Schedule Settings
        if ($UpdateConfig.ScheduledInstallDay -and $UpdateConfig.ScheduledInstallTime) {
            Write-SystemMessage -msg1 "- Configuring update schedule..."
            Write-Log "Setting update schedule - Day: $($UpdateConfig.ScheduledInstallDay), Time: $($UpdateConfig.ScheduledInstallTime)"
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Type DWord -Value $UpdateConfig.ScheduledInstallDay
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Type DWord -Value $UpdateConfig.ScheduledInstallTime
                Write-SuccessMessage -msg "Update schedule configured"
            } catch {
                Write-Log "Failed to set update schedule: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to set update schedule"
            }
        }

        Write-Log "Windows Update configuration completed successfully"
        return $true
    }
    catch {
        Write-Log "Error configuring Windows Update: $($_.Exception.Message)" -Level Error
        Write-ErrorMessage -msg "Failed to configure Windows Update"
        return $false
    }
}

function Set-ScheduledTasksConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$TasksConfig
    )
    
    try {
        Write-SystemMessage -Title "Configuring Scheduled Tasks"

        foreach ($task in $TasksConfig.Task) {
            Write-SystemMessage -msg1 "- Importing task: " -msg2 $task.Name
            Write-Log "Importing task: $($task.Name)"
            
            try {
                # Handle remote or local task XML
                if ($task.Path -match '^https?://') {
                    $tempPath = Join-Path $env:TEMP "$($task.Name).xml"
                    $script:tempFiles += $tempPath
                    Invoke-WebRequest -Uri $task.Path -OutFile $tempPath
                    $taskPath = $tempPath
                } else {
                    $taskPath = Join-Path $PSScriptRoot $task.Path
                }

                # Register the task
                if (Test-Path $taskPath) {
                    Register-ScheduledTask -TaskName $task.Name -Xml (Get-Content $taskPath -Raw) -Force
                    Write-Log "Task imported successfully: $($task.Name)"
                    Write-SystemMessage -msg1 "- Task imported successfully: " -msg2 $task.Name
                } else {
                    Write-Log "Task XML file not found: $taskPath" -Level Warning
                    Write-ErrorMessage -msg "Task XML file not found: $taskPath"
                }
            } catch {
                Write-Log "Failed to import task $($task.Name): $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to import task: $($task.Name)"
            }
        }

        Write-Log "Scheduled tasks configuration completed successfully"
        return $true
    }
    catch {
        Write-Log "Error configuring scheduled tasks: $($_.Exception.Message)" -Level Error
        Write-ErrorMessage -msg "Failed to configure scheduled tasks"
        return $false
    }
}

# Function to test if a font is installed
function Test-FontInstalled {
    param(
        [string]$FontName
    )

    $InstalledFonts = Get-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" |
                      Get-ItemProperty |
                      ForEach-Object { [PSCustomObject]@{ 
                            FontName = $_.PSObject.Properties.Name
                            FontFile = $_.PSObject.Properties.Value
                        }}

    $isFontInstalled = $InstalledFonts | Where-Object { $_.FontName -like "*$FontName*" }
    return $isFontInstalled
}

# Function to download font files from GitHub
function Get-Fonts {
    param (
        [string]$fontName,
        [string]$outputPath
    )

    try {
        $githubUrl = "https://github.com/google/fonts"
        $fontRepoUrl = "$githubUrl/tree/main/ofl/$fontName"

        if (-not (Test-Path -Path $outputPath)) {
            New-Item -ItemType Directory -Path $outputPath | Out-Null
        }

        Write-Log "Fetching font files from GitHub: $fontRepoUrl"
        $fontFilesPage = Invoke-WebRequest -Uri $fontRepoUrl -UseBasicParsing
        $fontFileLinks = $fontFilesPage.Links | Where-Object { $_.href -match "\.ttf$" -or $_.href -match "\.otf$" }

        if (-not $fontFileLinks) {
            throw "No font files found for $fontName"
        }

        foreach ($link in $fontFileLinks) {
            $fileUrl = "https://github.com" + $link.href.Replace("/blob/", "/raw/")
            $fileName = [System.IO.Path]::GetFileName($link.href)
            $outputFile = Join-Path -Path $outputPath -ChildPath $fileName

            Write-Log "Downloading $fileName"
            Invoke-WebRequest -Uri $fileUrl -OutFile $outputFile
            
            if (-not (Test-Path $outputFile)) {
                throw "Failed to download $fileName"
            }
        }
    }
    catch {
        Write-Log "Error downloading fonts: $($_.Exception.Message)" -Level Error
        throw
    }
}

# Function to install Google fonts from GitHub repository
function Install-Fonts {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$FontConfig
    )
    
    try {
        Write-SystemMessage -Title "Installing Fonts"
        
        $ProgressPreference = 'SilentlyContinue'
        $tempDownloadFolder = "$env:TEMP\google_fonts"
        $script:tempFiles += $tempDownloadFolder

        foreach ($fontName in $FontConfig.Font) {
            # Correct the font names for the GitHub repository
            $correctFontName = $fontName -replace "\+", ""

            # Check if the font is already installed
            if (Test-FontInstalled -FontName $correctFontName) {
                Write-Log "Font $correctFontName is already installed. Skipping..."
                Write-SystemMessage -msg1 "- $correctFontName is already installed. Skipping..." -msg1Color "Cyan"
                continue
            }

            Write-SystemMessage -msg1 "- Downloading & Installing: " -msg2 $correctFontName
            Write-Log "Downloading & Installing $correctFontName from Google Fonts GitHub repository..."

            try {
                # Download the font files
                Get-Fonts -fontName $correctFontName -outputPath $tempDownloadFolder

                # Install the font files
                $allFonts = Get-ChildItem -Path $tempDownloadFolder -Include *.ttf, *.otf -Recurse
                foreach ($font in $allFonts) {
                    $fontDestination = Join-Path -Path $env:windir\Fonts -ChildPath $font.Name
                    Copy-Item -Path $font.FullName -Destination $fontDestination -Force

                    # Register the font
                    Set-RegistryModification -Action add `
                        -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Fonts" `
                        -Name $font.BaseName `
                        -Value $font.Name `
                        -Type String
                }

                Write-Log "Font installed: $correctFontName"
                Write-SuccessMessage -msg "$correctFontName installed successfully"

            } catch {
                Write-Log "Failed to install font $correctFontName : $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to install font: $correctFontName"
                continue
            }
        }

        Write-Log "Font installation completed successfully"
        return $true
    }
    catch {
        Write-Log "Error installing fonts: $($_.Exception.Message)" -Level Error
        Write-ErrorMessage -msg "Failed to install fonts"
        return $false
    }
    finally {
        $ProgressPreference = 'Continue'
        if (Test-Path $tempDownloadFolder) {
            Remove-Item -Path $tempDownloadFolder -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Set-TaskbarConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$TaskbarConfig
    )
    
    try {
        Write-SystemMessage -Title "Configuring Taskbar Settings"

        # Taskbar Alignment (Left = 0, Center = 1)
        if ($TaskbarConfig.TaskbarAlignment) {
            Write-Log "Setting taskbar alignment to: $($TaskbarConfig.TaskbarAlignment)"
            $alignmentValue = if ($TaskbarConfig.TaskbarAlignment -eq 'Left') { 0 } else { 1 }
            Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Type DWord -Value $alignmentValue
        }

        # Meet Now
        if ($TaskbarConfig.DisableMeetNow -eq 'true') {
            Write-Log "Disabling Meet Now..."
            Set-RegistryModification -Action add -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1
            Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1
        }

        # Widgets
        if ($TaskbarConfig.DisableWidgets -eq 'true') {
            Write-Log "Disabling Widgets..."
            Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0
            Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Type DWord -Value 0
        }

        # Task View
        if ($TaskbarConfig.DisableTaskView -eq 'true') {
            Write-Log "Disabling Task View button..."
            Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
        }

        # Search
        if ($TaskbarConfig.DisableSearch -eq 'true') {
            Write-Log "Disabling Search icon..."
            Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
            Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSearchBox" -Type DWord -Value 0
        }

        # Restart Explorer to apply changes
        Write-Log "Restarting Explorer to apply taskbar changes..."
        Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
        Start-Process explorer

        Write-Log "Taskbar configuration completed successfully"
        return $true
    }
    catch {
        Write-Log "Error configuring taskbar: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Set-PowerConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$PowerConfig
    )
    
    try {
        Write-SystemMessage -Title "Configuring Power Settings"

        # Power Plan
        if ($PowerConfig.PowerPlan) {
            Write-SystemMessage -msg1 "- Setting power plan to: " -msg2 $PowerConfig.PowerPlan
            
            $guid = switch ($PowerConfig.PowerPlan) {
                "Balanced" { "381b4222-f694-41f0-9685-ff5bb260df2e" }
                "HighPerformance" { "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" }
                "PowerSaver" { "a1841308-3541-4fab-bc81-f71556f20b4a" }
                default {
                    Write-Log "Invalid power plan specified: $($PowerConfig.PowerPlan)" -Level Warning
                    Write-ErrorMessage -msg "Invalid power plan specified"
                    return $false
                }
            }
            
            try {
                powercfg /setactive $guid
                Write-SuccessMessage -msg "Power plan set to: $($PowerConfig.PowerPlan)"
            } catch {
                Write-Log "Failed to set power plan: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to set power plan"
                return $false
            }
        }

        # Sleep Settings
        if ($PowerConfig.DisableSleep -eq 'true') {
            Write-SystemMessage -msg1 "- Disabling sleep..."
            try {
                powercfg /change standby-timeout-ac 0
                powercfg /change standby-timeout-dc 0
                Write-SuccessMessage -msg "Sleep disabled"
            } catch {
                Write-Log "Failed to disable sleep: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable sleep"
            }
        }

        # Hibernate Settings
        if ($PowerConfig.DisableHibernate -eq 'true') {
            Write-SystemMessage -msg1 "- Disabling hibernate..."
            try {
                powercfg /hibernate off
                Write-SuccessMessage -msg "Hibernate disabled"
            } catch {
                Write-Log "Failed to disable hibernate: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable hibernate"
            }
        }

        # Timeouts (if specified)
        if ($PowerConfig.MonitorTimeout) {
            Write-SystemMessage -msg1 "- Setting monitor timeout to: " -msg2 "$($PowerConfig.MonitorTimeout) minutes"
            powercfg /change monitor-timeout-ac $PowerConfig.MonitorTimeout
            powercfg /change monitor-timeout-dc $PowerConfig.MonitorTimeout
        }

        # Fast Startup
        if ($PowerConfig.DisableFastStartup -eq 'true') {
            Write-SystemMessage -msg1 "- Disabling fast startup..."
            Write-Log "Disabling fast startup..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
                Write-SuccessMessage -msg "Fast startup disabled"
            } catch {
                Write-Log "Failed to disable fast startup: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable fast startup"
            }
        }

        Write-Log "Power configuration completed successfully"
        return $true
    }
    catch {
        Write-Log "Error configuring power settings: $($_.Exception.Message)" -Level Error
        Write-ErrorMessage -msg "Failed to configure power settings"
        return $false
    }
}

function Set-RegistryEntries {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$RegistryConfig
    )
    
    try {
        Write-SystemMessage -Title "Applying Registry Modifications"

        # Process registry additions
        if ($RegistryConfig.Add) {
            foreach ($entry in $RegistryConfig.Add.Entry) {
                Write-Log "Adding registry entry: $($entry.Path)\$($entry.Name)"
                Set-RegistryModification -Action add -Path $entry.Path -Name $entry.Name -Type $entry.Type -Value $entry.Value
            }
        }

        # Process registry removals
        if ($RegistryConfig.Remove) {
            foreach ($entry in $RegistryConfig.Remove.Entry) {
                Write-Log "Removing registry entry: $($entry.Path)\$($entry.Name)"
                Set-RegistryModification -Action remove -Path $entry.Path -Name $entry.Name
            }
        }

        Write-Log "Registry modifications completed successfully"
        return $true
    }
    catch {
        Write-Log "Error modifying registry entries: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Set-WindowsFeaturesConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$FeaturesConfig
    )
    
    try {
        Write-SystemMessage -Title "Configuring Windows Features"

        foreach ($feature in $FeaturesConfig.Feature) {
            Write-SystemMessage -msg1 "- Processing feature: " -msg2 $feature.Name
            Write-Log "Processing feature: $($feature.Name) with state: $($feature.State)"
            
            try {
                if ($feature.State -eq 'enabled') {
                    Write-Log "Enabling feature: $($feature.Name)"
                    $result = Enable-WindowsOptionalFeature -Online -FeatureName $feature.Name -NoRestart
                    if ($result.RestartNeeded) {
                        $script:restartRequired = $true
                        Write-Log "Restart will be required for feature: $($feature.Name)"
                    }
                    Write-SuccessMessage -msg "Feature enabled: $($feature.Name)"
                }
                elseif ($feature.State -eq 'disabled') {
                    Write-Log "Disabling feature: $($feature.Name)"
                    $result = Disable-WindowsOptionalFeature -Online -FeatureName $feature.Name -NoRestart
                    if ($result.RestartNeeded) {
                        $script:restartRequired = $true
                        Write-Log "Restart will be required for feature: $($feature.Name)"
                    }
                    Write-SuccessMessage -msg "Feature disabled: $($feature.Name)"
                }
                else {
                    Write-Log "Invalid state specified for feature $($feature.Name): $($feature.State)" -Level Warning
                    Write-ErrorMessage -msg "Invalid state specified for feature: $($feature.Name)"
                }
            }
            catch {
                Write-Log "Failed to configure feature $($feature.Name): $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to configure feature: $($feature.Name)"
            }
        }

        Write-Log "Windows features configuration completed successfully"
        return $true
    }
    catch {
        Write-Log "Error configuring Windows features: $($_.Exception.Message)" -Level Error
        Write-ErrorMessage -msg "Failed to configure Windows features"
        return $false
    }
}

function Set-GoogleConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$GoogleConfig
    )
    
    try {
        Write-SystemMessage -Title "Configuring Google Products"

        # Google Drive
        if ($GoogleConfig.InstallGoogleDrive -eq 'true') {

            if (Test-ProgramInstalled 'Google Drive') {
                Write-Log "Google Drive already installed. Skipping..."
                Write-SystemMessage -msg1 "- Google Drive is already installed. Skipping installation."
                return $true
            }

            Write-Log "Installing Google Drive..."
            Write-SystemMessage -msg1 "- Installing: " -msg2 "Google Drive"

            $driveSetupUrl = "https://dl.google.com/drive-file-stream/GoogleDriveSetup.exe"
            $driveSetupPath = Join-Path $env:TEMP "GoogleDriveSetup.exe"
            $script:tempFiles += $driveSetupPath
            
            Invoke-WebRequest -Uri $driveSetupUrl -OutFile $driveSetupPath
            Start-Process -FilePath $driveSetupPath -ArgumentList "/silent /install" -Wait
            Write-SuccessMessage -msg "Google Drive installed successfully"
        }

        # Google Chrome
        if ($GoogleConfig.InstallGoogleChrome -eq 'true') {
            Write-Log "Installing Google Chrome..."
            Write-SystemMessage -msg1 "- Installing: " -msg2 "Google Chrome"
            
            $chromeSetupUrl = "https://dl.google.com/chrome/install/latest/chrome_installer.exe"
            $chromeSetupPath = Join-Path $env:TEMP "chrome_installer.exe"
            $script:tempFiles += $chromeSetupPath
            
            Invoke-WebRequest -Uri $chromeSetupUrl -OutFile $chromeSetupPath
            Start-Process -FilePath $chromeSetupPath -ArgumentList "/silent /install" -Wait
            Write-SuccessMessage -msg "Google Chrome installed successfully"
        }

        # Google Credential Provider for Windows (GCPW)
        if ($GoogleConfig.InstallGCPW -eq 'true') {
            if (-not $GoogleConfig.EnrollmentToken) {
                Write-Log "GCPW installation skipped - EnrollmentToken is required but was not provided" -Level Error
                Write-ErrorMessage -msg "GCPW installation requires an EnrollmentToken in the configuration"
                return $false
            }

            $gcpwFileName = if ([Environment]::Is64BitOperatingSystem) {
                'gcpwstandaloneenterprise64.msi'
            } else {
                'gcpwstandaloneenterprise.msi'
            }
    
            $gcpwUrl = "https://dl.google.com/credentialprovider/$gcpwFileName"

            if (Test-ProgramInstalled 'Credential Provider') {
                Write-Log "GCPW already installed. Skipping..."
            } else {
                Write-Log "Installing Google Credential Provider for Windows (GCPW)..."
                Write-SystemMessage -msg1 "- Installing: " -msg2 "Google Credential Provider for Windows (GCPW)"
                
                Invoke-WebRequest -Uri $gcpwUrl -OutFile "$env:TEMP\$gcpwFileName"
    
                try {
                    $arguments = "/i ""$env:TEMP\$gcpwFileName"" /quiet"
                    $installProcess = Start-Process msiexec.exe -ArgumentList $arguments -PassThru -Wait
    
                    if ($installProcess.ExitCode -eq 0) {
                        Write-Log "GCPW Installation completed successfully!"
                        
                        # Set the required EnrollmentToken
                        Set-RegistryModification -action add -path "HKLM:\SOFTWARE\Policies\Google\CloudManagement" -name "EnrollmentToken" -type "String" -value $GoogleConfig.EnrollmentToken | Out-Null
                        
                        # Only set domains_allowed_to_login if it was provided
                        if ($GoogleConfig.DomainsAllowedToLogin) {
                            Set-RegistryModification -action add -path "HKLM:\Software\Google\GCPW" -name "domains_allowed_to_login" -type "String" -value $GoogleConfig.DomainsAllowedToLogin | Out-Null
                            Write-Log 'Domains allowed to login has been set successfully'
                        } else {
                            Write-Log 'DomainsAllowedToLogin not provided. Skipping setting domains.'
                        }
                    } else {
                        Write-ErrorMessage -msg "- Failed to install Google Credential Provider for Windows (GCPW). Exit code: $($installProcess.ExitCode)"
                        Write-Log "Failed to install GCPW. Exit code: $($installProcess.ExitCode)"
                    }
                } finally {
                    Remove-Item -Path "$env:TEMP\$gcpwFileName" -Force -ErrorAction SilentlyContinue | Out-Null
                }
            }

            Write-SuccessMessage -msg "Google Credential Provider for Windows (GCPW) installation completed."

        } else {
            Write-Log "Skipping Google Credential Provider for Windows (GCPW) installation. Missing configuration."
        }
        
        # Allowed Domains
        if ($GoogleConfig.DomainsAllowedToLogin) {
            Write-Log "Setting allowed domains..."
            Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "AuthServerAllowlist" -Type String -Value $GoogleConfig.DomainsAllowedToLogin
        }

        Write-Log "Google configuration completed successfully"
        return $true
    }
    catch {
        Write-Log "Error configuring Google products: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Set-OfficeConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$OfficeConfig
    )
    
    try {
        Write-SystemMessage -Title "Configuring Microsoft Office"

        # Create Office configuration XML
        Write-SystemMessage -msg1 "- Creating Office configuration file..."
        Write-Log "Creating Office configuration file..."
        
        $configXml = @"
<Configuration>
    <Add OfficeClientEdition="$($OfficeConfig.OfficeClientEdition)" Channel="$($OfficeConfig.Channel)">
        <Product ID="$($OfficeConfig.ProductID)">
            <Language ID="$($OfficeConfig.LanguageID)" />
        </Product>
    </Add>
    <Display Level="$($OfficeConfig.DisplayLevel)" AcceptEULA="TRUE" />
    <Property Name="FORCEAPPSHUTDOWN" Value="TRUE" />
    <Updates Enabled="$($OfficeConfig.UpdatesEnabled.ToString().ToLower())" />
    <RemoveMSI />
</Configuration>
"@
        $configPath = Join-Path $env:TEMP "OfficeConfig.xml"
        $script:tempFiles += $configPath
        $configXml | Out-File -FilePath $configPath -Encoding UTF8

        # Download Office Deployment Tool
        Write-SystemMessage -msg1 "- Downloading Office Deployment Tool..."
        Write-Log "Downloading Office Deployment Tool..."
        
        $odtUrl = "https://download.microsoft.com/download/2/7/A/27AF1BE6-DD20-4CB4-B154-EBAB8A7D4A7E/officedeploymenttool_15330-20102.exe"
        $odtPath = Join-Path $env:TEMP "ODT.exe"
        $script:tempFiles += $odtPath
        
        try {
            Invoke-WebRequest -Uri $odtUrl -OutFile $odtPath
            Write-SuccessMessage -msg "Office Deployment Tool downloaded successfully"
        } catch {
            Write-Log "Failed to download Office Deployment Tool: $($_.Exception.Message)" -Level Error
            Write-ErrorMessage -msg "Failed to download Office Deployment Tool"
            return $false
        }

        # Extract ODT
        Write-SystemMessage -msg1 "- Extracting Office Deployment Tool..."
        Write-Log "Extracting Office Deployment Tool..."
        Start-Process -FilePath $odtPath -ArgumentList "/quiet /extract:$env:TEMP\ODT" -Wait

        # Install Office
        Write-SystemMessage -msg1 "- Installing Microsoft Office..."
        Write-Log "Installing Microsoft Office..."
        $setupPath = Join-Path $env:TEMP "ODT\setup.exe"
        Start-Process -FilePath $setupPath -ArgumentList "/configure `"$configPath`"" -Wait

        # Activate Office if license key provided
        if ($OfficeConfig.LicenseKey) {
            Write-SystemMessage -msg1 "- Activating Microsoft Office..."
            Write-Log "Activating Microsoft Office..."
            
            $osppPath = "${env:ProgramFiles(x86)}\Microsoft Office\Office16\OSPP.VBS"
            if (Test-Path $osppPath) {
                try {
                    cscript $osppPath /inpkey:$($OfficeConfig.LicenseKey)
                    Start-Sleep -Seconds 2
                    cscript $osppPath /act
                    Write-SuccessMessage -msg "Microsoft Office activated successfully"
                } catch {
                    Write-Log "Failed to activate Office: $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to activate Office"
                }
            } else {
                Write-Log "Office activation path not found: $osppPath" -Level Warning
                Write-ErrorMessage -msg "Office activation path not found"
            }
        }

        Write-Log "Office configuration completed successfully"
        Write-SuccessMessage -msg "Microsoft Office installation completed"
        return $true
    }
    catch {
        Write-Log "Error configuring Office: $($_.Exception.Message)" -Level Error
        Write-ErrorMessage -msg "Failed to configure Microsoft Office"
        return $false
    }
}

function Set-ThemeConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$ThemeConfig
    )
    
    try {
        Write-SystemMessage -Title "Configuring Theme Settings"

        # Dark Mode
        if ($ThemeConfig.DarkMode -eq 'true') {
            Write-SystemMessage -msg1 "- Enabling dark mode..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 0
                Write-SuccessMessage -msg "Dark mode enabled"
            } catch {
                Write-Log "Failed to enable dark mode: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to enable dark mode"
            }
        }

        # Transparency Effects
        if ($ThemeConfig.TransparencyEffects -eq 'false') {
            Write-SystemMessage -msg1 "- Disabling transparency effects..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Type DWord -Value 0
                Write-SuccessMessage -msg "Transparency effects disabled"
            } catch {
                Write-Log "Failed to disable transparency effects: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable transparency effects"
            }
        }

        # Wallpaper
        if ($ThemeConfig.WallpaperPath) {
            Write-SystemMessage -msg1 "- Setting wallpaper from: " -msg2 $ThemeConfig.WallpaperPath
            try {
                $wallpaperPath = $ThemeConfig.WallpaperPath
                if ($wallpaperPath -match "^https?://") {
                    $tempWallpaperPath = "$env:TEMP\wallpaper.jpg"
                    Write-Log "Downloading wallpaper from: $wallpaperPath"
                    Invoke-WebRequest -Uri $wallpaperPath -OutFile $tempWallpaperPath
                    $wallpaperPath = $tempWallpaperPath
                    $script:tempFiles += $tempWallpaperPath
                }

                $setwallpapersrc = @"
using System.Runtime.InteropServices;

public class Wallpaper
{
    public const int SetDesktopWallpaper = 20;
    public const int UpdateIniFile = 0x01;
    public const int SendWinIniChange = 0x02;
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
    public static void SetWallpaper(string path)
    {
        SystemParametersInfo(SetDesktopWallpaper, 0, path, UpdateIniFile | SendWinIniChange);
    }
}
"@
                Add-Type -TypeDefinition $setwallpapersrc
                [Wallpaper]::SetWallpaper($wallpaperPath)
                
                Write-Log "Wallpaper set successfully."
                Write-SuccessMessage -msg "Wallpaper set successfully"
            }
            catch {
                Write-Log "Error setting wallpaper: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to set wallpaper"
            }
        }

        # Desktop Icon Size
        if ($ThemeConfig.DesktopIconSize) {
            Write-SystemMessage -msg1 "- Setting desktop icon size..."
            Write-Log "Setting desktop icon size..."
            try {
                $sizeValue = switch ($ThemeConfig.DesktopIconSize) {
                    "Small" { 0 }
                    "Medium" { 1 }
                    "Large" { 2 }
                    default {
                        Write-Log "Invalid desktop icon size specified: $($ThemeConfig.DesktopIconSize). Using Medium." -Level Warning
                        1
                    }
                }
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop" -Name "IconSize" -Type DWord -Value $sizeValue
                Write-SuccessMessage -msg "Desktop icon size set successfully"
            } catch {
                Write-Log "Failed to set desktop icon size: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to set desktop icon size"
            }
        }

        Write-Log "Theme configuration completed successfully"
        return $true
    }
    catch {
        Write-Log "Error configuring theme settings: $($_.Exception.Message)" -Level Error
        Write-ErrorMessage -msg "Failed to configure theme settings"
        return $false
    }
}

function Set-TweaksConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$TweaksConfig
    )
    
    try {
        Write-SystemMessage -Title "Applying System Tweaks"

        # Classic Right-Click Menu
        if ($TweaksConfig.ClassicRightClickMenu -eq 'true') {
            Write-Log "Enabling classic right-click menu..."
            Set-RegistryModification -Action add -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(Default)" -Type String -Value ""
        }

        # God Mode
        if ($TweaksConfig.EnableGodMode -eq 'true') {
            Write-Log "Creating God Mode folder..."
            $godModePath = Join-Path $env:USERPROFILE "Desktop\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"
            if (-not (Test-Path $godModePath)) {
                New-Item -Path $godModePath -ItemType Directory -Force
            }
        }

        Write-Log "System tweaks applied successfully"
        return $true
    }
    catch {
        Write-Log "Error applying system tweaks: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Set-NetworkConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$NetworkConfig
    )
    
    try {
        Write-SystemMessage -Title "Configuring Network Settings"

        # Network Discovery
        if ($NetworkConfig.NetworkDiscovery -eq 'true') {
            Write-SystemMessage -msg1 "- Enabling Network Discovery..."
            Write-Log "Enabling Network Discovery..."
            try {
                Get-NetFirewallRule -Group "@FirewallAPI.dll,-32752" | Set-NetFirewallRule -Profile Private -Enabled True
                Set-NetFirewallRule -Name "FPS-SMB-In-TCP" -Enabled True
                Write-SuccessMessage -msg "Network Discovery enabled"
            } catch {
                Write-Log "Failed to enable Network Discovery: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to enable Network Discovery"
            }
        }

        # File and Printer Sharing
        if ($NetworkConfig.FileAndPrinterSharing -eq 'true') {
            Write-SystemMessage -msg1 "- Enabling File and Printer Sharing..."
            Write-Log "Enabling File and Printer Sharing..."
            try {
                Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled True
                Write-SuccessMessage -msg "File and Printer Sharing enabled"
            } catch {
                Write-Log "Failed to enable File and Printer Sharing: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to enable File and Printer Sharing"
            }
        }

        # Network Drives
        if ($NetworkConfig.NetworkDrives) {
            foreach ($drive in $NetworkConfig.NetworkDrives.Drive) {
                Write-SystemMessage -msg1 "- Mapping network drive $($drive.Letter) to: " -msg2 $drive.Path
                Write-Log "Mapping network drive $($drive.Letter) to $($drive.Path)"
                
                try {
                    # Remove existing drive mapping if it exists
                    if (Test-Path "$($drive.Letter):") {
                        Remove-PSDrive -Name $drive.Letter -Force -ErrorAction SilentlyContinue
                        net use "$($drive.Letter):" /delete /y
                    }

                    # Test network path accessibility
                    if (Test-Path -Path $drive.Path) {
                        New-PSDrive -Name $drive.Letter -PSProvider FileSystem -Root $drive.Path -Persist -ErrorAction Stop
                        Write-SuccessMessage -msg "Network drive $($drive.Letter): mapped successfully"
                    } else {
                        Write-Log "Network path not accessible: $($drive.Path)" -Level Warning
                        Write-ErrorMessage -msg "Network path not accessible: $($drive.Path)"
                    }
                } catch {
                    Write-Log "Failed to map drive $($drive.Letter): $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to map network drive $($drive.Letter):"
                }
            }
        }

        Write-Log "Network configuration completed successfully"
        return $true
    }
    catch {
        Write-Log "Error configuring network settings: $($_.Exception.Message)" -Level Error
        Write-ErrorMessage -msg "Failed to configure network settings"
        return $false
    }
}

function Set-FileOperations {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$FileConfig
    )
    
    try {
        Write-SystemMessage -Title "Performing File Operations"

        # Copy Operations
        if ($FileConfig.Copy) {
            foreach ($file in $FileConfig.Copy.File) {
                Write-SystemMessage -msg1 "- Copying file from: " -msg2 $file.Source
                Write-Log "Copying file from $($file.Source) to $($file.Destination)"
                
                try {
                    # Create destination directory if it doesn't exist
                    $destinationDir = Split-Path -Parent $file.Destination
                    if (-not (Test-Path $destinationDir)) {
                        New-Item -Path $destinationDir -ItemType Directory -Force | Out-Null
                        Write-Log "Created destination directory: $destinationDir"
                    }

                    # Copy file
                    if (Test-Path $file.Source) {
                        Copy-Item -Path $file.Source -Destination $file.Destination -Force
                        Write-SuccessMessage -msg "File copied successfully"
                    } else {
                        Write-Log "Source file not found: $($file.Source)" -Level Warning
                        Write-ErrorMessage -msg "Source file not found: $($file.Source)"
                    }
                } catch {
                    Write-Log "Failed to copy file: $($_.Exception.Message)" -Level Warning
                    Write-ErrorMessage -msg "Failed to copy file"
                }
            }
        }

        # Delete Operations
        if ($FileConfig.Delete) {
            foreach ($file in $FileConfig.Delete.File) {
                Write-SystemMessage -msg1 "- Deleting file: " -msg2 $file
                Write-Log "Deleting file: $file"
                
                try {
                    if (Test-Path $file) {
                        Remove-Item -Path $file -Force
                        Write-SuccessMessage -msg "File deleted successfully"
                    } else {
                        Write-Log "File not found for deletion: $file" -Level Warning
                        Write-ErrorMessage -msg "File not found: $file"
                    }
                } catch {
                    Write-Log "Failed to delete file: $($_.Exception.Message)" -Level Warning
                    Write-ErrorMessage -msg "Failed to delete file"
                }
            }
        }

        Write-Log "File operations completed successfully"
        return $true
    }
    catch {
        Write-Log "Error performing file operations: $($_.Exception.Message)" -Level Error
        Write-ErrorMessage -msg "Failed to perform file operations"
        return $false
    }
}

function Set-Shortcuts {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$ShortcutConfig
    )
    
    try {
        Write-SystemMessage -Title "Creating Shortcuts"

        foreach ($shortcut in $ShortcutConfig.Shortcut) {
            Write-SystemMessage -msg1 "- Creating shortcut: " -msg2 $shortcut.Name
            Write-Log "Creating shortcut: $($shortcut.Name) -> $($shortcut.Target)"

            try {
                # Determine shortcut location
                $shortcutLocation = switch ($shortcut.Location) {
                    "Desktop" { [Environment]::GetFolderPath("Desktop") }
                    "StartMenu" { [Environment]::GetFolderPath("StartMenu") }
                    "Programs" { [Environment]::GetFolderPath("Programs") }
                    default { 
                        Write-Log "Invalid shortcut location specified: $($shortcut.Location). Using Desktop." -Level Warning
                        [Environment]::GetFolderPath("Desktop") 
                    }
                }

                $shortcutPath = Join-Path $shortcutLocation "$($shortcut.Name).lnk"

                # Create WScript Shell object
                $WScriptShell = New-Object -ComObject WScript.Shell
                $Shortcut = $WScriptShell.CreateShortcut($shortcutPath)

                # Set shortcut properties
                $Shortcut.TargetPath = $shortcut.Target
                
                if ($shortcut.Arguments) {
                    Write-Log "Setting shortcut arguments: $($shortcut.Arguments)"
                    $Shortcut.Arguments = $shortcut.Arguments
                }
                
                if ($shortcut.WorkingDirectory) {
                    Write-Log "Setting working directory: $($shortcut.WorkingDirectory)"
                    $Shortcut.WorkingDirectory = $shortcut.WorkingDirectory
                }
                
                if ($shortcut.IconLocation) {
                    Write-Log "Setting icon location: $($shortcut.IconLocation)"
                    $Shortcut.IconLocation = $shortcut.IconLocation
                }

                # Save shortcut
                $Shortcut.Save()
                Write-SuccessMessage -msg "Shortcut created successfully: $($shortcut.Name)"

            } catch {
                Write-Log "Failed to create shortcut $($shortcut.Name): $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to create shortcut: $($shortcut.Name)"
            } finally {
                if ($WScriptShell) {
                    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($WScriptShell) | Out-Null
                }
            }
        }

        Write-Log "Shortcuts creation completed successfully"
        return $true
    }
    catch {
        Write-Log "Error creating shortcuts: $($_.Exception.Message)" -Level Error
        Write-ErrorMessage -msg "Failed to create shortcuts"
        return $false
    }
}

# Main Execution Block
try {

    Clear-Host
    Set-SystemCheckpoint  # This is missing
    Write-SystemMessage -Title "Starting Winforge Configuration"

    # Verify running as administrator
    if (-not (Test-AdminPrivileges)) {
        throw "This script requires administrative privileges"
    }

    # Initialize configuration status tracking
    $configStatus = @{}

    # Load and validate configuration
    $configXML = Get-XmlConfig -Path $ConfigPath

    # System Configuration
    if ($configXML.System) {
        $configStatus['System'] = Set-SystemConfiguration -SystemConfig $configXML.System
    }

    # Environment Variables
    if ($configXML.EnvironmentVariables) {
        $configStatus['Environment'] = Set-EnvironmentVariables -EnvConfig $configXML.EnvironmentVariables
    }

    # Windows Activation
    if ($configXML.Activation) {
        $configStatus['Activation'] = Set-WindowsActivation -ActivationConfig $configXML.Activation
    }

    # Windows Update
    if ($configXML.WindowsUpdate) {
        $configStatus['WindowsUpdate'] = Set-WindowsUpdateConfiguration -UpdateConfig $configXML.WindowsUpdate
    }

    # Taskbar
    if ($configXML.Taskbar) {
        $configStatus['Taskbar'] = Set-TaskbarConfiguration -TaskbarConfig $configXML.Taskbar
    }

    # Privacy
    if ($configXML.Privacy) {
        $configStatus['Privacy'] = Set-PrivacyConfiguration -PrivacyConfig $configXML.Privacy
    }

    # Security
    if ($configXML.Security) {
        $configStatus['Security'] = Set-SecurityConfiguration -SecurityConfig $configXML.Security
    }

    # Applications
    if ($configXML.Applications) {
        $configStatus['Applications'] = Install-Applications -AppConfig $configXML.Applications
    }

    # Fonts
    if ($configXML.Fonts) {
        $configStatus['Fonts'] = Install-Fonts -FontConfig $configXML.Fonts
    }

    # Power
    if ($configXML.Power) {
        $configStatus['Power'] = Set-PowerConfiguration -PowerConfig $configXML.Power
    }

    # Registry
    if ($configXML.Registry) {
        $configStatus['Registry'] = Set-RegistryEntries -RegistryConfig $configXML.Registry
    }

    # Windows Features
    if ($configXML.WindowsFeatures) {
        $configStatus['WindowsFeatures'] = Set-WindowsFeaturesConfiguration -FeaturesConfig $configXML.WindowsFeatures
    }

    # Google Configuration
    if ($configXML.Google) {
        $configStatus['Google'] = Set-GoogleConfiguration -GoogleConfig $configXML.Google
    }

    # Office Configuration
    if ($configXML.Office) {
        $configStatus['Office'] = Set-OfficeConfiguration -OfficeConfig $configXML.Office
    }

    # Theme Configuration
    if ($configXML.Theme) {
        $configStatus['Theme'] = Set-ThemeConfiguration -ThemeConfig $configXML.Theme
    }

    # System Tweaks
    if ($configXML.Tweaks) {
        $configStatus['Tweaks'] = Set-TweaksConfiguration -TweaksConfig $configXML.Tweaks
    }

    # Network Configuration
    if ($configXML.Network) {
        $configStatus['Network'] = Set-NetworkConfiguration -NetworkConfig $configXML.Network
    }

    # File Operations
    if ($configXML.Files) {
        $configStatus['Files'] = Set-FileOperations -FileConfig $configXML.Files
    }

    # Shortcuts
    if ($configXML.Shortcuts) {
        $configStatus['Shortcuts'] = Set-Shortcuts -ShortcutConfig $configXML.Shortcuts
    }

    # Display configuration status
    Write-SystemMessage -Title "Configuration Status"
    foreach ($item in $configStatus.GetEnumerator()) {
        $status = if ($item.Value) { "Success" } else { "Failed" }
        $color = if ($item.Value) { "Green" } else { "Red" }
        Write-Host "$($item.Key): " -NoNewline
        Write-Host $status -ForegroundColor $color
    }

    # Check if any configurations failed
    if ($configStatus.Values -contains $false) {
        Write-ErrorMessage -msg "Some configurations failed. Please check the logs for details."
        exit 1
    }
    else {
        Write-SuccessMessage -msg "All configurations completed successfully"
        if ($script:restartRequired) {
            Write-SystemMessage -Title "Restart Required" -msg1 "Some changes require a system restart to take effect."
            $restart = Read-Host "Would you like to restart now? (Y/N)"
            if ($restart -eq 'Y') {
                Restart-Computer -Force
            }
        }
    }
}
catch {
    Write-Log "$($_.Exception.Message)" -Level Error
    Write-ErrorMessage -msg "$($_.Exception.Message)"
    exit 1
}
finally {
    Remove-TempFiles
}