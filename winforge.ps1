<#
    .SYNOPSIS
    This script automates the configuration of a Windows system using parameters specified in an INI file.

    .PARAMETER config
    The path to the configuration file. This can be a local path or a URL to an INI file containing the necessary configuration parameters.

    .DESCRIPTION
    This script performs a series of system configurations based on the values specified in the provided INI file. 
    The configurations include setting the computer name, locale, timezone, installing applications, setting wallpapers and lock screens, 
    modifying registry entries, configuring network settings, power settings, software updates, security settings, environment variables, 
    importing tasks into Task Scheduler, installing Google Chrome Enterprise, Google Credential Provider for Windows (GCPW), Google Drive, and activating Windows.

    .EXAMPLE
    .\install.ps1 -config="C:\Path\To\Config.ini"

    .EXAMPLE
    .\install.ps1 -config="https://www.github.com/Acme/Winforge/config.ini"

    Ensure that the script is run with administrative privileges to apply the configurations successfully.

#>

# Define paths and initialize variables
param (
    [Parameter(Mandatory=$true)]
    [string]$configFile
)

$logFile = Join-Path -Path $env:SYSTEMDRIVE -ChildPath "winforge-configuration.log"
$config = @{}

# Function to log messages
function Write-Log {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $message"
    Write-Output $logMessage | Out-File -Append -FilePath $logFile
}

# Function to read INI file
function Read-IniFile {
    param (
        [string]$path
    )
    $ini = @{}
    $section = ""
    Get-Content $path | ForEach-Object {
        $_ = $_.Trim()
        if ($_ -match '^\[(.+)\]$') {
            $section = $matches[1].Trim()
            $ini[$section] = @{}
        } elseif ($_ -match '^(.*)=(.*)$') {
            $name, $value = $matches[1].Trim(), $matches[2].Trim()
            $value = $value.Trim('"')  # Remove surrounding quotes
            $ini[$section][$name] = $value
        }
    }
    return $ini
}

# Function to get configuration value by key and section
function Get-ConfigValue {
    param (
        [string]$section,
        [string]$key
    )
    if ($config[$section] -and $config[$section][$key]) {
        return $config[$section][$key]
    } else {
        return $null
    }
}

# Function to validate required keys for sections
function Validate-RequiredKeys {
    param (
        [string]$section,
        [string[]]$requiredKeys
    )
    foreach ($key in $requiredKeys) {
        if (-not $config[$section][$key]) {
            Write-Log "Missing required key '$key' in section '$section'"
            return $false
        }
    }
    return $true
}

# Function to set computer name
function Set-ComputerName {
    try {
        $computerName = Get-ConfigValue -section "System" -key "ComputerName"
        if ($computerName) {
            Write-Log "Setting computer name to: $computerName"
            Rename-Computer -NewName $computerName -Force
            Write-Log "Computer name set successfully."
        } else {
            Write-Log "Computer name not set. Missing configuration."
        }
    } catch {
        Write-Log "Error setting computer name: $($_.Exception.Message)"
        exit 1
    }
}

# Function to set locale
function Set-Locale {
    try {
        $locale = Get-ConfigValue -section "System" -key "Locale"
        if ($locale) {
            Write-Log "Setting locale to: $locale"
            Set-WinUILanguageOverride -Language $locale
            Set-WinSystemLocale -SystemLocale $locale
            Set-WinUserLanguageList $locale -Force
            Write-Log "Locale set successfully."
        } else {
            Write-Log "Locale not set. Missing configuration."
        }
    } catch {
        Write-Log "Error setting locale: $($_.Exception.Message)"
        exit 1
    }
}

# Function to set timezone
function Set-SystemTimezone {
    try {
        $timezone = Get-ConfigValue -section "System" -key "Timezone"
        if ($timezone) {
            $currentTZ = (Get-TimeZone).Id
            if ($currentTZ -ne $timezone) {
                Write-Log "Setting timezone to: $timezone"
                Set-TimeZone -Id $timezone
                $currentTZ = (Get-TimeZone).Id
                if ($currentTZ -eq $timezone) {
                    Write-Log "Timezone set successfully to: $timezone"
                } else {
                    Write-Log "Failed to set timezone to: $timezone"
                }
            } else {
                Write-Log "Timezone is already set to: $timezone"
            }
        } else {
            Write-Log "Timezone not set. Missing configuration."
        }
    } catch {
        Write-Log "Error setting timezone: $($_.Exception.Message)"
        exit 1
    }
}

# Function to install applications via winget
function Install-Applications {
    try {
        $apps = Get-ConfigValue -section "Applications" -key "Apps"
        if ($apps) {
            $appList = $apps -split ','
            Write-Log "Installing applications: $apps"
            foreach ($app in $appList) {
                try {
                    $escapedApp = [regex]::Escape($app)
                    $isAppInstalled = winget list | Select-String -Pattern $escapedApp
                    if ($isAppInstalled) {
                        Write-Log "Application $app is already installed. Skipping installation."
                    } else {
                        winget install $app -e --id $app -h
                        Write-Log "Application installed: $app"
                    }
                } catch {
                    Write-Log "Error installing application ${app}: $($_.Exception.Message)"
                }
            }
            Write-Log "Applications installation completed."
        } else {
            Write-Log "No applications to install. Missing configuration."
        }
    } catch {
        Write-Log "Error processing applications: $($_.Exception.Message)"
        exit 1
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

    # Check if the partial font name exists in the filtered list
    $isFontInstalled = $InstalledFonts | Where-Object { $_.FontName -like "*$FontName*" }

    return $isFontInstalled
}


# Function to install Google fonts
function Install-Fonts {
    try {
        $fonts = Get-ConfigValue -section "Fonts" -key "Fonts"
        if ($fonts) {
            $fontsList = $fonts -split ','
            $ProgressPreference = 'SilentlyContinue'
            $tempDownloadFolder = "$env:TEMP\google_fonts"

            New-Item -Path $tempDownloadFolder -ItemType Directory -Force | Out-Null

            foreach ($fontName in $fontsList) {
                # Check if the font is already installed
                $isFontInstalled = Test-FontInstalled -FontName $fontName

                if ($isFontInstalled) {
                    Write-Log "Font ${fontName} is already installed. Skipping download and installation."
                    continue
                }

                $downloadedFontFolder = "$tempDownloadFolder\$fontName"

                Write-Log "Downloading & Installing ${fontName} from Google Fonts. Please wait..."

                Invoke-WebRequest -UseBasicParsing -Uri "https://fonts.google.com/download?family=$fontName" -OutFile "$tempDownloadFolder\$fontName.zip"

                try {
                    Expand-Archive -Path "$tempDownloadFolder\$fontName.zip" -DestinationPath $downloadedFontFolder -Force | Out-Null
                } catch {
                    Write-Log "Error downloading or extracting font $fontName: $($_.Exception.Message)"
                    continue
                }
                
                $allFonts = Get-ChildItem -Path $downloadedFontFolder -Include *.fon, *.otf, *.ttc, *.ttf -Recurse
                
                try {
                    foreach ($font in $allFonts) {
                        $fontDestination = Join-Path -Path $env:windir\Fonts -ChildPath $font.Name
                                
                        Copy-Item -Path $font.FullName -Destination $fontDestination -Force
                        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Fonts" -Name $font.BaseName -Value $font.Name -PropertyType String -Force | Out-Null
                    }
                    Write-Log "Font installed: ${fontName}"
                } catch {
                    Write-Log "Error installing font ${fontName}: $($_.Exception.Message)"
                    exit 1
                }

                # Clean up the extracted files and the zip file
                Remove-Item -Path $downloadedFontFolder -Recurse -Force
            }

            Write-Log "All fonts installed successfully."
        } else {
            Write-Log "No fonts to install. Missing configuration."
        }
    } catch {
        Write-Log "Error installing fonts: $($_.Exception.Message)"
        exit 1
    }
}


# Function to install Microsoft Office
function Install-Office {
    try {
        $requiredKeys = @("LicenseKey", "ProductID", "LanguageID", "UpdatesEnabled", "DisplayLevel", "SetupReboot", "Channel", "OfficeClientEdition")
        if (-not (Validate-RequiredKeys -section "Office" -requiredKeys $requiredKeys)) {
            Write-Log "Skipping Office installation due to missing keys."
            return
        }

        $licenseKey = Get-ConfigValue -section "Office" -key "LicenseKey"
        $productID = Get-ConfigValue -section "Office" -key "ProductID"
        $languageID = Get-ConfigValue -section "Office" -key "LanguageID"
        $updatesEnabled = Get-ConfigValue -section "Office" -key "UpdatesEnabled"
        $displayLevel = Get-ConfigValue -section "Office" -key "DisplayLevel"
        $setupReboot = Get-ConfigValue -section "Office" -key "SetupReboot"
        $channel = Get-ConfigValue -section "Office" -key "Channel"
        $officeClientEdition = Get-ConfigValue -section "Office" -key "OfficeClientEdition"

        $odtUrl = "https://download.microsoft.com/download/2/7/A/27AF1BE6-DD20-4CB4-B154-EBAB8A7D4A7E/officedeploymenttool_16731-20398.exe"
        $odtPath = $env:TEMP
        $odtFile = "$odtPath/ODTSetup.exe"
        $configurationXMLFile = "$odtPath\configuration.xml"

        Write-Log "Downloading Office Deployment Tool..."
        Invoke-WebRequest -Uri $odtUrl -OutFile $odtFile

        Write-Log "Creating configuration XML file..."
        @"
<Configuration>
  <Add OfficeClientEdition="$officeClientEdition" Channel="$channel">
    <Product ID="$productID">
      <Language ID="$languageID" />
    </Product>
  </Add>
  <Updates Enabled="$updatesEnabled" />
  <Display Level="$displayLevel" AcceptEULA="TRUE" />
  <Property Name="AUTOACTIVATE" Value="1" />
  <Property Name="PIDKEY" Value="$licenseKey" />
  <Setting Id="SETUP_REBOOT" Value="$setupReboot" />
</Configuration>
"@ | Out-File $configurationXMLFile

        Write-Log "Running the Office Deployment Tool..."
        Start-Process $odtFile -ArgumentList "/quiet /extract:$odtPath" -Wait

        Write-Log "Downloading and installing Microsoft Office..."
        Start-Process "$odtPath\Setup.exe" -ArgumentList "/configure `"$configurationXMLFile`"" -Wait -PassThru

        Write-Log "Microsoft Office installation completed successfully."

        # Clean up the extracted files and the zip file
        Remove-Item $odtFile
        Remove-Item $configurationXMLFile
    } catch {
        Write-Log "Error installing Microsoft Office: $($_.Exception.Message)"
        exit 1
    }
}

# Function to set wallpaper
function Set-Wallpaper {
    try {
        $wallpaperPath = Get-ConfigValue -section "Theme" -key "WallpaperPath"
        if ($wallpaperPath) {
            # Check if the path is a URL
            if ($wallpaperPath -match "^https?://") {
                $tempWallpaperPath = "$env:TEMP\wallpaper.jpg"
                Write-Log "Downloading wallpaper from: $wallpaperPath"
                Invoke-WebRequest -Uri $wallpaperPath -OutFile $tempWallpaperPath
                $wallpaperPath = $tempWallpaperPath
            }

            $registryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion"
            $registryKey = "PersonalizationCSP"
            $registryFullPath = "$registryPath\$registryKey"

            if (!(Test-Path $registryFullPath)) {
                New-Item -Path "$registryPath" -Name "$registryKey"
            }

            $registryItems = @(
                [pscustomobject]@{ Name = "DesktopImagePath"; Value = $wallpaperPath; Type = "String" }
                [pscustomobject]@{ Name = "DesktopImageUrl"; Value = $wallpaperPath; Type = "String" }
                [pscustomobject]@{ Name = "DesktopImageStatus"; Value = "1"; Type = "DWORD" }
            )

            foreach ($item in $registryItems) {
                New-ItemProperty -Path $registryFullPath -Name $item.Name -Value $item.Value -PropertyType $item.Type -Force
            }

            Stop-Process -name explorer
            Start-Process explorer

            Write-Log "Wallpaper set successfully."
        } else {
            Write-Log "Wallpaper not set. Missing configuration."
        }
    } catch {
        Write-Log "Error setting wallpaper: $($_.Exception.Message)"
        exit 1
    }
}


# Function to set lock screen image
function Set-LockScreenImage {
    try {
        $lockScreenPath = Get-ConfigValue -section "Theme" -key "LockScreenPath"
        if ($lockScreenPath) {
            # Check if the path is a URL
            if ($lockScreenPath -match "^https?://") {
                $tempLockScreenPath = "$env:TEMP\lockscreen.jpg"
                Write-Log "Downloading lock screen image from: $lockScreenPath"
                Invoke-WebRequest -Uri $lockScreenPath -OutFile $tempLockScreenPath
                $lockScreenPath = $tempLockScreenPath
            }

            $registryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion"
            $registryKey = "PersonalizationCSP"
            $registryFullPath = "$registryPath\$registryKey"

            if (!(Test-Path $registryFullPath)) {
                New-Item -Path "$registryPath" -Name "$registryKey"
            }

            $registryItems = @(
                [pscustomobject]@{ Name = "LockScreenImagePath"; Value = $lockScreenPath; Type = "String" }
                [pscustomobject]@{ Name = "LockScreenImageUrl"; Value = $lockScreenPath; Type = "String" }
                [pscustomobject]@{ Name = "LockScreenImageStatus"; Value = "1"; Type = "DWORD" }
            )

            foreach ($item in $registryItems) {
                New-ItemProperty -Path $registryFullPath -Name $item.Name -Value $item.Value -PropertyType $item.Type -Force
            }

            Stop-Process -name explorer
            Start-Process explorer

            Write-Log "Lock screen image set successfully."
        } else {
            Write-Log "Lock screen image not set. Missing configuration."
        }
    } catch {
        Write-Log "Error setting lock screen image: $($_.Exception.Message)"
        exit 1
    }
}


# Function to add registry entries
function Add-RegistryEntries {
    try {
        $registrySection = $config["RegistryAdd"]
        if ($registrySection) {
            foreach ($entry in $registrySection.Values) {
                $parts = $entry -split ","
                if ($parts.Length -ne 4) {
                    Write-Log "Invalid registry entry format: $entry"
                    continue
                }

                $keyName = $parts[0].Trim()
                $value = $parts[1].Trim()
                $type = $parts[2].Trim()
                $data = $parts[3].Trim()

                Write-Log "Adding registry entry: ${keyName}, ${value}, ${type}, ${data}"
                cmd.exe /c "reg add `"$keyName`" /v `"$value`" /t $type /d `"$data`" /f"
            }
            Write-Log "Registry entries added successfully."
        } else {
            Write-Log "No registry entries to add. Missing configuration."
        }
    } catch {
        Write-Log "Error adding registry entries: $($_.Exception.Message)"
        exit 1
    }
}


# Function to remove registry entries
function Remove-RegistryEntries {
    try {
        $registrySection = $config["RegistryRemove"]
        if ($registrySection) {
            foreach ($entry in $registrySection.Values) {
                $parts = $entry -split ","
                if ($parts.Length -ne 2) {
                    Write-Log "Invalid registry entry format: $entry"
                    continue
                }

                $keyName = $parts[0].Trim()
                $value = $parts[1].Trim()

                Write-Log "Removing registry entry: ${keyName}, ${value}"
                cmd.exe /c "reg delete `"$keyName`" /v `"$value`" /f"
            }
            Write-Log "Registry entries removed successfully."
        } else {
            Write-Log "No registry entries to remove. Missing configuration."
        }
    } catch {
        Write-Log "Error removing registry entries: $($_.Exception.Message)"
        exit 1
    }
}


# Helper function to convert subnet mask to prefix length
function Convert-SubnetMaskToPrefixLength {
    param (
        [string]$subnetMask
    )
    $binaryMask = $subnetMask.Split('.') | ForEach-Object { [Convert]::ToString($_, 2).PadLeft(8, '0') } -join ''
    return ($binaryMask -split '0')[0].Length
}

# Function to configure network settings
function Set-NetworkSettings {
    try {
        $ipAddress = Get-ConfigValue -section "Network" -key "IPAddress"
        $subnetMask = Get-ConfigValue -section "Network" -key "SubnetMask"
        $gateway = Get-ConfigValue -section "Network" -key "Gateway"
        $dns1 = Get-ConfigValue -section "Network" -key "DNS1"
        $dns2 = Get-ConfigValue -section "Network" -key "DNS2"

        if ($ipAddress -and $subnetMask -and $gateway -and $dns1) {
            $prefixLength = Convert-SubnetMaskToPrefixLength -subnetMask $subnetMask
            Write-Log "Configuring network settings..."
            New-NetIPAddress -IPAddress $ipAddress -PrefixLength $prefixLength -DefaultGateway $gateway
            Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses ($dns1, $dns2)
            Write-Log "Network settings configured successfully."
        } else {
            Write-Log "Network settings not set. Missing configuration."
        }
    } catch {
        Write-Log "Error configuring network settings: $($_.Exception.Message)"
        exit 1
    }
}


# Function to configure power settings
function Set-PowerSettings {
    try {
        $powerPlan = Get-ConfigValue -section "PowerSettings" -key "PowerPlan"
        $sleepTimeout = Get-ConfigValue -section "PowerSettings" -key "SleepTimeout"
        $hibernateTimeout = Get-ConfigValue -section "PowerSettings" -key "HibernateTimeout"

        if ($powerPlan) {
            Write-Log "Configuring power settings..."
            powercfg -setactive $powerPlan
            if ($sleepTimeout) {
                powercfg -change -monitor-timeout-ac $sleepTimeout
            }
            if ($hibernateTimeout) {
                powercfg -change -standby-timeout-ac $hibernateTimeout
            }
            Write-Log "Power settings configured successfully."
        } else {
            Write-Log "Power settings not set. Missing configuration."
        }
    } catch {
        Write-Log "Error configuring power settings: $($_.Exception.Message)"
        exit 1
    }
}

# Function to configure software updates
function Set-SoftwareUpdates {
    try {
        $autoUpdatesEnabled = Get-ConfigValue -section "WindowsUpdate" -key "AutoUpdatesEnabled"

        if ($autoUpdatesEnabled) {
            Write-Log "Configuring software updates..."
            if ($autoUpdatesEnabled -eq "TRUE") {
                Write-Log "Enabling automatic updates..."
                Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -Value 4
                Write-Log "Automatic updates enabled."
            } else {
                Write-Log "Disabling automatic updates..."
                Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -Value 1
                Write-Log "Automatic updates disabled."
            }
        } else {
            Write-Log "Software updates not configured. Missing configuration."
        }
    } catch {
        Write-Log "Error configuring software updates: $($_.Exception.Message)"
        exit 1
    }
}

# Function to configure security settings
function Set-SecuritySettings {
    try {
        $uacLevel = Get-ConfigValue -section "SecuritySettings" -key "UACLevel"
        $windowsDefenderEnabled = Get-ConfigValue -section "SecuritySettings" -key "WindowsDefenderEnabled"

        if ($uacLevel) {
            Write-Log "Setting UAC level to: $uacLevel"
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value $uacLevel
        } else {
            Write-Log "UAC level not set. Missing configuration."
        }

        if ($windowsDefenderEnabled) {
            if ($windowsDefenderEnabled -eq "TRUE") {
                Write-Log "Enabling Windows Defender..."
                Set-MpPreference -DisableRealtimeMonitoring $false
                Write-Log "Windows Defender enabled."
            } else {
                Write-Log "Disabling Windows Defender..."
                Set-MpPreference -DisableRealtimeMonitoring $true
                Write-Log "Windows Defender disabled."
            }
        } else {
            Write-Log "Windows Defender not configured. Missing configuration."
        }
    } catch {
        Write-Log "Error configuring security settings: $($_.Exception.Message)"
        exit 1
    }
}

# Function to set environment variables
function Set-EnvironmentVariables {
    try {
        $environmentVariables = $config["EnvironmentVariables"]
        if ($environmentVariables) {
            foreach ($key in $environmentVariables.Keys) {
                $value = $environmentVariables[$key]
                Write-Log "Setting environment variable: $key=$value"
                [System.Environment]::SetEnvironmentVariable($key, $value, "Machine")
            }
            Write-Log "Environment variables set successfully."
        } else {
            Write-Log "No environment variables to set. Missing configuration."
        }
    } catch {
        Write-Log "Error setting environment variables: $($_.Exception.Message)"
        exit 1
    }
}

# Function to check if the current user is an admin
function Test-IsAdmin {
    $admin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match 'S-1-5-32-544')
    return $admin
}

# Function to test if a program is installed
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

# Function to install Chrome Enterprise
function Install-ChromeEnterprise {
    $chromeFileName = if ([Environment]::Is64BitOperatingSystem) {
        'googlechromestandaloneenterprise64.msi'
    }
    else {
        'googlechromestandaloneenterprise.msi'
    }

    $chromeUrl = "https://dl.google.com/chrome/install/$chromeFileName"
    
    if (Test-ProgramInstalled 'Google Chrome') {
        Write-Log "Chrome Enterprise already installed. Skipping..."
    } 
    else {
        Write-Log "Downloading Chrome from $chromeUrl"
        Invoke-WebRequest -Uri $chromeUrl -OutFile "$env:TEMP\$chromeFileName"

        try {
            $arguments = "/i `"$env:TEMP\$chromeFileName`" /qn"
            $installProcess = Start-Process msiexec.exe -ArgumentList $arguments -PassThru -Wait

            if ($installProcess.ExitCode -eq 0) {
                Write-Log "Chrome Enterprise installed and enrolled."
            }
            else {
                Write-Log "Failed to install Chrome Enterprise. Exit code: $($installProcess.ExitCode)"
            }
        }
        finally {
            Remove-Item -Path "$env:TEMP\$chromeFileName" -Force -ErrorAction SilentlyContinue
        }
    }
}

# Function to install GCPW
function Install-GCPW {
    $requiredKeys = @("DomainsAllowedToLogin", "EnrollmentToken")
    if (-not (Validate-RequiredKeys -section "GoogleGCPW" -requiredKeys $requiredKeys)) {
        Write-Log "Skipping GCPW installation due to missing keys."
        return
    }

    $domainsAllowedToLogin = Get-ConfigValue -section "GoogleGCPW" -key "DomainsAllowedToLogin"
    $googleEnrollmentToken = Get-ConfigValue -section "GoogleGCPW" -key "EnrollmentToken"

    $gcpwFileName = if ([Environment]::Is64BitOperatingSystem) {
        'gcpwstandaloneenterprise64.msi'
    }
    else {
        'gcpwstandaloneenterprise.msi'
    }

    $gcpwUrl = "https://dl.google.com/credentialprovider/$gcpwFileName"
    if (Test-ProgramInstalled 'Credential Provider') {
        Write-Log "GCPW already installed. Skipping..."
    }
    else {
        Write-Log "Downloading GCPW from $gcpwUrl"
        Invoke-WebRequest -Uri $gcpwUrl -OutFile "$env:TEMP\$gcpwFileName"

        try {
            $arguments = "/i `"$env:TEMP\$gcpwFileName`" /quiet"
            $installProcess = Start-Process msiexec.exe -ArgumentList $arguments -PassThru -Wait

            if ($installProcess.ExitCode -eq 0) {
                Write-Log "GCPW Installation completed successfully!"
                
                try {
                    $gcpwRegistryPath = 'HKLM:\SOFTWARE\Policies\Google\CloudManagement'
                    New-Item -Path $gcpwRegistryPath -Force -ErrorAction Stop
                    Set-ItemProperty -Path $gcpwRegistryPath -Name "EnrollmentToken" -Value $googleEnrollmentToken -ErrorAction Stop
                }
                catch {
                    Write-Log "Error: $($_.Exception.Message)"
                }

                Set-ItemProperty -Path "HKLM:\Software\Google\GCPW" -Name "domains_allowed_to_login" -Value $domainsAllowedToLogin
                $domains = Get-ItemPropertyValue -Path "HKLM:\Software\Google\GCPW" -Name "domains_allowed_to_login"
                if ($domains -eq $domainsAllowedToLogin) {
                    Write-Log 'Domains have been set'
                }
            }
            else {
                Write-Log "Failed to install GCPW. Exit code: $($installProcess.ExitCode)"
            }
        }
        finally {
            Remove-Item -Path "$env:TEMP\$gcpwFileName" -Force -ErrorAction SilentlyContinue
        }
    }
}

# Function to install Google Drive
function Install-GoogleDrive {
    $driveFileName = 'GoogleDriveFSSetup.exe'
    $driveUrl = "https://dl.google.com/drive-file-stream/$driveFileName"
    if (Test-ProgramInstalled 'Google Drive') {
        Write-Log 'Google Drive already installed. Skipping...'
    }
    else {
        Write-Log "Downloading Google Drive from $driveUrl"
        Invoke-WebRequest -Uri $driveUrl -OutFile "$env:TEMP\$driveFileName"

        try {
            Start-Process -FilePath "$env:TEMP\$driveFileName" -Verb runAs -ArgumentList '--silent'
            Write-Log 'Google Drive Installation completed successfully!'
            try {
                Write-Log "Setting Google Drive Configurations"
                $driveRegistryPath = 'HKLM:\SOFTWARE\Google\DriveFS'
                New-Item -Path $driveRegistryPath -Force -ErrorAction Stop
                Set-ItemProperty -Path $driveRegistryPath -Name 'AutoStartOnLogin' -Value 1 -Type DWord -Force -ErrorAction Stop
                Set-ItemProperty -Path $driveRegistryPath -Name 'DefaultWebBrowser' -Value "$env:systemdrive\Program Files\Google\Chrome\Application\chrome.exe" -Type String -Force -ErrorAction Stop
                Set-ItemProperty -Path $driveRegistryPath -Name 'OpenOfficeFilesInDocs' -Value 0 -Type DWord -Force -ErrorAction Stop

                Write-Log 'Google Drive policies have been set'

            }
            catch {
                Write-Log "Google Drive policies have failed to be added to the registry"
                Write-Log "Error: $($_.Exception.Message)"
            }
            
        }
        catch {
            Write-Log "Installation failed!"
            Write-Log "Error: $($_.Exception.Message)"
        }
        finally {
            Remove-Item -Path "$env:TEMP\$driveFileName" -Force -ErrorAction SilentlyContinue
        }
    }
}

# Function to import tasks into Task Scheduler
function Import-Tasks {
    try {
        $tasksSection = $config["Tasks"]
        if ($tasksSection) {
            foreach ($key in $tasksSection.Keys) {
                $taskFile = $tasksSection[$key]

                # Download the task file if it's a URL
                if ($taskFile -match "^https?://") {
                    $tempTaskFile = "$env:TEMP\$key.xml"
                    Write-Log "Downloading task file from: $taskFile"
                    Invoke-WebRequest -Uri $taskFile -OutFile $tempTaskFile
                    $taskFile = $tempTaskFile
                }

                # Import the task into Task Scheduler
                Write-Log "Importing task: $taskFile"
                schtasks /create /tn $key /xml $taskFile /f
            }
            Write-Log "Tasks imported successfully."
        } else {
            Write-Log "No tasks to import. Missing configuration."
        }
    } catch {
        Write-Log "Error importing tasks: $($_.Exception.Message)"
        exit 1
    }
}

# Function to activate Windows
function Activate-Windows {
    try {
        $productKey = Get-ConfigValue -section "Activation" -key "ProductKey"
        $version = Get-ConfigValue -section "Activation" -key "Version"

        if ($productKey -and $version) {
            Write-Log "Activating Windows with product key: $productKey and version: $version"
            slmgr.vbs /ipk $productKey
            slmgr.vbs /skms kms.server.address
            slmgr.vbs /ato
            Write-Log "Windows activated successfully."
        } else {
            Write-Log "Windows activation not performed. Missing configuration."
        }
    } catch {
        Write-Log "Error activating Windows: $($_.Exception.Message)"
        exit 1
    }
}

# Download and read the configuration file if it's a URL
function Get-ConfigFile {
    param (
        [string]$configFile
    )
    if ($configFile -match "^https?://") {
        $tempConfigFile = "$env:TEMP\config.ini"
        Write-Log "Downloading configuration file from: $configFile"
        Invoke-WebRequest -Uri $configFile -OutFile $tempConfigFile
        $configFile = $tempConfigFile
    }
    return $configFile
}

# Main script execution
if (-not (Test-IsAdmin)) {
    Write-Log 'Please run as administrator!'
    exit 5
}

try {
    $configFile = Get-ConfigFile -configFile $configFile
    Write-Log "Loading configuration file: $configFile"
    $config = Read-IniFile -path $configFile
    Write-Log "Configuration file loaded successfully."
} catch {
    Write-Log "Error loading configuration file: $($_.Exception.Message)"
    exit 1
}

# Execute functions
Set-ComputerName
Set-Locale
Set-SystemTimezone
Install-Applications
Install-Fonts
Set-Wallpaper
Set-LockScreenImage
Add-RegistryEntries
Remove-RegistryEntries
Set-NetworkSettings
Set-PowerSettings
Set-SoftwareUpdates
Set-SecuritySettings
Set-EnvironmentVariables
Import-Tasks
Install-Office
Install-GCPW
Install-ChromeEnterprise
Install-GoogleDrive
Activate-Windows

# Remove the configuration file if it was downloaded
if ($configFile -match "$env:TEMP\config.ini") {
    Remove-Item -Path $configFile -Force -ErrorAction SilentlyContinue
    Write-Log "Temporary configuration file removed."
}

Write-Log "System configuration completed successfully."
