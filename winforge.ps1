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



# Function to check if the current user is an admin
function Test-IsAdmin {
    $admin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match 'S-1-5-32-544')
    return $admin
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

function Convert-ToBoolInt {
    param (
        [string]$value
    )
    if ($value -eq "TRUE") {
        return $true
    } elseif ($value -eq "FALSE") {
        return $false
    } else {
        throw "Invalid boolean value: $value. Expected 'TRUE' or 'FALSE'."
    }
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

# Function to log messages
function Write-Log {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $message"
    Write-Output $logMessage | Out-File -Append -FilePath $logFile
}

# Functions to output the script activity to the user
function Write-SystemMessage {
    param (
        [Parameter()]
        [string] $title = '',
  
        [Parameter()]
        [string] $msg1 = '',

        [Parameter()]
        [string] $msg2 = '',
  
        [Parameter()]
        $titleColor = 'Yellow',
  
        [Parameter()]
        $msg1Color = 'Cyan',

        [Parameter()]
        $msg2color = 'White'
    )
    
    
    if ($PSBoundParameters.ContainsKey('title')) {
        Write-Host
        Write-Host " $title " -ForegroundColor Black -BackgroundColor $titleColor
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
      $msg = "CRITICAL ERROR",
  
      [Parameter()]
      $colour = 'Black'
    )
  
    Write-Host
    Write-Host " $msg " -ForegroundColor $colour -BackgroundColor Red
    Write-Host
    Write-Host $_.Exception.Message -ForegroundColor White
    Write-Host
  }
  
function Write-SuccessMessage {
    param (
      [Parameter()]
      $msg = "COMPLETE",
  
      [Parameter()]
      $msgColor = 'Black'
    )
  
    Write-Host
    Write-Host " $msg " -ForegroundColor $msgColor -BackgroundColor Green
    Write-Host
  }


# Function to add, modify or remove registry settings
function RegistryTouch {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("add", "remove")]
        [string]$action,

        [Parameter(Mandatory=$true)]
        [string]$path,

        [Parameter(Mandatory=$true)]
        [string]$name,

        [Parameter()]
        [ValidateSet("String", "ExpandString", "Binary", "DWord", "MultiString", "QWord")]
        [string]$type = "String",  # Default to String

        [Parameter()]
        [string]$value
    )

    try {
        if ($action -eq "add") {
            # Check if the registry path exists, if not create it
            if (-not (Test-Path $path)) {
                Write-Log "Registry path does not exist. Creating path: $path"
                New-Item -Path $path -Force | Out-Null
            }

            # Check if the registry item exists
            if (-not (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue)) {
                Write-Log "Registry item does not exist. Creating item: $name with value: $value"
                New-ItemProperty -Path $path -Name $name -Value $value -PropertyType $type -Force | Out-Null
            } else {
                # Check if the existing value is different
                $currentValue = (Get-ItemProperty -Path $path -Name $name).$name
                if ($currentValue -ne $value) {
                    Write-Log "Registry value differs. Updating item: $name from $currentValue to $value"
                    Set-ItemProperty -Path $path -Name $name -Value $value -Force | Out-Null
                } else {
                    Write-Log "Registry item: $name with value: $value already exists. Skipping."
                }
            }
        } elseif ($action -eq "remove") {
            # Check if the registry name exists
            if (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue) {
                Write-Log "Removing registry item: $name from path: $path"
                Remove-ItemProperty -Path $path -Name $name -Force | Out-Null
            } else {
                Write-Log "Registry item: $name does not exist at path: $path. Skipping."
            }
        }
    } catch {
        Write-Log "Error Modifying the Registry: $($_.Exception.Message)"
        Show-ErrorMessage -msg "Error in Modifying the Registry: $($_.Exception.Message)"
    }
}

function Set-SystemCheckpoint {
    $date = Get-Date -Format "dd/MM/yyyy"
    $snapshotName = "Winforge - $date"
  
    try {
        Write-Log "Creating system restore point. Snapshot Name: $snapshotName"
        Write-SystemMessage -title "Creating System Restore Point" -msg1 "Snapshot Name: " -msg2 $snapshotName
        
        # Ensure system restore is enabled on the system drive
        Enable-ComputerRestore -Drive "$env:systemdrive"
        
        # Create the system restore point
        Checkpoint-Computer -Description $snapshotName -RestorePointType "MODIFY_SETTINGS" -Verbose
        
        Write-Log "System restore point created successfully."
        Write-SuccessMessage -msg "System restore point created successfully."

    } catch {
        Write-Log "Error creating system restore point: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Failed to create system restore point: $($_.Exception.Message)" -colour "Red"
        Return
    }
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
        Return
    }
}

# Function to set locale
function Set-Locale {
    try {
        $locale = Get-ConfigValue -section "System" -key "Locale"
        if ($locale) {
            Write-Log "Setting locale to: $locale"
            # Validate the locale against a list of supported locales if necessary
            if (Get-WinUserLanguageList | Where-Object { $_.LanguageTag -eq $locale }) {
                Set-WinUILanguageOverride -Language $locale
                Set-WinSystemLocale -SystemLocale $locale
                Set-WinUserLanguageList $locale -Force
                Write-Log "Locale set successfully."
            } else {
                Write-Log "Invalid or unsupported locale: $locale"
            }
        } else {
            Write-Log "Locale not set. Missing configuration."
        }
    } catch {
        Write-Log "Error setting locale: $($_.Exception.Message)"
        Return
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
        Return
    }
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

# Function to install applications via winget using manifest files
function Install-Applications {

    $appManifestFile = Get-ConfigValue -section "Applications" -key "WingetAppManifest"
    if ($appManifestFile) {
        Write-SystemMessage -title "Installing Applications"
        Write-Log "Installing applications via winget import"

            
        # Download the manifest file if it's a URL
        if ($appManifestFile -match "^https?://") {
            $tempAppManifestFile = "$env:TEMP\appManifest.json"
            Write-Log "Downloading app manifest file from: $appManifestFile"
            Write-SystemMessage -msg1 "- Downloading app manifest file from: " -msg2 $appManifestFile
            
            try {
                $appManifestFile = $tempAppManifestFile
                Invoke-WebRequest -Uri $appManifestFile -OutFile $tempAppManifestFile                
            }
            catch {
                Write-Log "Error downloading app manifest file from: $appManifestFile. Error: $($_.Exception.Message)"
                Write-ErrorMessage -msg "Error downloading app manifest file from: $appManifestFile. Error: $($_.Exception.Message)" -colour "Red"
                Return
            }

            Write-SuccessMessage -msg "App manifest downloaded."
        }


        try {
            # Reset Winget sources and accept agreements
            Write-Log "Resetting Winget sources and accepting agreements."
            Write-SystemMessage -msg1 "- Resetting Winget sources and accepting agreements."
                
            winget source reset --force
            winget source update
            winget source list --accept-source-agreements
            
            Write-Log "Winget sources reset and agreements accepted successfully."
            Write-SystemMessage -msg1 "- Winget sources reset and agreements accepted successfully." -msg1Color "Green"
        }
        catch {
            Write-Log "Error resetting Winget sources or accepting agreements: $($_.Exception.Message)"
            Write-ErrorMessage -msg "Error resetting Winget sources or accepting agreements: $($_.Exception.Message)" -colour "Red"
        }
            

        try {
            Write-Log "Installing applications from manifest file: $appManifestFile"
            Write-SystemMessage -msg1 "- Installing applications from manifest file"
            winget import -i $appManifestFile --accept-package-agreements --ignore-versions --accept-source-agreements
        }
        catch {
            Write-Log "Error installing applications from manifest file ${appManifestFile}: $($_.Exception.Message)"
            Write-ErrorMessage -msg "- Error installing applications from manifest file ${appManifestFile}: $($_.Exception.Message)" -colour "Red"
        }

        Write-Log "App installation complete."
        Write-SuccessMessage -msg "Applications installed successfully."
        Return

        
        else {
            Write-Log "No app manifest file provided."
            Write-SystemMessage -msg1 "No app manifest file provided." -msg1Color "Cyan"
        }
    }
    catch {
        Write-Log "Error processing applications: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Error processing applications: $($_.Exception.Message)" -colour "Red"
        Return
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

# Function to download font files from GitHub
function Get-Fonts {
    param (
        [string]$fontName,
        [string]$outputPath
    )

    $githubUrl = "https://github.com/google/fonts"
    $fontRepoUrl = "$githubUrl/tree/main/ofl/$fontName"

    # Create output directory if it doesn't exist
    if (-not (Test-Path -Path $outputPath)) {
        New-Item -ItemType Directory -Path $outputPath | Out-Null
    }

    # Fetch font file URLs from GitHub
    $fontFilesPage = Invoke-WebRequest -Uri $fontRepoUrl -UseBasicParsing
    $fontFileLinks = $fontFilesPage.Links | Where-Object { $_.href -match "\.ttf$" -or $_.href -match "\.otf$" }

    foreach ($link in $fontFileLinks) {
        $fileUrl = "https://github.com" + $link.href.Replace("/blob/", "/raw/")
        $fileName = [System.IO.Path]::GetFileName($link.href)

        # Download font file
        Write-Log "Downloading $fileName from: $fileUrl"
        Invoke-WebRequest -Uri $fileUrl -OutFile (Join-Path -Path $outputPath -ChildPath $fileName)
    }

    Write-Log "Download complete. Fonts saved to $outputPath"
}

# Function to install Google fonts from GitHub repository
function Install-Fonts {
    try {
        $fonts = Get-ConfigValue -section "Fonts" -key "Fonts"
        if ($fonts) {
            $fontsList = $fonts -split ',' | ForEach-Object { $_.Trim('"').ToLower() }
            $ProgressPreference = 'SilentlyContinue'
            $tempDownloadFolder = "$env:TEMP\google_fonts"
            Write-SystemMessage -title "Installing Fonts"

            foreach ($fontName in $fontsList) {
                # Correct the font names for the GitHub repository
                $correctFontName = $fontName -replace "\+", ""

                # Check if the font is already installed
                $isFontInstalled = Test-FontInstalled -FontName $correctFontName

                if ($isFontInstalled) {
                    Write-Log "Font $correctFontName is already installed. Skipping download and installation."
                    Write-SystemMessage -msg1 "- $correctFontName is already installed. Skipping installation." -msg1Color "Cyan"
                    continue
                }

                Write-Log "Downloading & Installing $correctFontName from Google Fonts GitHub repository. Please wait..."
                Write-SystemMessage -msg1 "- Downloading & Installing: " -msg2 $correctFontName

                # Download the font files
                Get-Fonts -fontName $correctFontName -outputPath $tempDownloadFolder

                # Install the font files
                $allFonts = Get-ChildItem -Path $tempDownloadFolder -Include *.ttf, *.otf -Recurse
                foreach ($font in $allFonts) {
                    $fontDestination = Join-Path -Path $env:windir\Fonts -ChildPath $font.Name
                    Copy-Item -Path $font.FullName -Destination $fontDestination -Force
                    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Fonts" -Name $font.BaseName -Value $font.Name -PropertyType String -Force | Out-Null
                }

                Write-Log "Font installed: $correctFontName"
                Write-SystemMessage -msg1 "- $correctFontName installed successfully." -msg1Color "Green"

                # Clean up the downloaded font files
                Remove-Item -Path $tempDownloadFolder -Recurse -Force
            }

            Write-Log "All fonts installed successfully."
            Write-SuccessMessage
        } else {
            Write-Log "No fonts to install. Missing configuration."
            Write-SystemMessage -msg1 "No fonts to install. Missing configuration." -msg1Color "Cyan"
        }
    } catch {
        Write-Log "Error installing fonts: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Error installing fonts: $($_.Exception.Message)" -colour "Red"
        Return
    }
}


# Function to install Microsoft Office
function Install-Office {
    try {
        $officeSectionExists = $config.ContainsKey("Office")
        if ($officeSectionExists) {
            Write-SystemMessage -title "Installing Microsoft Office"
            $requiredKeys = @("LicenseKey", "ProductID", "LanguageID", "UpdatesEnabled", "DisplayLevel", "SetupReboot", "Channel", "OfficeClientEdition")
            if (-not (Validate-RequiredKeys -section "Office" -requiredKeys $requiredKeys)) {
                Write-Log "Skipping Office installation due to missing keys."
                Write-SystemMessage -msg1 "Skipping Office installation due to missing keys." -msg1Color "Yellow"
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
            Write-SystemMessage -msg1 "Downloading Office Deployment Tool..."
            Invoke-WebRequest -Uri $odtUrl -OutFile $odtFile

            Write-Log "Creating configuration XML file..."
            Write-SystemMessage -msg1 "Creating configuration XML file..."
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
            Write-SystemMessage -msg1 "Running the Office Deployment Tool..."
            Start-Process $odtFile -ArgumentList "/quiet /extract:$odtPath" -Wait

            Write-Log "Downloading and installing Microsoft Office..."
            Write-SystemMessage -msg1 "Downloading and installing Microsoft Office..."
            $installProcess = Start-Process "$odtPath\Setup.exe" -ArgumentList "/configure `"$configurationXMLFile`"" -Wait -PassThru

            if ($installProcess.ExitCode -eq 0) {
                Write-Log "Microsoft Office installation completed successfully."
                Write-SuccessMessage -msg "Microsoft Office installation completed successfully."
            } else {
                Write-Log "Failed to install Microsoft Office. Exit code: $($installProcess.ExitCode)"
                Write-ErrorMessage -msg "Failed to install Microsoft Office. Exit code: $($installProcess.ExitCode)"
            }

            # Clean up the extracted files and the zip file
            Remove-Item $odtFile
            Remove-Item $configurationXMLFile
        } else {
            Write-Log "Office section not found in configuration file. Skipping Office installation."
            Write-SystemMessage -msg1 "Office section not found in configuration file. Skipping Office installation." -msg1Color "Yellow"
        }
    } catch {
        Write-Log "Error installing Microsoft Office: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Error installing Microsoft Office: $($_.Exception.Message)"
        Return
    }
}


# Function to set wallpaper
function Set-Wallpaper {
    try {
        $wallpaperPath = Get-ConfigValue -section "Theme" -key "WallpaperPath"
        if ($wallpaperPath) {
            Write-SystemMessage -title "Setting Wallpaper"
            Write-Log "Setting wallpaper..."

            # Check if the path is a URL
            if ($wallpaperPath -match "^https?://") {
                $tempWallpaperPath = "$env:TEMP\wallpaper.jpg"
                Write-Log "Downloading wallpaper from: $wallpaperPath"
                Write-SystemMessage -msg1 "Downloading wallpaper from: " -msg2 $wallpaperPath
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
                New-ItemProperty -Path $registryFullPath -Name $item.Name -Value $item.Value -PropertyType $item.Type -Force | Out-Null
            }

            Stop-Process -Name explorer
            Start-Sleep -Seconds 5
            if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) { Start-Process explorer }

            Write-Log "Wallpaper set successfully."
            Write-SuccessMessage -msg "Wallpaper set successfully."
        } else {
            Write-Log "Wallpaper not set. Missing configuration."
            Write-SystemMessage -msg1 "Wallpaper not set. Missing configuration." -msg1Color "Yellow"
        }
    } catch {
        Write-Log "Error setting wallpaper: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Error setting wallpaper: $($_.Exception.Message)"
        Return
    }
}



# Function to set lock screen image
function Set-LockScreenImage {
    try {
        $lockScreenPath = Get-ConfigValue -section "Theme" -key "LockScreenPath"
        if ($lockScreenPath) {
            Write-SystemMessage -title "Setting Lock Screen Image"
            Write-Log "Setting lock screen image..."

            # Check if the path is a URL
            if ($lockScreenPath -match "^https?://") {
                $tempLockScreenPath = "$env:TEMP\lockscreen.jpg"
                Write-Log "Downloading lock screen image from: $lockScreenPath"
                Write-SystemMessage -msg1 "Downloading lock screen image from: " -msg2 $lockScreenPath
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
                New-ItemProperty -Path $registryFullPath -Name $item.Name -Value $item.Value -PropertyType $item.Type -Force | Out-Null
            }

            Stop-Process -Name explorer
            Start-Sleep -Seconds 5
            if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) { Start-Process explorer }

            Write-Log "Lock screen image set successfully."
            Write-SuccessMessage -msg "Lock screen image set successfully."
        } else {
            Write-Log "Lock screen image not set. Missing configuration."
            Write-SystemMessage -msg1 "Lock screen image not set. Missing configuration." -msg1Color "Yellow"
        }
    } catch {
        Write-Log "Error setting lock screen image: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Error setting lock screen image: $($_.Exception.Message)"
        Return
    }
}



# Function to add registry entries
function Add-RegistryEntries {
    try {
        $registrySection = $config["RegistryAdd"]
        if ($registrySection) {
            Write-SystemMessage -title "Adding Registry Entries"
            foreach ($key in $registrySection.Keys) {
                $entry = $registrySection[$key] -split ","
                $entryDict = @{}
                foreach ($item in $entry) {
                    $keyValue = $item.Trim() -split "="
                    $entryDict[$keyValue[0].Trim()] = $keyValue[1].Trim().Trim('"')
                }

                # Ensure all required fields are present
                if ($entryDict.ContainsKey("Path") -and $entryDict.ContainsKey("Name") -and $entryDict.ContainsKey("Type") -and $entryDict.ContainsKey("Value")) {
                    $path = $entryDict["Path"]
                    $name = $entryDict["Name"]
                    $type = $entryDict["Type"]
                    $value = $entryDict["Value"]

                    Write-Log "Adding registry entry: Path=$path, Name=$name, Type=$type, Value=$value"
                    Write-SystemMessage -msg1 "- Adding: " -msg2 "Path=$path, Name=$name, Type=$type, Value=$value"

                    # Use RegistryTouch for adding the registry entry
                    RegistryTouch -action "add" -path $path -name $name -type $type -value $value
                } else {
                    Write-Log "Invalid registry entry format: $key"
                    Show-ErrorMessage -msg "Invalid registry entry format: $key"
                }
            }
            Write-Log "Registry entries added successfully."
            Show-SuccessMessage -msg "Registry entries added successfully."
        } else {
            Write-Log "No registry entries to add. Missing configuration."
            Write-SystemMessage -msg1 "No registry entries to add. Missing configuration." -msg1Color "Yellow"
        }
    } catch {
        Write-Log "Error adding registry entries: $($_.Exception.Message)"
        Show-ErrorMessage -msg "Error adding registry entries: $($_.Exception.Message)"
    }
}



# Function to remove registry entries
function Remove-RegistryEntries {
    try {
        $registrySection = $config["RegistryRemove"]
        if ($registrySection) {
            Write-SystemMessage -title "Removing Registry Entries"
            foreach ($key in $registrySection.Keys) {
                $entry = $registrySection[$key] -split ","
                $entryDict = @{}
                foreach ($item in $entry) {
                    $keyValue = $item.Trim() -split "="
                    $entryDict[$keyValue[0].Trim()] = $keyValue[1].Trim().Trim('"')
                }

                # Ensure all required fields are present
                if ($entryDict.ContainsKey("Path") -and $entryDict.ContainsKey("Name")) {
                    $path = $entryDict["Path"]
                    $name = $entryDict["Name"]

                    Write-Log "Removing registry entry: Path=$path, Name=$name"
                    Write-SystemMessage -msg1 "- Removing: " -msg2 "Path=$path, Name=$name"

                    # Use RegistryTouch for removing the registry entry
                    RegistryTouch -action "remove" -path $path -name $name
                } else {
                    Write-Log "Invalid registry entry format: $key"
                    Show-ErrorMessage -msg "Invalid registry entry format: $key"
                }
            }
            Write-Log "Registry entries removed successfully."
            Show-SuccessMessage -msg "Registry entries removed successfully."
        } else {
            Write-Log "No registry entries to remove. Missing configuration."
            Write-SystemMessage -msg1 "No registry entries to remove. Missing configuration." -msg1Color "Yellow"
        }
    } catch {
        Write-Log "Error removing registry entries: $($_.Exception.Message)"
        Show-ErrorMessage -msg "Error removing registry entries: $($_.Exception.Message)"
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
        Return
    }
}

# Function to configure Windows updates
function Set-WindowsUpdates {
    try {
        $enableAutoUpdates = Get-ConfigValue -section "WindowsUpdate" -key "EnableAutoUpdates"
        $auOptions = Get-ConfigValue -section "WindowsUpdate" -key "AUOptions"
        $autoInstallMinorUpdates = Get-ConfigValue -section "WindowsUpdate" -key "AutoInstallMinorUpdates"
        $scheduledInstallDay = Get-ConfigValue -section "WindowsUpdate" -key "ScheduledInstallDay"
        $scheduledInstallTime = Get-ConfigValue -section "WindowsUpdate" -key "ScheduledInstallTime"

        Write-SystemMessage -title "Configuring Windows Updates"

        # Convert EnableAutoUpdates to its opposite for NoAutoUpdate
        $noAutoUpdate = if ($enableAutoUpdates -eq "TRUE") { "FALSE" } else { "TRUE" }
        
        Write-Log "EnableAutoUpdates: $enableAutoUpdates"
        Write-Log "AUOptions: $auOptions"
        Write-Log "ScheduledInstallDay: $scheduledInstallDay"
        Write-Log "ScheduledInstallTime: $scheduledInstallTime"

        if ($noAutoUpdate -eq "TRUE") {
            Write-Log "Disabling automatic windows updates..."
            Write-SystemMessage -msg1 "- Disabling all automatic updates."
            RegistryTouch -action "add" -path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -name "NoAutoUpdate" -type "DWord" -value 1
            Write-Log "Automatic updates disabled."
            Write-SystemMessage -msg1 "- Automatic updates disabled." -msg1Color "Green"
        } else {
            Write-Log "Configuring Windows updates..."
            RegistryTouch -action "add" -path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -name "NoAutoUpdate" -type "DWord" -value 0

            if ($auOptions -and $scheduledInstallDay -and $scheduledInstallTime) {
                Write-Log "Setting AUOptions to: $auOptions"
                Write-SystemMessage -msg1 "- Setting AUOptions to: " -msg2 $auOptions
                RegistryTouch -action "add" -path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -name "AUOptions" -type "DWord" -value $auOptions

                Write-Log "Setting ScheduledInstallDay to: $scheduledInstallDay"
                Write-SystemMessage -msg1 "- Setting ScheduledInstallDay to: " -msg2 $scheduledInstallDay
                RegistryTouch -action "add" -path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -name "ScheduledInstallDay" -type "DWord" -value $scheduledInstallDay

                Write-Log "Setting ScheduledInstallTime to: $scheduledInstallTime"
                Write-SystemMessage -msg1 "- Setting ScheduledInstallTime to: " -msg2 $scheduledInstallTime
                RegistryTouch -action "add" -path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -name "ScheduledInstallTime" -type "DWord" -value $scheduledInstallTime
            } else {
                Write-Log "Missing AUOptions, ScheduledInstallDay, or ScheduledInstallTime configuration. Skipping scheduled updates settings."
                Write-SystemMessage -msg1 "Missing AUOptions, ScheduledInstallDay, or ScheduledInstallTime configuration. Skipping scheduled updates settings." -msg1Color "Yellow"
            }

            if ($autoInstallMinorUpdates) {
                $autoInstallValue = if ($autoInstallMinorUpdates -eq "TRUE") { 1 } else { 0 }
                Write-Log "Setting AutoInstallMinorUpdates to: $autoInstallValue"
                Write-SystemMessage -msg1 "- Setting AutoInstallMinorUpdates to: " -msg2 $autoInstallValue
                RegistryTouch -action "add" -path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -name "AutoInstallMinorUpdates" -type "DWord" -value $autoInstallValue
            } else {
                Write-Log "No AutoInstallMinorUpdates setting provided."
                Write-SystemMessage -msg1 "No AutoInstallMinorUpdates setting provided." -msg1Color "Yellow"
            }

            Write-Log "Windows updates configured successfully."
            Write-SystemMessage -msg1 "- Windows updates configured successfully." -msg1Color "Green"
        }
    } catch {
        Write-Log "Error configuring Windows updates: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Error configuring Windows updates: $($_.Exception.Message)"
        Return
    }
}


# Function to set optional windows features and services
function Set-Services {
    try {
        $services = $config["Services"]
        if ($services) {
            Write-SystemMessage -title "Configuring Services"
            foreach ($service in $services.GetEnumerator()) {
                $serviceName = $service.Key
                $serviceAction = $service.Value.ToLower()
                try {
                    if ($serviceAction -eq "enabled") {
                        Write-SystemMessage -msg1 "- Enabling: " -msg2 $serviceName
                        Write-Log "Enabling service: $serviceName"
                        Enable-WindowsOptionalFeature -FeatureName $serviceName -Online -NoRestart | Out-Null
                        Write-SystemMessage -msg1 "- $serviceName enabled successfully." -msg1Color "Green"
                    } elseif ($serviceAction -eq "disabled") {
                        Write-SystemMessage -msg1 "- Disabling: " -msg2 $serviceName
                        Write-Log "Disabling service: $serviceName"
                        Disable-WindowsOptionalFeature -FeatureName $serviceName -Online -NoRestart | Out-Null
                        Write-SystemMessage -msg1 "- $serviceName disabled successfully." -msg1Color "Green"
                    } else {
                        Write-SystemMessage -msg1 "- Invalid service action for: " -msg2 $serviceName -msg2Color "Red"
                        Write-Log "Invalid service action for ${serviceName}: $serviceAction"
                    }
                } catch {
                    Write-ErrorMessage -msg "$serviceName was not found as an optional service, check spelling and fix the configuration file."
                    Write-Log "Error configuring service ${serviceName}: $($_.Exception.Message)"
                }
            }
            Write-Log "Service configurations applied successfully."
            Write-SuccessMessage
        } else {
            Write-Log "No services to configure."
            Write-SystemMessage -msg1 "No services to configure." -msg1Color "Cyan"
        }
    } catch {
        Write-Log "Error configuring services: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Error configuring services: $($_.Exception.Message)" -colour "Red"
        Return
    }
}



# Function to configure security settings
function Set-SecuritySettings {
    try {
        $uacLevel = Get-ConfigValue -section "SecuritySettings" -key "UACLevel"
        $disableTelemetry = Convert-ToBoolInt (Get-ConfigValue -section "SecuritySettings" -key "DisableTelemetry")
        $showFileExtensions = Convert-ToBoolInt (Get-ConfigValue -section "SecuritySettings" -key "ShowFileExtensions")
        $disableCopilot = Convert-ToBoolInt (Get-ConfigValue -section "SecuritySettings" -key "DisableCopilot")
        $disableOneDrive = Convert-ToBoolInt (Get-ConfigValue -section "SecuritySettings" -key "DisableOneDrive")

        Write-Log "Configuring Security Settings"
        Write-SystemMessage -title "Configuring Security Settings"

        # Set UAC level
        if ($uacLevel) {
            Write-SystemMessage -msg1 "- Setting UAC level to: " -msg2 $uacLevel
            Write-Log "Setting UAC level to: $uacLevel"
            RegistryTouch -action "add" -path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -name "ConsentPromptBehaviorAdmin" -type "DWord" -value $uacLevel
            Write-SystemMessage -msg1 "- UAC level set to $uacLevel." -msg1Color "Green"
        } else {
            Write-ErrorMessage -msg "UAC level not set. Missing configuration." -colour "Cyan"
            Write-Log "UAC level not set. Missing configuration."
        }

        # Disable/Enable Telemetry
        Write-SystemMessage -msg1 "- Setting Windows Telemetry..."
        Write-Log "Setting Windows Telemetry to $disableTelemetry"
        $telemetryKeys = @(
            @{path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; name="AllowTelemetry"; value=$disableTelemetry; type="DWord"},
            @{path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; name="AllowTelemetry"; value=$disableTelemetry; type="DWord"},
            @{path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; name="MaxTelemetryAllowed"; value=$disableTelemetry; type="DWord"}
        )
        foreach ($key in $telemetryKeys) {
            RegistryTouch -action "add" -path $key.path -name $key.name -type $key.type -value $key.value
        }
        Write-SystemMessage -msg1 "- Windows Telemetry setting applied." -msg1Color "Green"
        Write-Log "Windows Telemetry setting applied."

        # Show/Hide file extensions
        Write-SystemMessage -msg1 "- Configuring file type extension visibility..."
        Write-Log "Configuring file type extension visibility to $showFileExtensions"
        RegistryTouch -action "add" -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name "HideFileExt" -type "DWord" -value $showFileExtensions
        Write-SystemMessage -msg1 "- File type extension visibility configured." -msg1Color "Green"
        Write-Log "File type extension visibility configured."

        # Disable/Enable Copilot
        Write-SystemMessage -msg1 "- Setting Windows Copilot..."
        Write-Log "Setting Windows Copilot to $disableCopilot"
        RegistryTouch -action "add" -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -name "CopilotEnabled" -type "DWord" -value $disableCopilot
        Write-SystemMessage -msg1 "- Windows Copilot setting applied." -msg1Color "Green"
        Write-Log "Windows Copilot setting applied."

        # Disable/Enable OneDrive
        Write-SystemMessage -msg1 "- Setting OneDrive..."
        Write-Log "Setting OneDrive to $disableOneDrive"
        $oneDriveKeys = @(
            @{path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"; name="DisableFileSyncNGSC"; value=$disableOneDrive; type="DWord"},
            @{path="HKLM:\SOFTWARE\Microsoft\OneDrive"; name="PreventNetworkTrafficPreWindows10Apps"; value=$disableOneDrive; type="DWord"}
        )
        foreach ($key in $oneDriveKeys) {
            RegistryTouch -action "add" -path $key.path -name $key.name -type $key.type -value $key.value
        }
        if ($disableOneDrive -eq 1) {
            Stop-Process -Name OneDrive -Force -ErrorAction SilentlyContinue
        }
        Write-SystemMessage -msg1 "- OneDrive setting applied." -msg1Color "Green"
        Write-Log "OneDrive setting applied."

        Write-SuccessMessage -msg "Security settings configured successfully."
    } catch {
        Write-ErrorMessage -msg "Error configuring security settings: $($_.Exception.Message)" -colour "Red"
        Write-Log "Error configuring security settings: $($_.Exception.Message)"
        Return
    }
}





# Function to set environment variables
function Set-EnvironmentVariables {
    try {
        $environmentVariables = $config["EnvironmentVariables"]
        if ($environmentVariables) {
            Write-SystemMessage -title "Setting Environment Variables"
            foreach ($key in $environmentVariables.Keys) {
                $value = $environmentVariables[$key]
                Write-SystemMessage -msg1 "- Setting: " -msg2 "$key=$value"
                Write-Log "Setting environment variable: $key=$value"
                [System.Environment]::SetEnvironmentVariable($key, $value, "Machine")
                Write-SystemMessage -msg1 "- Environment variable $key set to $value." -msg1Color "Green"
            }
            Write-Log "Environment variables set successfully."
            Write-SuccessMessage -msg "Environment variables set successfully."
        } else {
            Write-Log "No environment variables to set. Missing configuration."
            Write-SystemMessage -msg1 "No environment variables to set. Missing configuration." -msg1Color "Cyan"
        }
    } catch {
        Write-Log "Error setting environment variables: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Error setting environment variables: $($_.Exception.Message)"
        Return
    }
}





# Function to install Chrome Enterprise
function Install-ChromeEnterprise {
    $installChrome = Convert-ToBoolInt (Get-ConfigValue -section "Google" -key "InstallGoogleChrome")

    if ($installChrome) {
        Write-SystemMessage -title "Installing Google Chrome Enterprise"
        $chromeFileName = if ([Environment]::Is64BitOperatingSystem) {
            'googlechromestandaloneenterprise64.msi'
        } else {
            'googlechromestandaloneenterprise.msi'
        }

        $chromeUrl = "https://dl.google.com/chrome/install/$chromeFileName"

        if (Test-ProgramInstalled 'Google Chrome') {
            Write-SystemMessage -msg1 "- Google Chrome Enterprise is already installed. Skipping installation." -msg1Color "Cyan"
            Write-Log "Google Chrome Enterprise already installed. Skipping..."
        } else {
            Write-SystemMessage -msg1 "- Downloading: " -msg2 "Google Chrome Enterprise"
            Write-Log "Downloading Chrome from $chromeUrl"
            Invoke-WebRequest -Uri $chromeUrl -OutFile "$env:TEMP\$chromeFileName"

            try {
                $arguments = "/i `"$env:TEMP\$chromeFileName`" /qn"
                $installProcess = Start-Process msiexec.exe -ArgumentList $arguments -PassThru -Wait

                if ($installProcess.ExitCode -eq 0) {
                    Write-SystemMessage -msg1 "- Google Chrome Enterprise installed successfully." -msg1Color "Green"
                    Write-Log "Chrome Enterprise installed and enrolled."
                } else {
                    Write-ErrorMessage -msg "- Failed to install Google Chrome Enterprise. Exit code: $($installProcess.ExitCode)" -colour "Red"
                    Write-Log "Failed to install Chrome Enterprise. Exit code: $($installProcess.ExitCode)"
                }
            } finally {
                Remove-Item -Path "$env:TEMP\$chromeFileName" -Force -ErrorAction SilentlyContinue
            }
        }
        Write-SuccessMessage -msg "Google Chrome Enterprise installation completed."
    } else {
        Write-Log "Skipping Google Chrome Enterprise installation as per configuration."
        Write-SystemMessage -msg1 "Skipping Google Chrome Enterprise installation as per configuration." -msg1Color "Cyan"
    }
}


# Function to install GCPW
function Install-GCPW {
    $installGCPW = Convert-ToBoolInt (Get-ConfigValue -section "Google" -key "InstallGCPW")

    if ($installGCPW) {
        Write-SystemMessage -title "Installing Google Credential Provider for Windows (GCPW)"
        $requiredKeys = @("DomainsAllowedToLogin", "GCPW-EnrollmentToken")
        if (-not (Validate-RequiredKeys -section "Google" -requiredKeys $requiredKeys)) {
            Write-SystemMessage -msg1 "Skipping GCPW installation due to missing keys." -msg1Color "Cyan"
            Write-Log "Skipping GCPW installation due to missing keys."
            return
        }

        $domainsAllowedToLogin = Get-ConfigValue -section "Google" -key "DomainsAllowedToLogin"
        $googleEnrollmentToken = Get-ConfigValue -section "Google" -key "GCPW-EnrollmentToken"

        $gcpwFileName = if ([Environment]::Is64BitOperatingSystem) {
            'gcpwstandaloneenterprise64.msi'
        } else {
            'gcpwstandaloneenterprise.msi'
        }

        $gcpwUrl = "https://dl.google.com/credentialprovider/$gcpwFileName"
        if (Test-ProgramInstalled 'Credential Provider') {
            Write-SystemMessage -msg1 "- Google Credential Provider for Windows (GCPW) is already installed. Skipping installation." -msg1Color "Cyan"
            Write-Log "GCPW already installed. Skipping..."
        } else {
            Write-SystemMessage -msg1 "- Downloading: " -msg2 "Google Credential Provider for Windows (GCPW)"
            Write-Log "Downloading GCPW from $gcpwUrl"
            Invoke-WebRequest -Uri $gcpwUrl -OutFile "$env:TEMP\$gcpwFileName"

            try {
                $arguments = "/i `"$env:TEMP\$gcpwFileName`" /quiet"
                $installProcess = Start-Process msiexec.exe -ArgumentList $arguments -PassThru -Wait

                if ($installProcess.ExitCode -eq 0) {
                    Write-SystemMessage -msg1 "- Google Credential Provider for Windows (GCPW) installed successfully." -msg1Color "Green"
                    Write-Log "GCPW Installation completed successfully!"
                    
                    try {
                        $gcpwRegistryPath = 'HKLM:\SOFTWARE\Policies\Google\CloudManagement'
                        New-Item -Path $gcpwRegistryPath -Force -ErrorAction Stop
                        Set-ItemProperty -Path $gcpwRegistryPath -Name "EnrollmentToken" -Value $googleEnrollmentToken -ErrorAction Stop
                    } catch {
                        Write-ErrorMessage -msg "Error setting GCPW registry keys: $($_.Exception.Message)"
                        Write-Log "Error: $($_.Exception.Message)"
                    }

                    Set-ItemProperty -Path "HKLM:\Software\Google\GCPW" -Name "domains_allowed_to_login" -Value $domainsAllowedToLogin
                    $domains = Get-ItemPropertyValue -Path "HKLM:\Software\Google\GCPW" -Name "domains_allowed_to_login"
                    if ($domains -eq $domainsAllowedToLogin) {
                        Write-SystemMessage -msg1 "- Domains have been set successfully." -msg1Color "Green"
                        Write-Log 'Domains have been set'
                    }
                } else {
                    Write-ErrorMessage -msg "- Failed to install Google Credential Provider for Windows (GCPW). Exit code: $($installProcess.ExitCode)" -colour "Red"
                    Write-Log "Failed to install GCPW. Exit code: $($installProcess.ExitCode)"
                }
            } finally {
                Remove-Item -Path "$env:TEMP\$gcpwFileName" -Force -ErrorAction SilentlyContinue
            }
        }
        Write-SuccessMessage -msg "Google Credential Provider for Windows (GCPW) installation completed."
    } else {
        Write-Log "Skipping Google Credential Provider for Windows (GCPW) installation as per configuration."
        Write-SystemMessage -msg1 "Skipping Google Credential Provider for Windows (GCPW) installation as per configuration." -msg1Color "Cyan"
    }
}



# Function to install Google Drive
function Install-GoogleDrive {
    $installGoogleDrive = Convert-ToBoolInt (Get-ConfigValue -section "Google" -key "InstallGoogleDrive")

    if ($installGoogleDrive) {
        Write-SystemMessage -title "Installing Google Drive"
        $driveFileName = 'GoogleDriveFSSetup.exe'
        $driveUrl = "https://dl.google.com/drive-file-stream/$driveFileName"
        if (Test-ProgramInstalled 'Google Drive') {
            Write-SystemMessage -msg1 "- Google Drive is already installed. Skipping installation." -msg1Color "Cyan"
            Write-Log 'Google Drive already installed. Skipping...'
        } else {
            Write-SystemMessage -msg1 "- Downloading: " -msg2 "Google Drive"
            Write-Log "Downloading Google Drive from $driveUrl"
            Invoke-WebRequest -Uri $driveUrl -OutFile "$env:TEMP\$driveFileName"

            try {
                Write-SystemMessage -msg1 "- Installing: " -msg2 "Google Drive"
                Start-Process -FilePath "$env:TEMP\$driveFileName" -Verb runAs -ArgumentList '--silent' -Wait
                Write-Log 'Google Drive Installation completed successfully!'
                Write-SystemMessage -msg1 "- Google Drive installed successfully." -msg1Color "Green"
                
            } catch {
                Write-ErrorMessage -msg "Google Drive installation failed: $($_.Exception.Message)" -colour "Red"
                Write-Log "Installation failed!"
                Write-Log "Error: $($_.Exception.Message)"
            } finally {
                Remove-Item -Path "$env:TEMP\$driveFileName" -Force -ErrorAction SilentlyContinue
            }
        }
        Write-SuccessMessage -msg "Google Drive installation completed."
    } else {
        Write-Log "Skipping Google Drive installation as per configuration."
        Write-SystemMessage -msg1 "Skipping Google Drive installation as per configuration." -msg1Color "Cyan"
    }
}

# Function to import tasks into Task Scheduler
function Import-Tasks {
    try {
        $tasksSection = $config["Tasks"]
        if ($tasksSection) {
            Write-SystemMessage -title "Importing Scheduled Tasks"

            foreach ($key in $tasksSection.Keys) {
                $taskFile = $tasksSection[$key]

                # Check if the key is a folder
                if ($key -eq "TasksRepository") {
                    Write-SystemMessage -msg1 "- Checking remote folder: " -msg2 $taskFile
                    Write-Log "Checking remote folder: $taskFile"

                    # Validate if the URL exists
                    try {
                        $response = Invoke-WebRequest -Uri $taskFile -Method Head -ErrorAction Stop
                        if ($response.StatusCode -eq 200) {
                            Write-Log "Folder exists. Proceeding with download."
                            Write-SystemMessage -msg1 "- Remote folder exists. Proceeding with download." -msg1Color "Green"

                            # Proceed to download tasks from the folder
                            $tempFolder = "$env:TEMP\Tasks"
                            if (-not (Test-Path $tempFolder)) {
                                New-Item -ItemType Directory -Path $tempFolder | Out-Null
                            }

                            # Example logic to download and import tasks
                            $webRequest = Invoke-WebRequest -Uri $taskFile
                            $xmlFiles = $webRequest.Links | Where-Object { $_.href -match '\.xml$' }
                            
                            foreach ($xmlFile in $xmlFiles) {
                                $fileName = [System.IO.Path]::GetFileName($xmlFile.href)
                                $fileUrl = "$taskFile$fileName"
                                $downloadedFile = Join-Path -Path $tempFolder -ChildPath $fileName

                                Write-SystemMessage -msg1 "- Downloading task file: " -msg2 $fileUrl
                                Write-Log "Downloading task file: $fileUrl"
                                Invoke-WebRequest -Uri $fileUrl -OutFile $downloadedFile

                                # Import the task
                                Write-SystemMessage -msg1 "- Importing task: " -msg2 $downloadedFile
                                Write-Log "Importing task: $downloadedFile"
                                schtasks /create /tn "$key-$fileName" /xml $downloadedFile /f
                                Write-SystemMessage -msg1 "- Task $fileName imported successfully." -msg1Color "Green"
                            }
                        } else {
                            throw "Invalid response code $($response.StatusCode)"
                        }
                    } catch {
                        Write-ErrorMessage -msg "The remote folder does not exist or is inaccessible: $taskFile" -colour "Red"
                        Write-Log "Error: The remote folder does not exist or is inaccessible: $($_.Exception.Message)"
                        Return
                    }

                } else {
                    # Handle individual task files
                    try {
                        $response = Invoke-WebRequest -Uri $taskFile -Method Head -ErrorAction Stop
                        if ($response.StatusCode -eq 200) {
                            Write-Log "File exists. Proceeding with download."
                            Write-SystemMessage -msg1 "- Task file exists. Proceeding with download." -msg1Color "Green"
                            $tempTaskFile = "$env:TEMP\$key.xml"
                            Write-SystemMessage -msg1 "- Downloading task file from: " -msg2 $taskFile
                            Write-Log "Downloading task file from: $taskFile"
                            Invoke-WebRequest -Uri $taskFile -OutFile $tempTaskFile
                            $taskFile = $tempTaskFile
                        } else {
                            throw "Invalid response code $($response.StatusCode)"
                        }

                        # Import the task into Task Scheduler
                        Write-SystemMessage -msg1 "- Importing task: " -msg2 $taskFile
                        Write-Log "Importing task: $taskFile"
                        schtasks /create /tn $key /xml $taskFile /f
                        Write-SystemMessage -msg1 "- Task $key imported successfully." -msg1Color "Green"
                    } catch {
                        Write-ErrorMessage -msg "The task file does not exist or is inaccessible: $taskFile" -colour "Red"
                        Write-Log "Error: The task file does not exist or is inaccessible: $($_.Exception.Message)"
                        Return
                    }
                }
            }
            Write-Log "Scheduled Tasks imported successfully."
            Write-SuccessMessage -msg "Scheduled tasks imported successfully."
        } else {
            Write-Log "No scheduled tasks to import. Missing configuration."
            Write-SystemMessage -msg1 "No Scheduled tasks to import. Missing configuration." -msg1Color "Cyan"
        }
    } catch {
        Write-ErrorMessage -msg "Error importing tasks: $($_.Exception.Message)" -colour "Red"
        Write-Log "Error importing tasks: $($_.Exception.Message)"
        Return
    }
}




# Function to activate Windows
function Activate-Windows {
    try {
        $productKey = Get-ConfigValue -section "Activation" -key "ProductKey"
        $version = Get-ConfigValue -section "Activation" -key "Version"

        if ($productKey -and $version) {
            Write-SystemMessage -title "Activating Windows"
            Write-SystemMessage -msg1 "- Activating Windows with product key: " -msg2 $productKey
            Write-Log "Activating Windows with product key: $productKey and version: $version"
            slmgr.vbs /ipk $productKey
            slmgr.vbs /skms kms.server.address
            slmgr.vbs /ato
            Write-Log "Windows activated successfully."
            Write-SystemMessage -msg1 "- Windows activated successfully." -msg1Color "Green"
            Write-SuccessMessage -msg "Windows activation completed."
        } else {
            Write-Log "Windows activation not performed. Missing configuration."
            Write-SystemMessage -msg1 "Windows activation not performed. Missing configuration." -msg1Color "Cyan"
        }
    } catch {
        Write-ErrorMessage -msg "Error activating Windows: $($_.Exception.Message)" -colour "Red"
        Write-Log "Error activating Windows: $($_.Exception.Message)"
        Return
    }
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
    exit 3
}

# Execute functions
Clear-Host
Set-SystemCheckpoint
Set-ComputerName
Set-Locale
Set-SystemTimezone
Set-Wallpaper
Set-LockScreenImage
Install-Applications
Install-Office
Add-RegistryEntries
Remove-RegistryEntries
Set-PowerSettings
Set-WindowsUpdates
Set-SecuritySettings
Set-Services
Set-EnvironmentVariables
Import-Tasks
Install-Fonts
Install-GCPW
Install-ChromeEnterprise
Install-GoogleDrive
Activate-Windows

# Remove the configuration file if it was downloaded
if ($configFile -match [regex]::Escape("$env:TEMP\config.ini")) {
    Remove-Item -Path $configFile -Force -ErrorAction SilentlyContinue
    Write-Log "Temporary configuration file removed."
}


Write-Log "System configuration completed successfully."
Write-SystemMessage "System configuration completed successfully."
