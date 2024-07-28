# About
Winforge is your gateway to seamless configuration deployment on Windows machines from a simple INI configuration file. Effortlessly manage and apply system settings and streamline your Windows configuration processes.

## Overview

This PowerShell script automates the configuration of a Windows system using parameters specified in an INI file. It supports a wide range of configuration options, including setting the computer name, locale, timezone, installing applications, setting wallpapers and lock screens, modifying registry entries, configuring network settings, power settings, software updates, security settings, environment variables, importing tasks into Task Scheduler, and installing Google Chrome Enterprise, Google Credential Provider for Windows (GCPW), and Google Drive.

## Usage

### Running the Script Locally

To run the script locally, use the following command:

```powershell
.\install.ps1 -config="path\to\config.ini"
```

### Running the Script Remotely
```
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Graphixa/WinForge/main/winforge.ps1))) -config "https://raw.githubusercontent.com/Graphixa/WinforgeX/main/config.ini"
```

## INI File Setup

The INI file can contain the following sections and key-value pairs:

### [System]
- **ComputerName**: Desired computer name.
- **Locale**: Locale code (e.g., en-US).
- **Timezone**: Timezone ID (e.g., Pacific Standard Time).

### [Applications]
- **Apps**: Comma-separated list of applications to install via winget (e.g., notepad++,googlechrome,vlc).

### [Fonts]
- **Fonts**: Comma-separated list of fonts to install from Google Fonts (e.g., Roboto,OpenSans,Lato).

### [Office]
- **LicenseKey**: Office license key.
- **ProductID**: Office product ID (e.g., ProPlus2019Retail).
- **LanguageID**: Language ID (e.g., en-US).
- **UpdatesEnabled**: Enable or disable updates (TRUE/FALSE).
- **DisplayLevel**: Display level (e.g., Full).
- **SetupReboot**: Setup reboot option (e.g., Never).
- **Channel**: Update channel (e.g., SemiAnnual).
- **OfficeClientEdition**: Office client edition (32/64).

### [Backgrounds]
- **WallpaperPath**: Path to the wallpaper image.
- **LockScreenPath**: Path to the lock screen image.

### [Registry Add]
- **KeyName**: Registry key path.
- **Value**: Registry value name.
- **Type**: Registry value type (e.g., REG_DWORD).
- **Data**: Registry value data.

### [Registry Remove]
- **KeyName**: Registry key path.
- **Value**: Registry value name.

### [Network]
- **IPAddress**: IP address.
- **SubnetMask**: Subnet mask.
- **Gateway**: Gateway.
- **DNS1**: Primary DNS.
- **DNS2**: Secondary DNS.

### [PowerSettings]
- **PowerPlan**: Power plan (e.g., High performance).
- **SleepTimeout**: Sleep timeout in minutes.
- **HibernateTimeout**: Hibernate timeout in minutes.

### [SoftwareUpdates]
- **AutoUpdatesEnabled**: Enable or disable automatic updates (TRUE/FALSE).

### [SecuritySettings]
- **UACLevel**: User Account Control (UAC) level.
- **WindowsDefenderEnabled**: Enable or disable Windows Defender (TRUE/FALSE).

### [EnvironmentVariables]
- **VariableName**: Value of the environment variable.

### [GoogleGCPW]
- **DomainsAllowedToLogin**: Comma-separated list of domains allowed to log in.
- **EnrollmentToken**: GCPW enrollment token.

### [Tasks]
- **TaskFile**: Path or URL to the task XML file.

## Example INI File

```ini
[System]
ComputerName="MyComputer"
Locale="en-US"
Timezone="Pacific Standard Time"

[Applications]
Apps="notepad++,googlechrome,vlc"

[Fonts]
Fonts="Roboto,OpenSans,Lato"

[Office]
LicenseKey="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
ProductID="ProPlus2019Retail"
LanguageID="en-US"
UpdatesEnabled="TRUE"
DisplayLevel="Full"
SetupReboot="Never"
Channel="SemiAnnual"
OfficeClientEdition="64"

[Backgrounds]
WallpaperPath="C:\Path\To\Wallpaper.jpg"
LockScreenPath="C:\Path\To\LockScreen.jpg"

[Registry Add]
KeyName="HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System, Value=DisableLockScreenAppNotifications, Type=REG_DWORD, Data=1"
KeyName="HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System, Value=DisableTaskMgr, Type=REG_DWORD, Data=1"

[Registry Remove]
KeyName="HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System, Value=DisableLockScreenAppNotifications"

[Network]
IPAddress="192.168.1.100"
SubnetMask="255.255.255.0"
Gateway="192.168.1.1"
DNS1="8.8.8.8"
DNS2="8.8.4.4"

[PowerSettings]
PowerPlan="High performance"
SleepTimeout="30"
HibernateTimeout="60"

[SoftwareUpdates]
AutoUpdatesEnabled="TRUE"

[SecuritySettings]
UACLevel="2"
WindowsDefenderEnabled="TRUE"

[EnvironmentVariables]
CompanyName="MyCompany"
Department="IT"

[GoogleGCPW]
DomainsAllowedToLogin="example.com,anotherdomain.com"
EnrollmentToken="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

[Tasks]
TaskFile1="https://www.github.com/Acme/Winforge/Tasks/autologoff.xml"
TaskFile2="https://www.github.com/Acme/Winforge/Tasks/2ndTask.xml"
TaskFile3="C:\Tasks\Task3.xml"
TaskFile4="\\NETWORKSHARE\TASKS\Task4.xml"
```
