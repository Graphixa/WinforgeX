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
