# About
Winforge is a simple tool for seamless configuration deployment on Windows machines all from a simple INI configuration file hosted locally, on a network share or online via a private github repo, or google drive or dropbox link. 

## Overview
This PowerShell script automates the configuration of a Windows system using parameters specified in an INI file. It supports a wide range of configuration options, including:
- Setting the computer name,
- Locale,
- Timezone,
- Installing applications,
- Setting wallpapers and lock screens,
- Adding or removing registry entries,
- Network settings,
- Power settings,
- Windows updates,
- Security settings,
- Setting environment variables,
- Importing tasks into Task Scheduler, and
- Installing Google Chrome Enterprise, Google Credential Provider for Windows (GCPW), and Google Drive.

## Usage

### Running the Script Locally

Download a copy of the script and run it locally, use the following command:

```powershell
.\install.ps1 -config="path\to\config.ini"
```

### Running the Script Remotely
```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Graphixa/WinforgeX/main/winforge.ps1))) -config "https://raw.githubusercontent.com/Graphixa/WinforgeX/main/config.ini"
```

## INI File Setup
For detailed information on each configuration option, refer to the [Configuration Guide](https://github.com/Graphixa/WinforgeX/wiki/WinForgeX-Configuration-Script-Knowledge-Base).

## Requirements

- Windows 11 (Can be run on Windows 10 but Winget must be installed)
- **Winget** must be installed to install applications using the script
- Ability to run PowerShell scripts on your system - use the following to enable the running of scripts:

> [!NOTE]
> To enable the running of Powershell scripts on your system, open Powershell as administrator and run the following command:
```
set-executionpolicy bypass
```

## Contributing
Feel free to contribute to this project by submitting issues or pull requests. 

## License 
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

This project is licensed under the [MIT License](LICENSE) - see the [LICENSE](LICENSE) file for details.


## Fork It 🍴
Feel free to fork it and make it your own!
