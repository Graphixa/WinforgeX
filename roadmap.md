
## Features to Add
- Option to disable Start menu suggestions and windows advertising
- Enable bitlocker for drives (With our without TPM?) Options: Bitlocker="SystemDrive" or Bitlocker="All"
- Add chocolatey apps installer i.e. in the INI File:
  - ChocolateyApps="VLC,Steam,EpicGamesStore,Firefox" etc.
- Take Snapshot BEFORE Running any Winforge application so you can roll back.

### Tweaks
- Option to bring back old context menu tweak and other tweaks under a tweaks Key
- Taskbar-Alignment="Centre" or Left
- StartMenu-ShowTaskview="False" or true
- StartMenu-ShowWidgets="False" or True

### Privacy
- PersonlisdAdvertising="False" or true
- StartMenuTracking="False or True (Let windows improve start and search results by tracking app launches.)
- ActiityHistory="False" or True (store my activity history on this device)
-

## BUGFIXES
[] Fix Install-Apps function (Currently using just VLC for --id in winget and not working), need to find a way to have the apps appear as a list within the INI config file.
[] Check if Windows Features are already enabled/disabled and skip if config and current state are the same.
[] Set-ComputerName needs to have a check that checks if the computername is different from the config file.
Check if Office is already installed and skip if it is.
[] Speed up Invoke-WebRequests downloading for Google Drive etc.

