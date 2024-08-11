
## Features to Add

- Enable bitlocker for drives (With our without TPM?) Options: Bitlocker="SystemDrive" or Bitlocker="All"
- Add chocolatey apps installer i.e. in the INI File:
  - ChocolateyApps="VLC,Steam,EpicGamesStore,Firefox" etc.

### Tweaks
- Option to bring back old context menu tweak and other tweaks under a tweaks Key
- Taskbar-Alignment="Centre" or Left
- StartMenu-ShowTaskview="False" or true
- StartMenu-ShowWidgets="False" or True

### Privacy
- PersonlisdAdvertising="False" or true
- Option to disable Start menu suggestions and windows advertising
- StartMenuTracking="False or True (Let windows improve start and search results by tracking app launches.)
- ActiityHistory="False" or True (store my activity history on this device)

## BUGFIXES
[] Fix Install-Apps function (Currently using just VLC for --id in winget and not working), need to find a way to have the apps appear as a list within the INI config file.

