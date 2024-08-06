
## Features to Add
- Option to disable Start menu suggestions and windows advertising
- Enable bitlocker for drives (With our without TPM?) Options: Bitlocker="SystemDrive" or Bitlocker="All"
- Add app manifest option for Apps i.e. "AppManifest="www.github.com.au/applist.json""

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

## NOTES
- Operating out of: winforge-untested.ps1 for all correct system messaging.
- System messages enabled for:
  -  Install-Apps
  -  Set-Services 
  -  Install-Fonts


RENAME winforge-untested.ps1 to winforge.ps1 and rename old winforge.ps1 as winforge-backup-07.08.2024.ps1