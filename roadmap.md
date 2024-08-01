- Add option in config file to choose whether to install Google Drive, Google Chrome and GCPW + enrollment token settings
- option to disable Start menu suggestions and windows advertising
- Option to bring back old context menu tweak and other tweaks under a tweaks Key
- ! Check the DNS setting from Powershell script as it broke the adaptor last time.
  - ! Might need to have an option to choose the interface (wifi/ethernet/both)
  - Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses ("1.1.1.1","1.0.0.1")
  - Set-DnsClientServerAddress -InterfaceAlias "Wi-fi" -ServerAddresses ("1.1.1.1","1.0.0.1")
- Enable bitlocker for drives (With our without TPM?) Options: Bitlocker="SystemDrive" or Bitlocker="All"




