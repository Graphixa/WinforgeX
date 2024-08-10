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
