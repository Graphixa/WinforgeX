# Function to add, modify, or remove registry settings, including creation of missing subkeys
function RegistryTouch {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("add", "remove")]
        [string]$action,

        [Parameter(Mandatory = $true)]
        [string]$path,

        [Parameter(Mandatory = $true)]
        [string]$name,

        [Parameter()]
        [ValidateSet("String", "ExpandString", "Binary", "DWord", "MultiString", "QWord")]
        [string]$type = "String",  # Default to String

        [Parameter()]
        [object]$value  # Changed to object to handle various data types
    )

    try {
        # Detect the base registry hive
        switch -regex ($path) {
            '^HKLM:\\|^HKEY_LOCAL_MACHINE\\' {
                $baseKey = "HKLM:"
                $pathWithoutHive = $path -replace '^HKLM:\\|^HKEY_LOCAL_MACHINE\\', ''
            }
            '^HKCU:\\|^HKEY_CURRENT_USER\\' {
                $baseKey = "HKCU:"
                $pathWithoutHive = $path -replace '^HKCU:\\|^HKEY_CURRENT_USER\\', ''
            }
            '^HKCR:\\|^HKEY_CLASSES_ROOT\\' {
                $baseKey = "HKCR:"
                $pathWithoutHive = $path -replace '^HKCR:\\|^HKEY_CLASSES_ROOT\\', ''
            }
            '^HKU:\\|^HKEY_USERS\\' {
                $baseKey = "HKU:"
                $pathWithoutHive = $path -replace '^HKU:\\|^HKEY_USERS\\', ''
            }
            '^HKCC:\\|^HKEY_CURRENT_CONFIG\\' {
                $baseKey = "HKCC:"
                $pathWithoutHive = $path -replace '^HKCC:\\|^HKEY_CURRENT_CONFIG\\', ''
            }
            default {
                Write-Log "Unsupported registry hive in path: $path"
                Write-ErrorMessage -msg "Unsupported registry hive."
                return
            }
        }

        # Build the full registry path
        $fullKeyPath = $baseKey
        $subKeyParts = $pathWithoutHive -split "\\"

        # Incrementally create any missing registry keys
        foreach ($part in $subKeyParts) {
            $fullKeyPath = Join-Path $fullKeyPath $part
            if (-not (Test-Path $fullKeyPath)) {
                Write-Log "Creating missing registry key: $fullKeyPath"
                New-Item -Path $fullKeyPath -Force -ErrorAction Stop | Out-Null
            }
        }

        # Now that all parent keys exist, handle the registry value
        if ($action -eq "add") {
            $itemExists = Get-ItemProperty -Path $fullKeyPath -Name $name -ErrorAction SilentlyContinue

            if (-not $itemExists) {
                Write-Log "Registry item does not exist. Creating item: $name with value: $value"
                New-ItemProperty -Path $fullKeyPath -Name $name -Value $value -PropertyType $type -Force -ErrorAction Stop | Out-Null
            } else {
                # Retrieve the current value with proper data type handling
                $currentValue = (Get-ItemProperty -Path $fullKeyPath -Name $name).$name

                # Convert current value and new value to the appropriate types for comparison
                switch ($type) {
                    "DWord" {
                        $currentValue = [int]$currentValue
                        $value = [int]$value
                    }
                    "QWord" {
                        $currentValue = [long]$currentValue
                        $value = [long]$value
                    }
                    "Binary" {
                        $currentValue = [Byte[]]$currentValue
                        $value = [Byte[]]$value
                    }
                    default {
                        $currentValue = [string]$currentValue
                        $value = [string]$value
                    }
                }

                if (-not ($currentValue -eq $value)) {
                    Write-Log "Registry value differs. Updating item: $name from $currentValue to $value"
                    Set-ItemProperty -Path $fullKeyPath -Name $name -Value $value -Force -ErrorAction Stop
                } else {
                    Write-Log "Registry item: $name with value: $value already exists. Skipping."
                }
            }
        } elseif ($action -eq "remove") {
            # Check if the registry value exists
            if (Get-ItemProperty -Path $fullKeyPath -Name $name -ErrorAction SilentlyContinue) {
                Write-Log "Removing registry item: $name from path: $fullKeyPath"
                Remove-ItemProperty -Path $fullKeyPath -Name $name -Force -ErrorAction Stop
            } else {
                Write-Log "Registry item: $name does not exist at path: $fullKeyPath. Skipping."
            }
        }
    } catch {
        Write-Log "Error modifying the registry: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Error modifying the registry: $($_.Exception.Message)"
    }
}
