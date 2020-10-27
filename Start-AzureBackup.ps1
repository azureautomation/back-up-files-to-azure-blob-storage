<#
    .SYNOPSIS
        Creates a backup of the specified folders to Microsoft Azure

    .DESCRIPTION
        The Start-AzureBackup.ps1 script creates a backup of all the files in the specified folders to Azure Blob Storage. The script will check if any files within the given filter need to be copied either based on LastWriteTime (default) or based on the MD5 hash of the file content. If a file is newer, it will be copied to the Azure Storage Account.

    .PARAMETER Path
        One or more folders containing the files that will be copied to Azure.

    .PARAMETER Recurse
        Indicates that the items in the specified folders and all subfolders should be copied to Azure.

    .PARAMETER Filter
        Specifies the filter to use when looking for files to backup.

    .PARAMETER Exclude
        Specifies, as a string array, any items that need to be excluded from the backup job. These items can contain wildcards (eg. *.svn*).

    .PARAMETER Container
        The name of the container in the Azure storage account wher the files will be stored. This name should follow the container name prerequisites as defined by Azure.

    .PARAMETER Method
        Method to use when analyzing the file on Azure; valid values are either LastWrite or MD5Hash.

        LastWrite checks the LastWriteTime property of the local file, this property is compared with the lastwritetime metadata field in Azure. If the LastWriteTime of the local file is newer, the file is copied to Azure.

        MD5Hash compares the MD5 hash of the local file against the ContentMD5 property of the Azure Blob. If the hashes do not match, the file is assumed to be changed and is copied to Azure.

    .PARAMETER LogFile
        If this parameter is defined, all log messages will be written to the defined log file.

    .EXAMPLE
        Start-AzureBackup.ps1 -Path C:\Documents -Container backup2017

        Copies all files directly in path C:\Documents to a container in Azure named backup2017. Files which are already copied to Azure are compared based on LastWriteTime of the local file.

    .EXAMPLE
        Start-AzureBackup.ps1 -Path C:\Documents -Recurse

        Copies all files in C:\Documents and all files in the subfolders. Files which are already copied to Azure are compared based on LastWriteTime of the local file.

    .EXAMPLE
        Start-AzureBackup.ps1 -Path C:\Documents -Recurse -Method MD5Hash

        Copies all files in C:\Documents and all files in the subfolders. Files which are already copied to Azure are compared based on the MD5 hash of the file content.

    .EXAMPLE
        Start-AzureBackup.ps1 -Path C:\Documents -Recurse -Exclude *.svn*,*.git*

        Copies all files in C:\Documents and all files in the subfolders, but excludes any files which match the "*.svn*" or "*.git*" exclusion. Files which are already copied to Azure are compared based on LastWriteTime of the local file.
#>

<# Parameters #>
Param (
    [Parameter(Mandatory=$true,Position=0)][String[]]$Path,
    [Parameter(Mandatory=$false,Position=1)][Switch]$Recurse,
    [Parameter(Mandatory=$false,Position=2)][String]$Filter = "*",
    [Parameter(Mandatory=$false,Position=3)][String[]]$Exclude,
    [Parameter(Mandatory=$false,Position=4)][String]$Container = "backup",
    [Parameter(Mandatory=$false,Position=5)][ValidateSet("LastWrite","MD5Hash")][String]$Method = "LastWrite",
    [Parameter(Mandatory=$false,Position=6)][String]$LogFile
)

<# Global variables #>
    $Global:AzureStorageAccountName = "<STORAGE ACCOUNT NAME>"
    $Global:AzureStorageAccountKey = "<STORAGE ACCOUNT KEY>"

<# Functions #>
    Function Write-Log
    {
        Param (
            [Parameter(Mandatory=$true,Position=0)][String]$Value,
            [Parameter(Mandatory=$false,Position=1)][ConsoleColor]$Color = [ConsoleColor]::White
        )
        
        $date = ("[{0:yyyy-MM-dd HH:mm:ss}] " -f (Get-Date))
        Write-Host $date -ForegroundColor White -NoNewline
        Write-Host $Value -ForegroundColor $Color

        If ($LogFile -ne $null) {
            "$($date)$($Value)" | Add-Content -Path $LogFile
        }
    }

    Function ConvertTo-BlobName {
        Param (
            [Parameter(Mandatory=$true)][String]$Name
        )

        # Convert the full path to a valid Blob name
        $output = $Name.Replace("\","/").Replace(":","")

        # Append the computer name to prevent multiple computers to overwrite the data
        return "${env:COMPUTERNAME}/$output"
    }

    Function Get-MD5Hash {
        Param (
            [Parameter(Mandatory=$true)][String]$Path
        )

        If (Test-Path -Path $Path) {
            try {
                # Create the hasher and get the content
                $crypto = [System.Security.Cryptography.MD5]::Create()
                $content = [System.IO.File]::ReadAllBytes($Path)
                $hash = [System.Convert]::ToBase64String($crypto.ComputeHash($content))
                $content = $null
            } catch {
                $hash = $null
            }
        } Else {
            # File doesn't exist, can't calculate hash
            $hash = $null   
        }
        
        # Return the Base64 encoded MD5 hash
        return $hash
    }


<# Main script #>
    # Hide the progress bar
    $ProgressPreference = "SilentlyContinue"

    # Check if the Azure modules are loaded
    If ((Get-Module -Name Azure.Storage -ListAvailable).Count -le 0) {
        # Azure Storage module is not available
        # Exit script
        Write-Log -Value "ERROR: The Azure module is not available, exiting script" -Color Red
        Write-Log -Value "Please download the Azure PowerShell modules from https://azure.microsoft.com/en-us/downloads/" -Color Yellow

        return
    }

    # Initiate the Azure Storage Context
    $context = New-AzureStorageContext -StorageAccountName $Global:AzureStorageAccountName -StorageAccountKey $Global:AzureStorageAccountKey

    # Check if the defined container already exists
    Write-Log -Value "Checking availability of Azure container `"$Container`""
    try {
        $azcontainer = Get-AzureStorageContainer -Name $Container -Context $context -ErrorAction SilentlyContinue
    } catch {}

    If ($? -eq $false) {
        # Something went wrong, check the last error message
        If ($Error[0] -like "*Can not find the container*") {
            # Container doesn't exist, create a new one
            Write-Log -Value "Container `"$Container`" does not exist, trying to create container" -Color Yellow
            $azcontainer = New-AzureStorageContainer -Name $Container -Context $context -ErrorAction SilentlyContinue

            If ($azcontainer -eq $null) {
                # Couldn't create container
                Write-Log -Value "ERROR: could not create container `"$Container`"" -Color Red
                return
            } Else {
                # OK, container created
                Write-Log -Value "Container `"$Container`" successfully created" -Color Yellow
            }
        } ElseIf ($Error[0] -like "*Container name * is invalid*") {
            # Container name is invalid
            Write-Log -Value "ERROR: container name `"$Container`" is invalid" -Color Red
        } ElseIf ($Error[0] -like "*(403) Forbidden*") {
            # Storage Account key incorrect
            Write-Log -Value "ERROR: could not connect to Azure storage, please check the Azure Storage Account key" -Color Red
            return
        } ElseIf ($Error[0] -like "*(503) Server Unavailable*") {
            # Storage Account name incorrect
            Write-Log -Value "ERROR: could not connect to Azure storage, please check the Azure Storage Account name" -Color Red
            return
        } ElseIf ($Error[0] -like "*Please connect to internet*") {
            # No internet connection
            Write-Log -Value "ERROR: no internet connection found, please connect to the internet" -Color Red
            return
        }
    }

    # Retrieve the files in the given folders
    $files = @()
    ForEach ($localpath in $Path) {
        Write-Log -Value "Retrieving files from path $localpath"
        ForEach ($item in (Get-ChildItem -Path $Path -Recurse:($Recurse.ToBool()) -Filter $Filter | Where-Object {$_.PSIsContainer -eq $false})) {
            # Check if the exclusions need to be checked
            $addfile = $true
            If ($Exclude) {
                ForEach ($excludeitem in $Exclude) {
                    If ($item -like $excludeitem) {
                        # This file should be excluded
                        $addfile = $false
                    }
                }
            }

            If ($files -notcontains $item -and $addfile -eq $true) { $files += $item }
        }
    }

    # Parse each file
    Write-Log -Value "Found $($files.Count) files"
    ForEach ($file in ($files | Sort-Object -Property FullName)) {
        # Write log entry
        Write-Log -Value "Parsing file $($file.FullName)" -Color Yellow

        # Get the blob name for this file
        $blobname = ConvertTo-BlobName -Name $file.FullName

        # Check if the BLOB already exists
        $copyblob = $false
        $azblob = Get-AzureStorageBlob -Blob $blobname -Container $Container -Context $context -ErrorAction SilentlyContinue
        If ($azblob -ne $null) {
            # Blob already exists, check the lastwrite metadata
            $cloudblob = [Microsoft.WindowsAzure.Storage.Blob.CloudBlockBlob]$azblob.ICloudBlob
            If ($Method -eq "LastWrite") {
                Write-Log -Value "File exists on Azure Storage, checking LastWrite metadata"

                If ($cloudblob.Metadata.ContainsKey("lastwritetime")) {
                    # Convert the lastwritetime metadata
                    try { 
                        $remotedate = Get-Date ([Convert]::ToInt64($cloudblob.Metadata["lastwritetime"])) -ErrorAction SilentlyContinue

                        # Check if the lastwritetime of the local file is newer
                        If ($file.LastWriteTimeUTC -gt $remotedate) {
                            # Local file is newer, overwrite the Blob in Azure
                            Write-Log -Value "Local file is newer"
                            $copyblob = $true
                        } Else {
                            # Local file is newer, overwrite the Blob in Azure
                            Write-Log -Value "Local file is not newer, no need to copy file"
                            $copyblob = $false
                        }
                    } catch {
                        # Couldn't convert the lastwritetime field
                        Write-Log -Value "Lastwritetime metadata could not be converted, file needs to be copied again"
                        $copyblob = $true
                    }
                } Else {
                    # Remote Blob does not container lastwritetime metadata
                    # Overwrite the Blob
                    Write-Log -Value "Could not find lastwritetime metadata, file needs to be copied again"
                    $copyblob = $true
                }
            } ElseIf ($Method -eq "MD5Hash") {
                Write-Log -Value "File exists on Azure Storage, checking MD5 hash"

                # Retrieve the attributes (contains the Blob MD5 hash)
                $cloudblob.FetchAttributes()
                $localhash = Get-MD5Hash -Path $file.FullName

                If ($localhash -eq $null) {
                    # Could not calculate MD5 hash of local file
                    Write-Log -Value "WARNING: MD5 of local file could not be calculated, skipping upload" -Color Yellow
                    $copyblob = $false
                } ElseIf ($cloudblob.Properties.ContentMD5 -ne $localhash) {
                    # MD5 hashes are not equal, file changed
                    # Overwrite the file on Azure
                    Write-Log -Value "MD5 hashes do not match"
                    $copyblob = $true
                } Else {
                    # Local and remote MD5 hashes are equal, file did not change
                    Write-Log -Value "MD5 hashes match, no need to copy file"
                    $copyblob = $false
                }
            }
        } Else {
            # Blob doesn't exit, copy the file to Azure
            Write-Log -Value "File does not exist on Azure"
            $copyblob = $true
        }

        If ($copyblob -eq $true) {
            # Blob doesn't exist, upload the blob with lastwrite metadata
            Write-Log -Value "Copying local file $($file.Name) to blob $blobname in container $Container"

            try {
                $output = Set-AzureStorageBlobContent -File $file.FullName -Blob $blobname -Container $Container -Context $context -Metadata @{"lastwritetime" = $file.LastWriteTimeUTC.Ticks} -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Log -Value "ERROR: Could not copy file to Azure blob $($blobname): $($_.Exception.Message)" -Color Red
            }
        }
    }