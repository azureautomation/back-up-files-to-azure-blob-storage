Back up files to Azure Blob Storage
===================================

            
Description
This script creates a backup of all the files in the specified folders to Azure Blob storage. The script will check if any files within the given filter need to be copied either based on LastWriteTime (default) or based on the MD5 hash of the file
 content. If a file is newer, it will be copied to the Azure Storage Account.
Usage
To use the script, update AzureStorageAccountName and AzureStorageAccountKey variables on line 66 and 67 with your specific storage account name and key (primary or secondary). The script will create the container on Azure Storage if needed and writes
 the files in the folder structure as found on the computer executing the command. The script will prepend the computer name to allow running the script from multiple computers.






Use 'Get-Help Start-AzureBackup.ps1 -Full' to retrieve full help information and examples.

Prerequisites
This script needs to Azure PowerShell modules installed, which can be downloaded from [https://azure.microsoft.com/en-us/downloads/](https://azure.microsoft.com/en-us/downloads/). After creating an Azure Storage Account,
 copy the account name and primary or secondary key to the PowerShell script.
Code








 


        
    
TechNet gallery is retiring! This script was migrated from TechNet script center to GitHub by Microsoft Azure Automation product group. All the Script Center fields like Rating, RatingCount and DownloadCount have been carried over to Github as-is for the migrated scripts only. Note : The Script Center fields will not be applicable for the new repositories created in Github & hence those fields will not show up for new Github repositories.
