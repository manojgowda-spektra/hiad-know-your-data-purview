Param (
    [Parameter(Mandatory = $true)]
    [string]$AzureUserName,

    [string]$AzurePassword,

    [string]$AzureTenantID,

    [string]$AzureSubscriptionID,

    [string]$ODLID,

    [string]$InstallCloudLabsShadow,

    [string]$DeploymentID,

    [string]$vmAdminUsername,

    [string]$vmAdminPassword,

    [string]$trainerUserName,

    [string]$trainerUserPassword
)

# HIAD Use Case 2 - Know Your Data (Microsoft Purview)
# Adapted from the working HIAD Security Hack bootstrap.
# This lab is browser-based against the Microsoft Purview portal, so the reference
# script's Chocolatey / VS Code / Git installation has been removed - it added
# several minutes to provisioning with no learning benefit here.

Start-Transcript -Path C:\WindowsAzure\Logs\CloudLabsCustomScriptExtension.txt -Append

[Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

Function CreateCredFile($AzureUserName, $AzurePassword, $AzureTenantID, $AzureSubscriptionID, $DeploymentID)
{
    $WebClient = New-Object System.Net.WebClient
    New-Item -ItemType directory -Path C:\LabFiles -Force

    $WebClient.DownloadFile("https://experienceazure.blob.core.windows.net/templates/cloudlabs-common/AzureCreds.txt","C:\LabFiles\AzureCreds.txt")
    $WebClient.DownloadFile("https://experienceazure.blob.core.windows.net/templates/cloudlabs-common/AzureCreds.ps1","C:\LabFiles\AzureCreds.ps1")

    (Get-Content -Path "C:\LabFiles\AzureCreds.txt") |
        ForEach-Object {
            $_ -Replace "AzureUserNameValue", "$AzureUserName" `
               -Replace "AzurePasswordValue", "$AzurePassword" `
               -Replace "AzureTenantIDValue", "$AzureTenantID" `
               -Replace "AzureSubscriptionIDValue", "$AzureSubscriptionID" `
               -Replace "DeploymentIDValue", "$DeploymentID"
        } | Set-Content -Path "C:\LabFiles\AzureCreds.txt"

    (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") |
        ForEach-Object {
            $_ -Replace "AzureUserNameValue", "$AzureUserName" `
               -Replace "AzurePasswordValue", "$AzurePassword" `
               -Replace "AzureTenantIDValue", "$AzureTenantID" `
               -Replace "AzureSubscriptionIDValue", "$AzureSubscriptionID" `
               -Replace "DeploymentIDValue", "$DeploymentID"
        } | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"

    Copy-Item "C:\LabFiles\AzureCreds.txt" -Destination "C:\Users\Public\Desktop"
}

CreateCredFile $AzureUserName $AzurePassword $AzureTenantID $AzureSubscriptionID $DeploymentID

Function updateVMShadowFile
{
    # Replace vmAdminUsernameValue with VM Admin UserName in script content
    $drivepath = "C:\Users\Public\Documents"
    if (Test-Path "$drivepath\Shadow.ps1") {
        (Get-Content -Path "$drivepath\Shadow.ps1") |
            ForEach-Object {
                $_ -Replace "vmAdminUsernameValue", "$vmAdminUsername"
            } | Set-Content -Path "$drivepath\Shadow.ps1"
    }

    # Update trainer user password
    net user $trainerUserName $trainerUserPassword
}

updateVMShadowFile

# Open the Microsoft Purview portal on first sign-in so participants start in the right place.
Function SetPurviewStartPage
{
    $shortcut = "C:\Users\Public\Desktop\Microsoft Purview portal.url"
    Set-Content -Path $shortcut -Value "[InternetShortcut]`r`nURL=https://purview.microsoft.com"
}

SetPurviewStartPage

Start-Sleep -Seconds 10

Stop-Transcript
