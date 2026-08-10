using namespace System.Net

# Note: $sub (subscription id) and $DID (deployment id) are injected by the platform.
# This validation checks Microsoft Purview sensitivity label publishing state only.
# The lab deploys no Azure resources, so no Azure resource group lookup is required.
$rg = "m365-purview-$DID"
$count = 0
$found = $false

$policyName = "Zava Global Label Policy"
$requiredLabels = @(
    "Zava Public",
    "Zava Internal",
    "Zava Confidential",
    "Zava Highly Confidential"
)

function Get-PolicyLabelNames {
    param(
        [Parameter(Mandatory = $true)]
        $Policy,
        [Parameter(Mandatory = $true)]
        $AllLabels
    )

    $publishedLabelIds = @()

    if ($null -ne $Policy.Labels) {
        foreach ($labelRef in $Policy.Labels) {
            if ($null -ne $labelRef -and -not [string]::IsNullOrWhiteSpace([string]$labelRef)) {
                $publishedLabelIds += [string]$labelRef
            }
        }
    }

    $resolvedNames = @()
    foreach ($labelId in $publishedLabelIds) {
        $match = $AllLabels | Where-Object { $_.ImmutableId -eq $labelId -or $_.Guid -eq $labelId -or $_.Name -eq $labelId -or $_.DisplayName -eq $labelId }
        if ($null -ne $match) {
            foreach ($item in @($match)) {
                if (-not [string]::IsNullOrWhiteSpace($item.DisplayName)) {
                    $resolvedNames += [string]$item.DisplayName
                } elseif (-not [string]::IsNullOrWhiteSpace($item.Name)) {
                    $resolvedNames += [string]$item.Name
                }
            }
        }
    }

    return ($resolvedNames | Sort-Object -Unique)
}

function Connect-PurviewCompliance {
    # ExchangeOnlineManagement is not offered in the CloudLabs template module catalogue,
    # so the validator installs it on first run.
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    }
    Import-Module ExchangeOnlineManagement -ErrorAction Stop

    try {
        $existingConnection = Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object {
            $_.ConnectionUri -like '*compliance.protection.outlook.com*' -or $_.Name -like '*IPPSSession*'
        }
        if ($null -ne $existingConnection) { return }
    }
    catch {}

    $userName = if ($env:AzureAdUserEmail) { $env:AzureAdUserEmail } elseif ($env:AZUREADUSEREMAIL) { $env:AZUREADUSEREMAIL } else { $null }
    $userPassword = if ($env:AzureAdUserPassword) { $env:AzureAdUserPassword } elseif ($env:AZUREADUSERPASSWORD) { $env:AZUREADUSERPASSWORD } else { $null }

    if ([string]::IsNullOrWhiteSpace($userName) -or [string]::IsNullOrWhiteSpace($userPassword)) {
        throw "Validator could not obtain AzureAdUserEmail and AzureAdUserPassword for Compliance PowerShell sign-in."
    }

    # Non-interactive sign-in: -UserPrincipalName would prompt and hang the validator runtime.
    $securePassword = ConvertTo-SecureString $userPassword -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential ($userName, $securePassword)
    Connect-IPPSSession -Credential $credential -ErrorAction Stop | Out-Null
}

do {
    $count = $count + 1
    try {
        Set-AzContext -Subscription $sub -ErrorAction Stop

        Connect-PurviewCompliance

        $policy = Get-LabelPolicy -Identity $policyName -ErrorAction SilentlyContinue
        if ($null -eq $policy) {
            $message = @{
                Status  = "Failed"
                Message = "Label policy '$policyName' was not found. Create the policy and publish all four Zava labels."
            } | ConvertTo-Json
        } else {
            $allLabels = Get-Label -ErrorAction Stop
            $publishedLabelNames = Get-PolicyLabelNames -Policy $policy -AllLabels $allLabels
            $missingLabels = $requiredLabels | Where-Object { $_ -notin $publishedLabelNames }

            if ($missingLabels.Count -eq 0) {
                $found = $true
                $message = @{
                    Status  = "Succeeded"
                    Message = "Label policy '$policyName' exists and publishes all required labels: $($publishedLabelNames -join ', ')."
                } | ConvertTo-Json
            } else {
                $message = @{
                    Status  = "Failed"
                    Message = "Label policy '$policyName' exists, but it is missing these required labels: $($missingLabels -join ', '). Published labels resolved from the policy: $($publishedLabelNames -join ', ')."
                } | ConvertTo-Json
            }
        }

        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue

        Push-OutputBinding -Name Response -Clobber -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $message
        })
    }
    catch {
        try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch {}

        $message = @{
            Status  = "Failed"
            Message = "Error during check. Attempt $count of 3. Error: $($_.Exception.Message)"
        } | ConvertTo-Json
        Push-OutputBinding -Name Response -Clobber -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $message
        })
        Start-Sleep -Seconds 10
    }
} while ($count -lt 3 -and -not $found)

# Post-loop: if every attempt failed, emit a final failure JSON so CloudLabs
# always sees a structured result.
if (-not $found) {
    # Keep the last detailed result. Overwriting it here with a generic message is what
    # currently hides which labels were actually missing from the policy.
    if ([string]::IsNullOrWhiteSpace($message)) {
        $message = @{
            Status  = "Failed"
            Message = "Label policy '$policyName' not found or incomplete after 3 attempts. Required labels: $($requiredLabels -join ', ')."
        } | ConvertTo-Json
    }
    Push-OutputBinding -Name Response -Clobber -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $message
    })
}
