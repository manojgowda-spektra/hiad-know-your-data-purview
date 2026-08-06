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

do {
    $count = $count + 1
    try {
        Set-AzContext -Subscription $sub -ErrorAction Stop

        if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
            throw "ExchangeOnlineManagement module is not installed. This validation requires Security & Compliance PowerShell cmdlets such as Connect-IPPSSession, Get-LabelPolicy, and Get-Label."
        }

        Import-Module ExchangeOnlineManagement -ErrorAction Stop

        $alreadyConnected = $false
        try {
            $existingConnection = Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object { $_.ConnectionUri -like '*compliance.protection.outlook.com*' -or $_.Name -like '*IPPSSession*' }
            if ($null -ne $existingConnection) {
                $alreadyConnected = $true
            }
        }
        catch {
            $alreadyConnected = $false
        }

        if (-not $alreadyConnected) {
            if (-not $env:AZUREADUSEREMAIL -or [string]::IsNullOrWhiteSpace($env:AZUREADUSEREMAIL)) {
                throw "No active Security & Compliance PowerShell session was found, and AZUREADUSEREMAIL is unavailable for Connect-IPPSSession."
            }

            Connect-IPPSSession -UserPrincipalName $env:AZUREADUSEREMAIL -ErrorAction Stop | Out-Null
        }

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

        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $message
        })
    }
    catch {
        $message = @{
            Status  = "Failed"
            Message = "Error during check. Attempt $count of 3. Error: $($_.Exception.Message)"
        } | ConvertTo-Json
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $message
        })
        Start-Sleep -Seconds 10
    }
} while ($count -lt 3 -and -not $found)

# Post-loop: if every attempt failed, emit a final failure JSON so CloudLabs
# always sees a structured result.
if (-not $found) {
    $message = @{
        Status  = "Failed"
        Message = "Label policy '$policyName' not found or incomplete after 3 attempts. Required labels: $($requiredLabels -join ', ')."
    } | ConvertTo-Json
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $message
    })
}
