using namespace System.Net

$count = 0
$found = $false

function Test-LocationEnabled {
    param(
        [Parameter(Mandatory = $false)]
        $Value
    )

    if ($null -eq $Value) {
        return $false
    }

    if ($Value -is [System.Array]) {
        foreach ($item in $Value) {
            if ($null -ne $item -and $item.ToString() -ne 'None') {
                return $true
            }
        }
        return $false
    }

    return $Value.ToString() -ne 'None'
}

function Get-MinCountForSensitiveType {
    param(
        [Parameter(Mandatory = $true)]
        $ContentContainsSensitiveInformation,
        [Parameter(Mandatory = $true)]
        [string]$SensitiveTypeName
    )

    foreach ($entry in $ContentContainsSensitiveInformation) {
        $entryString = $entry | ConvertTo-Json -Depth 10
        if ($entryString -match [regex]::Escape($SensitiveTypeName)) {
            if ($entry.PSObject.Properties.Name -contains 'minCount') {
                return [int]$entry.minCount
            }
            if ($entry.PSObject.Properties.Name -contains 'MinCount') {
                return [int]$entry.MinCount
            }
            if ($entry.PSObject.Properties.Name -contains 'mincount') {
                return [int]$entry.mincount
            }
        }
    }

    return $null
}

do {
    $count = $count + 1
    try {
        Set-AzContext -Subscription $sub -ErrorAction Stop | Out-Null

        $policyName = 'Zava Auto-Label Policy'
        $policy = Get-AutoSensitivityLabelPolicy -Identity $policyName -ErrorAction Stop
        $rule = Get-AutoSensitivityLabelRule -Policy $policyName -ErrorAction Stop | Select-Object -First 1

        $allLabels = Get-Label -ErrorAction Stop
        $referenceLabel = $allLabels | Where-Object {
            $_.Name -match 'Highly Confidential' -and $_.Name -notlike 'Zava*'
        } | Select-Object -First 1

        if ($null -eq $referenceLabel) {
            throw "Could not locate the pre-published reference Highly Confidential label in the tenant."
        }

        $sharePointEnabled = Test-LocationEnabled -Value $policy.SharePointLocation
        $oneDriveEnabled = Test-LocationEnabled -Value $policy.OneDriveLocation
        $exchangeEnabled = Test-LocationEnabled -Value $policy.ExchangeLocation
        $simulationMode = $policy.Mode -eq 'TestWithoutNotifications'

        $labelMatches = ($policy.ApplySensitivityLabel -eq $referenceLabel.ImmutableId) -or
                        ($policy.ApplySensitivityLabel -eq $referenceLabel.Guid) -or
                        ($policy.ApplySensitivityLabel -eq $referenceLabel.Name)

        $sensitiveInfoConfig = $rule.ContentContainsSensitiveInformation
        $creditCardMinCount = Get-MinCountForSensitiveType -ContentContainsSensitiveInformation $sensitiveInfoConfig -SensitiveTypeName 'Credit Card Number'
        $ssnMinCount = Get-MinCountForSensitiveType -ContentContainsSensitiveInformation $sensitiveInfoConfig -SensitiveTypeName 'U.S. Social Security Number (SSN)'
        if ($null -eq $ssnMinCount) {
            $ssnMinCount = Get-MinCountForSensitiveType -ContentContainsSensitiveInformation $sensitiveInfoConfig -SensitiveTypeName 'U.S. Social Security Number'
        }

        $hasCreditCard = $null -ne $creditCardMinCount
        $hasSsn = $null -ne $ssnMinCount
        $thresholdsMatch = ($creditCardMinCount -eq 5) -and ($ssnMinCount -eq 5)

        if ($simulationMode -and $labelMatches -and $sharePointEnabled -and $oneDriveEnabled -and $exchangeEnabled -and $hasCreditCard -and $hasSsn -and $thresholdsMatch) {
            $found = $true
            $message = @{
                Status  = 'Succeeded'
                Message = "Auto-labeling policy '$policyName' is configured in simulation mode, applies reference label '$($referenceLabel.Name)', targets SharePoint, OneDrive, and Exchange, and includes Credit Card Number and U.S. Social Security Number with minimum count 5."
            } | ConvertTo-Json
        }
        else {
            $failureReasons = @()

            if (-not $simulationMode) {
                $failureReasons += "Mode is '$($policy.Mode)' instead of 'TestWithoutNotifications' (simulation mode)."
            }
            if (-not $labelMatches) {
                $failureReasons += "Applied label '$($policy.ApplySensitivityLabel)' does not match the reference Highly Confidential label '$($referenceLabel.Name)'."
            }
            if (-not $sharePointEnabled) {
                $failureReasons += 'SharePoint is not included in policy locations.'
            }
            if (-not $oneDriveEnabled) {
                $failureReasons += 'OneDrive is not included in policy locations.'
            }
            if (-not $exchangeEnabled) {
                $failureReasons += 'Exchange is not included in policy locations.'
            }
            if (-not $hasCreditCard) {
                $failureReasons += 'Credit Card Number is not present in the policy rule.'
            }
            if (-not $hasSsn) {
                $failureReasons += 'U.S. Social Security Number (SSN) is not present in the policy rule.'
            }
            if ($hasCreditCard -and $creditCardMinCount -ne 5) {
                $failureReasons += "Credit Card Number minimum count is '$creditCardMinCount' instead of '5'."
            }
            if ($hasSsn -and $ssnMinCount -ne 5) {
                $failureReasons += "U.S. Social Security Number minimum count is '$ssnMinCount' instead of '5'."
            }

            $message = @{
                Status  = 'Failed'
                Message = ($failureReasons -join ' ')
            } | ConvertTo-Json
        }

        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $message
        })
    }
    catch {
        $message = @{
            Status  = 'Failed'
            Message = "Error during check. Attempt $count of 3. Error: $($_.Exception.Message)"
        } | ConvertTo-Json
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $message
        })
        Start-Sleep -Seconds 10
    }
} while ($count -lt 3 -and -not $found)

if (-not $found) {
    $message = @{
        Status  = 'Failed'
        Message = "Auto-labeling policy 'Zava Auto-Label Policy' was not validated successfully after 3 attempts."
    } | ConvertTo-Json
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $message
    })
}
