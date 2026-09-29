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

    # The service does not return a flat list. ContentContainsSensitiveInformation
    # comes back as a nested graph - an array of groups, each holding a
    # sensitivetypes array - so the type name matches somewhere inside the JSON
    # while the top-level entry has no mincount property at all. Reading mincount
    # off the outer entry therefore returns null for a correctly configured rule.
    # Walk the graph and read mincount from the node that carries the matching name.

    function Get-NodeValue {
        param([object]$Node, [string[]]$Keys)
        foreach ($key in $Keys) {
            if ($Node -is [System.Collections.IDictionary]) {
                foreach ($k in $Node.Keys) {
                    if ("$k" -eq $key) { return $Node[$k] }
                }
            } else {
                $prop = $Node.PSObject.Properties | Where-Object { $_.Name -eq $key } | Select-Object -First 1
                if ($prop) { return $prop.Value }
            }
        }
        return $null
    }

    function Find-MinCount {
        param([object]$Node, [string]$Target, [int]$Depth = 0)

        if ($null -eq $Node -or $Depth -gt 12) { return $null }
        if ($Node -is [string] -or $Node -is [ValueType]) { return $null }

        $isRecord = $Node -is [System.Collections.IDictionary] -or
                    ($Node.PSObject -and $Node.PSObject.Properties.Name.Count -gt 0 -and
                     -not ($Node -is [System.Collections.IEnumerable]))

        if ($isRecord) {
            $name = Get-NodeValue -Node $Node -Keys @('name', 'Name')
            if ($name -and "$name".Trim() -eq $Target.Trim()) {
                $min = Get-NodeValue -Node $Node -Keys @('mincount', 'minCount', 'MinCount')
                if ($null -ne $min -and "$min" -match '^\s*(\d+)\s*$') {
                    return [int]$matches[1]
                }
                # A type named without an explicit mincount defaults to 1 in the service.
                return 1
            }

            $children = @()
            if ($Node -is [System.Collections.IDictionary]) {
                foreach ($k in $Node.Keys) { $children += , $Node[$k] }
            } else {
                foreach ($p in $Node.PSObject.Properties) { $children += , $p.Value }
            }
            foreach ($child in $children) {
                $r = Find-MinCount -Node $child -Target $Target -Depth ($Depth + 1)
                if ($null -ne $r) { return $r }
            }
            return $null
        }

        if ($Node -is [System.Collections.IEnumerable]) {
            foreach ($item in $Node) {
                $r = Find-MinCount -Node $item -Target $Target -Depth ($Depth + 1)
                if ($null -ne $r) { return $r }
            }
        }

        return $null
    }

    # No text-scan fallback here on purpose. An earlier version scanned the whole
    # serialised condition for the type name and then for any 'mincount' anywhere in
    # that same dump, which is fail-open: a rule whose description merely mentions
    # 'Credit Card Number and U.S. Social Security Number (SSN)' alongside an unrelated
    # mincount of 5 was reported as correctly configured. The walk above already
    # handles every shape the service returns - flat hashtables, the nested
    # groups/sensitivetypes graph, and the deserialised PSCustomObject form - so a null
    # here means the type genuinely is not in the condition, and the caller reports that.
    return Find-MinCount -Node $ContentContainsSensitiveInformation -Target $SensitiveTypeName
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
        Set-AzContext -Subscription $sub -ErrorAction Stop | Out-Null

        Connect-PurviewCompliance

        $policyName = 'Zava Auto-Label Policy'
        $policy = Get-AutoSensitivityLabelPolicy -Identity $policyName -ErrorAction Stop
        # A policy with no rule is the normal state until the attendee adds one, and
        # Get-AutoSensitivityLabelRule simply returns nothing in that case rather than
        # throwing. Passing the resulting null into Get-MinCountForSensitiveType raises a
        # parameter-binding error, so the attendee sees a .NET exception after three
        # retries instead of the failure reason below. Track it and skip the reads.
        $rules = @(Get-AutoSensitivityLabelRule -Policy $policyName -ErrorAction Stop)
        $hasRule = $rules.Count -gt 0

        $allLabels = Get-Label -ErrorAction Stop
        $targetLabelName = 'Zava Highly Confidential'
        $targetLabel = $allLabels | Where-Object {
            $_.DisplayName -eq $targetLabelName -or $_.Name -eq $targetLabelName
        } | Select-Object -First 1

        # A missing label is reported as a structured Failed result below rather than
        # thrown, so the attendee is told which task to complete instead of seeing a
        # generic 'Error during check' after three retries.

        $sharePointEnabled = Test-LocationEnabled -Value $policy.SharePointLocation
        $oneDriveEnabled = Test-LocationEnabled -Value $policy.OneDriveLocation
        $exchangeEnabled = Test-LocationEnabled -Value $policy.ExchangeLocation
        $simulationMode = $policy.Mode -eq 'TestWithoutNotifications'

        $labelMatches = $false
        if ($null -ne $targetLabel) {
            $labelMatches = ($policy.ApplySensitivityLabel -eq $targetLabel.ImmutableId) -or
                            ($policy.ApplySensitivityLabel -eq $targetLabel.Guid) -or
                            ($policy.ApplySensitivityLabel -eq $targetLabel.Name) -or
                            ($policy.ApplySensitivityLabel -eq $targetLabel.DisplayName)
        }

        # A rule built in the portal keeps its condition in AdvancedRule (JSON) and leaves
        # ContentContainsSensitiveInformation empty; a rule built with
        # New-AutoSensitivityLabelRule fills ContentContainsSensitiveInformation. Both were
        # seen on live tenants (SMB run 2, 28 Sep 2026; main lab, 29 Sep 2026). Read
        # whichever is populated, for every rule: the portal writes one rule per location,
        # and one under-configured location must not hide behind a correct one.
        $ccCounts = @()
        $ssnCounts = @()
        foreach ($r in $rules) {
            $cfg = $r.ContentContainsSensitiveInformation
            if ($null -eq $cfg -or @($cfg).Count -eq 0) {
                $cfg = $null
                if (-not [string]::IsNullOrWhiteSpace([string]$r.AdvancedRule)) {
                    try { $cfg = [string]$r.AdvancedRule | ConvertFrom-Json -ErrorAction Stop } catch { $cfg = $null }
                }
            }
            $cc = $null
            $ssn = $null
            if ($null -ne $cfg) {
                $cc = Get-MinCountForSensitiveType -ContentContainsSensitiveInformation $cfg -SensitiveTypeName 'Credit Card Number'
                $ssn = Get-MinCountForSensitiveType -ContentContainsSensitiveInformation $cfg -SensitiveTypeName 'U.S. Social Security Number (SSN)'
                if ($null -eq $ssn) {
                    $ssn = Get-MinCountForSensitiveType -ContentContainsSensitiveInformation $cfg -SensitiveTypeName 'U.S. Social Security Number'
                }
            }
            $ccCounts += , $cc
            $ssnCounts += , $ssn
        }

        $hasCreditCard = $hasRule -and -not ($ccCounts -contains $null)
        $hasSsn = $hasRule -and -not ($ssnCounts -contains $null)
        $creditCardMinCount = ($ccCounts | Where-Object { $null -ne $_ } | Measure-Object -Minimum).Minimum
        $ssnMinCount = ($ssnCounts | Where-Object { $null -ne $_ } | Measure-Object -Minimum).Minimum
        $thresholdsMatch = $hasCreditCard -and $hasSsn -and
                           (@($ccCounts | Where-Object { $_ -ne 5 }).Count -eq 0) -and
                           (@($ssnCounts | Where-Object { $_ -ne 5 }).Count -eq 0)

        if ($simulationMode -and $labelMatches -and $sharePointEnabled -and $oneDriveEnabled -and $exchangeEnabled -and $hasCreditCard -and $hasSsn -and $thresholdsMatch) {
            $found = $true
            $message = @{
                Status  = 'Succeeded'
                Message = "Auto-labeling policy '$policyName' is configured in simulation mode, applies the '$targetLabelName' label, targets SharePoint, OneDrive, and Exchange, and includes Credit Card Number and U.S. Social Security Number with minimum count 5."
            } | ConvertTo-Json
        }
        else {
            $failureReasons = @()

            if (-not $simulationMode) {
                $failureReasons += "Mode is '$($policy.Mode)' instead of 'TestWithoutNotifications' (simulation mode)."
            }
            if (-not $labelMatches) {
                if ($null -eq $targetLabel) {
                    $failureReasons += "The '$targetLabelName' label does not exist in this tenant. Complete Challenge 2 Task 1 and Task 2 before validating this step."
                }
                else {
                    $failureReasons += "Applied label '$($policy.ApplySensitivityLabel)' does not match the '$targetLabelName' label."
                }
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
            if (-not $hasRule) {
                # Reported on its own: without a rule there is no sensitive information
                # configuration to comment on, so the per-type reasons below would only
                # repeat this one.
                $failureReasons += 'The policy has no rule. Add a rule with Credit Card Number and U.S. Social Security Number (SSN) at a minimum count of 5.'
            }
            if ($hasRule -and -not $hasCreditCard) {
                $failureReasons += 'Credit Card Number is not present in the policy rule.'
            }
            if ($hasRule -and -not $hasSsn) {
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

        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue

        Push-OutputBinding -Name Response -Clobber -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $message
        })
    }
    catch {
        try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch {}

        $message = @{
            Status  = 'Failed'
            Message = "Error during check. Attempt $count of 3. Error: $($_.Exception.Message)"
        } | ConvertTo-Json
        Push-OutputBinding -Name Response -Clobber -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $message
        })
        Start-Sleep -Seconds 10
    }
} while ($count -lt 3 -and -not $found)

if (-not $found) {
    # Keep the last detailed result. Overwriting it here with a generic message is what
    # currently hides every specific failure reason from the attendee.
    if ([string]::IsNullOrWhiteSpace($message)) {
        $message = @{
            Status  = 'Failed'
            Message = "Auto-labeling policy 'Zava Auto-Label Policy' was not validated successfully after 3 attempts."
        } | ConvertTo-Json
    }
    Push-OutputBinding -Name Response -Clobber -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $message
    })
}
