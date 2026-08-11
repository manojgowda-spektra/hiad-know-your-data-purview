using namespace System.Net

# Note: $sub (subscription id) and $DID (deployment id) are injected by the platform.
$rg = "purview-$DID"
$count = 0
$found = $false

function Get-PolicyLocationValues {
    param(
        [object]$Policy,
        [string[]]$PropertyNames
    )

    $values = @()
    foreach ($propertyName in $PropertyNames) {
        if ($Policy.PSObject.Properties.Name -contains $propertyName) {
            $propertyValue = $Policy.$propertyName
            if ($null -ne $propertyValue) {
                if ($propertyValue -is [string]) {
                    if ($propertyValue.Trim() -ne '') {
                        $values += $propertyValue
                    }
                }
                elseif ($propertyValue -is [System.Collections.IEnumerable]) {
                    foreach ($item in $propertyValue) {
                        if ($null -ne $item -and "$item".Trim() -ne '') {
                            $values += "$item"
                        }
                    }
                }
                elseif ("$propertyValue".Trim() -ne '') {
                    $values += "$propertyValue"
                }
            }
        }
    }

    return $values
}

function Get-PolicyModeText {
    param([object]$Policy)

    $modeCandidates = @()
    foreach ($name in @('Mode','EnforcementMode','State','SimulationMode')) {
        if ($Policy.PSObject.Properties.Name -contains $name -and $null -ne $Policy.$name) {
            $modeCandidates += "$($Policy.$name)"
        }
    }

    return ($modeCandidates -join '; ')
}

function Test-IsSimulationMode {
    param([object]$Policy)

    $modeText = (Get-PolicyModeText -Policy $Policy).ToLowerInvariant()
    return (
        $modeText -match 'simulation' -or
        $modeText -match '^test' -or
        $modeText -match 'audit'
    )
}

function Get-RuleText {
    param([object[]]$Rules)

    # -Width matters. Without it Out-String wraps at the host console width (80
    # columns under the CloudLabs Functions host) and silently truncates long
    # property values such as a rule's Comment or its notification text, so a
    # correctly configured rule reads as a failure.
    $parts = @()
    foreach ($rule in $Rules) {
        $parts += ($rule | Format-List * | Out-String -Width 8192)
    }

    return ($parts -join "`n")
}

function Test-RuleContainsAll {
    param(
        [string]$RuleText,
        [string[]]$RequiredPatterns
    )

    foreach ($pattern in $RequiredPatterns) {
        if ($RuleText -notmatch $pattern) {
            return $false
        }
    }

    return $true
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

        if (-not (Get-Command Get-DlpCompliancePolicy -ErrorAction SilentlyContinue)) {
            throw 'Get-DlpCompliancePolicy cmdlet is not available in the validator runtime.'
        }

        $blockPolicyName = 'Block External Sharing of Highly Confidential'
        $aiPolicyName = 'Protect Data from AI Apps'

        $blockPolicy = Get-DlpCompliancePolicy -Identity $blockPolicyName -ErrorAction Stop -IncludeRulesMetadata
        $aiPolicy = Get-DlpCompliancePolicy -Identity $aiPolicyName -ErrorAction Stop -IncludeRulesMetadata

        $blockRules = @(Get-DlpComplianceRule -Policy $blockPolicyName -ErrorAction Stop)
        $aiRules = @(Get-DlpComplianceRule -Policy $aiPolicyName -ErrorAction Stop)

        $blockLocations = Get-PolicyLocationValues -Policy $blockPolicy -PropertyNames @(
            'SharePointLocation','OneDriveLocation','ExchangeLocation','TeamsLocation',
            'SharePointLocationException','OneDriveLocationException','ExchangeLocationException','TeamsLocationException'
        )
        $aiLocations = Get-PolicyLocationValues -Policy $aiPolicy -PropertyNames @(
            'EndpointDlpLocation','EndpointDlpLocationException','DeviceLocation','DevicesLocation'
        )

        $blockRuleText = Get-RuleText -Rules $blockRules
        $aiRuleText = Get-RuleText -Rules $aiRules

        $blockInSimulation = Test-IsSimulationMode -Policy $blockPolicy
        $aiInSimulation = Test-IsSimulationMode -Policy $aiPolicy

        $blockHasExpectedLocations = $false
        if (($blockLocations | Measure-Object).Count -gt 0) {
            $blockLocationText = ($blockLocations -join ' | ').ToLowerInvariant()
            if (
                $blockLocationText -match 'sharepoint' -or
                $blockLocationText -match 'onedrive' -or
                $blockLocationText -match 'exchange' -or
                $blockLocationText -match 'teams' -or
                $blockLocationText -match 'all'
            ) {
                $blockHasExpectedLocations = $true
            }
        }

        $aiHasDeviceScope = $false
        if (($aiLocations | Measure-Object).Count -gt 0) {
            $aiLocationText = ($aiLocations -join ' | ').ToLowerInvariant()
            if ($aiLocationText -match 'all' -or $aiLocationText -match 'device' -or $aiLocationText -match 'endpoint') {
                $aiHasDeviceScope = $true
            }
        }
        else {
            $aiPolicyText = ($aiPolicy | Format-List * | Out-String -Width 8192).ToLowerInvariant()
            if ($aiPolicyText -match 'endpoint' -or $aiPolicyText -match 'device') {
                $aiHasDeviceScope = $true
            }
        }

        $blockHasRequiredLogic = Test-RuleContainsAll -RuleText $blockRuleText.ToLowerInvariant() -RequiredPatterns @(
            'highly confidential|sensitivity label',
            'outside|external',
            'policy tip|user notification|notify',
            'alert|incident',
            'blockaccess|restrictaccess|block everyone|block people outside your organization'
        )

        $aiHasRequiredLogic = Test-RuleContainsAll -RuleText $aiRuleText.ToLowerInvariant() -RequiredPatterns @(
            'generative ai websites|sensitive service domain group',
            'upload to a restricted cloud service domain|restricted cloud service domain|uploadtorestrictedcloudservicedomain',
            'paste to supported browsers|paste to browser|pastetosupportedbrowsers'
        )

        if (
            $blockInSimulation -and
            $aiInSimulation -and
            $blockHasExpectedLocations -and
            $aiHasDeviceScope -and
            $blockHasRequiredLogic -and
            $aiHasRequiredLogic
        ) {
            $found = $true
            $message = @{
                Status  = 'Succeeded'
                Message = "Validated DLP policies '$blockPolicyName' and '$aiPolicyName'. Both are present in simulation mode. '$blockPolicyName' includes collaboration locations and rule logic for Highly Confidential external sharing protection with blocking, policy tip, and alert indicators. '$aiPolicyName' is device-scoped and includes Generative AI Websites protections with upload-to-restricted-cloud-service-domain and paste-to-supported-browsers activities."
            } | ConvertTo-Json
        }
        else {
            $details = @()
            if (-not $blockInSimulation) {
                $details += "'$blockPolicyName' is not in simulation mode. Detected mode: $(Get-PolicyModeText -Policy $blockPolicy)"
            }
            if (-not $aiInSimulation) {
                $details += "'$aiPolicyName' is not in simulation mode. Detected mode: $(Get-PolicyModeText -Policy $aiPolicy)"
            }
            if (-not $blockHasExpectedLocations) {
                $details += "'$blockPolicyName' does not expose expected Microsoft 365 collaboration locations. Detected locations: $($blockLocations -join ', ')"
            }
            if (-not $aiHasDeviceScope) {
                $details += "'$aiPolicyName' is not scoped to Devices/Endpoint DLP. Detected endpoint locations: $($aiLocations -join ', ')"
            }
            if (-not $blockHasRequiredLogic) {
                $details += "'$blockPolicyName' rules do not show all required Highly Confidential external sharing restriction, policy tip, alert, and blocking indicators."
            }
            if (-not $aiHasRequiredLogic) {
                $details += "'$aiPolicyName' rules do not show the required Generative AI Websites domain group and both device activities."
            }

            $message = @{
                Status  = 'Failed'
                Message = ($details -join ' ')
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

# Post-loop: if every attempt failed, emit a final failure JSON so CloudLabs
# always sees a structured result.
if (-not $found) {
    $message = @{
        Status  = 'Failed'
        Message = "DLP Policies validation did not succeed after 3 attempts. Required policies 'Block External Sharing of Highly Confidential' and/or 'Protect Data from AI Apps' were not found or did not match the expected simulation, scope, and activity configuration checks."
    } | ConvertTo-Json
    Push-OutputBinding -Name Response -Clobber -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $message
    })
}
