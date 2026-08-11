using namespace System.Net

# Note: $sub (subscription id) and $DID (deployment id) are injected by the platform.
$rg = "purview-$DID"
$count = 0
$found = $false

function Get-NonEmptyPropertyValues {
    param(
        [object]$InputObject,
        [string[]]$PropertyNames
    )

    $values = @()
    # A missing policy or rule must produce an empty result rather than throw,
    # so the caller can report the specific setting instead of an exception.
    if ($null -eq $InputObject) { return $values }

    foreach ($propertyName in $PropertyNames) {
        # Property spellings drift between Compliance PowerShell builds, so the
        # caller passes every spelling it accepts and each one is probed for
        # existence before it is read.
        if ($InputObject.PSObject.Properties.Name -contains $propertyName) {
            $propertyValue = $InputObject.$propertyName
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

function Test-PropertyIsConfigured {
    param(
        [object]$InputObject,
        [string[]]$PropertyNames
    )

    # The Compliance cmdlets return placeholder values such as 'NotSet' or 'None'
    # for settings the author never touched, so a property that merely exists and
    # is non-null is not evidence that the learner configured anything.
    $values = Get-NonEmptyPropertyValues -InputObject $InputObject -PropertyNames $PropertyNames
    foreach ($value in $values) {
        if ("$value".Trim().ToLowerInvariant() -notin @('notset','none','false','0','off','disabled')) {
            return $true
        }
    }

    return $false
}

function Get-RuleLabelConditionText {
    param([object]$Rule)

    # Only the condition-bearing properties are serialised, and only so that a
    # label identifier resolved from Get-Label can be located inside their nested
    # structures. This is not the old keyword scan: the string searched for is the
    # GUID of the label the guide names, which is absent unless the rule really
    # conditions on that label. Exception properties are deliberately excluded -
    # an ExceptIf condition is the opposite of the condition being asserted.
    if ($null -eq $Rule) { return '' }

    $parts = @()
    foreach ($propertyName in @('ContentContainsSensitiveInformation','AdvancedRule')) {
        if ($Rule.PSObject.Properties.Name -contains $propertyName) {
            $propertyValue = $Rule.$propertyName
            if ($null -eq $propertyValue) { continue }
            try {
                $parts += ($propertyValue | ConvertTo-Json -Depth 20 -Compress -ErrorAction Stop)
            }
            catch {
                # Some builds return types ConvertTo-Json cannot walk; the flat
                # rendering of the same property still carries the identifier.
                $parts += ($propertyValue | Out-String -Width 8192)
            }
        }
    }

    return ($parts -join "`n")
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

        $aiRuleText = Get-RuleText -Rules $aiRules

        $blockInSimulation = Test-IsSimulationMode -Policy $blockPolicy
        $aiInSimulation = Test-IsSimulationMode -Policy $aiPolicy

        # Each workload is tested on its own. The old check merged all four
        # locations into one bucket, so a policy scoped to a single workload
        # passed. The *Exception properties are excluded: a list of sites the
        # policy skips is not evidence that the location itself is switched on.
        $workloadLocationProperties = [ordered]@{
            'Exchange'   = @('ExchangeLocation')
            'SharePoint' = @('SharePointLocation')
            'OneDrive'   = @('OneDriveLocation')
            'Teams'      = @('TeamsLocation')
        }

        $blockPresentLocations = @()
        $blockMissingLocations = @()
        foreach ($workloadName in $workloadLocationProperties.Keys) {
            $workloadValues = Get-NonEmptyPropertyValues -InputObject $blockPolicy -PropertyNames $workloadLocationProperties[$workloadName]
            if (($workloadValues | Measure-Object).Count -gt 0) {
                $blockPresentLocations += $workloadName
            }
            else {
                $blockMissingLocations += $workloadName
            }
        }
        $blockHasExpectedLocations = (($blockMissingLocations | Measure-Object).Count -eq 0)

        # Device scope must come from a populated endpoint location. The old
        # fallback scanned the policy's own property names for 'endpoint' and
        # 'device'; those names are present on every policy object, so it could
        # never fail. Exception properties are not accepted as evidence either.
        $aiEndpointLocations = Get-NonEmptyPropertyValues -InputObject $aiPolicy -PropertyNames @(
            'EndpointDlpLocation','DeviceLocation','DevicesLocation'
        )
        $aiHasDeviceScope = (($aiEndpointLocations | Measure-Object).Count -gt 0)

        # The guide scopes this policy to Devices only, so any populated
        # collaboration location means extra workloads were left switched on.
        $aiUnexpectedLocations = @()
        foreach ($workloadName in $workloadLocationProperties.Keys) {
            $aiWorkloadValues = Get-NonEmptyPropertyValues -InputObject $aiPolicy -PropertyNames $workloadLocationProperties[$workloadName]
            if (($aiWorkloadValues | Measure-Object).Count -gt 0) {
                $aiUnexpectedLocations += $workloadName
            }
        }
        $aiScopedToDevicesOnly = (($aiUnexpectedLocations | Measure-Object).Count -eq 0)

        # The rule stores the sensitivity label by identifier, not by display
        # name, so the identifier has to be resolved before the rule's condition
        # can be checked against it.
        $expectedLabelName = 'Zava Highly Confidential'
        $labelIdentifiers = @()
        if (Get-Command Get-Label -ErrorAction SilentlyContinue) {
            $expectedLabel = Get-Label -ErrorAction SilentlyContinue | Where-Object {
                "$($_.DisplayName)".Trim() -eq $expectedLabelName -or "$($_.Name)".Trim() -eq $expectedLabelName
            } | Select-Object -First 1
            foreach ($labelCandidate in (Get-NonEmptyPropertyValues -InputObject $expectedLabel -PropertyNames @('Guid','ImmutableId','Name','ExchangeObjectId'))) {
                # Only GUID-shaped identifiers are kept; a short free-text value
                # could match unrelated content inside the serialised condition.
                if ("$labelCandidate" -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
                    $labelIdentifiers += "$labelCandidate"
                }
            }
        }

        # The guide grades the rule name, so it is compared exactly rather than
        # inferred from the policy it sits under.
        $expectedBlockRuleName = 'Block Highly Confidential external sharing'
        $blockRule = $blockRules | Where-Object { "$($_.Name)".Trim() -eq $expectedBlockRuleName } | Select-Object -First 1
        $blockRuleNameMatches = ($null -ne $blockRule)
        if ($null -eq $blockRule) {
            # Fall back to the single rule the guide has learners create so the
            # remaining assertions still name the setting that is wrong, instead
            # of collapsing into a lone name failure.
            $blockRule = $blockRules | Select-Object -First 1
        }

        $blockRestrictsAccess = $false
        foreach ($blockAccessValue in (Get-NonEmptyPropertyValues -InputObject $blockRule -PropertyNames @('BlockAccess'))) {
            if ("$blockAccessValue".Trim() -match '^(true|1|yes)$') { $blockRestrictsAccess = $true }
        }

        # 'NotInOrganization' is the condition spelling and 'PerAnonymousUser' is
        # the equivalent spelling on the block action, so either one proves the
        # rule targets people outside the organisation.
        $blockTargetsExternal = $false
        foreach ($scopeValue in (Get-NonEmptyPropertyValues -InputObject $blockRule -PropertyNames @('AccessScope','BlockAccessScope'))) {
            if ("$scopeValue" -match '(?i)notinorganization|peranonymoususer') { $blockTargetsExternal = $true }
        }

        $blockLabelConditionText = Get-RuleLabelConditionText -Rule $blockRule
        $blockConditionsOnLabel = $false
        foreach ($labelIdentifier in $labelIdentifiers) {
            if ($blockLabelConditionText -match [regex]::Escape($labelIdentifier)) { $blockConditionsOnLabel = $true }
        }
        if (-not $blockConditionsOnLabel -and $blockLabelConditionText -match [regex]::Escape($expectedLabelName)) {
            # Some builds store the display name alongside the identifier.
            $blockConditionsOnLabel = $true
        }

        $blockNotifiesUser = Test-PropertyIsConfigured -InputObject $blockRule -PropertyNames @(
            'NotifyUser','NotifyEmailCustomText','NotifyPolicyTipCustomText'
        )
        $blockReportsIncident = Test-PropertyIsConfigured -InputObject $blockRule -PropertyNames @(
            'GenerateIncidentReport','GenerateAlert'
        )

        $blockHasRequiredLogic = (
            $blockRestrictsAccess -and
            $blockTargetsExternal -and
            $blockConditionsOnLabel -and
            $blockNotifiesUser -and
            $blockReportsIncident
        )

        # The AI rule name is the learner's choice, so only its description is
        # graded here.
        $aiRule = $aiRules | Select-Object -First 1
        $aiRuleHasDescription = Test-PropertyIsConfigured -InputObject $aiRule -PropertyNames @('Comment','Description')

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
            $aiScopedToDevicesOnly -and
            $blockRuleNameMatches -and
            $blockHasRequiredLogic -and
            $aiRuleHasDescription -and
            $aiHasRequiredLogic
        ) {
            $found = $true
            $message = @{
                Status  = 'Succeeded'
                Message = "Validated DLP policies '$blockPolicyName' and '$aiPolicyName'. Both are in simulation mode. '$blockPolicyName' is enabled for Exchange, SharePoint, OneDrive and Teams, and its rule '$expectedBlockRuleName' has BlockAccess set to true, an access scope of people outside the organisation, a condition on the '$expectedLabelName' sensitivity label, a user notification, and an incident report or alert. '$aiPolicyName' is scoped to Devices only, its rule carries a description, and its rules include the Generative AI Websites domain group with upload-to-restricted-cloud-service-domain and paste-to-supported-browsers activities."
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
                $details += "'$blockPolicyName' is not enabled for: $($blockMissingLocations -join ', '). Enabled locations: $(if (($blockPresentLocations | Measure-Object).Count -gt 0) { $blockPresentLocations -join ', ' } else { 'none' })."
            }
            if (-not $aiHasDeviceScope) {
                $details += "'$aiPolicyName' has no populated Devices/Endpoint DLP location, so it is not scoped to Devices."
            }
            if (-not $aiScopedToDevicesOnly) {
                $details += "'$aiPolicyName' also has these locations enabled: $($aiUnexpectedLocations -join ', '). The guide requires Devices only."
            }
            if (($blockRules | Measure-Object).Count -eq 0) {
                $details += "'$blockPolicyName' has no DLP rules."
            }
            elseif (-not $blockRuleNameMatches) {
                $details += "'$blockPolicyName' has no rule named '$expectedBlockRuleName'. Detected rule names: $(($blockRules | ForEach-Object { $_.Name }) -join ', ')."
            }
            if (-not $blockHasRequiredLogic) {
                $missingRuleLogic = @()
                if (-not $blockRestrictsAccess)   { $missingRuleLogic += 'the restrict-access action (BlockAccess is not true)' }
                if (-not $blockTargetsExternal)   { $missingRuleLogic += 'an access scope of people outside the organisation (AccessScope is not NotInOrganization)' }
                if (-not $blockConditionsOnLabel) { $missingRuleLogic += "a condition on the '$expectedLabelName' sensitivity label" }
                if (-not $blockNotifiesUser)      { $missingRuleLogic += 'a user notification / policy tip (NotifyUser is empty)' }
                if (-not $blockReportsIncident)   { $missingRuleLogic += 'an incident report or alert (GenerateIncidentReport and GenerateAlert are both empty)' }
                $details += "Rule '$(if ($null -ne $blockRule) { $blockRule.Name } else { 'not found' })' in '$blockPolicyName' is missing: $($missingRuleLogic -join '; ')."
            }
            if (-not $blockConditionsOnLabel -and ($labelIdentifiers | Measure-Object).Count -eq 0) {
                $details += "Get-Label returned no label named '$expectedLabelName', so the rule's sensitivity label condition could not be resolved."
            }
            if (($aiRules | Measure-Object).Count -eq 0) {
                $details += "'$aiPolicyName' has no DLP rules."
            }
            elseif (-not $aiRuleHasDescription) {
                $details += "The rule '$($aiRule.Name)' in '$aiPolicyName' has no description. Add the description the guide specifies to the rule."
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
        Message = "DLP Policies validation did not succeed after 3 attempts. Required policies 'Block External Sharing of Highly Confidential' and/or 'Protect Data from AI Apps' were not found, or did not match the expected simulation mode, workload locations, rule names, rule actions and activity configuration checks."
    } | ConvertTo-Json
    Push-OutputBinding -Name Response -Clobber -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $message
    })
}
