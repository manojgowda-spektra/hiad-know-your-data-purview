using namespace System.Net

# Note: $sub (subscription id) and $DID (deployment id) are injected by the platform.
# This validation runs server-side and checks Microsoft Purview configuration by using
# Security & Compliance PowerShell rather than local machine state.
$rg = "purview-$DID"
$count = 0
$found = $false

function Get-LabelActionSetting {
    # Purview stores label configuration in LabelActions, not as flat properties and
    # not in the Settings collection. Each entry is JSON of the form
    #   {"Type":"encrypt","SubType":null,"Settings":[{"Key":"disabled","Value":"false"},...]}
    param(
        [object]$Label,
        [string]$Type,
        [string]$Key,
        [string]$SubType
    )

    foreach ($action in @($Label.LabelActions)) {
        if ($null -eq $action) { continue }
        try { $parsed = $action | ConvertFrom-Json -ErrorAction Stop } catch { continue }
        if ($parsed.Type -ne $Type) { continue }
        if ($SubType -and $parsed.SubType -ne $SubType) { continue }
        foreach ($setting in @($parsed.Settings)) {
            if ($setting.Key -eq $Key) { return $setting.Value }
        }
    }
    return $null
}

function Test-LabelActionPresent {
    param([object]$Label, [string]$Type, [string]$SubType)

    foreach ($action in @($Label.LabelActions)) {
        if ($null -eq $action) { continue }
        try { $parsed = $action | ConvertFrom-Json -ErrorAction Stop } catch { continue }
        if ($parsed.Type -ne $Type) { continue }
        if ($SubType -and $parsed.SubType -ne $SubType) { continue }
        # an action whose 'disabled' setting is true is configured but switched off
        $disabled = $null
        foreach ($setting in @($parsed.Settings)) {
            if ($setting.Key -eq 'disabled') { $disabled = "$($setting.Value)" }
        }
        if ($disabled -and $disabled.Trim().ToLowerInvariant() -eq 'true') { return $false }
        return $true
    }
    return $false
}

function Get-SettingValue {
    param(
        [object]$Label,
        [string]$Name
    )

    $value = $null

    if ($null -ne $Label.PSObject.Properties[$Name]) {
        $value = $Label.$Name
        if ($null -ne $value) {
            return $value
        }
    }

    $settingsCandidates = @()
    if ($null -ne $Label.PSObject.Properties['Settings']) {
        $settingsCandidates += $Label.Settings
    }
    if ($null -ne $Label.PSObject.Properties['settings']) {
        $settingsCandidates += $Label.settings
    }

    foreach ($settings in $settingsCandidates) {
        if ($null -eq $settings) {
            continue
        }

        if ($settings -is [System.Collections.IDictionary]) {
            if ($settings.Contains($Name)) {
                return $settings[$Name]
            }
        }

        foreach ($entry in $settings) {
            if ($null -eq $entry) {
                continue
            }

            if ($entry -is [System.Collections.DictionaryEntry]) {
                if ($entry.Key -eq $Name) {
                    return $entry.Value
                }
            }

            if ($entry.PSObject.Properties['Key'] -and $entry.PSObject.Properties['Value']) {
                if ($entry.Key -eq $Name) {
                    return $entry.Value
                }
            }

            if ($entry.PSObject.Properties['Name'] -and $entry.PSObject.Properties['Value']) {
                if ($entry.Name -eq $Name) {
                    return $entry.Value
                }
            }
        }
    }

    return $null
}

function Test-ValueEquals {
    param(
        [object]$Actual,
        [string]$Expected
    )

    if ($null -eq $Actual) {
        return $false
    }

    return ([string]$Actual).Trim() -eq $Expected
}

function Test-ValueFalseLike {
    param([object]$Actual)

    if ($null -eq $Actual) {
        return $true
    }

    $text = ([string]$Actual).Trim().ToLowerInvariant()
    return ($text -in @('', 'false', 'none', 'disabled', 'null', '0'))
}

function Test-ValueTrueLike {
    param([object]$Actual)

    if ($null -eq $Actual) {
        return $false
    }

    $text = ([string]$Actual).Trim().ToLowerInvariant()
    return ($text -in @('true', 'enabled', '1'))
}

function Test-ContainsText {
    param(
        [object]$Actual,
        [string]$ExpectedText
    )

    if ($null -eq $Actual) {
        return $false
    }

    return ([string]$Actual).ToLowerInvariant().Contains($ExpectedText.ToLowerInvariant())
}

do {
    $count = $count + 1
    try {
        Set-AzContext -Subscription $sub -ErrorAction Stop

        # ExchangeOnlineManagement is not offered in the CloudLabs template module catalogue,
        # so the validator installs it on first run.
        $module = Get-Module -ListAvailable ExchangeOnlineManagement | Sort-Object Version -Descending | Select-Object -First 1
        if (-not $module) {
            Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        }

        Import-Module ExchangeOnlineManagement -ErrorAction Stop | Out-Null

        $userName = $null
        $userPassword = $null

        if (Get-Command Get-AutomationVariable -ErrorAction SilentlyContinue) {
            try { $userName = Get-AutomationVariable -Name 'AzureAdUserEmail' } catch {}
            try { $userPassword = Get-AutomationVariable -Name 'AzureAdUserPassword' } catch {}
        }

        if (-not $userName -and $env:AzureAdUserEmail) {
            $userName = $env:AzureAdUserEmail
        }
        if (-not $userPassword -and $env:AzureAdUserPassword) {
            $userPassword = $env:AzureAdUserPassword
        }

        if (-not $userName -or -not $userPassword) {
            throw "Validator could not obtain AzureAdUserEmail and AzureAdUserPassword for Compliance PowerShell sign-in."
        }

        $securePassword = ConvertTo-SecureString $userPassword -AsPlainText -Force
        $credential = [pscredential]::new($userName, $securePassword)

        Connect-IPPSSession -Credential $credential -ErrorAction Stop | Out-Null

        $requiredLabels = @(
            'Zava Public',
            'Zava Internal',
            'Zava Confidential',
            'Zava Highly Confidential'
        )

        $allLabels = Get-Label -ErrorAction Stop

        $labels = @{}
        foreach ($labelName in $requiredLabels) {
            # Match DisplayName as well as Name: Get-Label -Identity accepts only Name, DN
            # or GUID, and a label's Name is not guaranteed to equal its display name.
            $label = $allLabels | Where-Object {
                $_.DisplayName -eq $labelName -or $_.Name -eq $labelName
            } | Select-Object -First 1
            if ($null -ne $label) {
                $labels[$labelName] = $label
            }
        }

        $missingLabels = $requiredLabels | Where-Object { -not $labels.ContainsKey($_) }
        if ($missingLabels.Count -gt 0) {
            $message = "Missing required sensitivity labels: $($missingLabels -join ', ')."
        }
        else {
            $failures = New-Object System.Collections.Generic.List[string]

            $public = $labels['Zava Public']
            if (Test-LabelActionPresent -Label $public -Type 'encrypt') {
                $failures.Add("Zava Public must not use encryption.")
            }
            if (Test-LabelActionPresent -Label $public -Type 'applycontentmarking' -SubType 'header') {
                $failures.Add("Zava Public must not have a header.")
            }
            if (Test-LabelActionPresent -Label $public -Type 'applycontentmarking' -SubType 'footer') {
                $failures.Add("Zava Public must not have a footer.")
            }
            if (Test-LabelActionPresent -Label $public -Type 'applywatermarking') {
                $failures.Add("Zava Public must not have a watermark.")
            }

            $internal = $labels['Zava Internal']
            if (Test-LabelActionPresent -Label $internal -Type 'encrypt') {
                $failures.Add("Zava Internal must not use encryption.")
            }
            if (-not (Test-LabelActionPresent -Label $internal -Type 'applycontentmarking' -SubType 'header')) {
                $failures.Add("Zava Internal must have the header enabled.")
            }
            if (-not (Test-ValueEquals (Get-LabelActionSetting -Label $internal -Type 'applycontentmarking' -SubType 'header' -Key 'text') 'Zava Internal')) {
                $failures.Add("Zava Internal header text must equal 'Zava Internal'.")
            }

            $confidential = $labels['Zava Confidential']
            if (-not (Test-LabelActionPresent -Label $confidential -Type 'encrypt')) {
                $failures.Add("Zava Confidential must use encryption.")
            }
            if (-not (Test-LabelActionPresent -Label $confidential -Type 'applywatermarking')) {
                $failures.Add("Zava Confidential must have a watermark enabled.")
            }
            if (-not (Test-ValueEquals (Get-LabelActionSetting -Label $confidential -Type 'applywatermarking' -Key 'text') 'Confidential')) {
                $failures.Add("Zava Confidential watermark text must equal 'Confidential'.")
            }
            # Structural check. The previous keyword match could never pass: granting rights
            # to everyone in the organization stores the tenant's own domain, and 'any
            # authenticated users' stores AuthenticatedUsers - neither contains 'all',
            # 'organization', 'tenant' or 'internal'.
            $confidentialRights = Get-LabelActionSetting -Label $confidential -Type 'encrypt' -Key 'rightsdefinitions'

            # rightsdefinitions is stored as JSON, normally an array of
            #   {"Identity":"user@zava.com","Rights":"VIEW,VIEWRIGHTSDATA,..."}
            # Deserialise it and read Identity from each element; only fall back to the
            # documented Identity:Rights string form when that fails. Anything neither
            # form can account for is a failure. The previous version split on ';' and ':'
            # and silently accepted whatever came out, so a grant to an external domain
            # that did not split cleanly was reported as internal-only - fail-open.
            $rightsIdentities = @()
            $unreadableRights = @()

            $rightsEntries = @()
            foreach ($entry in @($confidentialRights)) {
                if ($null -eq $entry) { continue }
                if ($entry -is [string]) {
                    if ([string]::IsNullOrWhiteSpace($entry)) { continue }
                    $parsed = $null
                    try { $parsed = $entry | ConvertFrom-Json -ErrorAction Stop } catch { $parsed = $null }
                    if ($null -ne $parsed) { $rightsEntries += @($parsed) } else { $rightsEntries += , $entry }
                }
                else {
                    $rightsEntries += , $entry
                }
            }

            foreach ($entry in $rightsEntries) {
                if ($null -eq $entry) { continue }

                if ($entry -isnot [string]) {
                    $identity = if ($entry.PSObject.Properties['Identity']) { [string]$entry.Identity } else { '' }
                    if (-not [string]::IsNullOrWhiteSpace($identity)) {
                        $rightsIdentities += $identity.Trim().ToLowerInvariant()
                    }
                    else {
                        # An object with no Identity is not something this check can judge.
                        $text = $entry | ConvertTo-Json -Depth 5 -Compress -ErrorAction SilentlyContinue
                        if ([string]::IsNullOrWhiteSpace($text)) { $text = ($entry | Out-String).Trim() }
                        $unreadableRights += $text
                    }
                    continue
                }

                # Fallback form: 'identity:rights' pairs separated by ';'. Every pair must
                # yield a non-empty identity and at least one right, otherwise the value is
                # not in this form and must not be guessed at.
                $pairs = @(([string]$entry) -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                $pairIdentities = @()
                $wellFormed = $pairs.Count -gt 0
                foreach ($pair in $pairs) {
                    $parts = $pair -split ':'
                    if ($parts.Count -lt 2) { $wellFormed = $false; break }
                    $name = $parts[0].Trim()
                    $rights = ($parts[1..($parts.Count - 1)] -join ':').Trim()
                    if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($rights)) { $wellFormed = $false; break }
                    $pairIdentities += $name.ToLowerInvariant()
                }

                if ($wellFormed) { $rightsIdentities += $pairIdentities }
                else { $unreadableRights += ([string]$entry).Trim() }
            }

            $tenantDomain = if ($userName -like '*@*') { (($userName -split '@')[-1]).Trim().ToLowerInvariant() } else { '' }
            $externalIdentities = @()
            $unresolvedIdentities = @()
            foreach ($identity in $rightsIdentities) {
                if ([string]::IsNullOrWhiteSpace($identity)) { continue }
                if ($identity -in @('authenticatedusers', 'allauthenticatedusers', 'allstaff', 'myorganization')) { continue }
                $domain = if ($identity -like '*@*') { ($identity -split '@')[-1] } elseif ($identity -like '*.*') { $identity } else { '' }
                if ([string]::IsNullOrWhiteSpace($domain)) {
                    # No domain and not a known organization-wide identity, so there is no
                    # way to place it inside the tenant. Report it instead of assuming.
                    $unresolvedIdentities += $identity
                    continue
                }
                if ($domain -like '*.onmicrosoft.com') { continue }
                if ($tenantDomain -and $domain -eq $tenantDomain) { continue }
                $externalIdentities += $identity
            }

            if ($rightsIdentities.Count -eq 0 -and $unreadableRights.Count -eq 0) {
                $failures.Add("Zava Confidential must use encryption with permissions assigned to users in your organization.")
            }
            if ($unreadableRights.Count -gt 0) {
                $failures.Add("Zava Confidential encryption permissions could not be read, so internal-only access cannot be confirmed. Unrecognised rights value: $($unreadableRights -join ' | ').")
            }
            if ($externalIdentities.Count -gt 0) {
                $failures.Add("Zava Confidential must assign encryption permissions for internal users only. Rights are granted to: $($externalIdentities -join ', ').")
            }
            if ($unresolvedIdentities.Count -gt 0) {
                $failures.Add("Zava Confidential must assign encryption permissions for internal users only. This identity could not be confirmed as belonging to your organization: $($unresolvedIdentities -join ', ').")
            }

            $highly = $labels['Zava Highly Confidential']
            if (-not (Test-LabelActionPresent -Label $highly -Type 'encrypt')) {
                $failures.Add("Zava Highly Confidential must use encryption.")
            }
            # Auto-labeling cannot write a user-defined-permissions label to SharePoint or
            # OneDrive, and Challenge 2 Task 3 targets both. Assign permissions now with
            # non-expiring access is the configuration that policy requires.
            if (Test-ValueTrueLike (Get-LabelActionSetting -Label $highly -Type 'encrypt' -Key 'donotforward')) {
                $failures.Add("Zava Highly Confidential must use 'Assign permissions now' rather than Do Not Forward, because an auto-labeling policy cannot apply a user-defined-permissions label to SharePoint or OneDrive content.")
            }
            $highlyProtectionType = [string](Get-LabelActionSetting -Label $highly -Type 'encrypt' -Key 'protectiontype')
            if ($highlyProtectionType -match 'UserDefined') {
                $failures.Add("Zava Highly Confidential must use 'Assign permissions now' rather than letting users assign permissions.")
            }
            $highlyExpiry = [string](Get-LabelActionSetting -Label $highly -Type 'encrypt' -Key 'contentexpiredondateindaysorever')
            if (-not [string]::IsNullOrWhiteSpace($highlyExpiry) -and $highlyExpiry -notmatch 'Never') {
                $failures.Add("Zava Highly Confidential must set user access to content to never expire, which auto-labeling requires for SharePoint and OneDrive locations.")
            }
            if (-not (Test-LabelActionPresent -Label $highly -Type 'applywatermarking')) {
                $failures.Add("Zava Highly Confidential must have a watermark enabled.")
            }
            if (-not (Test-ValueEquals (Get-LabelActionSetting -Label $highly -Type 'applywatermarking' -Key 'text') 'Highly Confidential')) {
                $failures.Add("Zava Highly Confidential watermark text must equal 'Highly Confidential'.")
            }
            $contentType = [string](Get-SettingValue -Label $highly -Name 'ContentType')
            if (-not ($contentType -match 'Site|UnifiedGroup')) {
                $failures.Add("Zava Highly Confidential must include Groups & sites in scope.")
            }
            $sharingControl = [string](Get-LabelActionSetting -Label $highly -Type 'protectsiteandgroup' -Key 'sharingcapability')
            if (-not ($sharingControl -match 'OnlyPeopleInYourOrganization|Disabled')) {
                $failures.Add("Zava Highly Confidential must restrict external sharing to Only people in your organization.")
            }

            if ($failures.Count -eq 0) {
                $found = $true
                $message = "Validated sensitivity labels Zava Public, Zava Internal, Zava Confidential, and Zava Highly Confidential with the required no-encryption, header, watermark, encryption, assign-permissions-now, and Groups & sites settings."
            }
            else {
                $message = $failures -join ' '
            }
        }

        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue

        if ($found) {
            $message = @{
                Status  = "Succeeded"
                Message = $message
            } | ConvertTo-Json
        } else {
            $message = @{
                Status  = "Failed"
                Message = $message
            } | ConvertTo-Json
        }
        Push-OutputBinding -Name Response -Clobber -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $message
        })
    }
    catch {
        try {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        }
        catch {}

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
    # currently hides every specific failure reason from the attendee.
    if ([string]::IsNullOrWhiteSpace($message)) {
        $message = @{
            Status  = "Failed"
            Message = "Sensitivity labels not validated after 3 attempts."
        } | ConvertTo-Json
    }
    Push-OutputBinding -Name Response -Clobber -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $message
    })
}
