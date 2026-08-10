using namespace System.Net

# Note: $sub (subscription id) and $DID (deployment id) are injected by the platform.
# This validation runs server-side and checks Microsoft Purview configuration by using
# Security & Compliance PowerShell rather than local machine state.
$rg = "purview-$DID"
$count = 0
$found = $false

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
            if (-not (Test-ValueFalseLike (Get-SettingValue -Label $public -Name 'EncryptionEnabled'))) {
                $failures.Add("Zava Public must not use encryption.")
            }
            if (-not (Test-ValueFalseLike (Get-SettingValue -Label $public -Name 'ApplyContentMarkingHeaderEnabled'))) {
                $failures.Add("Zava Public must not have a header.")
            }
            if (-not (Test-ValueFalseLike (Get-SettingValue -Label $public -Name 'ApplyContentMarkingFooterEnabled'))) {
                $failures.Add("Zava Public must not have a footer.")
            }
            if (-not (Test-ValueFalseLike (Get-SettingValue -Label $public -Name 'ApplyWaterMarkingEnabled'))) {
                $failures.Add("Zava Public must not have a watermark.")
            }

            $internal = $labels['Zava Internal']
            if (-not (Test-ValueFalseLike (Get-SettingValue -Label $internal -Name 'EncryptionEnabled'))) {
                $failures.Add("Zava Internal must not use encryption.")
            }
            if (-not (Test-ValueTrueLike (Get-SettingValue -Label $internal -Name 'ApplyContentMarkingHeaderEnabled'))) {
                $failures.Add("Zava Internal must have the header enabled.")
            }
            if (-not (Test-ValueEquals (Get-SettingValue -Label $internal -Name 'ApplyContentMarkingHeaderText') 'Zava Internal')) {
                $failures.Add("Zava Internal header text must equal 'Zava Internal'.")
            }

            $confidential = $labels['Zava Confidential']
            if (-not (Test-ValueTrueLike (Get-SettingValue -Label $confidential -Name 'EncryptionEnabled'))) {
                $failures.Add("Zava Confidential must use encryption.")
            }
            if (-not (Test-ValueTrueLike (Get-SettingValue -Label $confidential -Name 'ApplyWaterMarkingEnabled'))) {
                $failures.Add("Zava Confidential must have a watermark enabled.")
            }
            if (-not (Test-ValueEquals (Get-SettingValue -Label $confidential -Name 'ApplyWaterMarkingText') 'Confidential')) {
                $failures.Add("Zava Confidential watermark text must equal 'Confidential'.")
            }
            # Structural check. The previous keyword match could never pass: granting rights
            # to everyone in the organization stores the tenant's own domain, and 'any
            # authenticated users' stores AuthenticatedUsers - neither contains 'all',
            # 'organization', 'tenant' or 'internal'.
            $confidentialRights = Get-SettingValue -Label $confidential -Name 'EncryptionRightsDefinitions'
            $rightsIdentities = @()
            foreach ($entry in @($confidentialRights)) {
                if ($null -eq $entry) { continue }
                if ($entry.PSObject.Properties['Identity'] -and -not [string]::IsNullOrWhiteSpace([string]$entry.Identity)) {
                    $rightsIdentities += ([string]$entry.Identity).Trim().ToLowerInvariant()
                    continue
                }
                # Documented Identity:Rights string form, one or more pairs per entry.
                foreach ($pair in (([string]$entry) -split ';')) {
                    if ([string]::IsNullOrWhiteSpace($pair)) { continue }
                    $rightsIdentities += ((($pair -split ':')[0]).Trim()).ToLowerInvariant()
                }
            }

            $tenantDomain = if ($userName -like '*@*') { (($userName -split '@')[-1]).Trim().ToLowerInvariant() } else { '' }
            $externalIdentities = @()
            foreach ($identity in $rightsIdentities) {
                if ([string]::IsNullOrWhiteSpace($identity)) { continue }
                if ($identity -in @('authenticatedusers', 'allauthenticatedusers', 'allstaff', 'myorganization')) { continue }
                $domain = if ($identity -like '*@*') { ($identity -split '@')[-1] } elseif ($identity -like '*.*') { $identity } else { '' }
                if ([string]::IsNullOrWhiteSpace($domain)) { continue }
                if ($domain -like '*.onmicrosoft.com') { continue }
                if ($tenantDomain -and $domain -eq $tenantDomain) { continue }
                $externalIdentities += $identity
            }

            if ($rightsIdentities.Count -eq 0) {
                $failures.Add("Zava Confidential must use encryption with permissions assigned to users in your organization.")
            }
            elseif ($externalIdentities.Count -gt 0) {
                $failures.Add("Zava Confidential must assign encryption permissions for internal users only. Rights are granted to: $($externalIdentities -join ', ').")
            }

            $highly = $labels['Zava Highly Confidential']
            if (-not (Test-ValueTrueLike (Get-SettingValue -Label $highly -Name 'EncryptionEnabled'))) {
                $failures.Add("Zava Highly Confidential must use encryption.")
            }
            # Auto-labeling cannot write a user-defined-permissions label to SharePoint or
            # OneDrive, and Challenge 2 Task 3 targets both. Assign permissions now with
            # non-expiring access is the configuration that policy requires.
            if (Test-ValueTrueLike (Get-SettingValue -Label $highly -Name 'EncryptionDoNotForward')) {
                $failures.Add("Zava Highly Confidential must use 'Assign permissions now' rather than Do Not Forward, because an auto-labeling policy cannot apply a user-defined-permissions label to SharePoint or OneDrive content.")
            }
            $highlyProtectionType = [string](Get-SettingValue -Label $highly -Name 'EncryptionProtectionType')
            if ($highlyProtectionType -match 'UserDefined') {
                $failures.Add("Zava Highly Confidential must use 'Assign permissions now' rather than letting users assign permissions.")
            }
            $highlyExpiry = [string](Get-SettingValue -Label $highly -Name 'EncryptionContentExpiredOnDateInDaysOrNever')
            if (-not [string]::IsNullOrWhiteSpace($highlyExpiry) -and $highlyExpiry -notmatch 'Never') {
                $failures.Add("Zava Highly Confidential must set user access to content to never expire, which auto-labeling requires for SharePoint and OneDrive locations.")
            }
            if (-not (Test-ValueTrueLike (Get-SettingValue -Label $highly -Name 'ApplyWaterMarkingEnabled'))) {
                $failures.Add("Zava Highly Confidential must have a watermark enabled.")
            }
            if (-not (Test-ValueEquals (Get-SettingValue -Label $highly -Name 'ApplyWaterMarkingText') 'Highly Confidential')) {
                $failures.Add("Zava Highly Confidential watermark text must equal 'Highly Confidential'.")
            }
            $contentType = [string](Get-SettingValue -Label $highly -Name 'ContentType')
            if (-not ($contentType -match 'Site|UnifiedGroup')) {
                $failures.Add("Zava Highly Confidential must include Groups & sites in scope.")
            }
            $sharingControl = [string](Get-SettingValue -Label $highly -Name 'SiteExternalSharingControlType')
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
