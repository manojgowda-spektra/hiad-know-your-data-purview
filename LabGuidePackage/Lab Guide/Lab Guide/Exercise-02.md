# Challenge 2: Classify data with sensitivity labels and auto-labeling

### Estimated Duration: 75 Minutes

## Scenario

Zava now has evidence of where sensitive data sits, but nothing in the tenant yet says how that data must be handled. There is no classification taxonomy at all, so everything the organization will rely on has to be built here. You will create the Zava label set, publish it so it can actually be used, and define an auto-labeling policy that stays in simulation mode so Zava can validate scope and impact before any content is labeled automatically.

## Overview

In this challenge, you turn on the tenant settings that label protection depends on, create four sensitivity labels with exact names and behaviors, publish them through a global label policy, and configure a simulation-based auto-labeling policy that applies Zava Highly Confidential to Microsoft 365 data.

## Objectives

1. Task 1: Prepare the tenant and create the four Zava sensitivity labels.
2. Task 2: Publish the Zava labels through a global label policy.
3. Task 3: Configure the auto-labeling policy in simulation mode.

## Task 1: Prepare the tenant and create the four Zava sensitivity labels

In this task, you will turn on the tenant settings that label protection depends on, then build the Zava label taxonomy exactly as required.

1. Turn on sensitivity labels for Office files in SharePoint and OneDrive. This is off in a new tenant, and until it is on, the labels you create have no effect on content held in those two locations. Do it in the portal: go to **Settings** > **Information Protection**, find the setting for processing content in Office online files in SharePoint and OneDrive, and turn it on. If the portal does not offer it, run this on the lab VM instead:

   ```powershell
   Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser -Force -AllowClobber
   Connect-SPOService -Url https://<your-tenant>-admin.sharepoint.com
   Set-SPOTenant -EnableAIPIntegration $true
   Get-SPOTenant | Select-Object EnableAIPIntegration      # expect True
   ```

   Replace `<your-tenant>` with the first part of your lab tenant name, which you can read from your sign-in address.
2. Turn on sensitivity labels for Microsoft 365 groups and sites, then run a label sync to Microsoft Entra ID so that the container settings become configurable. This one is not a portal setting, so run the commands in the block below from **Windows PowerShell on your lab VM**, signing in with your lab account when prompted.

   ```powershell
   # 1. Turn on container labelling (the Group.Unified directory setting).
   #    Microsoft.Graph.Authentication is the only module needed - the setting is
   #    read and written through the Graph v1.0 groupSettings endpoint directly.
   Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber
   Connect-MgGraph -Scopes 'Directory.ReadWrite.All'

   $uri = 'https://graph.microsoft.com/v1.0/groupSettings'
   $setting = (Invoke-MgGraphRequest -Method GET -Uri $uri).value |
              Where-Object { $_.displayName -eq 'Group.Unified' }

   if (-not $setting) {
       # No Group.Unified setting exists yet, so create one from its template.
       $template = (Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/groupSettingTemplates').value |
                   Where-Object { $_.displayName -eq 'Group.Unified' }
       $body = @{
           templateId = $template.id
           values     = @($template.values | ForEach-Object { @{ name = $_.name; value = $_.defaultValue } })
       }
       Invoke-MgGraphRequest -Method POST -Uri $uri -Body ($body | ConvertTo-Json -Depth 5) | Out-Null
       $setting = (Invoke-MgGraphRequest -Method GET -Uri $uri).value |
                  Where-Object { $_.displayName -eq 'Group.Unified' }
   }

   $values = @($setting.values | ForEach-Object {
       @{ name = $_.name; value = $(if ($_.name -eq 'EnableMIPLabels') { 'True' } else { $_.value }) }
   })
   Invoke-MgGraphRequest -Method PATCH -Uri "$uri/$($setting.id)" `
       -Body (@{ values = $values } | ConvertTo-Json -Depth 5)

   # 2. Sync the labels into Microsoft Entra ID
   Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber
   Connect-IPPSSession
   Execute-AzureAdLabelSync
   ```

   Confirm the setting took effect by running the check below. It must print `True`.

   ```powershell
   ((Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/groupSettings').value |
     Where-Object { $_.displayName -eq 'Group.Unified' }).values |
     Where-Object { $_.name -eq 'EnableMIPLabels' } | Select-Object -ExpandProperty value
   ```
3. Create a sensitivity label named Zava Public and configure it with no encryption and no header, footer, or watermark.
4. Create a sensitivity label named Zava Internal and configure it with a header exactly set to Zava Internal and no encryption.
5. Create a sensitivity label named Zava Confidential. Enable encryption, choose to assign permissions now, and grant access to all users and groups in your organization so that no external identity is given rights. Enable content marking and add a watermark whose text is exactly Confidential.
6. Create a sensitivity label named Zava Highly Confidential and configure it with encryption, choosing Assign permissions now, granting access to users and groups in your organization only, and setting user access to content to never expire. Do not choose Do Not Forward or any other option that lets users assign permissions: an auto-labeling policy cannot write a user-defined-permissions label to SharePoint or OneDrive content, and the policy you build in Task 3 targets both.
7. Ensure Zava Highly Confidential also includes Groups & sites, restricts external sharing to Only people in your organization, and applies a watermark exactly set to Highly Confidential.
8. Review the four labels together and confirm the names and protection settings match the design requirements with no extra behaviors added.

> **Note:** Steps 1 and 2 come first for a reason. While sensitivity labels are not enabled for groups and sites, the Groups & sites scope and its external sharing controls are visible in the label wizard but cannot be configured, so step 7 cannot be completed and Zava Highly Confidential will fail validation.

> **Note:** Steps 1 and 2 are the only parts of this lab that may need PowerShell rather than the browser. Container labelling in step 2 is a Microsoft Entra directory setting with no portal user interface at all. Both need Global Administrator, which your lab account holds. Allow a few minutes after `Execute-AzureAdLabelSync` before the Groups & sites options become selectable in the label wizard; if they are still greyed out, sign out of the Purview portal and back in.

> [!Note]
> The first time you create a label with encryption, Microsoft Purview activates Azure Rights
> Management for the tenant. On a newly provisioned tenant this service starts dormant, so the first
> save can take a minute or fail once with a message about the tenant not being found in Azure Rights
> Management. If that happens, wait a minute and save the label again — the second attempt succeeds.

<validation step="Sensitivity Labels"/>

## Task 2: Publish the Zava labels through a global label policy

In this task, you will make the taxonomy usable by publishing it, and settle the ordering that decides which label wins.

1. Review the tenant's label list and confirm the four labels you created in Task 1 are present and named exactly as specified. Nothing classified data in this tenant before you did, so the Zava set is the taxonomy the rest of the lab depends on.
2. Confirm the four labels are ordered from least to most sensitive, with Zava Public lowest and Zava Highly Confidential highest, and reorder them if they are not. Label order sets priority, and priority decides which label applies when more than one condition matches the same item.
3. Create a label policy named Zava Global Label Policy.
4. Publish all four Zava labels through Zava Global Label Policy, scoped to all users and groups.
5. Confirm the policy lists all four Zava labels and that none of them was left out of the publishing scope.
6. Record which label you expect to carry the strongest protection in practice, and how the encryption and sharing settings you configured in Task 1 support that expectation.

> **Note:** A label has to be published to at least one user before an auto-labeling policy can apply it, which is why this task comes before Task 3. Publishing to users' Office apps can take up to 24 hours, but that delay does not affect the administrative surfaces you work in for the rest of this lab.

<validation step="Zava Global Label Policy"/>

## Task 3: Configure the auto-labeling policy in simulation mode

In this task, you will define a simulation-first auto-labeling policy for Microsoft 365 workloads. The configured policy is the deliverable here, not a finished simulation.

1. Create an auto-labeling policy named Zava Auto-Label Policy.
2. Configure the policy to apply the Zava Highly Confidential label you created in Task 1 and published in Task 2. Content holding five or more credit card numbers or Social Security numbers is Zava's highest-risk material, so it takes the highest-risk label. This is why Task 1 had you configure that label with Assign permissions now rather than a user-defined-permissions option: auto-labeling cannot write a user-defined-permissions label to SharePoint or OneDrive content.
3. Target SharePoint, OneDrive, and Exchange as the policy locations.
4. Add Credit Card Number and U.S. Social Security Number (SSN) to the same condition group, set the group to Any of these, and set the instance count on each type to a minimum of 5. Setting the group to All of these would require both types in the same document and would report almost nothing against the content you placed in Challenge 1.
5. Run the policy in simulation mode, leave the option that automatically turns the policy on after seven days unselected, and do not turn the policy on yourself.
6. Open the saved policy and confirm it shows Zava Highly Confidential as the label to apply, all three locations, and both sensitive information types at a minimum count of 5. These are the values this challenge is graded on.
7. Working from the policy conditions rather than from results, predict which of the documents you placed in Challenge 1 this policy would label. For each document, record the sensitive information type it contains and how many instances of that type are present, then state whether the count reaches the minimum of 5. A document holding a single credit card number does not match, and that is the threshold working as designed rather than a detection failure.
8. Record a short outcome statement explaining what Zava gains by proving this policy in simulation first, and what evidence the team would want before turning it on.

> **Note:** A simulation takes about 12 hours to complete, and for roughly 24 hours after a policy is created its Turn on policy, Edit, and Delete actions are greyed out while the service finishes provisioning it. Neither window fits inside this lab. An empty Items to review tab and a disabled Turn on policy button are the expected state at this point, not a failure, so do not wait on either.

> **Note:** The auto-labeling page shows a pay-as-you-go billing notice for non-Microsoft 365 data sources. This policy targets Microsoft 365 locations only, so nothing you configure here is billed that way.

<validation step="AutoSensitivityLabelPolicy"/>

## Summary

You turned on the tenant settings that label protection depends on, created four Zava sensitivity labels, published them through Zava Global Label Policy, and configured Zava Auto-Label Policy in simulation mode to apply Zava Highly Confidential using the required locations, sensitive information types, and thresholds. Zava now owns its classification baseline end to end, and the DLP and investigation work in the next challenges builds directly on it.
