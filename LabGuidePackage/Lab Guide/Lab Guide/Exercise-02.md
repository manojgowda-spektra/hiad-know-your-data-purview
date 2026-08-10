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

1. Turn on sensitivity labels for Office files in SharePoint and OneDrive. This is off in a new tenant, and until it is on, the labels you create have no effect on content held in those two locations.
2. Turn on sensitivity labels for Microsoft 365 groups and sites, then run a label sync to Microsoft Entra ID so that the container settings become configurable.
3. Create a sensitivity label named Zava Public and configure it with no encryption and no header, footer, or watermark.
4. Create a sensitivity label named Zava Internal and configure it with a header exactly set to Zava Internal and no encryption.
5. Create a sensitivity label named Zava Confidential and configure it with encryption, permissions for internal users only, and a watermark exactly set to Confidential.
6. Create a sensitivity label named Zava Highly Confidential and configure it with encryption using Do Not Forward.
7. Ensure Zava Highly Confidential also includes Groups & sites, restricts external sharing to Only people in your organization, and applies a watermark exactly set to Highly Confidential.
8. Review the four labels together and confirm the names and protection settings match the design requirements with no extra behaviors added.

> **Note:** Steps 1 and 2 come first for a reason. While sensitivity labels are not enabled for groups and sites, the Groups & sites scope and its external sharing controls are visible in the label wizard but cannot be configured, so step 7 cannot be completed and Zava Highly Confidential will fail validation. Enabling it is a Microsoft Entra directory setting followed by a label sync run from Security and Compliance PowerShell, and it requires Global Administrator.

<validation step="Sensitivity Labels"/>

## Task 2: Publish the Zava labels through a global label policy

In this task, you will make the taxonomy usable by publishing it, and settle the ordering that decides which label wins.

1. Review the tenant's label list and confirm the only labels present are the four you created in Task 1. This tenant ships with no classification taxonomy, so the Zava set is the whole of it.
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
2. Configure the policy to apply the Zava Highly Confidential label you created in Task 1 and published in Task 2.
3. Target SharePoint, OneDrive, and Exchange as the policy locations.
4. Configure the policy to detect Credit Card Number and U.S. Social Security Number (SSN), with a minimum count of 5 for each type.
5. Run the policy in simulation mode, leave the option that automatically turns the policy on after seven days unselected, and do not turn the policy on yourself.
6. Open the saved policy and confirm it shows Zava Highly Confidential as the label to apply, all three locations, and both sensitive information types at a minimum count of 5. These are the values this challenge is graded on.
7. Working from the policy conditions rather than from results, predict which of the documents you placed in Challenge 1 this policy would label, and record the sensitive information type and instance count that drives each match.
8. Record a short outcome statement explaining what Zava gains by proving this policy in simulation first, and what evidence the team would want before turning it on.

> **Note:** A simulation takes about 12 hours to complete, and for roughly 24 hours after a policy is created its Turn on policy, Edit, and Delete actions are greyed out while the service finishes provisioning it. Neither window fits inside this lab. An empty Items to review tab and a disabled Turn on policy button are the expected state at this point, not a failure, so do not wait on either.

> **Note:** The auto-labeling page shows a pay-as-you-go billing notice for non-Microsoft 365 data sources. This policy targets Microsoft 365 locations only, so nothing you configure here is billed that way.

<validation step="AutoSensitivityLabelPolicy"/>

## Summary

You turned on the tenant settings that label protection depends on, created four Zava sensitivity labels, published them through Zava Global Label Policy, and configured Zava Auto-Label Policy in simulation mode to apply Zava Highly Confidential using the required locations, sensitive information types, and thresholds. Zava now owns its classification baseline end to end, and the DLP and investigation work in the next challenges builds directly on it.
