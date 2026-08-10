# Know Your Data - Discover, Classify and Protect Sensitive Information with Microsoft Purview

### Estimated Duration: 20 Minutes

## Scenario

Zava has asked you to act as a compliance and information protection practitioner in a Microsoft 365 E5 tenant. You will establish that Microsoft Purview can detect Zava's sensitive data, build the classification and protection controls the business needs, and reason about insider risk. Some Microsoft Purview signals take time to appear, so the lab is sequenced to let background processing run while you work on the next challenge.

## Lab Overview

This lab is a challenge-based experience made up of four progressive challenges. You will first prove that Microsoft Purview detects Zava's sensitive data and instrument the estate to report on it, then create Zava-specific sensitivity labels and publishing controls, build DLP policies aligned to the reference design, and finally configure and reason about insider risk detection. All challenge work is done in the browser against Microsoft 365 and Microsoft Purview. A Windows lab virtual machine is also deployed for you as a workspace, but no Azure configuration is required in any challenge.

## Objectives

1. Confirm sensitive information type detection, place representative content, and instrument discovery across SharePoint and OneDrive.
2. Create and compare Zava-specific sensitivity labels and an auto-labelling policy in simulation mode.
3. Configure DLP policies to reduce external sharing risk and generative AI app exposure.
4. Configure a departing-user insider risk policy and interpret the risk indicators it depends on.

## Prerequisites

1. Use a supported desktop browser and ensure pop-ups or downloads are not blocked for Microsoft 365 and Microsoft Purview.
2. Sign in with the lab account provided. It must be able to administer Information Protection, Data Loss Prevention and Insider Risk Management in Microsoft Purview.
3. Use only the reserved test values supplied in the lab. Do not place real sensitive data in the tenant.
4. Expect some Microsoft Purview results to take up to an hour to appear. Where a challenge depends on that, it tells you to continue and return later.

## Sign-in

1. Open <https://purview.microsoft.com/> and sign in with Username: <inject key="AzureAdUserEmail"/> and the access code shown as **Temporary Access Pass** on your Environment tab: <inject key="AzureAdUserPassword"/>.
2. **Confirm you are in the lab tenant before you begin.** Open **Settings** and check that **Account overview** shows the lab tenant name, not your own organization. If you are on a corporate device, your browser may sign you in to your employer's tenant automatically, and the portal looks identical. If that happens, sign out and sign back in with the lab account above.
3. Confirm that you can reach Information Protection, Data Loss Prevention and Insider Risk Management under Solutions. If any of them opens as a read-only overview page, your account is missing the required Microsoft Purview role and you should contact your lab operator before continuing.
4. Keep your deployment reference available as **Deployment ID: <inject key="DeploymentID" enableCopy="false"/>** in case your lab operator asks you to confirm the active environment.

## Architecture

This lab uses a browser-based Microsoft 365 tenant with Microsoft Purview available. You work from your browser into the Microsoft Purview portal, and from there into four solution areas:

| Solution area | What it holds for this lab | Used in |
|---|---|---|
| **Sensitive information types** | The detection patterns you validate and then rely on | Challenge 1 |
| **Information Protection** | The Zava sensitivity labels and publishing policy you create | Challenge 2 |
| **Data Loss Prevention** | Collaboration policies and endpoint DLP evidence | Challenge 3 |
| **Insider Risk Management** | The departing-user policy you configure and its risk indicators | Challenge 4 |

**Security Copilot in Purview** sits alongside these and is used to summarise findings in Challenges 1 and 4.

## Components

1. **Microsoft 365 E5 demo tenant** provides the Microsoft 365 workloads and permissions context used throughout the lab.
2. **Microsoft Purview sensitive information types** provide the detection patterns for credit card numbers, U.S. Social Security numbers, IBANs and health-related content, and can be tested directly for an immediate result.
3. **Reserved test values** are used for all sensitive content you create, so detection behaves realistically without any real data entering the tenant.
4. **Simulation mode** lets Data Loss Prevention report on existing SharePoint and OneDrive content without enforcing anything, which is how discovery evidence is produced.
5. **Auto-labelling in simulation mode** lets you validate scope and impact before any label is applied in production.
6. **Endpoint DLP settings** include the built-in Generative AI Websites sensitive service domain group used by the device-scoped policy.
7. **Insider Risk Management policy templates** provide the departing-user detection model used in the final challenge.
8. **Security Copilot in Purview** helps summarize discovery findings and insider risk evidence during the challenges.

## Challenge Map

1. **Challenge 1: Discover sensitive data across the Microsoft 365 estate** focuses on validating sensitive information type detection, placing representative content, and instrumenting discovery with a simulation-mode policy.
2. **Challenge 2: Classify data with sensitivity labels and auto-labelling** focuses on creating four exact Zava labels, publishing them, and configuring an auto-labelling policy in simulation mode.
3. **Challenge 3: Prevent oversharing with Data Loss Prevention** focuses on creating two exact DLP policies, including a device-scoped policy that uses the built-in Generative AI Websites sensitive service domain group.
4. **Challenge 4: Detect and investigate insider risk** focuses on configuring a departing-user insider risk policy and reasoning about the indicators and evidence it relies on.

## What to expect

1. Some Microsoft Purview results take up to an hour to appear. Challenge 1 starts a simulation early and asks you to return to it, so background processing runs while you work on Challenge 2.
2. You will build the Zava configuration yourself, and use reserved test values so no real sensitive data enters the tenant.
3. Challenge 2 and Challenge 3 are validated through automated configuration checks. Challenge 1 and Challenge 4 are assessed through the evidence and reasoning you record.
4. You should keep notes as you progress because several challenges require you to capture summary findings and compare observed risk signals.
