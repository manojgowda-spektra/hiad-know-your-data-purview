# Challenge 4: Detect and investigate insider risk with Security Copilot

### Estimated Duration: 60 Minutes

## Scenario

Zava wants to understand whether recent user activity associated with departing employees indicates routine behavior or probable data theft. You will configure the required insider risk policy, review two seeded alerts, and use Security Copilot in Purview to produce an investigation summary based on available evidence.

## Overview

In this challenge, you create a departing-user insider risk policy, review pre-seeded alerts, compare suspicious behaviors, and use Security Copilot in Purview to summarize user activity, affected files, and final risk conclusions.

## Objectives

1. Task 1: Configure the insider risk policy.
2. Task 2: Review the seeded insider risk alerts.
3. Task 3: Use Security Copilot in Purview to complete the investigation.

## Task 1: Configure the insider risk policy

In this task, you will define the insider risk policy required for the Zava scenario.

1. Create an insider risk policy named Zava Departing Employee Data Theft.
2. Use the Data theft by departing users template.
3. Tie the policy to the HR data connector resignation date trigger.
4. Include indicators for downloading files from SharePoint, copying data to personal cloud storage, and sending email with attachments to external recipients.
5. Review the completed policy and confirm the template, trigger, and indicators align to the intended departing-user risk scenario.

## Task 2: Review the seeded insider risk alerts

In this task, you will examine the available insider risk evidence for two departing employees.

1. Open the insider risk alerts that are already present in the tenant.
2. Review the first alert and identify the user activity, the files involved, and the behaviors that may indicate elevated exfiltration risk.
3. Review the second alert and compare its activity pattern with the first alert.
4. Determine which behaviors are more consistent with suspicious data theft and which may reflect lower-risk activity in context.
5. Answer the inline knowledge check when prompted.

<question>

## Task 3: Use Security Copilot in Purview to complete the investigation

In this task, you will use Security Copilot in Purview to summarize and defend your investigation outcome.

1. Use Security Copilot in Purview to summarize the first insider risk alert, including accessed files and overall user risk level.
2. Compare the Copilot interpretation with the evidence you reviewed directly in the alert details.
3. Use the second alert to contrast behaviors that indicate elevated exfiltration risk versus standard or less concerning activity.
4. Capture an investigation summary that explains the suspicious activity, affected content, and final risk assessment.
5. Answer the remaining inline knowledge checks when prompted.

<question>

<question>

## Summary

You configured the required departing-user insider risk policy, reviewed the seeded alerts for two employees, and used Security Copilot in Purview to produce an evidence-based risk summary. This challenge closes the lab by connecting configuration, signals, and investigation reasoning into a practical Microsoft Purview response workflow.
