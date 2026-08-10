# Challenge 4: Configure insider risk detection for departing users

### Estimated Duration: 45 Minutes

## Scenario

Zava can now find its sensitive data, classify it, and stop it leaving through collaboration and endpoint channels. The risk none of those controls was designed to catch is the employee who already holds legitimate access and is about to leave. Zava has no insider risk detection configured at all, so your job is to stand it up: turn the solution on, enable the signals a departing-user policy depends on, and build the policy that will score that activity when it happens.

## Overview

In this challenge, you enable Insider Risk Management and the tenant-wide policy indicators it depends on, create the Zava departing-user policy from the built-in Data theft by departing users template, prioritize the content Zava cares most about, and record how the policy will behave and how the compliance team should respond once it starts producing alerts.

## Objectives

1. Task 1: Enable Insider Risk Management and its policy indicators.
2. Task 2: Create the Zava departing-user insider risk policy.
3. Task 3: Confirm detection readiness and record the response design.

## Task 1: Enable Insider Risk Management and its policy indicators

In this task, you will turn the solution on and enable the signals every departing-user policy depends on. An indicator that is not enabled here cannot be chosen in the policy wizard, so this step decides what your policy is capable of detecting.

1. Open Insider Risk Management in Microsoft Purview. If prompted, accept the solution's data access consent so it can correlate activity across Exchange, SharePoint, OneDrive, and Teams. Confirm that the Overview, Policies, Alerts, and Cases tabs are all available before going any further.
2. Open the insider risk settings and find the policy indicators page. This page holds the tenant-wide list of signals, all of which are off in a new tenant, and a policy can only use an indicator that has been enabled here first.
3. Enable the Office indicators that represent exfiltration of Microsoft 365 content, including downloading content from SharePoint and sharing SharePoint files and folders with people outside the organization. Office indicators cover SharePoint, Teams, and email, and unlike every other category they need no onboarded device, no connector, and no pay-as-you-go billing.
4. Enable the email indicator for sending email with attachments to recipients outside the organization. Together with the two SharePoint indicators from step 3, that gives you three exfiltration signals that work in a tenant with no onboarded devices and no connectors.
5. Review the Device indicators and the Cloud storage indicators, and treat both categories as out of scope for this challenge. Device indicators such as copying data to a personal cloud storage service or to a USB device produce signal only from a device onboarded to endpoint data loss prevention, and no device is onboarded in this lab. Cloud storage indicators for services such as Box, Dropbox, and Google Drive additionally require those apps to be connected in Microsoft Defender.
6. Open the Policy timeframes setting and review the past activity detection period and the activation window. Together they decide how far on either side of a triggering event this policy scores activity, which for a departing employee means the run-up to the departure as well as what happens after it.
7. Record the indicator set you enabled and the timeframes you reviewed, and record separately which of Zava's intended departing-user signals depend on device onboarding. Anything in that second list is a detection gap that no policy setting can compensate for.

> **Tip:** If an indicator you expect is greyed out in the policy wizard, it has not been enabled tenant-wide. Turn it on from the Turn on indicators prompt in the wizard, or come back to this settings page. Enabling an indicator and selecting it in a policy are two separate actions, and the wizard only offers what has already been enabled.

## Task 2: Create the Zava departing-user insider risk policy

In this task, you will build the policy that scores departing-employee activity, using the content and classifications you established earlier in this lab.

1. Create an insider risk policy named Zava Departing Employee Data Theft and build it from the built-in Data theft by departing users template.
2. Scope the policy to include all users and groups, so the detection window opens for whoever leaves rather than for a list somebody has to maintain.
3. Choose Microsoft Entra account deleted as the triggering event. The departing-user template accepts either a resignation or termination date from an HR data connector or a Microsoft Entra account deletion, and this tenant has no HR data connector configured. Record which trigger Zava should use in production, and why a resignation date from an HR feed gives earlier warning than an account deletion does.
4. Prioritize the content this lab has already identified as Zava's most sensitive: the SharePoint site you used in Challenge 1, the Zava Highly Confidential label you created in Challenge 2, and the Credit Card Number and U.S. Social Security Number (SSN) types you validated in Challenge 1. Prioritized content raises the risk score when activity involves it, which is what separates a departing employee taking a team calendar from one taking a customer payment record.
5. On the policy indicators page, confirm the policy uses the three exfiltration indicators you enabled in Task 1: downloading content from SharePoint, sharing SharePoint files and folders with people outside the organization, and sending email with attachments to recipients outside the organization.
6. Finish the wizard, then find the policy on the policies dashboard and read whatever its Status column reports. Policy health names the exact dependency the service thinks is missing, which is more useful to you than a green tick.

> **Note:** If the Zava Highly Confidential label is not offered in the prioritized content picker, prioritize the SharePoint site and the two sensitive information types instead, and record the label as a follow-up. Everything except the template and the name can be changed after a policy is created, so nothing has to be rebuilt.

## Task 3: Confirm detection readiness and record the response design

In this task, you will establish what the policy will and will not do in its first hours of life, and write the response design Zava's compliance team needs before the first alert arrives.

1. Open the policy from the policies page and confirm that its template, scope, trigger, indicators, and prioritized content all match what Zava asked for.
2. Confirm the alerts queue is empty, and establish why that is the expected result. Insider Risk Management scores users on a daily evaluation cycle, and only after a triggering event has occurred for a user in scope, so a policy created minutes ago cannot yet have produced an alert. An empty queue here is evidence that the policy is new, not evidence that it is broken.
3. Record the three conditions that must all be true before this policy raises its first alert: a user in scope reaches the triggering event, that user's activity matches one or more of the indicators you enabled, and the accumulated risk score crosses the policy's alert threshold.
4. For each of the three exfiltration indicators in the policy, write down the departing-employee behavior it represents and the evidence an analyst would expect the resulting alert to carry: the user, the files, the destination, and the timing relative to the departure.
5. Rank those three indicators by how strongly you would read each one as intent rather than routine work, and justify the ranking. Downloading content from SharePoint is the most ambiguous of the three, so state what additional context would move it from ambiguous to suspicious.
6. Record a short response design covering who triages an alert from this policy, what evidence they gather first, and the point at which Zava escalates to HR and legal.
7. Capture a closing statement that places this policy against the rest of the lab, naming which control finds Zava's sensitive data, which classifies it, which prevents it leaving, and which addresses the person who already has access to it.

> **Note:** Where Security Copilot in Purview is available, use it to summarise the policy you configured and to draft the response design in step 6, then compare its output with the reasoning you recorded yourself. Security Copilot requires provisioned capacity and is not part of a Microsoft 365 E5 licence, so treat this step as optional. The challenge is complete without it.

## Summary

You enabled Insider Risk Management and the tenant-wide indicators a departing-user policy depends on, created Zava Departing Employee Data Theft from the Data theft by departing users template with a documented trigger and with Zava's most sensitive content prioritized, and recorded both why a newly created policy has an empty alert queue and how the compliance team should respond when it does not. Zava now has coverage for the risk its labels and DLP policies cannot address: the person who already holds legitimate access and is on the way out.
