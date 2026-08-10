# Challenge 3: Prevent oversharing with Data Loss Prevention

### Estimated Duration: 45 Minutes

## Scenario

Zava needs protection controls that reduce two immediate risks: highly confidential content being shared outside the organization and sensitive data being exposed through generative AI websites on managed devices. You will define both policies in Microsoft Purview and leave both in simulation mode, so the design can be assessed from the configuration itself rather than from enforcement events this tenant has not yet produced.

## Overview

In this challenge, you create one DLP policy for external sharing scenarios and one Endpoint DLP policy for AI app scenarios. You will name each rule precisely, set exact conditions and actions, and verify both policies from their own configuration, so that nothing in this challenge depends on a blocked action being recorded during the lab.

## Objectives

1. Task 1: Create the external sharing DLP policy.
2. Task 2: Create the AI app Endpoint DLP policy.
3. Task 3: Verify both policies and interpret the available evidence.

## Task 1: Create the external sharing DLP policy

In this task, you will define a DLP policy that reduces the risk of highly confidential data leaving the organization.

1. Create a custom DLP policy named exactly **Block External Sharing of Highly Confidential**. This exact name is checked when you validate the challenge, so add no prefix, no suffix, and no Zava wording.
2. Apply the policy to the four Microsoft 365 collaboration locations: **Exchange email**, **SharePoint sites**, **OneDrive accounts**, and **Teams chat and channel messages**, leaving each at its default scope of all users and all sites.
3. Choose the option to create or customize advanced DLP rules. A template-based policy names the rule for you, and the rule name is part of what is assessed.
4. Name the rule exactly **Block Highly Confidential external sharing**.
5. Set the rule description exactly to **Restrict access to block people outside your organization when content carries the Zava Highly Confidential label, show a policy tip, and raise an alert for the compliance team.**
6. Add a condition that the content is labelled with the **Zava Highly Confidential** sensitivity label you created in Challenge 2, using the sensitivity label itself rather than an equivalent sensitive information type.
7. Add a second condition group joined with **or** that matches content containing **Credit Card Number** or **U.S. Social Security Number (SSN)** with an instance count of 1 or more, so unlabelled sensitive content is caught as well.
8. Add the condition that content is shared from Microsoft 365 **with people outside my organization**, then set the action to **Restrict access or encrypt the content in Microsoft 365 locations** with **Block only people outside your organization**.
9. Turn on user notifications with a policy tip whose custom text is exactly **This content is labelled Highly Confidential and is restricted from being shared outside your organization.**, and turn on incident reports with your own lab account as the recipient. This tenant has no compliance distribution group, so the report goes to the account you signed in with.
10. On the last page, run the policy in simulation mode and enable the option to show policy tips while in simulation. Do not turn the policy on.
11. Reopen the finished policy and confirm the policy name, rule name, rule description, the four locations, both condition groups, the action, and the simulation status all match the steps above.

> **Note:** The Zava Highly Confidential label is created in Challenge 2 Task 1 and published in Task 2. If it is not yet offered in the sensitivity label picker, wait a few minutes and reopen the condition, since label propagation to the DLP rule options is not instant. No content in this tenant carries the label yet, so expect the simulation to report no label matches; the second condition group in step 7 is what gives this policy something it can match.

## Task 2: Create the AI app Endpoint DLP policy

In this task, you will define a device-scoped DLP policy for generative AI website protections.

1. Open the Endpoint DLP settings under the Purview data loss prevention settings and confirm **Generative AI Websites** is listed under **Sensitive service domain groups**. The group is built in and maintained by Microsoft, so you do not need to create or populate it.
2. Create a custom DLP policy named exactly **Protect Data from AI Apps**. As in Task 1, this exact name is checked when you validate the challenge.
3. Scope the policy to the **Devices** location only and clear every other location, so it functions as an Endpoint DLP policy.
4. Choose the option to create or customize advanced DLP rules, then name the rule exactly **Block sensitive content to Generative AI Websites**.
5. Set the rule description exactly to **Uses the built-in Generative AI Websites sensitive service domain group to control Upload to a restricted cloud service domain and Paste to supported browsers activities.**
6. Set the device activities **Upload to a restricted cloud service domain** and **Paste to supported browsers** to Block, and point both at the **Generative AI Websites** sensitive service domain group. Do not confuse this with **Restricted apps and app groups**, which is a different endpoint control governing which applications may open protected files.
7. Add a content condition matching **Credit Card Number** or **U.S. Social Security Number (SSN)** with an instance count of 1 or more. Without a content condition the rule would restrict every upload and paste to those domains regardless of sensitivity, and these are the two types you confirmed in Challenge 1.
8. Turn on a policy tip whose custom text is exactly **Paste to supported browsers and Upload to a restricted cloud service domain are restricted for Generative AI Websites.**
9. On the last page, run the policy in simulation mode and do not turn the policy on, then reopen the policy and confirm the policy name, rule name, rule description, the Devices location, both activities, and the simulation status all match the steps above.

> **Note:** No device is onboarded to Microsoft Purview in this tenant, and none is needed. Creating and configuring an Endpoint DLP policy does not require an onboarded device. It does mean this policy will never record an activity here, because on devices a simulation evaluates only new actions and there is no device to produce them. The configuration is the deliverable for this task, not a blocked upload.

## Task 3: Verify both policies and interpret the available evidence

In this task, you will confirm both policies are configured as intended and draw the conclusions the available evidence actually supports.

1. Open the data loss prevention policy list and confirm both policies show a simulation status rather than on or off.
2. Open Block External Sharing of Highly Confidential and check every item against Task 1: policy name, rule name, rule description, the four collaboration locations, both condition groups, the external sharing condition, the restrict access action, the policy tip text, and the incident report recipient.
3. Open Protect Data from AI Apps and check every item against Task 2: policy name, rule name, rule description, the Devices location, both device activities, the Generative AI Websites domain group, the content condition, and the policy tip text.
4. Record the time you finished both policies. DLP policy distribution takes about an hour, so no simulation result can appear before then.
5. If you return later in the lab and the simulation for Block External Sharing of Highly Confidential has reported, review its matches against the SharePoint and OneDrive content you placed in Challenge 1. In SharePoint and OneDrive a simulation evaluates existing items as well as new ones, which is why that content can match.
6. Treat an empty simulation as a valid outcome and do not wait on it. No content in this tenant carries the Zava Highly Confidential label yet, no device is onboarded, and on devices, Teams and Exchange a simulation evaluates only new activity.
7. Compare the two policies and record how one protects the collaboration boundary while the other protects the endpoint browser boundary, which Zava risk each one answers, and why a configuration review is the appropriate evidence in this environment.

<validation step="DLP Policies"/>

## Summary

You created the two required DLP policies with the exact policy names, rule names, rule descriptions, scopes, conditions, and actions for external sharing control and generative AI website protection, and you left both in simulation mode. These policies extend Zava's protection model from data classification into leakage prevention, and both are verifiable from their own configuration rather than from enforcement events this tenant cannot yet produce.
