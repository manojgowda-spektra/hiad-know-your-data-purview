# Challenge 3: Prevent oversharing with Data Loss Prevention

### Estimated Duration: 45 Minutes

## Scenario

Zava needs protection controls that reduce two immediate risks: highly confidential content being shared outside the organization and sensitive data being exposed through generative AI websites on managed devices. You will define both policies in Microsoft Purview and keep the work aligned to simulation-first validation and existing activity evidence.

## Overview

In this challenge, you create one DLP policy for external sharing scenarios and one Endpoint DLP policy for AI app scenarios. You will focus on correct scope, conditions, and intended actions so the policies can be validated without relying on new enforcement events during the lab.

## Objectives

1. Task 1: Create the external sharing DLP policy.
2. Task 2: Create the AI app Endpoint DLP policy.
3. Task 3: Review the expected control outcomes.

## Task 1: Create the external sharing DLP policy

In this task, you will define a DLP policy that reduces the risk of highly confidential data leaving the organization.

1. Create a DLP policy named Block External Sharing of Highly Confidential.
2. Configure the policy to detect content protected with the Highly Confidential label or equivalent sensitive data conditions aligned to the reference design.
3. Configure the policy to prevent sharing outside the organization.
4. Ensure the policy also surfaces a policy tip and alerts the compliance team.
5. Keep the policy aligned to simulation-first review so the configuration can be assessed without waiting for new enforcement behavior.
6. Review the completed policy definition and confirm the name, purpose, and response actions are all correct.

## Task 2: Create the AI app Endpoint DLP policy

In this task, you will define a device-scoped DLP policy for generative AI website protections.

1. Create a DLP policy named Protect Data from AI Apps.
2. Scope the policy to Devices so it functions as an Endpoint DLP policy.
3. Use the built-in Generative AI Websites sensitive service domain group in the device-scoped policy logic.
4. Include the activities Upload to a restricted cloud service domain and Paste to supported browsers.
5. Configure the policy so it reflects the intended protection outcome for sensitive data shared to third-party generative AI websites.
6. Keep the configuration aligned to reviewable policy settings and existing endpoint evidence rather than waiting for new blocked actions to occur.

## Task 3: Review the expected control outcomes

In this task, you will validate that both DLP policies address the intended risk scenarios.

1. Review Block External Sharing of Highly Confidential and confirm it addresses oversharing risk for highly confidential content.
2. Review Protect Data from AI Apps and confirm it addresses browser-based upload and paste scenarios for generative AI websites on onboarded devices.
3. Compare both policies and note how one protects collaboration boundaries while the other protects endpoint-based AI interactions.
4. Record a short summary that explains why simulation-first validation is appropriate for this lab environment.

<validation step="DLP Policies"/>

## Summary

You created the two required DLP policies with the exact names, scopes, and intended logic for external sharing control and AI app protection. These policies extend Zava's protection model from data classification into active leakage prevention while staying grounded in reviewable configuration outcomes.
