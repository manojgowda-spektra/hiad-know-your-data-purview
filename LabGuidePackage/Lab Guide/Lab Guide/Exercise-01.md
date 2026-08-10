# Challenge 1: Discover Sensitive Data Across the Microsoft 365 Estate

### Estimated Duration: 55 Minutes

## Scenario

Zava leadership wants evidence showing where sensitive information is stored across Microsoft 365 and where unprotected content presents the greatest business risk. Nobody has yet proven that Microsoft Purview can even see Zava's sensitive data, so your first job is to establish that detection works, place representative content into the estate, and stand up the instrumentation that will report on it.

## Overview

In this challenge, you confirm that Microsoft Purview detects the sensitive information types Zava cares about, place representative sensitive content into SharePoint and OneDrive, configure a detection policy in simulation mode so the estate is instrumented, and then interpret the resulting evidence to identify the highest-risk location.

## Objectives

1. Task 1: Confirm Microsoft Purview detects Zava's sensitive information types.
2. Task 2: Place representative sensitive content into the Microsoft 365 estate.
3. Task 3: Instrument the estate and interpret the discovery evidence.

## Task 1: Confirm Microsoft Purview detects Zava's sensitive information types

In this task, you will prove that the classification engine recognises the data types that matter to Zava, before relying on it for anything else.

1. Open the sensitive information type definitions in Microsoft Purview and locate the four types Zava depends on: **Credit Card Number**, **U.S. Social Security Number (SSN)**, **IBAN**, and a health-related type such as **All Full Names** combined with a health condition indicator.
2. Review the detection definition for Credit Card Number and note the confidence level and the supporting evidence the pattern requires.
3. Use the built-in test capability for Credit Card Number with sample content containing the reserved test value `4111 1111 1111 1111` and confirm the type reports a match.
4. Repeat the test for U.S. Social Security Number (SSN) using a value in the documented `xxx-xx-xxxx` format.
5. Record which types matched, at what confidence, and what evidence each one required. This is your baseline: any later gap in discovery is a coverage problem, not a detection problem.

> **Tip:** Testing a sensitive information type returns a result immediately. This is the only discovery step in the lab that does not depend on background processing, which makes it the right place to start.

## Task 2: Place representative sensitive content into the Microsoft 365 estate

In this task, you will create the content that Zava's discovery controls will act on.

1. Create three documents containing the sensitive information types you validated in Task 1, using reserved test values rather than real data. Give each a name that reflects a plausible business purpose, such as a customer payment record, a payroll extract, and a patient contact list.
2. Place one document in a SharePoint site that represents a broadly shared team location.
3. Place a second document in the same SharePoint site inside a separate library, so you have two locations in one site to compare.
4. Place the third document in your OneDrive.
5. Record the exact locations you used. You will compare them in Task 3, and Challenges 2 and 3 will act on this same content.

> **Note:** Reserved test values are used throughout so that no real sensitive data enters the lab tenant. Detection behaves identically.

## Task 3: Instrument the estate and interpret the discovery evidence

In this task, you will configure the control that reports on sensitive content, then reason about what it tells you.

1. Create a Data Loss Prevention policy in **simulation mode** scoped to SharePoint and OneDrive, matching the sensitive information types you validated in Task 1. Simulation mode reports matches without enforcing anything.
2. Confirm the policy is running in simulation and not turned on. In SharePoint and OneDrive, simulation evaluates existing items as well as new ones, which is why it can report on the content you placed in Task 2.
3. Record the time you started the simulation. Results typically appear within about an hour, so continue to Challenge 2 and return to this task once the simulation has reported.
4. Review the simulation results and compare the locations you used. Determine which location holds the highest concentration of unprotected sensitive content.
5. Confirm your conclusion using two independent signals: the volume of sensitive matches in that location, and the absence of any sensitivity label protecting it.
6. Document the location you identified, and explain why it represents higher risk than the others you reviewed.
7. Record a short risk statement covering the likely business impact if that location were overshared internally or externally, and note which sensitive information types drove your assessment.

> **Note:** Where Security Copilot in Purview is available, use it to summarise the unlabelled sensitive content across the tenant and compare its summary with the evidence you gathered. Security Copilot requires provisioned capacity and is not part of a Microsoft 365 E5 licence, so treat this step as optional. The challenge is complete without it.

## Summary

You proved that Microsoft Purview detects the sensitive information types Zava depends on, placed representative content across SharePoint and OneDrive, instrumented the estate with a simulation-mode Data Loss Prevention policy, and produced an evidence-based finding identifying the highest-risk location. These findings establish the baseline for the protection controls you will create in the next challenge.
