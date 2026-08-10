# Challenge 1: Discover Sensitive Data Across the Microsoft 365 Estate

### Estimated Duration: 55 Minutes

## Scenario

Zava leadership wants immediate evidence showing where sensitive information is stored across Microsoft 365 and where unprotected content presents the greatest business risk. Because the tenant is already populated and indexed, your focus is to interpret existing Microsoft Purview findings, capture reporting evidence, and explain why the riskiest location matters.

## Overview

In this challenge, you review Content Explorer findings for the required sensitive information types, determine which SharePoint location contains the highest concentration of unprotected sensitive content, export a report for evidence, and use Security Copilot in Purview to summarize unlabelled sensitive content.

## Objectives

- Task 1: Review seeded discovery findings in Content Explorer
- Task 2: Identify the highest-risk SharePoint location
- Task 3: Export reporting evidence and summarize risk with Security Copilot

## Task 1: Review seeded discovery findings in Content Explorer

In this task, you will examine the pre-indexed discovery results for the sensitive information types that matter to Zava.

1. Open Microsoft Purview and work in the Content Explorer experience for the tenant.
2. Review results for the following sensitive information types and record the counts you observe across Exchange, SharePoint, OneDrive, and Teams-backed content:
   - Credit Card Number
   - U.S. Social Security Number (SSN)
   - IBAN
   - Health-related sensitive information
3. Compare the distribution of results across workloads and note which workloads hold the largest concentration of each sensitive data type.
4. Open the underlying locations for the highest-volume result sets and confirm whether the content is already protected by a sensitivity label or appears unlabelled.
5. Record your findings in a working note that separates labelled from unlabelled sensitive content.

> **Tip:** Content Explorer supports export of the view you are currently reviewing. Capture findings only after you verify that the selected view reflects the required data type and location scope.

## Task 2: Identify the highest-risk SharePoint location

In this task, you will determine where the largest concentration of unprotected sensitive content exists in SharePoint.

1. Focus your review on SharePoint results and compare locations that contain the required sensitive information types.
2. Determine which SharePoint site, library, or folder represents the highest concentration of unprotected sensitive content.
3. Confirm your conclusion by comparing both the volume of sensitive matches and the absence of protection indicators.
4. Document the exact SharePoint location you identified and explain why it represents higher risk than the other locations you reviewed.
5. Add a short risk statement that explains the likely business impact if the location were overshared internally or externally.

## Task 3: Export reporting evidence and summarize risk with Security Copilot

In this task, you will capture evidence from the seeded environment and produce a tenant-wide summary of unlabelled sensitive content.

1. Export a summary view that reflects the tenant’s sensitive data distribution by type and location.
2. Save the exported evidence so you can reference it while completing later challenges.
3. Open Security Copilot in Purview and prompt it to summarize unlabelled content containing sensitive information types across the tenant.
4. Review the Copilot summary and compare it to the evidence you collected from Content Explorer.
5. Record the final key findings, including:
   - the most sensitive data types present
   - the workload or location with the highest risk concentration
   - why unlabelled sensitive content creates immediate governance risk
   - whether the Copilot summary aligns with the discovery evidence

## Summary

You used pre-indexed Content Explorer results to produce evidence-based discovery findings, identified the highest-risk SharePoint location, exported a report for reference, and used Security Copilot in Purview to summarize the tenant’s unlabelled sensitive content risk. These findings establish the baseline for the protection controls you will create in the next challenge.
