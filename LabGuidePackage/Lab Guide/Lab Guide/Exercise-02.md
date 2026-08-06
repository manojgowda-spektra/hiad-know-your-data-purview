# Challenge 2: Classify data with sensitivity labels and auto-labeling

### Estimated Duration: 75 Minutes

## Scenario

Zava wants a tenant-specific classification model that clearly separates business-ready protection settings from the reference baseline that already exists in the tenant. You will create a new Zava label set, publish it for use, and define an auto-labeling policy that stays in simulation mode so the organization can validate scope and impact before enforcement.

## Overview

In this challenge, you create four sensitivity labels with exact names and behaviors, compare them with the pre-published reference labels, publish them through a global label policy, and configure a simulation-based auto-labeling policy for Microsoft 365 data.

## Objectives

1. Task 1: Create the four Zava sensitivity labels.
2. Task 2: Compare and publish the Zava labels.
3. Task 3: Configure and review the auto-labeling simulation.

## Task 1: Create the four Zava sensitivity labels

In this task, you will build the Zava label taxonomy exactly as required.

1. Create a sensitivity label named Zava Public and configure it with no encryption and no header, footer, or watermark.
2. Create a sensitivity label named Zava Internal and configure it with a header exactly set to Zava Internal and no encryption.
3. Create a sensitivity label named Zava Confidential and configure it with encryption, permissions for internal users only, and a watermark exactly set to Confidential.
4. Create a sensitivity label named Zava Highly Confidential and configure it with encryption using Do Not Forward.
5. Ensure Zava Highly Confidential also includes Groups & sites, restricts external sharing to Only people in your organization, and applies a watermark exactly set to Highly Confidential.
6. Review the four labels together and confirm the names and protection settings match the design requirements with no extra behaviors added.

<validation step="Sensitivity Labels"/>

## Task 2: Compare and publish the Zava labels

In this task, you will distinguish your new labels from the tenant baseline and make them available through a publishing policy.

1. Review the pre-published reference sensitivity labels that already exist in the tenant.
2. Compare the reference labels with your Zava labels and note the difference between tenant baseline controls and learner-created controls.
3. Create a label policy named Zava Global Label Policy.
4. Publish all four Zava labels through Zava Global Label Policy.
5. Confirm the policy scope and published label set reflect the full Zava taxonomy.
6. Record how the comparison helps you tell apart existing reference configuration from the controls you created during the lab.

<validation step="Zava Global Label Policy"/>

## Task 3: Configure and review the auto-labeling simulation

In this task, you will define a simulation-first auto-labeling policy for Microsoft 365 workloads.

1. Create an auto-labeling policy named Zava Auto-Label Policy.
2. Configure the policy to apply the pre-published reference Highly Confidential label rather than one of the new Zava labels.
3. Target SharePoint, OneDrive, and Exchange as the policy locations.
4. Configure the policy to detect Credit Card Number and U.S. Social Security Number (SSN), with a minimum count of 5 for each type.
5. Keep the policy in simulation mode and do not turn it on for production labeling.
6. Review the simulation results and confirm they align with the pre-warmed environment rather than expecting fresh propagation during the lab window.
7. Capture a short outcome statement that explains what the simulation demonstrates about future labeling impact.

<validation step="AutoSensitivityLabelPolicy"/>

## Summary

You created four Zava sensitivity labels, compared them with the tenant's pre-published reference labels, published them through Zava Global Label Policy, and configured Zava Auto-Label Policy in simulation mode using the required locations, sensitive information types, and thresholds. Zava now has a clear classification baseline that supports downstream DLP and investigation scenarios.
