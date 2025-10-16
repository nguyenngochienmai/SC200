[Site to File - https___learn.microsoft.com_en-us_training_paths_sc-200-mitigate-threats-using-microsoft-365-defender_.md](https://github.com/user-attachments/files/22944149/Site.to.File.-.https___learn.microsoft.com_en-us_training_paths_sc-200-mitigate-threats-using-microsoft-365-defender_.md)
The entire content from https://learn.microsoft.com/en-us/training/paths/sc-200-mitigate-threats-using-microsoft-365-defender/ up to 2 levels deep.  
---------------------------------------------  

---------------------------------------------The entire content from https://learn.microsoft.com/en-us/training/paths/sc-200-mitigate-threats-using-microsoft-365-defender/ up to 2 levels deep.  
---------------------------------------------    
# SC-200: Mitigate threats using Microsoft Defender XDR

## Title  
SC-200: Mitigate threats using Microsoft Defender XDR

## Summary  
Analyze threat data across domains and rapidly remediate threats with built-in orchestration and automation in Microsoft Defender XDR. This learning path aligns with exam SC-200: Microsoft Security Operations Analyst.

## Prerequisites  
- Fundamental understanding of Microsoft security, compliance, and identity products  
- Basic understanding of Microsoft Defender XDR

## Modules name in the learning path  
1. Introduction to Microsoft Defender XDR threat protection  
2. Mitigate incidents using Microsoft Defender  
3. Remediate risks with Microsoft Defender for Office 365  
4. Manage Microsoft Entra Identity Protection  
5. Safeguard your environment with Microsoft Defender for Identity  
6. Secure your cloud apps and services with Microsoft Defender for Cloud Apps  
----------------------------------------------------------------------    
# Introduction to Microsoft Defender XDR threat protection

- 28 min  
- Module  
- 7 Units

## Intermediate

- Security Operations Analyst  
- Microsoft Defender for Cloud Apps  
- Microsoft Defender for Identity  
- Microsoft 365  
- Microsoft Defender XDR

In this module, you'll learn how to use the Microsoft Defender XDR integrated threat protection suite.

## Learning objectives

In this module, you learned the role that Microsoft Defender XDR plays in a modern SOC. You should now be able to:

- Understand Microsoft Defender XDR solutions by domain  
- Understand the Microsoft Defender XDR role in a Modern SOC

## Prerequisites

None

## This module is part of these learning paths

- SC-200: Mitigate threats using Microsoft Defender XDR

## Units in this module

- Introduction (3 min)  
- Explore Extended Detection & Response (XDR) response use cases (3 min)  
- Understand Microsoft Defender XDR in a Security Operations Center (SOC) (3 min)  
- Explore Microsoft Security Graph (10 min)  
- Investigate security incidents in Microsoft Defender XDR (3 min)  
- Module assessment (3 min)  
- Summary and resources (3 min)

---

## Module assessment

Assess your understanding of this module. Sign in and answer all questions correctly to earn a pass designation on your profile.  
--------------------------------------------------    
# Introduction to Microsoft Defender XDR threat protection

## Introduction

**Completed 100 XP**

- 3 minutes

Microsoft Defender XDR is an integrated threat protection suite with solutions that detect malicious activity across email, endpoints, applications, and identity. These solutions provide a complete attack chain compromise story that enables a complete understanding of the threat. And, enables you to remediate and protect your organization from future attacks.

In the sample attack chain graphic example, see the attacker activity visible to each Microsoft Defender XDR product.

![Diagram of Microsoft Defender XDR tools to defend across attack chains.](https://learn.microsoft.com/en-us/training/wwl-sci/introduction-microsoft-365-threat-protection/media/defend-attack-chains.png)

You're a Security Operations Analyst working at a company that is implementing Microsoft Defender XDR solutions. You need to understand how Extended Detection and Response (XDR) combines signals from:

- endpoints  
- identity  
- email  
- applications

to detect and mitigate threats.  
--------------------------------------------------    
# Explore Extended Detection & Response (XDR) response use cases

**Completed 100 XP**

- 3 minutes

The following are examples of detection and mitigation use cases.

## Detection of Threat

This scenario depicts a case where Microsoft Defender for Endpoint detects a malicious payload (which could come from any source, including personal email or a USB drive).

![Diagram the Detection of a Compromised endpoint.](https://learn.microsoft.com/en-us/training/wwl-sci/introduction-microsoft-365-threat-protection/media/compromised-endpoint.png)

The victim receives a malicious email on a personal email account not protected by Microsoft Defender for Office 365 (MDO) or a USB drive and opens the attachment. Once the attachment opens, the malware infects the computer. The user is unaware that an attack occurred. But Microsoft Defender for Endpoints (MDE) detects this attack, raises an alert to security operations, and provides details about the threat to the Security team. Disable user access from device while infected - MDE communicates to Intune that the risk level on this endpoint has changed. An Intune Compliance Policy configured with an MDE risk level severity is triggered and marks the account as noncompliant with organizations policy. The Conditional Access created in Microsoft Entra ID blocks user access to apps.

### Remediation

MDE remediates threat – either via automated remediation, security analyst approval of automated remediation, or analyst manual investigation of threat.    
MDE also remediates this threat across your enterprise and across our Microsoft MDE customers by adding information on this attack to Microsoft Threat Intelligence system

### Share Intelligence and Restore Access

Restore Access – Once the infected devices are remediated, MDE signals Intune to change the device risk status and Microsoft Entra ID Conditional Access then allows access to enterprise resources (more on the next slide). Remediate Threat Variants in MDO and others – The threat signals in Microsoft Threat intelligence are used by Microsoft tools securing other parts of your organization’s attack surface. MDO and Microsoft Defender for Cloud use the signals to detect and remediate threats in email, office collaboration, Azure, and more.

## From the previous graphic when the user’s device was still compromised

![Diagram of steps to Suspend access during compromise.](https://learn.microsoft.com/en-us/training/wwl-sci/introduction-microsoft-365-threat-protection/media/suspend-access-compromise.png)

### Access Restricted

Conditional Access knows about device risk because Microsoft Defender for Endpoint (MDE) notified Intune, which then updated the compliance status of the device in Microsoft Entra ID.

During this time, the user is restricted from accessing corporate resources. This applies to all new resource requests and blocks any current access to resources that support continuous access evaluation (CAE). People are able to do general internet productivity tasks, like research YouTube, Wikipedia, and anything else that doesn’t require corporate authentication, but won’t have access to corporate resources.

### Access Restored

Once the threat has been remediated and cleaned up, MDE triggers Intune to update Microsoft Entra ID, and Conditional Access restores the user’s access to corporate resources.

This mitigates risk to the organization by ensuring attackers who might be in control of these devices can't access corporate resources, while minimizing the impact on user productivity to minimize disruption of business processes.  
--------------------------------------------------    
# Understand Microsoft Defender XDR in a Security Operations Center (SOC)

**Completed 100 XP**

- 3 minutes

The following graphic provides an overview of how Microsoft Defender XDR and Microsoft Sentinel are integrated in a Modern Security Operations Center (SOC).

![Diagram that shows the layers and technologies of Security Operations.](https://learn.microsoft.com/en-us/training/wwl-sci/introduction-microsoft-365-threat-protection/media/security-operations.png)

## Security Operations Model - Functions and Tools

While the assignment of responsibilities to individual people and teams vary based on organization size and other factors, security operations are composed of several distinct functions. Each function/team has a primary focus area and also must collaborate closely with other functions and outside teams to be effective. This diagram depicts the full model with fully staffed teams. In smaller organizations, these functions are often combined into a single role or team, performed by IT Operations (for technical roles), or are performed as a temporary function by leadership/delegates (for incident management)

> **Note**  
>   
> We primarily refer to the analysts by the team name, not the Tier numbers as these teams each have unique specialized skills, they aren't a literal ranking/hierarchical of value.

![Diagram that shows the Security Operations Model with functions and tools.](https://learn.microsoft.com/en-us/training/wwl-sci/introduction-microsoft-365-threat-protection/media/security-operations-model.png)

### Triage and Automation

We start with handling reactive alerts – which begins with:

- **Automation** – Near real-time resolution of known incident types with automation. These are well-defined attacks that the organization has seen many times.  
- **Triage (aka Tier 1)** – Triage analysts focus on rapid remediation of a high volume of well-known incident types that still require (quick) human judgment. These are often tasked with approving automated remediation workflows and identifying anything anomalous or interesting that warrant escalation or consultation with investigation (Tier 2) teams.

    Key learnings for Triage and Automation:

    - **90% true positive** - We recommend setting a quality standard of 90% true positive for any alert feeds that require an analyst to respond so analysts aren’t required to respond to a high volume of false alarms.  
    - **Alert Ratio** – In Microsoft’s experience from our Cyber Defense Operations Center, XDR alerts produce most of the high-quality alerts, with the remainders coming from user reported issues, classic log query based alerts, and other sources  
    - **Automation** is a key enabler for triage teams as it helps empower these analysts and reduce the burden of manual effort (for example, provide automated investigation and then prompt them for a human review before approving the remediation sequence that was automatically built for this incident).  
    - **Tool Integration** - One of the most powerful time saving technologies that improved time to remediation in Microsoft’s CDOC is the integration of XDR tools together into Microsoft Defender XDR so analysts have a single console for endpoint, email, identity, and more. This integration enables analysts to rapidly discover and clean up attacker phishing emails, malware, and compromised accounts before they can do significant damage.  
    - **Focus** - These teams can't maintain their high speed of resolution for all types of technologies and scenarios, so they keep their focus narrow on a few technical areas and/or scenarios. Most often this is on user productivity, like email, endpoint AV alerts (versus EDR that goes into investigations), and first response for user reports.

### Investigation and Incident Management (Tier 2)

This team serves as the escalation point for issues from Triage (Tier 1), and directly monitors alerts that indicate a more sophisticated attacker. Specifically alerts that trigger behavioral alerts, special case alerts related to business-critical assets, and monitoring for ongoing attack campaigns. Proactively, this team also periodically reviews the Triage team alert queue and can proactively hunt using XDR tools in their spare time.

This team provides deeper investigation into a lower volume of more complex attacks, often multi-stage attacks conducted by human attack operators. This team pilots new/unfamiliar alert types to document processes for Triage team and automation, often including alerts generated by Microsoft Defender for Cloud on cloud hosted apps, VMs, containers, and Kubernetes, SQL databases, etc.

**Incident Management** – This team takes on the nontechnical aspects of managing incidents including coordination with other teams like communications, legal, leadership, and other business stakeholders.

### Hunt and Incident Management (Tier 3)

This is a multi-disciplinary team focused on identifying attackers that could have slipped through the reactive detections and handling major business-impacting events.

- **Hunt** – This team proactively hunts for undetected threats, assists with escalations and advanced forensics for reactive investigations, and refines alerts/automation. These teams operate in more of a hypothesis-driven model than a reactive alert model and are also where red/purple teams connect with security operations.

### How It Comes Together

To give you an idea of how this works, let’s follow a common incident lifecycle

1. **Triage (Tier 1)** analyst claims a malware alert from the queue and investigates (for example, with Microsoft Defender XDR console)  
2. While most Triage cases are rapidly remediated and closed, this time the analyst observes that malware might require more involved/advanced remediation (for example, device isolation and cleanup). Triage escalates the case to the Investigation analyst (Tier 2), who takes lead for investigation. The Triage team has option to stay involved and learn more (Investigation team might use Microsoft Sentinel or another SIEM for broader context)  
3. **Investigation** verifies investigation conclusions (or digs further into it) and proceeds with remediation, closes case.  
4. Later, **Hunt (Tier 3)** might notice this case while reviewing closed incidents to scan for commonalities or anomalies worth digging into:  
    - Detections that might be eligible for autoremediation  
    - Multiple similar incidents that might have a common root cause  
    - Other potential process/tool/alert improvements  
    In one case, Tier 3 reviewed the case and found that the user had fallen for a tech scam. This detection was then flagged as a potentially higher priority alert because the scammers had managed to get admin level access on the endpoint. A higher risk exposure.

### Threat intelligence

**Threat Intelligence teams** provide context and insights to support all other functions (using a threat intelligence platform (TIP) in larger organizations). This could include many different facets including

- Reactive technical research for active incidents  
- Proactive technical research into attacker groups, attack trends, high profile attacks, emerging techniques, etc.  
- Strategic analysis, research, and insights to inform business and technical processes and priorities.  
- And more  
--------------------------------------------------    
# Explore Microsoft Security Graph

Completed 100 XP

- 10 minutes

Microsoft Graph provides a unified programmability model that you can use to access the data in Microsoft 365, Windows, and Enterprise Mobility + Security. You can use the data in Microsoft Graph to build customized apps for your organization.

The Microsoft Graph API offers a single endpoint (either v1.0 or beta versions). You can use REST APIs or SDKs to access the endpoint and build apps that support Microsoft 365 scenarios. Microsoft Graph also includes a powerful set of services that manage user and device identity, access, compliance, and security and help protect organizations from data leakage or loss.

### What's in Microsoft Graph?

Microsoft Graph exposes REST APIs and client libraries to access data on the following Microsoft cloud services:

- Microsoft 365 core services: Bookings, Calendar, Delve, Excel, Microsoft Purview eDiscovery, Microsoft Search, OneDrive, OneNote, Outlook/Exchange, People (Outlook contacts), Planner, SharePoint, Teams, To Do, Viva Insights  
- Enterprise Mobility + Security services: _Advanced Threat Analytics_, _Advanced Threat Protection_, Microsoft Entra ID, Identity Manager, and Intune  
- Windows services: activities, devices, notifications, Universal Print  
- Dynamics 365 Business Central services

### Microsoft Graph Security API

The Microsoft Graph security API is an intermediary service (or broker) that provides a single programmatic interface to connect multiple Microsoft Graph security providers. Requests to the Microsoft Graph security API are federated to all applicable security providers. The results are aggregated and returned to the requesting application in a common schema.

Developers can use the Security Graph to build intelligent security services that:

- Integrate and correlate security alerts from multiple sources.  
- Stream alerts to security information and event management (SIEM) solutions.  
- Automatically send threat indicators to Microsoft security solutions to enable alert, block, or allow actions.  
- Unlock contextual data to inform investigations.  
- Discover opportunities to learn from the data and train your security solutions.  
- Automate SecOps for greater efficiency.

### Use the Microsoft Graph Security API

There are two versions of the Microsoft Graph Security API:

- Microsoft Graph REST API v1.0  
- Microsoft Graph REST API Beta

The beta version provides new or enhanced APIs that are still in preview status. APIs in preview status are subject to change, and may break existing scenarios without notice.

For Security Operations Analysts, both Microsoft Graph API versions support advanced hunting using the **runHuntingQuery** method. This method includes a query in Kusto Query Language (KQL).

- Advanced hunting example in Microsoft Defender XDR:

```http  
POST https://graph.microsoft.com/v1.0/security/runHuntingQuery

{  
    "Query": "DeviceProcessEvents | where InitiatingProcessFileName =~ "powershell.exe" | project Timestamp, FileName, InitiatingProcessFileName | order by Timestamp desc | limit 2"  
}  
```

You can use Graph Explorer to run the hunting query.

**Additional reading** - For more information, see The Microsoft Graph Security API.

--------------------------------------------------    
# Investigate security incidents in Microsoft Defender XDR

**Completed 100 XP**

- 3 minutes

The following cloud guide demonstrates Microsoft Defender XDR and Microsoft Sentinel working together to investigate a security incident in a hybrid environment.

---

**Next unit: Module assessment**  
--------------------------------------------------    
# Module assessment

Completed 200 XP

- 3 minutes

Choose the best response for each of the questions below.

## Check your knowledge

1. Which Microsoft Defender XDR solution can detect an Active Directory Domain compromise?  
   - Microsoft Defender for Identity  
   - Microsoft Defender for Endpoint  
   - Microsoft Defender for Office 365

2. Which Microsoft Defender XDR solution can detect a phishing email?  
   - Microsoft Defender for Identity  
   - Microsoft Defender for Endpoint  
   - Microsoft Defender for Office 365

3. Which Microsoft Defender XDR solution can detect a malware installation?  
   - Microsoft Defender for Identity  
   - Microsoft Defender for Endpoint  
   - Microsoft Defender for Office 365

Submit answers

You must answer all questions before checking your work.  
--------------------------------------------------    
# Summary and resources

**Completed** 100 XP

- 3 minutes

You should have learned the role that Microsoft Defender XDR plays in a modern SOC.

You should now be able to:

- Understand Microsoft Defender XDR solution by domain  
- Understand Microsoft Defender XDR role in a Modern SOC

## Learn more

You can learn more by reviewing the following.

- Microsoft Cybersecurity Reference Architectures  
--------------------------------------------------    
# Mitigate incidents using Microsoft Defender

- 1 hr 11 min  
- Module  
- 15 Units

## Intermediate

**Role:** Security Operations Analyst    
**Products:** Microsoft Defender XDR, Microsoft Defender

Learn how the Microsoft Defender portal provides a unified view of incidents from the Microsoft Defender family of products.

---

## Learning objectives

Upon completion of this module, the learner is able to:

- Manage incidents in Microsoft Defender  
- Investigate incidents in Microsoft Defender  
- Conduct advanced hunting in Microsoft Defender

---

## Prerequisites

Intermediate understanding of Microsoft Defender.

---

## This module is part of these learning paths

- Defend against cyberthreats with Microsoft Defender XDR  
- SC-200: Mitigate threats using Microsoft Defender XDR

---

## Units in this module

- Introduction (3 min)  
- Use the Microsoft Defender portal (5 min)  
- Manage incidents (8 min)  
- Investigate incidents (4 min)  
- Manage and investigate alerts (10 min)  
- Manage automated investigations (3 min)  
- Use the action center (14 min)  
- Explore advanced hunting (3 min)  
- Investigate Microsoft Entra sign-in logs (3 min)  
- Understand Microsoft Secure Score (3 min)  
- Analyze threat analytics (3 min)  
- Analyze reports (3 min)  
- Configure the Microsoft Defender portal (3 min)  
- Module assessment (3 min)  
- Summary and resources (3 min)

---

## Module assessment

Assess your understanding of this module. Sign in and answer all questions correctly to earn a pass designation on your profile.  
--------------------------------------------------    
# Introduction

**Completed 100 XP**

- 3 minutes

Microsoft Defender XDR is a unified pre- and post-breach enterprise defense suite that natively coordinates detection, prevention, investigation, and response across endpoints, identities, email, and applications to provide integrated protection against sophisticated attacks.

With the integrated Microsoft Defender XDR solution, security professionals can coordinate the threat signals that each of these products receive and determine the full scope and impact of the threat. How the threat entered the environment, what it's affecting, and how it's currently impacting the organization.

You're a Security Operations Analyst working at a company that implemented Microsoft Defender XDR solutions, including Defender for Endpoint, Defender for Identity, and Microsoft Defender for Cloud Apps.

You need to see related alerts across all the solutions as one incident to see the incident's full impact and do a root cause investigation. The Microsoft Defender portal is a unified view of incidents and actions taken.  
--------------------------------------------------    
# Use the Microsoft Defender portal

**Completed 100 XP**

- 5 minutes

The Microsoft Defender portal (https://security.microsoft.com/) is a specialized workspace designed to meet the needs of security teams. These solutions are integrated across Microsoft 365 services and provide actionable insights to help reduce risks and safeguard your digital estate.

You can investigate the alerts that affect your network, understand what they mean, and collate evidence associated with the incidents so that you can devise an effective remediation plan.

The Home page shows many of the common cards that security teams need. The composition of cards and data is dependent on the user's role. Because the Microsoft Defender portal uses role-based access control, different roles see cards that are more meaningful to their day-to-day jobs.

This at-a-glance information helps you keep up with the latest activities in your organization. The Microsoft Defender portal brings together signals from different sources to present a holistic view of your Microsoft 365 environment.

The Microsoft Defender portal combines protection, detection, investigation, and response to email, collaboration, identity, device, and app threats, in a central place.

This single pane of glass brings together functionality from existing Microsoft security portals, like the Microsoft Defender portal and the Office 365 Security & Microsoft Purview portal. The Microsoft Defender portal emphasizes quick access to information, simpler layouts, and bringing related information together for easier use. It includes:

- **Microsoft Defender for Office 365** - Helps organizations secure their enterprise with prevention, detection, investigation, and hunting features to protect email and Office 365 resources.  
- **Microsoft Defender for Endpoint** - Delivers preventative protection, post-breach detection, automated investigation, and response for devices in your organization.  
- **Microsoft Defender XDR** - Part of Microsoft’s Extended Detection and Response (XDR) solution that uses the Microsoft 365 security portfolio to automatically analyze threat data across domains and build a picture of an attack on a single dashboard.  
- **Microsoft Defender for Cloud Apps** - A comprehensive cross-SaaS and PaaS solution bringing deep visibility, strong data controls, and enhanced threat protection to your cloud apps.  
- **Microsoft Defender for Identity** - A cloud-based security solution that uses on-premises Active Directory signals to identify, detect, and investigate advanced threats, compromised identities, and malicious insider actions.  
- **Microsoft Defender Vulnerability Management** - Delivers continuous asset visibility, intelligent risk-based assessments, and built-in remediation tools to help prioritize and address critical vulnerabilities and misconfigurations.  
- **Microsoft Defender for IoT** - Designed to secure Operational Technology (OT) environments in sectors such as manufacturing, utilities, and more.  
- **Microsoft Sentinel** - Integrate Microsoft Defender XDR with Microsoft Sentinel to stream all Defender XDR incidents and advanced hunting events into Microsoft Sentinel and keep incidents and events synchronized between the Azure and Microsoft Defender portals.

The **More resources** option in the portal provides a list of related portals:

| Portal | Description |  
| --- | --- |  
| Microsoft Purview portal | Manage compliance needs across Microsoft 365 services using integrated solutions for information governance, classification, case management, and more. |  
| Microsoft Entra ID | Manage your organization's identities. Set up multifactor authentication, track user sign-ins, edit company branding, and more. |  
| Microsoft Entra ID Protection | Detect potential vulnerabilities affecting your organization's identities. Investigate suspicious incidents and set up automated responses. |  
| Azure Information Protection | Configure and manage the Azure Information Protection client and scanner to classify and protect email and docs. Use reports to monitor label usage and identify sensitive info. |  
| Microsoft Defender for Cloud | Protect data centers and get advanced threat protection for Azure and non-Azure workloads in the cloud and on premises. Secure Azure services with autoprovisioned, native protection. |

## Map Microsoft Defender XDR Unified role-based access control (RBAC) permissions

All permissions listed within the Microsoft Defender XDR Unified RBAC model align to existing permissions in the individual RBAC models. Once you activate the Unified RBAC model, the permissions and assignments configured in your imported roles replace the existing roles in the individual RBAC models.

This article describes how existing roles and permissions in Microsoft Defender for Endpoint, Microsoft Defender Vulnerability Management, Microsoft Defender for Office 365, Microsoft Defender for Identity, and Microsoft Entra roles map to the roles and permission in the Microsoft Defender XDR Unified RBAC model.

**Important:**  
- Use roles with the fewest permissions to improve security.  
- Global Administrator is highly privileged and should be limited to emergency scenarios.

## Map Microsoft Defender XDR Unified RBAC permissions to existing RBAC permissions

**Important:**  
- Starting February 16, 2025, the Unified RBAC model will be the default for new Microsoft Defender Endpoint tenants.  
- Starting March 2, 2025, new Microsoft Defender for Identity tenants will also have the Unified RBAC model as default.

Use the tables in the following sections to learn more about how your existing individual RBAC role definitions map to your new Microsoft Defender XDR Unified RBAC roles:

1. Map Defender for Endpoint and Defender Vulnerability Management permissions  
2. Map Defender for Office 365 permissions to the Unified RBAC permissions  
3. Map Microsoft Defender for Identity permissions  
4. Microsoft Entra Global roles access

### Map Defender for Endpoint and Defender Vulnerability Management permissions

| Defender for Endpoint and Defender Vulnerability Management permissions | Microsoft Defender XDR Unified RBAC permission |  
| --- | --- |  
| View data - Security operations | Security operations  Security data  Security data basics (read) |  
| View data - Defender Vulnerability Management | Security posture  Posture management  Vulnerability management (read) |  
| Alerts investigation | Security operations  Security data  Alerts (manage) |  
| Active remediation actions - Security operations | Security operations  Security data  Response (manage) |  
| Active remediation actions - Defender Vulnerability Management - Exception handling | Security posture  Posture management  Exception handling (manage) |  
| Active remediation actions - Defender Vulnerability Management - Remediation handling | Security posture  posture management  Remediation handling (manage) |  
| Active remediation actions - Defender Vulnerability Management - Application handling | Security posture  Posture management  Application handling (manage) |  
| Defender Vulnerability management – Manage security baselines assessment profiles | Security posture  posture management  Security baselines assessment (manage) |  
| Live response capabilities | Security operations  Basic live response (manage) |  
| Live response capabilities - advanced | Security operations  Advanced live response (manage)  Security operations  Security data  File collection (manage) |  
| Manage security settings in the Security Center | Authorization and settings  Security settings  Core security settings (manage)  Authorization and settingsSecurity settings  Detection tuning (manage) |  
| Manage portal system settings | Authorization and settings  System setting (Read and manage) |  
| Manage endpoint security settings in Microsoft Intune | Not supported - managed in the Microsoft Intune admin center |

### Map Defender for Office 365 permissions

#### Email & collaboration permissions mapping

| Email & collaboration permission | Type | Microsoft Defender XDR Unified RBAC permission |  
| --- | --- | --- |  
| Global Reader | Role group | Security operations  Security data  Security data basics (read)  Security operations  Raw data (Email & collaboration)  Email & collaboration metadata (read)  Security operations  Security data  Response (manage)  Authorization and settings  Security settings  Core security settings (read)  Authorization and settings  System setting (read) |  
| Organization Management | Role group | Security operations  Security data  Security data basics (read)  Security operations  Security data  Alerts (manage)  Security operations  Raw data (Email & collaboration)  Email & collaboration metadata (read)  Security operations  Security data  Response (manage)  Security operations  Security data  Email advanced actions (manage)  Security operations  Security data  Email quarantine (manage)  Authorization and settings  Authorization (Read and manage)  Authorization and settings  Security setting (All permissions)  Authorization and settings  System settings (Read and manage) |  
| Security Administrator | Role group | Security operations  Security data  Security data basics (read)  Security operations  Security data  Alerts (manage)  Security operations  Raw data (Email & collaboration)  Email & collaboration metadata (read)  Security operations  Security data  Response (manage)  Security operations  Security data  Email quarantine (manage)  Authorization and settings  Authorization (read)  Authorization and settings  Security setting (All permissions)  Authorization and settings  System settings (Read and manage) |  
| Security Reader | Role group | Security operations  Security data Security data basics (read)  Security operations  Raw data (Email & collaboration)  Email & collaboration metadata (read)  Security operations  Security data  Response (manage)  Authorization and settings  Security settings  Core security settings (read)  Authorization and settings  System setting (read) |  
| Audit Logs | Role | Security operations  Security data  Security data basics (read) |  
| Manage Alerts | Role | Security operations  Security data  Security data basics (read)  Security operations  Security data  Alerts (manage) |  
| Preview | Role | Security operations Security operations  Raw data (Email & collaboration)  Email & collaboration content (read) |  
| Quarantine | Role | Security operations  Security data  Email quarantine (manage) |  
| Role Management | Role | Authorization and settings  Authorization (Read and manage) |  
| Search and Purge | Role | Security operations  Security data  Email advanced actions (manage) |  
| View-Only Manage Alerts | Role | Security operations  Security data  Security data basics (read) |  
| View-Only Recipients | Role | Security operations  Security data  Security data basics (read)  Security operations  Raw data (Email & collaboration)  Email & collaboration metadata (read) |  
| View-only Audit Logs | Role | Security operations  Security data  Security data basics (read) |

#### Exchange Online permissions mapping

| Exchange Online permission | Type | Microsoft Defender XDR Unified RBAC permission |  
| --- | --- | --- |  
| Hygiene Management | Role group | Security operations  Security data  Email quarantine (manage)  Authorization and settings  Security settings  Core security settings (manage)  Authorization and settings  Security settings  Detection tuning (manage) |  
| Organization Management | Role group | Security operations  Raw data (email & collaboration)  Email & collaboration metadata (read)  Authorization and settings  Security settings  Core security settings (manage)  Authorization and settings  Security settings  Detection tuning (manage)  Authorization and settings  System settings (Read and manage) |  
| Security Administrator | Role group | Authorization and settings  Security settings  Detection tuning (manage)  Authorization and settings  System settings (Read and manage) |  
| View-Only Organization Management | Role group | Authorization and settings  Security settings (Read-only)  Authorization and settings  System settings (Read-only) |  
| Tenant AllowBlockList Manager | Role | Authorization and settings  Security settings  Detection tuning (manage) |  
| View-only Recipients | Role | Security operations  Raw data (email & collaboration)  Email & collaboration metadata (read) |

### Map Microsoft Defender for Identity permissions

| Defender for Identity permission | Defender XDR Unified RBAC permission |  
| --- | --- |  
| MDI admin | Security operations  Security data  Security data basics (read)  Security operations  Security data  Alerts (manage)  Authorization and settings  Authorization (Read and manage)  Authorization and settings  Security setting (All permissions)  Authorization and settings  System settings (Read and manage) |  
| MDI user | Security operations  Security data  Security data basics (read)  Security operations  Security data  Alerts (manage)  Authorization and settings  Security setting (All permissions)  Authorization and settings  System setting (read) |  
| MDI viewer | Security operations  Security data  Security data basics (read)  Authorization and settings  Security settings  Core security settings (read)  Authorization and settings  System setting (read) |

**Note:** Defender for Identity experiences will also adhere to permissions granted from Microsoft Defender for Cloud Apps. Exception: If you have configured Scoped deployment for Microsoft Defender for Identity alerts in Microsoft Defender for Cloud Apps, these permissions do not carry over. You need to explicitly grant the Security operations  Security data  Security data basics (read) permissions for the relevant portal users.

### Map Microsoft Defender for Cloud Apps permissions

| Defender for Cloud Apps permission | Defender XDR Unified RBAC permission |  
| --- | --- |  
| Local Global administrator | Security operations  Security data  Security data basics (read)  Security operations  Security data  Alerts (manage)  Authorization and settings  Authorization (all permissions)  Authorization and settings  Security settings (all permissions)  Authorization and settings  System settings (all permissions) |  
| Local Security operator | Security operations  Security data  Security data basics (read)  Security operations  Security data  Alerts (manage)  Authorization and settings  Authorization (read)  Authorization and settings  Security setting (all permissions)  Authorization and settings  System setting (read) |  
| Local Security reader | Security operations  Security data  Security data basics (read)  Authorization and settings  Authorization (read)  Authorization and settings  Security settings  Security settings (read)  Authorization and settings  System settings (read) |  
| Local Compliance administrator | Security operations  Security data  Security data basics (read)  Security operations  Security data  Alerts (manage)  Authorization and settings  Authorization (read)  Authorization and settings  Security settings  Security settings (all permissions)  Authorization and settings  System settings (read) |

### Microsoft Entra Global roles access

| Microsoft Entra role | Microsoft Defender XDR Unified RBAC assigned permissions for all workloads | Microsoft Defender XDR Unified RBAC assigned permissions – workload specific |  
| --- | --- | --- |  
| Global administrator | Security operations  Security data  Security data basics (read)  Security operations  Security data  Alerts (manage)  Security operations  Security data  Response (manage)  Security posture  Posture management  Secure Score (read)  Security posture  Posture management  Secure Score (manage)  Authorization and settings  Authorization (Read and manage)  Authorization and settings  Security settings (All permissions)  Authorization and settings  System settings (Read and manage) | Defender for Endpoint and Defender Vulnerability Management permissions, Defender for Office only permissions |  
| Security administrator | Same as Global administrator | Same as Global administrator |  
| Global reader | Security operations  Security data  Security data basics (read)  Security posture  Posture management  Secure Score (read) | Defender for Endpoint and Defender Vulnerability Management permissions, Defender for Office only permissions, Defender for Office and Defender for Identity only permissions |  
| Security reader | Security operations  Security data  Security data basics (read)  Security posture  Posture management  Secure Score (read) | Defender for Endpoint and Defender Vulnerability Management permissions, Defender for Office only permissions, Defender for Office and Defender for Identity only permissions |  
| Security operator | Security operations  Security data  Security data basics (read)  Security operations  Security data  Alerts (manage)  Security operations  Security data  Response (manage)  Security posture  Posture management  Secure Score (read)  Authorization and settings  Security settings (All permissions) | Defender for Endpoint and Defender Vulnerability Management permissions, Defender for Office only permissions, Defender for Identity only permissions |  
| Exchange Administrator | Security posture  Posture management  Secure Score (read)  Security posture  Posture management  Secure Score (manage) | Defender for Office only permissions |  
| SharePoint Administrator | Security posture  Posture management  Secure Score (read)  Security posture  Posture management  Secure Score (manage) | not applicable |  
| Service Support Administrator | Security posture  Posture management  Secure Score (read) | not applicable |  
| User Administrator | Security posture  Posture management  Secure Score (read) | not applicable |  
| HelpDesk Administrator | Security posture  Posture management  Secure Score (read) | not applicable |  
| Compliance administrator | not applicable | Defender for Office only permissions |  
| Compliance data administrator | not applicable | Same as Compliance administrator |  
| Billing admin | not applicable | not applicable |

**Note:** By activating the Microsoft Defender XDR Unified RBAC model, users with Security Reader and Global Reader roles can access Defender for Endpoint data.  
--------------------------------------------------    
# Manage incidents

Completed 100 XP

* 8 minutes

Microsoft Defender XDR provides a cross-domain threat correlation and purpose-driven portal to investigate threats. Incidents are based on related alerts created when a malicious event or activity is seen on your network. Individual alerts provide valuable clues about an on-going attack. However, attacks typically employ various vectors and techniques to carry out a breach. Piecing individual clues together can be challenging and time-consuming.

This short video gives an overview of incidents in Microsoft Defender XDR.

An incident is a collection of correlated alerts that make up the story of an attack. Microsoft Defender XDR automatically aggregates malicious and suspicious events that are found in different device, user, and mailbox entities in the network. Grouping related alerts into an incident gives security defenders a comprehensive view of an attack.

For instance, security defenders can see where the attack started, what tactics were used, and how far the attack has gone into the network. Security defenders can also see the scope of the attack. Like how many devices, users, and mailboxes were impacted, how severe the impact was, and other details about affected entities.

If enabled, Microsoft Defender XDR can automatically investigate and resolve the individual alerts through automation and artificial intelligence. Security defenders can also perform more remediation steps to resolve the attack straight from the incidents view.

Incidents from the last 30 days are shown in the incident queue. From here, security defenders can see which incidents should be prioritized based on risk level and other factors.

Security defenders can also rename incidents, assign them to individual analysts, classify, and add tags to incidents for a better and more customized incident management experience.

## Prioritize incidents

Microsoft Defender XDR applies correlation analytics and aggregates all related alerts and investigations from different products into one incident. Microsoft Defender XDR also triggers unique alerts on activities that can only be identified as malicious given the end-to-end visibility that Microsoft Defender XDR has across the entire estate and suite of products. This view gives your security operations analyst the broader attack story, which helps them better understand and deal with complex threats across the organization.

The Incidents queue shows a collection of flagged incidents from across devices, users, and mailboxes. It helps you sort through incidents to prioritize and create an informed cybersecurity response decision.

By default, the queue in the Microsoft Defender portal displays incidents seen in the last 30 days. The most recent incident is at the top of the list so that you can see it first.

The incident queue exposes customizable columns that give you visibility into different characteristics of the incident or the contained entities. This deeper layer of information helps you make an informed decision regarding the prioritization of incidents to handle.

For more clarity at a glance, automatic incident naming generates incident names based on alert attributes such as the number of endpoints affected, users affected, detection sources, or categories. The automatic naming allows you to quickly understand the scope of the incident.

### Available filters

**Status**

You can choose to limit the list of incidents shown based on their status to see which ones are active or resolved.

**Severity**

The severity of an incident is indicative of the impact it can have on your assets. The higher the severity, the bigger the impact and typically requires the most immediate attention.

**Incident assignment**

You can choose to show alerts that are assigned to you or the alerts handled by automation.

**Multiple service source**

Select No (default), or yes to enable.

**Service sources**

Filter to only see incidents that contain alerts from different sources. Sources include: Microsoft Defender for Endpoint, Microsoft Cloud App Security, Microsoft Defender for Identity, Microsoft Defender for Office 365.

**Tags**

Filter on assigned tags. Any assigned Tags will appear once you select the _Type tag name_ field.

**Multiple category**

You can choose to see only incidents that have mapped to multiple categories and can thus potentially cause more damage.

**Categories**

Choose categories to focus on specific tactics, techniques, or attack components seen.

**Entities**

Filter on entity name or ID.

**Data sensitivity**

Some attacks focus on targeting to exfiltrate sensitive or valuable data. By applying a filter to see if sensitive data is involved in the incident, you can quickly determine if sensitive information has been compromised. And if a compromise is found you can prioritize a response to those incidents. This filtering ability is only applicable if Microsoft Purview Information Protection is turned on.

**Device group**

Filter by defined device groups.

**OS platform**

Limit the incident queue view by operating system.

**Classification**

Filter incidents based on the set classifications of the related alerts. The values include true alerts, false alerts, or not set.

**Automated Investigation state**

Filter incidents by the status of the automated investigation.

**Associated Threat**

Selecting the _Type associated threat_ field will allow you to enter threat information, and bring up previous search criteria.

## Preview incidents

The portal pages provide preview information for most list-related data.

In this screenshot, the three highlighted areas are the circle, the greater than symbol, and the actual link.

**Circle**

Selecting the circle will open a details window on the right side of the page with a preview of the line item with an option to open the full page of information.

**Greater than symbol**

If there are related records that can be displayed, selecting the greater than sign will display the records below the current record.

**Link**

The link will navigate you to the full page for the line item.

## Manage incidents

Managing incidents is critical in ensuring that threats are contained and addressed. In Microsoft Defender XDR, you have access to managing incidents on devices, users, and mailboxes. You can manage incidents by selecting an incident from the Incidents queue.

You can edit the name of an incident, resolve it, set its classification and determination. You can also assign the incident to yourself, add incident tags and comments.

In cases where you would like to move alerts from one incident to another, during an investigation, you can also do so from the Alerts tab. Using the Alerts tab allows you to create a larger or smaller incident that includes all relevant alerts.

### Edit incident name

Incidents are automatically assigned a name based on alert attributes such as the number of endpoints affected, users affected, detection sources, or categories. Naming based on alert attributes allows you to quickly understand the scope of the incident. You can modify the incident name to better align with your preferred naming convention.

### Assign incidents

If an incident hasn't yet been assigned, you can select Assign to me to assign the incident to yourself. Doing so assumes ownership of not just the incident but also all the alerts associated with it.

### Set status and classification

**Incident status**

You can categorize incidents (as Active, or Resolved) by changing their status as your investigation progresses. This ability to update status helps you organize and manage how your team can respond to incidents.

For example, your SOC analyst can review the urgent Active incidents for the day and decide to assign them to themselves for investigation.

Alternatively, your SOC analyst might set the incident as Resolved if the incident has been remediated. Resolving an incident will automatically close all open alerts that are part of the incident.

**Classification and determination**

You can choose not to set a classification or decide to specify whether an incident is true alert or false alert. Doing so helps the team see patterns and learn from them.

### Add comments

You can add comments and view historical events about an incident to see previous changes made to it.

Whenever a change or comment is made to an alert, it's recorded in the Comments and history section.

Added comments instantly appear on the pane.

### Add incident tags

You can add custom tags to an incident, for example, to flag a group of incidents with common characteristics. You can later filter the incidents queue for all incidents that contain a specific tag.

---

Next unit: Investigate incidents  
--------------------------------------------------    
# Investigate incidents

**Completed 100 XP**

- 4 minutes

The incident page provides the following information and navigation links.

## Incident overview

The overview page gives you a snapshot glance into the top things to notice about the incident.

- The attack categories give you a visual and numeric view of how advanced the attack has progressed against the kill chain. As with other Microsoft security products, Microsoft Defender XDR is aligned to the MITRE ATT&CK™ framework.  
- The scope section gives you a list of top impacted assets that are part of this incident. If there's specific information regarding this asset, such as risk level, investigation priority, and any tagging on the assets, it will also surface in this section.  
- The alerts timeline provides a sneak peek into the chronological order in which the alerts occurred and the reasons that these alerts linked to this incident.  
- The evidence section provides a summary of how many different artifacts were included in the incident and their remediation status, so you can immediately identify if any action is needed on your end.

This overview can help the initial triage of the incident by providing insight into the top characteristics of the incident that you should be aware of.

## Alerts

You can view all the alerts related to the incident and other information about them such as severity, entities that were involved in the alert, the source of the alerts (Microsoft Defender for Identity, Microsoft Defender for Endpoint, Microsoft Defender for Office 365), and the reason they were linked together.

By default, the alerts are ordered chronologically to allow you to first view how the attack played out over time. Clicking on each alert will lead you to the **relevant alert page,** where you can conduct an in-depth investigation of that alert.

## Devices

The devices tab lists all the devices where alerts related to the incident are seen.

Clicking on the name link of the machine where the attack was conducted navigates you to its Device page. On the Device page, you can see alerts that were triggered on it and related events provided to ease investigation.

## Users

See users that have been identified to be part of or related to a given incident.

Clicking the username navigates you to the **user's Microsoft Defender for Cloud Apps page,** where further investigation can be conducted.

## Mailboxes

Investigate mailboxes that have been identified to be part of or related to an incident.

## Apps

Investigate Apps that have been identified to be part of or related to an incident.

## Investigations

Select Investigations to see all the automated investigations triggered by alerts in this incident. The investigations will perform remediation actions or wait for analyst approval of actions.

Select an investigation to navigate to its Investigation details page to get full information on the investigation and remediation status. If any actions are pending for approval as part of the investigation, they'll appear in the Pending actions tab.

## Evidence and Responses

Microsoft Defender XDR automatically investigates all the incidents' supported events and suspicious entities in the alerts, providing you with autoresponse and information about the important files, processes, services, emails, and more. This helps quickly detect and block potential threats in the incident.

Each of the analyzed entities will be marked with a verdict (Malicious, Suspicious, Clean) and a remediation status. This helps you understand the remediation status of the entire incident and the next steps to further remediate.

## Graph

The graph visualizes associated cybersecurity threats information into an incident so you can see the patterns and correlations coming in from various data points. You can view such correlation through the incident graph.

The Graph tells the story of the cybersecurity attack. For example, it shows you the entry point, which indicator of compromise or activity was observed on which device, etc.

You can select the circles on the incident graph to view the details of the malicious files, associated file detections, how many instances have there been worldwide, whether it’s been observed in your organization, if so, how many instances.  
--------------------------------------------------    
# Manage and investigate alerts

You can manage alerts by selecting an alert in the Alerts queue or the Alerts tab of the Device page for an individual device. Selecting an alert in either of those places brings up the Alert management pane.

## Alert management

You can view and set metadata on the Alert preview or Alert details page.

The metadata fields and actions include:

### Severity

- **High (Red)** - Alerts commonly seen associated with advanced persistent threats (APT). These alerts indicate a high risk because of the severity of damage they can inflict on devices. Examples include credential theft tools activities, ransomware activities not associated with any group, tampering with security sensors, or any malicious activities indicative of a human adversary.  
- **Medium (Orange)** - Alerts from endpoint detection and response post-breach behaviors that might be a part of an advanced persistent threat (APT). This includes observed behaviors typical of attack stages, anomalous registry change, execution of suspicious files, and so forth. Although some might be part of internal security testing, it requires investigation as it might also be a part of an advanced attack.  
- **Low (Yellow)** - Alerts on threats associated with prevalent malware. For example, hack-tools, nonmalware hack tools, such as running exploration commands, clearing logs, etc. often don't indicate an advanced threat targeting the organization. It could also come from an isolated security tool testing by a user in your organization.  
- **Informational (Grey)** - Alerts that might not be considered harmful to the network but can drive organizational security awareness on potential security issues.

Microsoft Defender Antivirus (Microsoft Defender AV) and Defender for Endpoint alert severities are different because they represent different scopes. The Microsoft Defender AV threat severity represents the absolute severity of the detected threat (malware) and is assigned based on the potential risk to the individual device if infected.

The Defender for Endpoint alert severity represents the severity of the detected behavior, the actual risk to the device, and most importantly, the potential risk to the organization.

So, for example:

- The severity of a Defender for Endpoint alert about a Microsoft Defender AV detected threat that was prevented and didn't infect the device is categorized as "Informational" because there was no actual damage.  
- An alert about a commercial malware was detected while executing, but blocked and remediated by Microsoft Defender AV, is categorized as "Low" because it may have caused some damage to the individual device but poses no organizational threat.  
- An alert about malware detected while executing which can pose a threat not only to the individual device but to the organization, regardless if it was eventually blocked, may be ranked as "Medium" or "High".  
- Suspicious behavioral alerts, which weren't blocked or remediated will be ranked "Low", "Medium" or "High" following the same organizational threat considerations.

### Categories

The alert categories align closely with the attack tactics and techniques in the MITRE ATT&CK Enterprise matrix.

> Note: The alert categories also include items (like `Unwanted Software`) that are not part of the ATT&CK matrices.

The categories are:

- **Collection** - Locating and collecting data for exfiltration  
- **Command and control** - Connecting to attacker-controlled network infrastructure to relay data or receive commands  
- **Credential access** - Obtaining valid credentials to extend control over devices and other resources in the network  
- **Defense evasion** - Avoiding security controls by, for example, turning off security apps, deleting implants, and running rootkits  
- **Discovery** - Gathering information about important devices and resources, such as administrator computers, domain controllers, and file servers  
- **Execution** - Launching attacker tools and malicious code, including RATs and backdoors  
- **Exfiltration** - Extracting data from the network to an external, attacker-controlled location  
- **Exploit** - Exploit code and possible exploitation activity  
- **Initial access** - Gaining initial entry to the target network, usually involving password-guessing, exploits, or phishing emails  
- **Lateral movement** - Moving between devices in the target network to reach critical resources or gain network persistence  
- **Malware** - Backdoors, trojans, and other types of malicious code  
- **Persistence** - Creating autostart extensibility points (ASEPs) to remain active and survive system restarts  
- **Privilege escalation** - Obtaining higher permission levels for code by running it in the context of a privileged process or account  
- **Ransomware** - Malware that encrypts files and extorts payment to restore access  
- **Suspicious activity** - Atypical activity that could be malware activity or part of an attack  
- **Unwanted software** - Low-reputation apps and apps that impact productivity and the user experience; detected as potentially unwanted applications (PUAs)

### Link to another incident

You can create a new incident from the alert or link to an existing incident.

### Assign alerts

If an alert isn't yet assigned, you can select Assign to me to assign the alert to yourself.

### Suppress alerts

There might be scenarios where you need to suppress alerts from appearing in Microsoft Defender Security Center. Defender for Endpoint lets you create suppression rules for specific alerts that are known to be innocuous, such as known tools or processes in your organization.

Suppression rules can be created from an existing alert. They can be disabled and re-enabled if needed.

When a suppression rule is created, it takes effect from the point when the rule is created. The rule won't affect existing alerts already in the queue prior to the rule creation. The rule will only be applied to alerts that satisfy the conditions set after the rule is created.

There are two contexts for a suppression rule that you can choose from:

- Suppress alert on this device  
- Suppress alert in my organization

The context of the rule lets you tailor what gets surfaced into the portal and ensure that only real security alerts are surfaced into the portal.

### Change the status of an alert

You can categorize alerts as New, In Progress, or Resolved by changing their status as your investigation progresses. This helps you organize and manage how your team can respond to alerts.

For example, a team leader can review all New alerts, and decide to assign them to the In Progress queue for further analysis.

Alternatively, the team leader might assign the alert to the Resolved queue if they know the alert is benign, coming from an irrelevant device (such as one belonging to a security administrator), or is being dealt with through an earlier alert.

### Alert classification

You can choose not to set a classification or specify whether an alert is a true alert or a false alert. It's important to provide the classification of true positive/false positive because it's used to monitor alert quality and make alerts more accurate. The "determination" field defines extra fidelity for a "true positive" classification.

### Add comments and view the history of an alert

You can add comments and view historical events about an alert to see previous changes made to the alert. Whenever a change or comment is made to an alert, it's recorded in the Comments and history section. Added comments instantly appear on the pane.

## Alert investigation

Investigate alerts that are affecting your network, understand what they mean, and how to resolve them.

Select an alert from the alerts queue to go to alert page. This view contains the alert title, the affected assets, the details side pane, and the alert story.

From the alert page, begin your investigation by selecting the affected assets or any of the entities under the alert story tree view. The details pane automatically populates with further information about what you selected.

### Investigate using the alert story

The alert story details why the alert was triggered, related events that happened before and after, and other related entities.

Entities are clickable, and every entity that isn't an alert is expandable using the expand icon on the right side of that entity's card. The entity in focus will be indicated by a blue stripe to the left side of that entity's card, with the alert in the title being in focus at first.

Selecting an entity switches the context of the details pane to this entity, and will allow you to review further information, and manage that entity. Selecting ... to the right of the entity card reveals all actions available for that entity. These same actions appear in the details pane when that entity is in focus.

### Take action from the details pane

Once you've selected an entity of interest, the details pane changes to display information about the selected entity type, historic information when it's available, and offer controls to take action on this entity directly from the alert page.

Once you're done investigating, go back to the alert you started with, mark the alert's status as Resolved and classify it as either False alert or True alert. Classifying alerts helps tune this capability to provide more true alerts and fewer false alerts.

If you classify it as a true alert, you can also select a determination.

If you're experiencing a false alert with a line-of-business application, create a suppression rule to avoid this type of alert in the future.  
--------------------------------------------------    
# Manage automated investigations

## Manage automated investigations

Your security operations team receives an alert whenever Microsoft Defender detects a malicious or suspicious artifact from an Endpoint. Security operations teams face challenges in addressing the multitude of alerts that arise from the seemingly never-ending flow of threats. Microsoft Defender for Endpoint includes automated investigation and remediation (AIR) capabilities that can help your security operations team address threats more efficiently and effectively.

The technology in automated investigation uses various inspection algorithms and is based on processes that are used by security analysts. AIR capabilities are designed to examine alerts and take immediate action to resolve breaches. AIR capabilities significantly reduce alert volume, allowing security operations to focus on more sophisticated threats and other high-value initiatives. The Action center keeps track of all the investigations that were initiated automatically, along with details, such as investigation status, detection source, and any pending or completed actions.

## How the automated investigation starts

When an alert is triggered, a security playbook goes into effect. Depending on the security playbook, an automated investigation can start. For example, suppose a malicious file resides on a device. When that file is detected, an alert is triggered, and the automated investigation process begins. Microsoft Defender for Endpoint checks to see if the malicious file is present on any other devices in the organization. Details from the investigation, including verdicts (Malicious, Suspicious, and No threats found) are available during and after the automated investigation.

### Details of an automated investigation

During and after an automated investigation, you can view details about the investigation. Select a triggering alert to view the investigation details. From there, you can go to the Investigation graph, Alerts, Devices, Evidence, Entities, and Log tabs.

- **Alerts** - The alert(s) that started the investigation.  
- **Devices** - The device(s) where the threat was seen.  
- **Evidence** - The entities that were found to be malicious during an investigation.  
- **Entities** - Details about each analyzed entity, including a determination for each entity type (Malicious, Suspicious, or No threats found).  
- **Log** - The chronological, detailed view of all the investigation actions taken on the alert.  
- **Pending actions** - If there are any actions awaiting approval as a result of the investigation, the Pending actions tab is displayed. On the Pending actions tab, you can approve or reject each action.

### How an automated investigation expands its scope

While an investigation is running, any other alerts generated from the device are added to an ongoing automated investigation until that investigation is completed. In addition, if the same threat is seen on other devices, those devices are added to the investigation.

If an incriminated entity is seen in another device, the automated investigation process expands its scope to include that device, and a general security playbook starts on that device. If ten or more devices are found during this expansion process from the same entity, then that expansion action requires approval and is visible on the Pending actions tab.

### How threats are remediated

As alerts are triggered and an automated investigation runs, a verdict is generated for each piece of evidence investigated. Verdicts can be Malicious, Suspicious, or No threats found.

As verdicts are reached, automated investigations can result in one or more remediation actions. Examples of remediation actions include sending a file to quarantine, stopping a service, removing a scheduled task, and more.

Depending on the level of automation set for your organization, and other security settings, remediation actions can occur automatically or only upon approval by your security operations team. Other security settings that can affect automatic remediation include protection from potentially unwanted applications (PUA).

All remediation actions, whether pending or completed, can be viewed in the Action Center. If necessary, your security operations team can undo a remediation action.

## Automation levels in automated investigation and remediation capabilities

Automated investigation and remediation (AIR) capabilities in Microsoft Defender for Endpoint can be configured to one of several levels of automation. Your automation level affects whether remediation actions following AIR investigations are taken automatically or only upon approval.

- Full automation (recommended) means remediation actions are taken automatically on artifacts determined to be malicious.  
- Semi-automation means some remediation actions are taken automatically, but other remediation actions await approval before being taken.  
- All remediation actions, whether pending or completed, are tracked in the Action Center

### Levels of automation

**Full - remediate threats automatically (also referred to as full automation)**

With full automation, remediation actions are performed automatically. All remediation actions that are taken can be viewed in the Action Center on the History tab. If necessary, a remediation action can be undone.

**Semi - require approval for any remediation (also referred to as semi-automation)**

With this level of semi-automation, approval is required for any remediation action. Such pending actions can be viewed and approved in the Action Center, on the Pending tab.

**Semi - require approval for core folders remediation (also a type of semi-automation)**

With this level of semi-automation, approval is required for any remediation actions needed on files or executables that are in core folders. Core folders include operating system directories, such as the Windows (windows*).

Remediation actions can be taken automatically on files or executables that are in other (non-core) folders.

Pending actions for files or executables in core folders can be viewed and approved in the Action Center, on the Pending tab.

Actions that were taken on files or executables in other folders can be viewed in the Action Center, on the History tab.

**Semi - require approval for non-temp folders remediation (also a type of semi-automation)**

With this level of semi-automation, approval is required for any remediation actions needed on files or executables that aren't in temporary folders.

Temporary folders can include the following examples:

- users*appdatalocaltemp*  
- documents and settings*local settingstemp*  
- documents and settings*local settingstemporary*  
- windowstemp*  
- users*downloads*  
- program files  
- program files (x86)*  
- documents and settings*users*

Remediation actions can be taken automatically on files or executables that are in temporary folders.

Pending actions for files or executables that aren't in temporary folders can be viewed and approved in the Action Center, on the Pending tab.

Actions that were taken on files or executables in temporary folders can be viewed and approved in the Action Center on the History tab.

**No automated response (also referred to as no automation)**

With no automation, the automated investigation doesn't run on your organization's devices. As a result, no remediation actions are taken or pending as a result of an automated investigation. However, other threat protection features, such as protection from potentially unwanted applications, can be in effect, depending on how your antivirus and next-generation protection features are configured.

Using the no automation option isn't recommended because it reduces the security posture of your organization's devices. Consider setting up your automation level to full automation (or at least semi-automation).

### Important points about automation levels

Full automation has proven to be reliable, efficient, and safe, and is recommended for all customers. Full automation frees up your critical security resources so they can focus more on your strategic initiatives. If your security team has defined device groups with a level of automation, those settings aren't changed by the new default settings that are rolling out.  
--------------------------------------------------    
# Use the action center

## Action center

The unified Action center of the Microsoft Defender portal lists pending and completed remediation actions for your devices, email & collaboration content, and identities in one location.

The unified Action center brings together remediation actions across Defender for Endpoint and Defender for Office 365. It defines a common language for all remediation actions and provides a unified investigation experience. Your security operations team has a "single pane of glass" experience to view and manage remediation actions.

The Action Center consists of pending and historical items:

- **Pending** displays a list of ongoing investigations that require attention. Recommended actions are presented that your security operations team can approve or reject. The Pending tab appears only if there are pending actions to be approved (or rejected).  
- **History** as an audit log for all of the following items:  
    - Remediation actions that were taken as a result of an automated investigation  
    - Remediation actions that were approved by your security operations team (some actions, such as sending a file to quarantine, can be undone)  
    - Commands that were run and remediation actions that were applied in Live Response sessions (some actions can be undone)  
    - Remediation actions that were applied by Microsoft Defender Antivirus (some actions can be undone)

Select Automated Investigations, then Action center.

When an automated investigation runs, a verdict is generated for each piece of evidence investigated. Verdicts can be Malicious, Suspicious, or No threats found depending on:

- Type of threat  
- Resulting verdict  
- How your organization's device groups are configured

Remediation actions can occur automatically or only upon approval by your organization’s security operations team.

### Review pending actions

To approve or reject a pending action:

- Select any item on the Pending tab.  
- Select an investigation from any of the categories to open a panel where you can approve or reject remediation actions.

Other details, such as file or service details, investigation details, and alert details are displayed. From the panel, you can select the Open investigation page link to see the investigation details. You can also select multiple investigations to approve or reject actions on multiple investigations.

### Review completed actions

To review completed actions:

- Select the History tab. (If need be, expand the time period to display more data.)  
- Select an item to view more details about that remediation action.

### Undo completed actions

You’ve determined that a device or a file isn't a threat. You can undo remediation actions that were taken, whether those actions were taken automatically or manually. You can undo any of the following actions:

- Source  
    - Automated investigation  
    - Microsoft Defender Antivirus  
    - Manual response actions  
- Supported Actions  
    - Isolate device  
    - Restrict code execution  
    - Quarantine a file  
    - Remove a registry key  
    - Stop a service  
    - Disable a driver  
    - Remove a scheduled task

### Remove a file from quarantine across multiple devices

To remove a file from quarantine across multiple devices:

1. On the History tab, select a file that has the Action type Quarantine file.  
2. In the pane on the right side of the screen, select Apply to X more instances of this file, and then select Undo.

### Viewing action source details

The Action center includes an Action source column that tells you where each action came from. The following table describes possible Action source values:

| Action source value         | Description                                                                 |  
|----------------------------|-----------------------------------------------------------------------------|  
| Manual device action        | A manual action taken on a device. Examples include device isolation or file quarantine. |  
| Manual email action         | A manual action taken on email. An example includes soft-deleting email messages or remediating an email message. |  
| Automated device action     | An automated action taken on an entity, such as a file or process. Examples of automated actions include sending a file to quarantine, stopping a process, and removing a registry key. |  
| Automated email action      | An automated action taken on email content, such as an email message, attachment, or URL. Examples of automated actions include soft-deleting email messages, blocking URLs, and turning off external mail forwarding. |  
| Advanced hunting action     | Actions taken on devices or email with advanced hunting. |  
| Explorer action             | Actions taken on email content with Explorer. |  
| Manual live response action | Actions taken on a device with live response. Examples include deleting a file, stopping a process, and removing a scheduled task. |  
| Live response action        | Actions taken on a device with Microsoft Defender for Endpoint APIs. Examples of actions include isolating a device, running an antivirus scan, and getting information about a file. |

## Submissions

In Microsoft 365 organizations with Exchange Online mailboxes, admins can use the Submissions portal in the Microsoft Defender portal to submit email messages, URLs, and attachments to Microsoft for scanning.

When you submit an email message for analysis, you'll get:

- Email authentication check: Details on whether email authentication passed or failed when it was delivered.  
- Policy hits: Information about any policies that may have allowed or blocked the incoming email into your tenant, overriding our service filter verdicts.  
- Payload reputation/detonation: Up-to-date examination of any URLs and attachments in the message.  
- Grader analysis: Review done by human graders in order to confirm whether or not messages are malicious.

**Important:** Payload reputation/detonation and grader analysis are not done in all tenants. Information is blocked from going outside the organization when data is not supposed to leave the tenant boundary for compliance purposes.

### What do you need to know before you begin?

- To submit messages and files to Microsoft, you need to have one of following roles:  
    - Security Administrator or Security Reader in the Microsoft Defender portal.  
- Admins can submit messages as old as 30 days if it's still available in the mailbox and not purged by the user or another admin.  
- Admin submissions are throttled at the following rates:  
    - Maximum submissions in any 15-minutes period: 150 submissions  
    - Same submissions in a 24 hour period: Three submissions  
    - Same submissions in a 15-minute period: One submission

### Report suspicious content to Microsoft

On the Submissions page, verify that the Emails, Email attachments, or URLs tab is selected based on the type of content you want to report. And then select the Submit to Microsoft for analysis icon. Submit to Microsoft for analysis.

Use the Submit to Microsoft for analysis flyout that appears to submit the respective type of content (email, URL, or email attachment).

**Note:** File and URL submissions are not available in the clouds that do not allow for data to leave the environment. The ability to select File or URL will be greyed out.

### Notify users from within the portal

On the Submissions page, select User reported messages tab, and then select the message you want to mark and notify.

Select the Mark as and notify drop-down, and then select No threats found > Phishing or Junk.

The reported message will be marked as a false positive or a false negative. An email notification is sent automatically from within the portal to the user who reported the message.

### Submit a questionable email to Microsoft

1. In the Select the submission type box, verify that Email is selected in the dropdown list.  
2. In the Add the network message ID or upload the email file section, use one of the following options:  
    - Add the email network message ID: The ID is a GUID value that's available in the X-MS-Exchange-Organization-Network-Message-Id header in the message or in the X-MS-Office365-Filtering-Correlation-Id header in quarantined messages.  
    - Upload the email file (.msg or .eml): Select Browse files. In the dialog that opens, find and select the .eml or .msg file, and then select Open.  
    In the Choose a recipient who had an issue box, specify the recipient that you would like to run a policy check against. The policy check will determine if the email bypassed scanning due to user or organization policies.  
3. In the Select a reason for submitting to Microsoft section, select one of the following options:  
    - Shouldn't have been blocked (False positive)  
    - Should have been blocked (False negative): In the, **"The email should have been categorized as"** section that appears, select one of the following values (if you're not sure, use your best judgment): Phish, Malware, or Spam  
4. When you're finished, select Submit.

### Send a suspect URL to Microsoft

1. In the Select the submission type box, select URL from the dropdown list.  
2. In the URL box that appears, enter the full URL. For example, `https://www.fabrikam.com/marketing.html`.  
3. In the Select a reason for submitting to Microsoft section, select one of the following options:  
    - Shouldn't have been blocked (False positive)  
    - Should have been blocked (False negative): In the, **"This URL should have been categorized as"** section that appears, select one of the following values (if you're not sure, use your best judgment): Phish, Malware  
4. When you're finished, select Submit.

### Submit a suspected email attachment to Microsoft

1. In the Select the submission type box, select Email attachment from the dropdown list.  
2. In the File section that appears, select Browse files. In the dialog that opens, find and select the file, and then select Open.  
3. In the Select a reason for submitting to Microsoft section, select one of the following options:  
    - Shouldn't have been blocked (False positive)  
    - Should have been blocked (False negative): In the, **"This file should have been categorized as"** section that appears, select one of the following values (if you're not sure, use your best judgment): Phish, Malware  
4. When you're finished, select Submit.

**Note:** If malware filtering has replaced the message attachments with the Malware Alert Text.txt file, you need to submit the original message from quarantine that contains the original attachments. For more information on quarantine and how to release messages with malware false positives, see Manage quarantined messages and files as an admin.

### View admin submissions to Microsoft

On the Submissions page, verify that the Emails, URL, or Email attachment tab is selected.

You can sort the entries by clicking on an available column header. Select Customize columns to show a maximum of seven columns. The default values are marked with an asterisk (*):

- Submission name*  
- Sender*  
- Recipient  
- Date submitted*  
- Reason for submitting*  
- Status*  
- Result*  
- Filter verdict  
- Delivery/Block reason  
- Submission ID  
- Network Message ID/Object ID  
- Direction  
- Sender IP  
- Bulk compliant level (BCL)  
- Destination  
- Policy action  
- Submitted by  
- Phish simulation  
- Tags*  
- Allow

When you're finished, select Apply.

### Admin submission result details

Messages that are submitted in admin submissions are reviewed and results shown in the submissions detail flyout:

- If there was a failure in the sender's email authentication at the time of delivery.  
- Information about any policy hits that could have affected or overridden the verdict of a message.  
- Current detonation results to see if the URLs or files contained in the message are malicious or not.  
- Feedback from graders.

If an override was found, the result should be available in several minutes. If there wasn't a problem in email authentication or delivery wasn't affected by an override, then the feedback from graders could take up to a day.

### View user submissions to Microsoft

If you've deployed the Report Message add-in, the Report Phishing add-in, or people use the built-in reporting in Outlook on the web, you can see what users are reporting on the User reported message tab.

On the Submissions page, select the User reported messages tab.

You can sort the entries by clicking on an available column header. Select Customize columns to show the options. The default values are marked with an asterisk (*):

- Email subject*  
- Reported by*  
- Date reported*  
- Sender*  
- Reported reason*  
- Result*  
- Message reported ID  
- Network Message ID  
- Sender IP  
- Reported from  
- Phish simulation  
- Converted to admin submission  
- Tags*  
- Marked as*  
- Marked by  
- Date marked

When you're finished, select Apply.

**Note:** If organizations are configured to send user reported messages to the custom mailbox only, reported messages will appear in User reported messages but their results will always be empty (as they would not have been rescanned).

### Undo user submissions

Once a user submits a suspicious email to the custom mailbox, the user and admin don't have an option to undo the submission. If the user would like to recover the email, it will be available for recovery in the Deleted Items or Junk Email folders.

### Converting user reported messages from the custom mailbox into an admin submission

If you've configured the custom mailbox to intercept user-reported messages without sending the messages to Microsoft, you can find and send specific messages to Microsoft for analysis.

On the User reported messages tab, select a message in the list, select Submit to Microsoft for analysis, and then select one of the following values from the dropdown list:

- Report clean  
- Report phishing  
- Report malware  
- Report spam  
- Trigger investigation  
--------------------------------------------------    
# Explore advanced hunting

**Completed 100 XP**

- 3 minutes

Advanced hunting is a query-based threat-hunting tool that lets you explore up to 30 days of raw data. You can proactively inspect events in your network to locate threat indicators and entities. The flexible access to data enables unconstrained hunting for both known and potential threats.

You can use the same threat-hunting queries to build custom detection rules. These rules run automatically to check for and then respond to suspected breach activity, misconfigured machines, and other findings. The advanced hunting capability supports queries that check a broader data set from:

- Microsoft Defender for Endpoint  
- Microsoft Defender for Office 365  
- Microsoft Defender for Cloud Apps  
- Microsoft Defender for Identity

To use advanced hunting, turn on Microsoft Defender XDR.

## Data freshness and update frequency

Advanced hunting data can be categorized into two distinct types, each consolidated differently.

- **Event or activity data**—populates tables about alerts, security events, system events, and routine assessments. Advanced hunting receives this data almost immediately after the sensors that collect them successfully transmit them to the corresponding cloud services. For example, you can query event data from healthy sensors on workstations or domain controllers almost immediately after they're available on Microsoft Defender for Endpoint and Microsoft Defender for Identity.  
- **Entity data**—populates tables with information about users and devices. This data comes from both relatively static data sources and dynamic sources, such as Active Directory entries and event logs. To provide fresh data, tables are updated with any new information every 15 minutes, adding rows that might not be fully populated. Every 24 hours, data is consolidated to insert a record that contains the latest, most comprehensive data set about each entity.

## Time zone

Time information in advanced hunting is in the UTC zone.

## Data schema

The advanced hunting schema is made up of multiple tables that provide either event information or information about devices, alerts, identities, and other entity types. To effectively build queries that span multiple tables, you need to understand the tables and the columns in the advanced hunting schema.

### Get schema information

While constructing queries, use the built-in schema reference to quickly get the following information about each table in the schema:

- Table description—type of data contained in the table and the source of that data.  
- Columns—all the columns in the table.  
- Action types—possible values in the ActionType column representing the event types supported by the table. This information is provided only for tables that contain event information.  
- Sample query—example queries that feature how the table can be utilized.

### Access the schema reference

To quickly access the schema reference, select the View reference action next to the table name in the schema representation. You can also select Schema reference to search for a table.

### Learn the schema tables

The following reference lists all the tables in the schema. Each table name links to a page describing the column names for that table. Table and column names are also listed in the security center as part of the schema representation on the advanced hunting screen.

| Table name | Description |  
| --- | --- |  
| AlertEvidence | Files, IP addresses, URLs, users, or devices associated with alerts |  
| AlertInfo | Alerts from Microsoft Defender for Endpoint, Microsoft Defender for Office 365, Microsoft Cloud App Security, and Microsoft Defender for Identity, including severity information and threat categorization |  
| CloudAppEvents | Events involving accounts and objects in Office 365 and other cloud apps and services |  
| DeviceEvents | Multiple event types, including events triggered by security controls such as Windows Defender Antivirus and exploit protection |  
| DeviceFileCertificateInfo | Certificate information of signed files obtained from certificate verification events on endpoints |  
| DeviceFileEvents | File creation, modification, and other file system events |  
| DeviceImageLoadEvents | DLL loading events |  
| DeviceInfo | Machine information, including OS information |  
| DeviceLogonEvents | Sign-ins and other authentication events on devices |  
| DeviceNetworkEvents | Network connection and related events |  
| DeviceNetworkInfo | Network properties of devices, including physical adapters, IP and MAC addresses, as well as connected networks and domains |  
| DeviceProcessEvents | Process creation and related events |  
| DeviceRegistryEvents | Creation and modification of registry entries |  
| DeviceTvmSecureConfigurationAssessment | Threat & Vulnerability Management assessment events, indicating the status of various security configurations on devices |  
| DeviceTvmSecureConfigurationAssessmentKB | Knowledge base of various security configurations used by Threat & Vulnerability Management to assess devices; includes mappings to various standards and benchmarks |  
| DeviceTvmSoftwareInventory | Inventory of software installed on devices, including their version information and end-of-support status |  
| DeviceTvmSoftwareVulnerabilities | Software vulnerabilities found on devices and the list of available security updates that address each vulnerability |  
| DeviceTvmSoftwareVulnerabilitiesKB | Knowledge base of publicly disclosed vulnerabilities, including whether exploit code is publicly available |  
| EmailAttachmentInfo | Information about files attached to emails |  
| EmailEvents | Microsoft 365 email events, including email delivery and blocking events |  
| EmailPostDeliveryEvents | Security events that occur post-delivery, after Microsoft 365 has delivered the emails to the recipient mailbox |  
| EmailUrlInfo | Information about URLs on emails |  
| IdentityDirectoryEvents | Events involving an on-premises domain controller running Active Directory (AD). This table covers a range of identity-related events and system events on the domain controller. |  
| IdentityInfo | Account information from various sources, including Microsoft Entra ID |  
| IdentityLogonEvents | Authentication events on Active Directory and Microsoft online services |  
| IdentityQueryEvents | Queries for Active Directory objects, such as users, groups, devices, and domains |

## Custom detections

With custom detections, you can proactively monitor for and respond to various events and system states, including suspected breach activity and misconfigured endpoints. This is made possible by customizable detection rules that automatically trigger alerts and response actions.

Custom detections work with advanced hunting, which provides a powerful, flexible query language that covers a broad set of event and system information from your network. You can set them to run at regular intervals, generating alerts and taking response actions whenever there are matches.

Custom detections provide:

- Alerts for rule-based detections built from advanced hunting queries  
- Automatic response actions that apply to files and devices

### Create detection rules

To create detection rules:

**1. Prepare the query.**

In Microsoft Defender Security Center, go to Advanced hunting and select an existing query or create a new query. When using a new query, run the query to identify errors and understand possible results.

> **Important**  
> To prevent the service from returning too many alerts, each rule is limited to generating only 100 alerts whenever it runs. Before creating a rule, tweak your query to avoid alerting for normal, day-to-day activity.

To use a query for a custom detection rule, the query must return the following columns:

- Timestamp  
- DeviceId  
- ReportId

Simple queries, such as those that don't use the project or summarize operator to customize or aggregate results, typically return these common columns.

There are various ways to ensure more complex queries return these columns. For example, if you prefer to aggregate and count by DeviceId, you can still return Timestamp and ReportId by getting them from the most recent event involving each device.

The sample query below counts the number of unique devices (DeviceId) with antivirus detections and uses this to find only those devices with more than five detections. To return the latest Timestamp and the corresponding ReportId, it uses the summarize operator with the arg_max function.

```kusto  
DeviceEvents  
| where Timestamp > ago(7d)  
| where ActionType == "AntivirusDetection"  
| summarize (Timestamp, ReportId)=arg_max(Timestamp, ReportId), count() by DeviceId  
| where count_ > 5  
```

**2. Create a new rule and provide alert details.**

With the query in the query editor, select Create detection rule and specify the following alert details:

- Detection name—name of the detection rule  
- Frequency—interval for running the query and taking action. See additional guidance below  
- Alert title—title displayed with alerts triggered by the rule  
- Severity—potential risk of the component or activity identified by the rule.  
- Category—type of threat component or activity, if any.  
- MITRE ATT&CK techniques—one or more attack techniques identified by the rule as documented in the MITRE ATT&CK framework. This section isn't available with certain alert categories, such as malware, ransomware, suspicious activity, and unwanted software  
- Description—more information about the component or activity identified by the rule  
- Recommended actions—additional actions that responders might take in response to an alert

**3. Rule frequency**

When saved, a new custom detection rule immediately runs and checks for matches from the past 30 days of data. The rule then runs again at fixed intervals and lookback durations based on the frequency you choose:

- Every 24 hours—runs every 24 hours, checking data from the past 30 days  
- Every 12 hours—runs every 12 hours, checking data from the past 48 hours  
- Every 3 hours—runs every 3 hours, checking data from the past 12 hours  
- Every hour—runs hourly, checking data from the past 4 hours  
- Continuous (NRT)—runs continuously, checking data from events as they are collected and processed in near real-time (NRT)

Select the frequency that matches how closely you want to monitor detections, and consider your organization's capacity to respond to the alerts.

> **Note**  
> Setting a custom detection to run in Continuous (NRT) frequency allows you to increase your organization's ability to identify threats faster.

**4. Choose the impacted entities.**

Identify the columns in your query results where you expect to find the main affected or impacted entity. For example, a query might return both device and user IDs. Identifying which of these columns represents the main impacted entity helps the service aggregate relevant alerts, correlate incidents, and target response actions.

You can select only one column for each entity type. Columns that aren't returned by your query can't be selected.

**5. Specify actions.**

Your custom detection rule can automatically take actions on files or devices that are returned by the query.

**Actions on devices**

These actions are applied to devices in the DeviceId column of the query results:

- Isolate device—applies full network isolation, preventing the device from connecting to any application or service, except for the Defender for Endpoint service.  
- Collect investigation package—collects device information in a ZIP file.  
- Run antivirus scan—performs a full Microsoft Defender Antivirus scan on the device  
- Initiate investigation—starts an automated investigation on the device

**Actions on files**

These actions are applied to files in the SHA1 or the InitiatingProcessSHA1 column of the query results:

- Allow/Block—automatically adds the file to your custom indicator list so that it's always allowed to run or blocked from running. You can set the scope of this action so that it's taken only on selected device groups. This scope is independent of the scope of the rule.  
- Quarantine file—deletes the file from its current location and places a copy in quarantine

**6. Set the rule scope.**

Set the scope to specify which devices are covered by the rule:

- All devices  
- Specific device groups

Only data from devices in scope will be queried. Also, actions will be taken only on those devices.

**7. Review and turn on the rule.**

After reviewing the rule, select Create to save it. The custom detection rule immediately runs. It runs again based on configured frequency to check for matches, generate alerts, and take response actions.  
--------------------------------------------------    
# Investigate Microsoft Entra sign-in logs

**Completed 100 XP**

- 3 minutes

To perform a sign-in investigation including conditional access policies evaluated, you can query the following tables with KQL:

| Location                              | Table              |  
|---------------------------------------|--------------------|  
| Microsoft Defender XDR Threat Hunting | AADSignInEventsBeta|  
| Microsoft Entra ID Log Analytics      | SigninLogs         |

The Microsoft Entra monitoring Sign-in Logs provide access to the same information available in the SigninLogs table. To access the Sign-in Logs blade, select Microsoft Entra ID in the Azure portal, then Sign-in Logs in the Monitoring Group. The query output will provide default columns including the Date, User, Application, Status, and Conditional Access (policy applied).  
--------------------------------------------------    
# Understand Microsoft Secure Score

Completed 100 XP

- 3 minutes

The _Secure Score_ is a holistic view of the _Microsoft Secure Score (365)_, which is a measurement of an organization's security posture, with a higher number indicating more recommended actions taken, and the _Cloud Secure score (Risk based)_, that is a representation of your organizations cloud security posture. They're part of the _Exposure Management_ tools in the Microsoft Defender portal.

Following the Secure Score recommendations can protect your organization from threats. From a centralized dashboard in the Microsoft Defender portal, organizations can monitor and work on the security of their Microsoft 365 identities, apps, and devices.

Organizations gain access to robust visualizations of metrics and trends, integration with other Microsoft products, score comparison with similar organizations, and much more. The score can also reflect when third-party solutions have addressed recommended actions.

### Products included in Secure Score

Currently there are recommendations for the following products:

- Microsoft Defender for Office  
- Exchange Online  
- Microsoft Entra ID  
- Microsoft Defender for Endpoint  
- Microsoft Defender for Identity  
- Microsoft Defender for Cloud Apps  
- Microsoft Purview Information Protection  
- Defender for Cloud Apps  
- Microsoft Teams  
- App governance  
- Citrix ShareFile  
- Docusign  
- GitHub  
- Okta  
- Salesforce  
- ServiceNow  
- SharePoint Online  
- Zoom

You can also mark the improvement actions as covered by a third party or alternate mitigation.

### Take action to improve your score

The **Recommended actions** tab lists the security recommendations that address possible attack surfaces. It also includes their status (to address, planned, risk accepted, resolved through third party, resolved through alternate mitigation, and completed). You can search, filter, and group all the improvement actions.  
--------------------------------------------------    
# Analyze threat analytics

Threat analytics is a threat intelligence solution from expert Microsoft security researchers. It's designed to assist security teams to be as efficient as possible while facing emerging threats, such as:

- Active threat actors and their campaigns  
- Popular and new attack techniques  
- Critical vulnerabilities  
- Common attack surfaces  
- Prevalent malware

You can access threat analytics either from the upper left-hand side of Microsoft Defender security portal's navigation menu by expanding _Threat intelligence_, or from a dedicated _Threat analytics_ dashboard card that shows the threats to your org, both in terms of impact, and in terms of exposure.

High impact threats have the greatest potential to cause harm, while high exposure threats are the ones that your assets are most vulnerable to. Getting visibility on active or ongoing campaigns and knowing what to do through threat analytics can help equip your security operations team with informed decisions.

With more sophisticated adversaries and new threats emerging frequently and prevalently, it's critical to be able to quickly:

- Identify and react to emerging threats  
- Learn if you're currently under attack  
- Assess the impact of the threat to your assets  
- Review your resilience against or exposure to the threats  
- Identify the mitigation, recovery, or prevention actions you can take to stop or contain the threats

Each report provides an analysis of a tracked threat and extensive guidance on how to defend against that threat. It also incorporates data from your network, indicating whether the threat is active and if you have applicable protections in place.

### View the threat analytics dashboard

The threat analytics dashboard highlights the reports that are most relevant to your organization. It summarizes the threats in the following sections:

- **Latest threats**—lists the most recently published or updated threat reports, along with the number of active and resolved alerts.  
- **High-impact threats**—lists the threats that have the highest impact to your organization. This section lists threats with the highest number of active and resolved alerts first.  
- **Highest exposure**—lists threats with the highest exposure levels first. The exposure level of a threat is calculated using two pieces of information: how severe the vulnerabilities associated with the threat are, and how many devices in your organization could be exploited by those vulnerabilities.

Selecting a threat from the dashboard views the report for that threat.

Each threat analytics report provides information in several sections:

- Overview  
- Analyst report  
- Related incidents  
- Impacted assets  
- Prevented email attempts  
- Exposure & mitigations

### Overview: Quickly understand the threat, assess its impact, and review defenses

The Overview section provides a preview of the detailed analyst report. It also provides charts that highlight the impact of the threat to your organization, and your exposure through misconfigured and unpatched devices.

### Assess impact on your organization

Each report includes charts designed to provide information about the organizational impact of a threat:

- **Related incidents**—provides an overview of the impact of the tracked threat to your organization with the number of active alerts and the number of active incidents they're associated with and severity of active incidents  
- **Alerts over time**—shows the number of related Active and Resolved alerts over time. The number of resolved alerts indicates how quickly your organization responds to alerts associated with a threat. Ideally, the chart should be showing alerts resolved within a few days.  
- **Impacted assets**—shows the number of distinct devices and email accounts (mailboxes) that currently have at least one active alert associated with the tracked threat. Alerts are triggered for mailboxes that received threat emails. Review both org- and user-level policies for overrides that cause the delivery of threat emails.  
- **Prevented email attempts**—shows the number of emails from the past seven days that were either blocked before delivery or delivered to the junk mail folder.

### Review security resilience and posture

Each report includes charts that provide an overview of how resilient your organization is against a given threat:

- **Secure configuration status**—shows the number of devices with misconfigured security settings. Apply the recommended security settings to help mitigate the threat. Devices are considered Secure if they've applied all the tracked settings.  
- **Vulnerability patching status**—shows the number of vulnerable devices. Apply security updates or patches to address vulnerabilities exploited by the threat.

### View reports per threat tags

You can filter the threat report list and view the most relevant reports according to a specific threat tag (category) or a report type.

- **Threat tags**—assist you in viewing the most relevant reports according to a specific threat category. For example, all reports related to ransomware.  
- **Report types**—assist you in viewing the most relevant reports according to a specific report type. For example, all reports that cover tools and techniques.  
- **Filters**—assist you in efficiently reviewing the threat report list and filtering the view based on a specific threat tag or report type. For example, review all threat reports related to ransomware category, or threat reports that cover vulnerabilities.

### How does it work?

The Microsoft Threat Intelligence team has added threat tags to each threat report:

Four threat tags are now available:

- Ransomware  
- Phishing  
- Vulnerability  
- Activity group

Threat tags are presented at the top of the threat analytics page. There are counters for the number of available reports under each tag.

### Analyst report: Get expert insight from Microsoft security researchers

In the Analyst report section, read through the detailed expert write-up. Most reports provide detailed descriptions of attack chains, including tactics and techniques mapped to the MITRE ATT&CK framework, exhaustive lists of recommendations, and powerful threat hunting guidance.

### Related incidents: View and manage related incidents

The Related incidents tab provides the list of all incidents related to the tracked threat. You can assign incidents or manage alerts linked to each incident.

### Impacted assets: Get list of impacted devices and mailboxes

An asset is considered impacted if it's affected by an active, unresolved alert. The Impacted assets tab lists the following types of impacted assets:

- **Impacted devices**—endpoints that have unresolved Microsoft Defender for Endpoint alerts. These alerts typically fire on sightings of known threat indicators and activities.  
- **Impacted mailboxes**—mailboxes that have received email messages that have triggered Microsoft Defender for Office 365 alerts. While most messages that trigger alerts are typically blocked, user- or org-level policies can override filters.

### Prevented email attempts: View blocked or junked threat emails

Microsoft Defender for Office 365 typically blocks emails with known threat indicators, including malicious links or attachments. In some cases, proactive filtering mechanisms that check for suspicious content will instead send threat emails to the junk mail folder. In either case, the chances of the threat launching malware code on the device is reduced.

The Prevented email attempts tab lists all the emails that have either been blocked before delivery or sent to the junk mail folder by Microsoft Defender for Office.

### Exposure and mitigations: Review list of mitigations and the status of your devices

In the Exposure & mitigations section, review the list of specific actionable recommendations that can help you increase your organizational resilience against the threat. The list of tracked mitigations includes:

- Security updates—deployment of supported software security updates for vulnerabilities found on onboarded devices  
- Supported security configurations  
    - Cloud-delivered protection  
    - Potentially unwanted application (PUA) protection  
    - Real-time protection

Mitigation information in this section incorporates data from threat and vulnerability management, which also provides detailed drill-down information from various links in the report.

### Set up email notifications for report updates

You can set up email notifications that send you updates on threat analytics reports.

To set up email notifications for threat analytics reports, perform the following steps:

1. Select Settings in the Microsoft Defender XDR sidebar. Select Microsoft Defender XDR from the list of settings.  
2. Choose Email notifications > Threat analytics, and select the button, + Create a notification rule. A flyout appears.  
3. Follow the steps listed in the flyout. First, give your new rule a name. The description field is optional, but a name is required. You can toggle the rule on or off using the checkbox under the description field.  
    - Note: The name and description fields for a new notification rule only accept English letters and numbers. They don't accept spaces, dashes, underscores, or any other punctuation.  
4. Choose which kind of reports you want to be notified about. You can choose between being updated about all newly published or updated reports, or only those reports that have a certain tag or type.  
5. Add at least one recipient to receive the notification emails. You can also use this screen to check how the notifications will be received, by sending a test email.  
6. Review your new rule. If there's anything you would like to change, select the Edit button at the end of each subsection. Once your review is complete, select the Create rule button.

Your new rule has been successfully created. Select the Done button to complete the process and close the flyout. Your new rule will now appear in the list of Threat analytics email notifications.  
--------------------------------------------------    
# Analyze reports

**Completed 100 XP**

- 3 minutes

The Reports blade in the Microsoft Defender portal provides access to all the available reports for Microsoft Defender for Endpoint and Microsoft Defender for Office 365.

## General

| Name            | Description                                                                                       |  
|-----------------|---------------------------------------------------------------------------------------------------|  
| Security report | View information about security trends and track the protection status of your identities, data, devices, apps, and infrastructure. |

## Endpoints

| Name                        | Description                                                                                                   |  
|-----------------------------|---------------------------------------------------------------------------------------------------------------|  
| Threat protection           | See details about the security detections and alerts in your organization.                                     |  
| Device health and compliance| Monitor the health state, antivirus status, operating system platforms, and Windows 10 versions for devices in your organization. |  
| Vulnerable devices          | View information about the vulnerable devices in your organization, including their exposure to vulnerabilities by severity level, exploitability, age, and more. |  
| Web protection              | Get information about the web activity and web threats detected within your organization.                      |  
| Firewall                    | View connections blocked by your firewall including related devices, why they were blocked, and which ports were used |  
| Device control              | This report shows your organization's media usage data.                                                        |  
| Attack surface reduction rules | View information about detections, misconfiguration, and suggested exclusions in your environment.           |

## Email & Collaboration

| Name                        | Description                                                                                                   |  
|-----------------------------|---------------------------------------------------------------------------------------------------------------|  
| Email & collaboration reports| Review Microsoft recommended actions to help improve email and collaboration security.                        |  
| Manage schedules            | Manage the schedule for the reports security teams use to mitigate and address threats to your organization.   |  
| Reports for download        | Download one or more of your reports.                                                                         |  
| Exchange mail flow reports  | Deep link to Exchange mail flow report in the Exchange admin center.                                          |

---

**Next unit: Configure the Microsoft Defender portal**  
--------------------------------------------------    
# Configure the Microsoft Defender portal

**Completed 100 XP**

- 3 minutes

The Settings page lets you configure related Microsoft Defender products. The specific settings for the Defender products will be discussed in the related learning content. The primary setting for Microsoft Defender XDR is the notifications email configuration.

## Types of Microsoft Defender portal email notifications

When you set up email notifications, you can choose from two types, as described in the following table:

| Notification type | Description |  
| --- | --- |  
| Incidents | When new Incidents are created |  
| Threat Analytics | When new Threat Analytic reports are created |

### Manage Incident email notifications

To view, add or edit Incident email notification settings for your organization, follow these steps:

1. In the navigation pane, select Settings, and then select Microsoft Defender XDR. Then, select Email notifications.  
2. Next, select Incidents

To add a new notification:  
- Select Add incident email notification.  
- Enter a name and description, then next.  
- Select device and alert criteria, then next.  
- Enter the recipients email address, then next.  
- Select the Create rule button.

### Manage Threat Analytics email notifications

To view, add or edit Threat Analytics email notification settings for your organization, follow these steps:

1. In the navigation pane, select Settings, and then select Microsoft Defender XDR. Then, select Email notifications.  
2. Next, select Threat Analytics

To add a new notification:  
- Select Create a notification rule.  
- Enter a name and description, then next.  
- Select threat analytics criteria, then next.  
- Enter the recipients email address, then next.  
- Select the Create rule button.

---

**Next unit: Module assessment**  
--------------------------------------------------    
# Module assessment

Completed 200 XP

- 3 minutes

Choose the best response for each of the questions below.

## Check your knowledge

1. When you're reviewing a specific incident, which tab is contained on the incident page?  
    - Networks  
    - Non-Azure Machines  
    - Assets

2. You can classify an Incident as which of the following?  
    - True positive  
    - High alert  
    - Test alert

3. The Devices page shows information from which Defender product?  
    - Microsoft Cloud App Security  
    - Microsoft Defender for Identity  
    - Microsoft Defender for Endpoint

Submit answers

You must answer all questions before checking your work.  
--------------------------------------------------    
# Summary and resources

**Completed 100 XP**

- 3 minutes

You should have learned how Microsoft Defender XDR provides a purpose-driven user interface to manage and investigate security incidents and alerts across Microsoft 365 services.

You should now be able to:

- Manage incidents for Microsoft Defender XDR  
- Investigate incidents for Microsoft Defender XDR  
- Conduct advanced hunting for Microsoft Defender XDR

## Learn more

You can learn more by reviewing the following.

- MITRE ATT&CK Matrix for Enterprise  
- Become a Microsoft Defender XDR Ninja  
- Microsoft Tech Community Security Webinars  
--------------------------------------------------    
# Remediate risks with Microsoft Defender for Office 365

- 49 min  
- Module  
- 5 Units

## Description  
Learn about the Microsoft Defender for Office 365 component of Microsoft Defender XDR.

## Learning objectives  
In this module, you will learn how to:

- Define the capabilities of Microsoft Defender for Office 365.  
- Understand how to simulate attacks within your network.  
- Explain how Microsoft Defender for Office 365 can remediate risks in your environment.

## Prerequisites  
- Intermediate understanding of Microsoft 365

## This module is part of these learning paths  
- Defend against threats with Microsoft 365  
- SC-200: Mitigate threats using Microsoft Defender XDR

## Units  
- Introduction to Microsoft Defender for Office 365 (3 min)  
- Automate, investigate, and remediate (8 min)  
- Configure, protect, and detect (28 min)  
- Simulate attacks (5 min)  
- Summary and knowledge check (5 min)

## Module assessment  
Assess your understanding of this module. Sign in and answer all questions correctly to earn a pass designation on your profile.  
--------------------------------------------------    
# Introduction to Microsoft Defender for Office 365

**Completed 100 XP**

- 3 minutes

## Learn Office 365 specific terminology, threats, and concepts

**Microsoft Defender for Office 365** is a cloud-based email filtering service that helps protect your organization against unknown malware and viruses by providing robust zero-day protection. It includes features to safeguard your organization from harmful links in real time. Microsoft Defender for Office 365 has rich reporting and URL trace capabilities that give administrators insight into the kind of attacks happening in your organization.

![Icons representing Microsoft Defender for Office 365 capabilities.](https://learn.microsoft.com/en-us/training/wwl/m365-threat-remediate/media/defender-office-365.png)

Microsoft Defender for Office 365 provides the following benefits:

- **Industry-leading Protection.** Microsoft Defender for Office 365 uses 6.5 trillion signals daily from email alone to quickly and accurately detect threats and protect users against sophisticated attacks such as phishing and zero-day malware. Microsoft Defender for Office 365 blocked 5 billion phish emails and analyzed 300k phish campaigns in 2018 protecting 4 million unique users from advanced threats.  
- **Actionable Insights.** Actionable insights are presented to security administrators by correlating signals from a broad range of data to help identify, prioritize, and provide recommendations on how to address potential problems. The recommendations include remediation actions empowering administrators to proactively secure their organization.  
- **Automated response.** Investigation and remediation in post-breach scenarios can be difficult, expensive, and time-consuming. Most organizations lack the expertise and resources needed for rapid investigation and effective remediation. Microsoft Defender for Office 365 provides advanced automated response options that security operations can use saving a significant amount of time, money, and resources.  
- **Training & awareness.** Social engineering attacks such as phishing often look legitimate and are hard to spot for busy users. It's critical to train end users to make the right decisions in the event of an attack. In-product notifications help users understand the risks of performing an action such as clicking on a suspicious link. Features such as attack simulator help administrators launch realistic threat simulations to train users to be more aware and vigilant. User reporting capabilities empower users to notify Microsoft of suspicious content.

The following are the primary ways you can use Microsoft Defender for Office 365 for message protection:

- In a Microsoft Defender for Office 365 filtering-only scenario, Microsoft Defender for Office 365 provides cloud-based email protection for your on-premises Exchange Server environment or any other on-premises SMTP email solution.  
- Microsoft Defender for Office 365 can be enabled to protect Exchange Online cloud-hosted mailboxes.  
- In a hybrid deployment, Microsoft Defender for Office 365 can be configured to protect your messaging environment and control mail routing when you have a mix of on-premises and cloud mailboxes with Exchange Online Protection for inbound email filtering.  
--------------------------------------------------    
# Automate, investigate, and remediate

**Completed** 100 XP

- 8 minutes

## Save time with automated investigation and response

When you're investigating a potential cyberattack, time is of the essence. The sooner you identify and mitigate threats, the better off your organization is. Automated investigation and response (AIR) capabilities include a set of security playbooks that can be launched automatically, such as when an alert is triggered, or manually, such as from a view in Explorer. AIR can save your security operations team time and effort in mitigating threats effectively and efficiently.

Let's start with a native alert generated by Office 365. These alerts are typically investigated manually today – this process is where AIR comes in. Attackers frequently send through benign URLs in emails to bypass notice from security solutions, then they weaponize them after delivery to activate their attack. Notice in the following screenshot that the alert identifies that a URL that was recently weaponized was detected by Microsoft Defender for Office 365 through Safe Links URL detonation (under **Details** on the right-hand side).

Microsoft Defender for Office 365 triggered an AIR playbook based on this alert and resolved the alert given the auto investigation having completed.

Selecting the investigation link from the alert brings us into the Microsoft Defender Summary Investigation Graph. The graph shows the evidence, entities: URLs, emails, users (and their activities), and devices that have been automatically investigated as part of the triggered alert. It also shows the relationships between these entities.

Specifically:

- Emails that were identified as being relevant to this investigation (based on sender, IP, domain, URL, and other email attributes) and a subset of them were identified as being malicious, sent from an internal user in the organization, which itself is a strong indicator of a compromised user.  
- A user pivot on this investigation also identifies anomalies for one user with respect to a suspicious sign-in and mass downloads of documents.  
- With the compromised user, user anomalies and compromised device threats identified in this investigation, Microsoft Defender for Office 365 ran auto remediations such as blocking the URL, deleting any emails in mailboxes related to this URL, and triggering the Microsoft Entra workflows for password reset and MFA for the compromised user. The ability to take automatic action or drive remediations with manual approval, based on policy, are core elements of AIR.

AIR in Microsoft Defender for Office 365 includes certain remediation actions. Whenever an automated investigation is running or has completed, you'll typically see one or more remediation actions that require approval by your security operations team to proceed. Such remediation actions include:

- Soft delete email messages or clusters  
- Block URL (time-of-click)  
- Turn off external mail forwarding  
- Turn off delegation

For this alert, these actions can be found in the **Pending actions** tab under the selected investigation.

---

**Next unit: Configure, protect, and detect**  
--------------------------------------------------    
# Configure, protect, and detect

**Completed 100 XP**

- 28 minutes

With Microsoft Defender for Office 365, your organization's security team can configure protection by defining policies in the Microsoft Defender portal. The policies that are defined for your organization determine the behavior and protection level for predefined threats. Policy options are flexible. For example, your organization's security team can set fine-grained threat protection at the user, organization, recipient, and domain level. It's important to review your policies regularly because new threats and challenges emerge daily.

## Safe Attachments

Microsoft Defender for Office 365 Safe Attachments protects against unknown malware and viruses, and provides zero-day protection to safeguard your messaging system. All messages and attachments that don't have a known virus/malware signature are routed to a special environment where Microsoft Defender for Office 365 uses various machine learning and analysis techniques to detect malicious intent. If no suspicious activity is detected, the message is released for delivery to the mailbox.

When you're creating a Safe Attachments policy, the following options can be selected:

- Under the **Action for unknown malware** in Attachments:  
    - **Off**. Attachments won't be scanned for malware.  
    - **Monitor**. Continues delivering the message after malware is detected and track the scanning results.  
    - **Block**. Blocks the current and future emails and attachments with detected malware.  
    - **Replace**. Blocks the attachments with detected malware but continues to deliver the message body to the user.  
    - **Dynamic delivery**. Immediately delivers the message body without attachments and reattaches attachments after scanning if they're found to be safe.  
- Under **Redirect attachment on detection** you have the ability to enable one or both of the following settings:  
    - If you want to forward attachments that are blocked, replaced, or monitored to a security administrator in your organization for further investigation, check the **Enable redirect** checkbox and enter an email address.  
    - You can also have those attachments forwarded if the scanning process should time out by selecting the **Apply the above selection if malware scanning for attachments times out or error occurs** checkbox.

Once you've configured these settings, you can target users with that policy by specific domain, username, or group membership (or a combination). There are also exceptions that can be configured for this targeting, by users, groups, or domain.

Sometimes it's useful to allow mail to flow without delay from internal senders such as scans or faxes that send attachments that are known to be safe and from a trusted source. It isn't recommended to skip filtering for all internal messages as a compromised account would be able to potentially send malicious content. You can create a transport rule, also known as a mail flow rule, in the Exchange admin center (EAC) to bypass safe attachments scanning. As part of the mail flow rule, modify the message properties to set a message header with the **X-MS-Exchange-Organization-SkipSafeAttachmentProcessing** as the header name to bypass the safe attachment policy.

## Safe Links

The Microsoft Defender for Office 365 Safe Links feature proactively protects your users from malicious URLs in a message or in an Office document. The protection remains every time they select the link, as malicious links are dynamically blocked while good links can be accessed.

Safe Links is available for URLs in the following apps:

- Microsoft 365 apps for enterprise on Windows or Mac  
- Office for the web (Word for the web, Excel for the web, PowerPoint for the web, and OneNote for the web)  
- Word, Excel, PowerPoint, and Visio on Windows, as well as Office apps on iOS and Android devices  
- Microsoft Teams channels and chats

Safe links are both client and location agnostic, in that the location and device being used by the end user won't affect the behavior of wrapped links. Additionally, Safe links can be configured to support links in Office 2016 clients where the user is signed in with their Office 365 credential.

Safe links include a default policy that controls global settings such as which links to block and which links to wrap. You can't delete this policy, but you can edit it in your environment as needed, such as blocking a malicious link specific to your environment. It's recommended that you apply Microsoft Defender for Office 365 safe links policies to ALL users in your organization.

The following options can be configured as part of the Safe Links policy:

- For **Select the action for unknown potentially malicious URLs in messages**, selecting **On** will allow URLs to be rewritten and checked.  
- **Use Safe Attachments to scan downloadable content** will enable URL detection to scan files hosted on web sites. For example, if an email contains a link such as `https://contoso.com/maliciousfile.pdf`, the .pdf file is opened in a separate hypervisor environment and, if the file is found to be malicious, users will see a warning page if they select the link.  
- **Apply safe links to messages sent within the organization** will provide the same level of protection when links are sent by email within the organization.  
- **Do not track when users click safe links** enables or disables storing Safe Links select data for clicked URLs. Microsoft recommends leaving this setting unselected, which enables tracking for clicked URLs.  
- **Do not allow users to click through to the original URL** will prevent users from proceeding to the target web site if it's found to be malicious.  
- If users frequently receive links from web sites that are known to be safe, you can enter those URLs under **Do not rewrite the following URL**. For example, you might add the URL to a partner's website if users frequently receive emails from the partner that include URLs to the external organization's website.

Similar to bypassing safe attachments, you can also create a transport rule to bypass safe links. The message header for bypassing safe links is **X-MS-Exchange-Organization-SkipSafeLinksProcessing**.

## Anti-phishing policies

Microsoft Defender for Office 365 anti-phishing checks incoming messages for indicators that a message might be a phishing attempt. When users are covered by Microsoft Defender for Office 365 policies (Safe Attachments, Safe Links, or anti-phishing), incoming messages are evaluated by multiple machine learning models that analyze messages. The appropriate action is taken, based on the configured policies.

There's no default Microsoft Defender for Office 365 anti-phishing policy. When you're creating one, only targeting is originally configured. Impersonation settings play a large role in Microsoft Defender for Office 365 anti-phishing policies. Impersonation is where the sender or the sender's email domain in a message looks similar to a real sender or domain:

- An example impersonation of the domain contoso.com is ćóntoso.com.  
- An example impersonation of the user michelle@contoso.com is michele@contoso.com.

An impersonated domain might otherwise be considered legitimate (registered domain, configured email authentication records, etc.), except its intent is to deceive recipients. In the Microsoft Defender for Office 365 anti-phishing policy, you can configure a set of users to protect, domains to protect, actions for protected users (such as redirect messages or sending to junk folders), safety tips, trusted senders, and domains and more. These settings are exclusive to Microsoft Defender for Office 365 anti-phishing. Anti-spoofing settings are also included in Microsoft Defender for Office 365 anti-phishing policies.

### Explore how to safeguard your organization with Microsoft Defender for Office 365

View a video version of the interactive guide (captions available in more languages).

Be sure to select the full-screen option in the video player. When you're done, use the **Back** arrow in your browser to come back to this page.

---

Next unit: Simulate attacks  
--------------------------------------------------    
# Simulate attacks

**Completed 100 XP**

- 5 minutes

![Illustration of Technological shifts for Defenders.](https://learn.microsoft.com/en-us/training/wwl/m365-threat-remediate/media/defender-shift.png)

Microsoft Defender for Office 365 includes best-of-class threat investigation and response tools that enable your organization's security team to anticipate, understand, and prevent malicious attacks.

> **Note**  
>  
> The following capabilities are now found in Microsoft Defender XDR (Extended Detection and Response) which includes Microsoft Defender for Office 365, Microsoft Defender for Endpoint, and Microsoft Defender for Identity. Microsoft Defender XDR provides a unified view of threats across your organization, and enables you to investigate and respond to threats across your Microsoft 365 environment.

- **Threat trackers** provide the latest intelligence on prevailing cybersecurity issues. For example, you can view information about the latest malware, and take countermeasures before it becomes an actual threat to your organization. Available trackers include Noteworthy trackers, Trending trackers, Tracked queries, and Saved queries.  
- **Threat Explorer** (or real-time detections) (also referred to as Explorer) is a real-time report that allows you to identify and analyze recent threats. You can configure Explorer to show data for custom periods.  
- **Attack Simulator** allows you to run realistic attack scenarios in your organization to identify vulnerabilities. Simulations of current types of attacks are available, including spear phishing, credential harvest and attachment attacks, and password spray and brute force password attacks.

Threat Explorer enables you to begin delving into granular data for your organization. Inside Threat Explorer, you're first shown the variety of threat families impacting our organization over time. Additionally, you're shown the top threats and top targeted users inside the organization.

You can also change the category for the graph. In this case, All email is shown, and you can filter the Threat Explorer graph on many options including the Sender address, Recipients, and even the detection technology used to stop a threat. The Detection technology identifies if an email is blocked by Microsoft Defender for Cloud's sandboxing or through an Exchange Online Protection (EOP) filter. The graph adjusts to reflect the category being examined.

![Screenshot of Threat Explorer graph.](https://learn.microsoft.com/en-us/training/wwl/m365-threat-remediate/media/threat-explorer-graph.png)

Threat Explorer allows a deeper look into a threat, beginning with a thorough description of this malware family's behavior. Threat Explorer provides a definition of the threat, the message traces of emails delivering the threat, technical details of the threat, global details of the threat, and advanced analysis.

On the **Top targeted users** tab, you could see each instance that a user in the organization was sent an attachment containing a malware threat. You can not only see the specific recipients and subject, but the sender domain and the sender IP as well. The **Delivery action** column tells you if the email was caught and blocked before it ever reached the user, or if it was delivered as spam.

![Screenshot of Malware family description.](https://learn.microsoft.com/en-us/training/wwl/m365-threat-remediate/media/malware-family-description.png)

If a user received and opened the email that would also appear under Status enabling you to reach out to the user and take the appropriate remediation steps, such as scanning their device.

---

**Next unit: Summary and knowledge check**  
--------------------------------------------------    
# Summary and knowledge check

**Completed 200 XP**

- 5 minutes

In this module, you learned about the Microsoft Defender for Office 365 component of Microsoft Defender XDR.

Now that you've completed this module, you should be able to:

- Define the capabilities of Microsoft Defender for Office 365.  
- Understand how to simulate attacks within your network.  
- Explain how Microsoft Defender for Office 365 can remediate risks in your environment.

## Check your knowledge

1. **True or false?** Microsoft Defender for Office 365 requires an agent to be deployed to all Windows 10 devices in your organization for the best protection.  
    - True  
    - False

2. **What describes Safe Attachments from Microsoft Defender for Office 365?**  
    - Messages and attachments are routed to a special environment where Microsoft Defender for Office 365 uses various machine learning and analysis techniques to detect malicious intent.  
    - Protects your users from malicious URLs in a message or in an Office document.  
    - A powerful report that enables your Security Operations team to investigate and respond to threats effectively and efficiently.

3. **Which of the following is not an Attack Simulator scenario?**  
    - Spear phishing  
    - Password spray  
    - Bitcoin mining

--------------------------------------------------    
# Manage Microsoft Entra Identity Protection

**1100 XP**

- 50 min  
- Module  
- 10 Units

## Description  
Protecting a user's identity by monitoring their usage and sign-in patterns ensures a secure cloud solution. Explore how to design and implement Microsoft Entra Identity protection.

## Learning objectives  
By the end of this module you're able to:

- Implement and manage a user risk policy.  
- Implement and manage sign-in risk policies.  
- Implement and manage MFA registration policy.  
- Monitor, investigate, and remediate elevated risky users.

## Prerequisites  
None

## Get started with Azure  
Choose the Azure account that's right for you. Pay as you go or try Azure free for up to 30 days.

## This module is part of these learning paths  
- SC-200: Mitigate threats using Microsoft Defender XDR  
- SC-300: Implement an Authentication and Access Management solution

## Units  
- Introduction (1 min)  
- Review identity protection basics (4 min)  
- Implement and manage user risk policy (6 min)  
- Exercise: enable sign-in risk policy (10 min)  
- Exercise: configure Microsoft Entra multifactor authentication registration policy (5 min)  
- Monitor, investigate, and remediate elevated risky users (16 min)  
- Implement security for workload identities (3 min)  
- Explore Microsoft Defender for Identity (1 min)  
- Module assessment (3 min)  
- Summary and resources (1 min)

## Assessment  
Take the module assessment to assess your understanding of this module. Sign in and answer all questions correctly to earn a pass designation on your profile.

**Note:** The author created this module with assistance from AI.  
--------------------------------------------------    
# Introduction

Completed 100 XP

* 1 minute

Protecting users' identity by monitoring their usage and sign-in patters ensures a secure cloud solution. Explore how to design and implement Microsoft Entra Identity Protection.

### Watch this video

In this video, get a high-level overview of Identity Protection, a feature of Microsoft Entra ID. You’ll learn about different types of detections, risks, and risk policies that exist in Identity Protection. The video explains the benefits of the risk policies, recent UX enhancements, powerful APIs, improved risk assessment, and overall alignment along risky users and risky sign-ins.

## Learning objectives

In this module, you will:

* Review Identity Protection basics.  
* Implement and manage a user risk policy.  
* Implement and manage sign-in risk policies.  
* Implement and manage multifactor authentication (MFA) registration policy.  
* Monitor, investigate, and remediate elevated risky users.  
* Explore Microsoft Defender for Identity  
--------------------------------------------------    
# Review identity protection basics

**Completed 100 XP**

- 4 minutes

Identity Protection is a service that enables organizations to view the security posture of any account. Organizations can accomplish three key tasks:

- Automate the detection and remediation of identity-based risks.  
- Investigate risks using data in the portal.  
- Export risk detection data to third-party utilities for further analysis.

Always remember that Microsoft Entra Identity Protection requires a Microsoft Entra ID Premium P2 license to operate. Licensing is covered in more detail in a later unit.

Identity Protection uses the knowledge Microsoft has gained from its position in organizations with Microsoft Entra ID, the consumer space with Microsoft Accounts, and in gaming with Xbox to protect your users. Microsoft analyzes 6.5 trillion signals per day to identify and protect customers from threats.

The signals generated by and fed to Identity Protection can be further fed into tools like Conditional Access to make access decisions or fed back to a security information and event management (SIEM) tool for further investigation based on your organization's enforced policies.

## Risk detection and remediation

Identity Protection identifies risks in the following classifications:

| **Risk detection type**              | **Description**                                                                 |  
|--------------------------------------|---------------------------------------------------------------------------------|  
| Anonymous IP address                 | Sign in from an anonymous IP address (for example: Tor browser, anonymizer VPNs). |  
| Atypical travel                      | Sign in from an atypical location based on the user's recent sign ins.           |  
| Malware-linked IP address            | Sign in from a malware-linked IP address.                                        |  
| Unfamiliar sign in properties        | Sign in with properties we've not seen recently for the given user.              |  
| Leaked credentials                   | Indicates that the user's valid credentials have been leaked.                    |  
| Password spray                       | Indicates that multiple usernames are being attacked using common passwords in a unified brute-force manner. |  
| Microsoft Entra threat intelligence  | Microsoft's internal and external threat intelligence sources have identified a known attack pattern. |  
| New country                          | This detection is discovered by Microsoft Defender for Cloud Apps (MDCA).        |  
| Activity from anonymous IP address   | This detection is discovered by MDCA.                                            |  
| Suspicious inbox forwarding          | This detection is discovered by MDCA.                                            |

## Permissions

Identity Protection requires users be a Security Reader, Security Operator, Security Administrator, Global Reader Administrator in order to access.

| **Role**               | **Can do**                                                                 | **Can't do**                                         |  
|------------------------|-----------------------------------------------------------------------------|------------------------------------------------------|  
| Security Administrator | Full access to Identity Protection                                          | Reset password for a user                            |  
| Security Operator      | View all Identity Protection reports and Overview screen, Dismiss user risk, confirm safe sign-in, confirm compromise | Configure or change policies, Reset password for a user, Configure alerts |  
| Security Reader        | View all Identity Protection reports and Overview screen                     | Configure or change policies, Reset password for a user, Configure alerts, Give feedback on detections |

Currently, the Security Operator role cannot access the Risky sign ins report. Conditional Access Administrators can also create policies that factor in sign-in risk as a condition.

## License requirements

Using this feature requires a Microsoft Entra ID Premium P2 license.

| **Capability**                        | **Details**                                         | **Microsoft Entra ID Free / Microsoft 365 Apps** | **Microsoft Entra ID Premium P1** | **Microsoft Entra ID Premium P2** |  
|----------------------------------------|-----------------------------------------------------|--------------------------------------------------|------------------------------------|-----------------------------------|  
| Risk policies                         | User risk policy (via Identity Protection)          | No                                               | No                                 | Yes                              |  
| Risk policies                         | Sign-in risk policy (via Identity Protection or Conditional Access) | No                                               | No                                 | Yes                              |  
| Security reports                      | Overview                                            | No                                               | No                                 | Yes                              |  
| Security reports                      | Risky users                                        | Limited information. Only users with medium and high risk are shown. No details drawer or risk history. | Limited information. Only users with medium and high risk are shown. No details drawer or risk history. | Full access                       |  
| Security reports                      | Risky sign ins                                      | Limited information. No risk detail or risk level is shown. | Limited information. No risk detail or risk level is shown. | Full access                       |  
| Security reports                      | Risk detections                                     | No                                               | Limited information. No details drawer. | Full access                       |  
| Notifications                         | Users at risk detected alerts                       | No                                               | No                                 | Yes                              |  
| Notifications                         | Weekly digest                                       | No                                               | No                                 | Yes                              |  
| MFA registration policy                |                                                     | No                                               | No                                 | Yes                              |

--------------------------------------------------    
# Implement and manage user risk policy

Completed 100 XP

*6 minutes*

There are two risk policies that can be enabled in the directory:

- **Sign-in risk policy**: The sign-in risk policy detects suspicious actions that come along with the sign-in. It's focused on the sign-in activity itself and analyzes the probability that the sign-in was performed by some other than the user.

- **User risk policy**: The user risk policy detects the probability that a user account has been compromised by detecting risk events that are atypical of a user's behavior.

Both policies work to automate the response to risk detections in your environment and allow users to self-remediate when risk is detected.

### Watch the video

In this video, learn how to deploy Microsoft Entra Identity Protection by configuring risk-based policies (user risk and sign-in risk) in your organization. You also learn best practices on how to gradually roll out these policies and MFA registration in your organization.

---

## Prerequisites

If your organization wants to allow users to self-remediate when risks are detected, users must be registered for both self-service password reset and multifactor authentication. We recommend enabling the combined security information registration experience. Allowing users to self-remediate gets them back to a productive state more quickly without requiring administrator intervention. Administrators can still see these events and investigate them after the fact.

---

## Choosing acceptable risk levels

Organizations must decide the level of risk they're willing to accept, balancing user experience and security posture.

Microsoft's recommendation is to set the user risk policy threshold to **High** and the sign-in risk policy to **Medium and higher**.

Choosing a **High** threshold reduces the number of times a policy is triggered and minimizes the challenge to users. However, it excludes **Low** and **Medium** risk detections from the policy, which does not block an attacker from exploiting a compromised identity. Selecting a **Low** threshold introduces extra user interrupts but increased security posture.

---

## Exclusions

All of the policies allow for excluding users such as your emergency access or break-glass administrator accounts. Organizations determine when they need to exclude other accounts from specific policies based on the way the accounts are used. All exclusions should be reviewed regularly to see if they're still applicable.

Configured trusted network locations are used by Identity Protection in some risk detections to reduce false positives.  
--------------------------------------------------    
# Exercise enable sign-in risk policy

Completed 100 XP

*10 minutes*

## Enable user risk policy

1. Sign in to the Microsoft Entra admin center using a Global administrator account.  
2. Open the portal menu and then select **Identity**.  
3. On the Identity menu, select **Protection**.  
4. On the Security blade, in the left navigation, select **Identity protection**.  
5. In the Identity protection blade, in the left navigation, select User risk policy.  
     
   ![Screenshot of the User risk policy page and highlighted browsing path.](https://learn.microsoft.com/en-us/training/wwl-sci/manage-azure-active-directory-identity-protection/media/browse-identity-protection.png)  
     
6. Under **Assignments**, select **All users** and review the available options. You can select from **All users** or **Select individuals and groups** if limiting your rollout. Additionally, you can choose to exclude users from the policy.  
7. Under **User risk**, select **Low and above**.  
8. In the User risk pane, select **High** and then select **Done**.  
9. Under **Controls**, then **Access**, and then select **Block access**.  
10. In the Access pane, review the available options.

> **Tip**  
>  
> Microsoft's recommendation is to Allow access and Require password change.

11. Select the **Require password change** check box and then select **Done**.  
12. Under **Enforce Policy**, select **On** and then select **Save**.

## Enable sign-in risk policy

1. On the Identity protection blade, in the left navigation, select **Sign-in risk policy**.  
2. As with the User risk policy, the Sign-in risk policy can be assigned to users and groups and allows you to exclude users from the policy.  
3. Under **Sign-in risk**, select **Medium and above**.  
4. In the Sign-in risk pane, select **High** and then select **Done**.  
5. Under **Controls**, then **Access**, and then select **Block access**.  
6. Select the **Require multifactor authentication** check box and then select **Done**.  
7. Under **Enforce Policy**, select **On** and then select **Save**.  
--------------------------------------------------    
# Exercise configure Microsoft Entra multifactor authentication registration policy

**Completed 100 XP**

- 5 minutes

## Policy configuration

Multifactor authentication provides a means to verify who you are using more than just a username and password. It provides a second layer of security to user sign-ins. For users to be able to respond to MFA prompts, they must first register for multifactor authentication.

1. Sign in to the Microsoft Entra admin center using a Global administrator account.  
2. Open the portal menu and then select **Identity**.  
3. On the Identity menu, select **Protection**.  
4. On the Security blade, in the left navigation, select **Identity protection**.  
5. In the Identity protection blade, in the left navigation, select **Multifactor authentication registration policy**.  
6. Under **Assignments**, select **All users** and review the available options. You can select from **All users** or **Select individuals and groups** if limiting your rollout. Additionally, you can choose to exclude users from the policy.  
7. Under **Controls**, notice that the **Require Microsoft Entra ID multifactor authentication registration** is selected and cannot be changed.  
8. Under **Enforce Policy**, select **Enabled** and then select **Save**.  
--------------------------------------------------    
# Monitor, investigate, and remediate elevated risky users

**Completed 100 XP**

- 16 minutes

## Investigate risk

Identity Protection provides organizations with three reports to investigate identity risks: **risky users**, **risky sign-ins**, and **risk detections**. Investigating these events helps identify weak points in your security strategy.

- All reports allow downloading events in .CSV format for further analysis. Risky users and risky sign-ins reports allow up to 2,500 entries; risk detections up to 5,000 records.  
- Microsoft Graph API integrations can aggregate data with other sources.  
- Reports are found in the **Microsoft Entra admin center** under **Identity > Protection - Identity Protection**.

### Navigating the reports  
- Each report lists all detections for the selected period.  
- Columns can be added/removed; data can be downloaded in .CSV or .JSON.  
- Reports are filterable.  
- Selecting entries enables actions like confirming sign-in as compromised/safe, confirming user as compromised, or dismissing user risk.  
- Details view allows investigation and actions on each detection.

### Risky users  
- Find which users are at risk, have had risk remediated, or dismissed.  
- View detection details, history of risky sign-ins, and risk history.  
- Actions: reset password, confirm user compromise, dismiss user risk, block sign-in, investigate further using Azure ATP.

### Risky sign-ins  
- Contains filterable data for up to 30 days.  
- Find which sign-ins are at risk, confirmed compromised/safe, dismissed, or remediated.  
- View risk levels, detection types, Conditional Access policies, MFA, device, application, and location info.  
- Actions: confirm sign-in compromise or safe.

### Risk detections  
- Contains filterable data for up to 90 days.  
- Find info about each risk detection, other risks at the same time, and sign-in location.  
- Can return to user/sign-ins report to take action.  
- Provides a link to the detection in Microsoft Defender for Cloud Apps for more logs and alerts.

> **Note:** If a risk event is a false positive or remediated by policy (like MFA or password change), the system dismisses the risk state and marks it as “AI confirmed sign-in safe.”

## Remediate risks and unblock users

After investigation, take action to remediate risk or unblock users. Automated remediation can be enabled via risk policies. Microsoft recommends closing events as soon as possible.

### Remediation  
- All active risk detections contribute to the _user risk level_ (low, medium, high).  
- Goal: close all risk detections so users are no longer at risk.  
- Some detections are marked "Closed (system)" if no longer risky.  
- Remediation options:  
    - Self-remediation with risk policy  
    - Manual password reset  
    - Dismiss user risk  
    - Close individual risk detections manually

#### Self-remediation with risk policy  
- Users can unblock themselves with MFA and self-service password reset (SSPR) if registered.  
- Some detections may not require self-remediation but should still be evaluated.

#### Manual password reset  
- If user risk policy reset isn't an option, admins can reset passwords manually.  
- Two options:  
    - **Generate a temporary password:** Immediate safe state, user must change password at next sign-in.  
    - **Require user to reset password:** Self-recovery for users registered for MFA and SSPR.

#### Dismiss user risk  
- If password reset isn't possible (e.g., user deleted), dismiss user risk detections. This closes events but does not secure the identity.

#### Close individual risk detections manually  
- Lowers user risk level, typically after investigation.  
- Actions: confirm user compromised, dismiss user risk, confirm sign-in safe, confirm sign-in compromised.

### Unblocking users  
- Admins may block sign-in based on risk policy or investigation.

#### Unblocking based on user risk  
- Options:  
    - **Reset password**  
    - **Dismiss user risk**  
    - **Exclude user from policy**  
    - **Disable policy**

#### Unblocking based on sign-in risk  
- Options:  
    - **Sign in from familiar location/device**  
    - **Exclude user from policy**  
    - **Disable policy**

### PowerShell preview  
- Microsoft Graph PowerShell SDK Preview module can manage risk via PowerShell. Sample code is available in the Azure GitHub repo.

## Use the Microsoft Graph API

Microsoft Graph is the unified API endpoint for Microsoft Entra Identity Protection APIs. Three APIs expose information about risky users and sign-ins: `riskDetection`, `riskyUsers`, and `signIn`.

- `riskDetection`: Query for user and sign-in linked risk detections.  
- `riskyUsers`: Query for users detected as risky.  
- `signIn`: Query for sign-ins with risk properties.

### Steps to access Identity Protection data via Microsoft Graph  
1. Retrieve your domain name from the Microsoft Entra admin center.  
2. Create a new app registration.  
3. Configure API permissions (IdentityRiskEvent.Read.All, IdentityRiskyUser.Read.All).  
4. Configure a valid credential (client secret).

### Authenticate and query the API  
- Send a POST request to `https://login.microsoft.com` with required parameters to get an authentication token.  
- Use the token to call the API, e.g., `https://graph.microsoft.com/v1.0/identityProtection/riskDetections`.  
- Sample PowerShell code is provided for authentication and querying.

### Example queries  
- **Get all offline risk detections:**  
    ```  
    GET https://graph.microsoft.com/v1.0/identityProtection/riskDetections?$filter=detectionTimingType eq 'offline'  
    ```  
- **Get users who passed MFA challenge due to risky sign-ins policy:**  
    ```  
    GET https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$filter=riskDetail eq 'userPassedMFADrivenByRiskBasedPolicy'  
    ```  
--------------------------------------------------    
# Implement security for workload identities

**Completed 100 XP**

- 3 minutes

Microsoft Entra Identity Protection has historically protected users in detecting, investigating, and remediating identity-based risks. Identity protection has extended these capabilities to workload identities to protect applications, service principals, and Managed Identities.

A workload identity is an identity that allows an application or service principal access to resources, sometimes in the context of a user. These workload identities differ from traditional user accounts as they:

- Can’t perform multifactor authentication.  
- Often have no formal lifecycle process.  
- Need to store their credentials or secrets somewhere.

These differences make workload identities harder to manage and put them at higher risk for compromise.

### Requirements to use workload identity protection

To make use of workload identity risk, including the new Risky workload identities (preview) blade and the Workload identity detections tab in the Risk detections blade, in the Azure portal you must have the following.

- Microsoft Entra ID Premium P2 licensing  
- Logged in user must be assigned either:  
    - Security administrator  
    - Security operator  
    - Security reader

### What types of risks are detected?

| **Detection name** | **Detection type** | **Description** |  
| --- | --- | --- |  
| Microsoft Entra threat intelligence | Offline | This risk detection indicates some activity that is consistent with known attack patterns based on Microsoft's internal and external threat intelligence sources. |  
| Suspicious Sign-ins | Offline | This risk detection indicates sign-in properties or patterns that are unusual for this service principal. The detection learns the baselines sign-in behavior for workload identities in your tenant in between 2 and 60 days, and fires if one or more of the following unfamiliar properties appear during a later sign-in: IP address / ASN, target resource, user agent, hosting/non-hosting IP change, IP country, credential type. |  
| Unusual addition of credentials to an OAuth app | Offline | This detection is discovered by Microsoft Defender for Cloud Apps. This detection identifies the suspicious addition of privileged credentials to an OAuth app. This can indicate that an attacker has compromised the app, and is using it for malicious activity. |  
| Admin confirmed account compromised | Offline | This detection indicates an admin has selected 'Confirm compromised' in the Risky Workload Identities UI or using riskyServicePrincipals API. To see which admin has confirmed this account compromised, check the account’s risk history (via UI or API). |  
| Leaked Credentials (public preview) | Offline | This risk detection indicates that the account's valid credentials have been leaked. This leak can occur when someone checks in the credentials in public code artifact on GitHub, or when the credentials are leaked through a data breach. |

### Add conditional access protection

Using **Conditional Access for workload identities**, you can block access for specific accounts you choose when Identity Protection marks them "at risk." Policy can be applied to single-tenant service principals that have been registered in your tenant. Third-party SaaS, multi-tenanted apps, and managed identities are out of scope.  
--------------------------------------------------    
# Explore Microsoft Defender for Identity

Microsoft Defender for Identity (formerly Azure Advanced Threat Protection, also known as Azure ATP) is a cloud-based security solution. Defender for Identity uses your on-premises Active Directory signals to identify, detect, and investigate advanced threats, compromised identities, and malicious insider actions directed at your organization. Defender for Identity enables SecOp analysts and security professionals struggling to detect advanced attacks in hybrid environments to:

- Monitor users, entity behavior, and activities with learning-based analytics  
- Protect user identities and credentials stored in Active Directory  
- Identify and investigate suspicious user activities and advanced attacks throughout the kill chain  
- Provide clear incident information on a simple timeline for fast triage

### Process flow for Defender for Identity

Defender for Identity consists of the following components:

- **Defender for Identity portal** - The Defender for Identity portal allows the creation of your Defender for Identity instance, displays the data received from Defender for Identity sensors, and enables you to monitor, manage, and investigate threats in your network environment.  
- **Defender for Identity sensor** - Defender for Identity sensors can be directly installed on the following servers:  
    - Domain controllers: The sensor directly monitors domain controller traffic, without the need for a dedicated server, or configuration of port mirroring.  
    - Active Directory Federated Services (AD FS): The sensor directly monitors network traffic and authentication events.  
- **Defender for Identity cloud service** - Defender for Identity cloud service runs on Azure infrastructure and is currently deployed in the US, Europe, and Asia. Defender for Identity cloud service is connected to Microsoft's intelligent security graph.  
--------------------------------------------------    
# Module assessment

Completed 200 XP

- 3 minutes

Choose the best response for each of the questions below.

## Check your knowledge

1. **Which task can a user with the Security Operator role perform?**  
   - Configure alerts  
   - Confirm safe sign-in  
   - Reset a password for a user

2. **There are two risk policies that can be enabled in the directory. One is user risk policy. Which is the other risk policy?**  
   - Mobile device access risk policy  
   - Sign-in risk policy  
   - Hybrid identity sign-in risk policy

3. **In Microsoft Graph, which three APIs expose information about risky users and sign-ins**  
   - `riskDetection, riskyUsers, signIns`  
   - `riskDetection, itemActivity, signIns`  
   - `riskyUsers, signIns, IdentitySet`

Submit answers

You must answer all questions before checking your work.  
--------------------------------------------------    
# Summary and resources

Completed 100 XP

*1 minute*

Now that you have reviewed this module, you should be able to:

- Review Identity Protection basics.  
- Implement and manage a user risk policy.  
- Implement and manage sign-in risk policies.  
- Implement and manage multifactor authentication (MFA) registration policy.  
- Monitor, investigate, and remediate elevated risky users.  
- Explore Microsoft Defender for Identity

## Resources

Use these resources to discover more.

- Enabling combined security information registration in Microsoft Entra ID  
- Manage emergency access accounts in Microsoft Entra ID  
- How To: Configure and enable risk policies  
- What are managed identities for Azure resources?  
- Remediate risks and unblock users  
- Microsoft Entra Identity Protection notifications  
- Identity Protection policies  
- What is Microsoft Defender for Identity

## Get started with Azure

Choose the Azure account that's right for you. Pay as you go or try Azure free for up to 30 days. Sign up.  
--------------------------------------------------    
# Safeguard your environment with Microsoft Defender for Identity

- **600 XP**  
- **Duration:** 1 hr 8 min  
- **Module**  
- **5 Units**  
- **Level:** Intermediate  
- **Roles:** Administrator  
- **Products:** Microsoft 365, Azure, Microsoft Defender, Microsoft Defender XDR

Learn about the Microsoft Defender for Identity component of Microsoft Defender XDR.

## Learning objectives

Upon completion of this module, you should be able to:

- Define the capabilities of Microsoft Defender for Identity.  
- Understand how to configure Microsoft Defender for Identity sensors.  
- Explain how Microsoft Defender for Identity can remediate risks in your environment.

## Prerequisites

- Intermediate understanding of Microsoft 365

## Get started with Azure

Choose the Azure account that's right for you. Pay as you go or try Azure free for up to 30 days.

## This module is part of these learning paths

- Defend against threats with Microsoft 365  
- SC-200: Mitigate threats using Microsoft Defender XDR

## Units in this module

- Introduction to Microsoft Defender for Identity (35 min)  
- Configure Microsoft Defender for Identity sensors (5 min)  
- Review compromised accounts or data (19 min)  
- Integrate with other Microsoft tools (5 min)  
- Summary and knowledge check (4 min)

## Module Assessment

Assess your understanding of this module. Sign in and answer all questions correctly to earn a pass designation on your profile.  
--------------------------------------------------    
# Introduction to Microsoft Defender for Identity

**Completed 100 XP**

- 35 minutes

Microsoft Defender for Identity is a cloud-based security solution that leverages your on-premises Active Directory signals to identify, detect, and investigate advanced threats, compromised identities, and malicious insider actions directed at your organization.

![The benefits of Microsoft Defender for Identity.](https://learn.microsoft.com/en-us/training/m365/m365-threat-safeguard/media/azure-benefits.png)

Microsoft Defender for Identity provides the following benefits:

- Monitor users, entity behavior, and activities with learning-based analytics  
- Protect user identities and credentials stored in Active Directory  
- Identify and investigate suspicious user activities and advanced attacks throughout the kill chain  
- Provide clear incident information on a simple timeline for fast triage

## Monitor and profile user behavior and activities

Microsoft Defender for Identity monitors and analyzes user activities and information across your network, such as permissions and group membership. It then creates a behavioral baseline for each user. Microsoft Defender for Identity then identifies anomalies with adaptive built-in intelligence, giving you insights into suspicious activities and events, revealing the advanced threats, compromised users, and insider threats facing your organization. Microsoft Defender for Identity's proprietary sensors monitor organizational domain controllers, providing a comprehensive view for all user activities from every device.

![Overview of user activities.](https://learn.microsoft.com/en-us/training/m365/m365-threat-safeguard/media/user-activities-view.png)

## Protect user identities and reduce the attack surface

Microsoft Defender for Identity provides you invaluable insights on identity configurations and suggested security best-practices. Through security reports and user profile analytics, Microsoft Defender for Identity helps dramatically reduce your organizational attack surface, making it harder to compromise user credentials and advance an attack. Microsoft Defender for Identity's visual Lateral Movement Paths help you quickly understand exactly how an attacker can move laterally inside your organization to compromise sensitive accounts and assists in preventing those risks in advance. Microsoft Defender for Identity security reports help identify users and devices that authenticate using clear-text passwords and provide additional insights to improve your organizational security posture and policies.

![Security Report user improvement suggestions.](https://learn.microsoft.com/en-us/training/m365/m365-threat-safeguard/media/security-report-improvement-action-cropped.png)

## Identify suspicious activities and advanced attacks across the cyber-attack kill-chain

Typically, attacks are launched against any accessible entity, such as a low-privileged user, and then quickly move laterally until the attacker gains access to valuable assets – such as sensitive accounts, domain administrators, and highly sensitive data. Microsoft Defender for Identity has a large range of detections across the Kill-chain from **reconnaissance** through to **compromised credentials** to **lateral movements** and **domain dominance**.

![Lateral movement across the kill chain.](https://learn.microsoft.com/en-us/training/m365/m365-threat-safeguard/media/lateral-movement-across-kill-chain.png)

For example, in the reconnaissance stage, LDAP reconnaissance is used by attackers to gain critical information about the domain environment. Information that helps attackers map the domain structure, and identify privileged accounts for use later. This detection is triggered based on computers performing suspicious LDAP enumeration queries or queries targeting sensitive groups.

Brute force attacks are a common way to compromise credentials. This is when an attacker attempts to authenticate with multiple passwords on different accounts until a correct password is found or by using one password in a large-scale password spray that works for at least one account. Once found, the attacker logs in using the authenticated account. Microsoft Defender for Identity can detect this when it notices multiple authentication failures occurring using Kerberos, NTLM, or use of a password spray.

The next stage is when attackers attempt to move laterally through your environment, using pass-the-ticket, for example. Pass-the-ticket is a lateral movement technique in which attackers steal a Kerberos ticket from one computer and use it to gain access to another computer by reusing the stolen ticket. In this detection, a Kerberos ticket is being used on two (or more) different computers.

Ultimately, attackers want to establish domain dominance. One method, for example is the DCShadow attack. This attack is designed to change directory objects using malicious replication. This attack can be performed from any machine by creating a rogue domain controller using a replication process. If this occurs, Microsoft Defender for Identity triggers an alert when a machine in the network tries to register as a rogue domain controller.

This is not the complete set of detections, but it shows the breadth of detections Microsoft Defender for Identity covers.

---

**Next unit: Configure Microsoft Defender for Identity sensors**  
--------------------------------------------------    
# Configure Microsoft Defender for Identity sensors

**Completed 100 XP**

*5 minutes*

At a high level, the following steps are required to enable Microsoft Defender for Identity:

1. Create an instance on Microsoft Defender for Identity management portal.  
2. Specify an on-premises AD service account in the Microsoft Defender for Identity portal.  
3. Download and install the sensor package.  
4. Install the Microsoft Defender for Identity sensor on all domain controllers.  
5. Integrate your VPN solution (optional).  
6. Exclude the sensitive accounts you've listed during the design process.  
7. Configure the required permissions for the sensor to make SAM-R calls.  
8. Configure integration with Microsoft Defender for Cloud Apps.  
9. Configure integration with Microsoft Defender XDR (optional).

The following diagram shows the Microsoft Defender for Identity architecture. In this unit, we will discuss how to configure the Microsoft Defender for Identity Sensor.

![Microsoft Defender for Identity architecture](https://learn.microsoft.com/en-us/training/m365/m365-threat-safeguard/media/defender-identity-architecture-topology.png)

Installed directly on your domain controllers, the Microsoft Defender for Identity sensor accesses the event logs it requires directly from the domain controller. After the logs and network traffic are parsed by the sensor, Microsoft Defender for Identity sends only the parsed information to the Microsoft Defender for Identity cloud service (only a percentage of the logs are sent).

The Microsoft Defender for Identity sensor has the following core functionality:

* Capture and inspect domain controller network traffic (local traffic of the domain controller)  
* Receive Windows events directly from the domain controllers  
* Receive RADIUS accounting information from your VPN provider  
* Retrieve data about users and computers from the Active Directory domain  
* Perform resolution of network entities (users, groups, and computers)  
* Transfer relevant data to the Microsoft Defender for Identity cloud service

The Microsoft Defender for Identity sensor has the following requirements:

* KB4487044 is installed on Server 2019. Microsoft Defender for Identity sensors already installed on 2019 servers without this update will be automatically stopped.  
* The Microsoft Defender for Identity sensor supported domain controller OS list:  
    * Windows Server 2008 R2 SP1 (not including Server Core)  
    * Windows Server 2012  
    * Windows Server 2012 R2  
    * Windows Server 2016 (including Windows Server Core but not Windows Nano Server)  
    * Windows Server 2019 (including Windows Core but not Windows Nano Server)  
* The domain controller can be a read-only domain controller (RODC).  
* 10 GB of disk space is recommended. This includes space needed for the Microsoft Defender for Identity binaries, Microsoft Defender for Identity logs, and performance logs.  
* The Microsoft Defender for Identity sensor requires a minimum of two cores and 6 GB of RAM installed on the domain controller.  
* Power option of the Microsoft Defender for Identity sensor to high performance.  
* Microsoft Defender for Identity sensors can be deployed on domain controllers of various loads and sizes, depending on the amount of network traffic to and from the domain controllers, and the amount of resources installed.  
* When running as a virtual machine, dynamic memory or any other memory ballooning feature is not supported.

### To install the Microsoft Defender for Identity sensor

1. Download and extract the sensor file. Run **Microsoft Defender for Identity sensor setup.exe** and follow the setup wizard.  
2. On the Welcome page, select your language and click **Next**.

![Install steps: Choose Language.](https://learn.microsoft.com/en-us/training/m365/m365-threat-safeguard/media/install-choose-language.png)

3. The installation wizard automatically checks if the server is a domain controller or a dedicated server. If it's a domain controller, the Microsoft Defender for Identity sensor is installed. If it's a dedicated server, the Microsoft Defender for Identity standalone sensor is installed. For example, for a Microsoft Defender for Identity sensor, the following screen is displayed to let you know that a Microsoft Defender for Identity sensor is installed on your dedicated server:

![Install steps: Determine server type.](https://learn.microsoft.com/en-us/training/m365/m365-threat-safeguard/media/install-server-type.png)

4. Under **Configure the sensor**, enter the installation path and the access key, based on your environment:  
    * **Installation path**: The location where the Microsoft Defender for Identity sensor is installed. By default, the path is **%programfiles%Microsoft Defender for Identity sensor**. Leave the default value.  
    * **Access key**: Retrieved from the Microsoft Defender for Identity portal.

![Install steps: Configure the sensor.](https://learn.microsoft.com/en-us/training/m365/m365-threat-safeguard/media/install-configure-sensor.png)

5. Click **Install**.

After the Microsoft Defender for Identity sensor is installed, do the following to configure Microsoft Defender for Identity sensor settings:

1. Click **Launch** to open your browser and sign into the Microsoft Defender for Identity portal.  
2. In the Microsoft Defender for Identity portal, go to **Configuration**. Under the System section, select **Sensors**.

![Install steps: Select sensors in Microsoft Defender for Office 365 portal.](https://learn.microsoft.com/en-us/training/m365/m365-threat-safeguard/media/install-select-sensors.png)

3. Click on the sensor you want to configure and enter the following information:  
    * **Description**: Enter a description for the Microsoft Defender for Identity sensor (optional).  
    * **Domain Controllers** (FQDN) (required for the Microsoft Defender for Identity standalone sensor, this can't be changed for the Microsoft Defender for Identity sensor): Enter the complete FQDN of your domain controller and click the **plus sign** to add it to the list. For example, dc01.contoso.com.  
        * All domain controllers whose traffic is being monitored via port mirroring by the Microsoft Defender for Identity standalone sensor must be listed in the Domain Controllers list. If a domain controller isn't listed in the Domain Controllers list, detection of suspicious activities might not function as expected.  
        * At least one domain controller in the list should be a global catalog. This enables Microsoft Defender for Identity to resolve computer and user objects in other domains in the forest.  
    * **Capture Network adapters** (required):  
        * For Microsoft Defender for Identity sensors, all network adapters that are used for communication with other computers in your organization.  
        * For Microsoft Defender for Identity standalone sensor on a dedicated server, select the network adapters that are configured as the destination mirror port. These network adapters receive the mirrored domain controller traffic.

![Install steps: Enter information to configure sensor.](https://learn.microsoft.com/en-us/training/m365/m365-threat-safeguard/media/install-configure-sensor-info.png)

4. Click **Save**.  
--------------------------------------------------    
# Review compromised accounts or data

**Completed 100 XP**

- 19 minutes

Microsoft Defender for Identity security alerts explain suspicious activities detected by Microsoft Defender for Identity sensors on your network, and the actors and computers involved in each threat. Alert evidence lists contain direct links to the involved users and computers, to help make your investigations easy and direct.

Microsoft Defender for Identity security alerts are divided into the following categories or phases, like the phases seen in a typical cyber-attack kill chain:

- Reconnaissance phase alerts  
- Compromised credential phase alerts  
- Lateral movement phase alerts  
- Domain dominance phase alerts  
- Exfiltration phase alerts

Each Microsoft Defender for Identity security alert includes:

- **Alert title.** Official Microsoft Defender for Identity name of the alert.  
- **Description.** Brief explanation of what happened.  
- **Evidence.** Additional relevant information and related data about what happened to help in the investigation process.  
- **Excel download.** Detailed Excel download report for analysis

![Microsoft Defender for Identity security alert.](https://learn.microsoft.com/en-us/training/m365/m365-threat-safeguard/media/security-alert.png)

Alerts can also be viewed within Microsoft Defender for Cloud Apps:

![Microsoft Defender for Cloud Apps alert.](https://learn.microsoft.com/en-us/training/m365/m365-threat-safeguard/media/cloud-app-security-alerts.png)

The following scenario describes an investigation into an attacker gaining administrator access to the domain controller and compromising the Active Directory domain and forest.

The first alert we notice in the Defender for Cloud Apps portal shows **User and IP address reconnaissance** (SMB). Clicking into this alert, we see (under Description) that a user was able to learn the IP addresses of two accounts by enumerating SMB sessions on the domain controller.

![User and I P address reconnaissance.](https://learn.microsoft.com/en-us/training/m365/m365-threat-safeguard/media/user-ip-address-reconnaissance.png)

Within the alert, we can also find the activity log, which shows more information about the command that was run.

![Activity log.](https://learn.microsoft.com/en-us/training/m365/m365-threat-safeguard/media/activity-log.png)

Back in the Alerts overview, we can see a more recent alert pointing to an **overpass-the-hash attack**.

![Alert: Overpass-the-hash-attack.](https://learn.microsoft.com/en-us/training/m365/m365-threat-safeguard/media/overpass-hash-attack.png)

Opening the suspected overpass-the-hash-attack (Kerberos) alert, we see evidence that the user account was part of a lateral movement path.

![Open the suspected attack alert.](https://learn.microsoft.com/en-us/training/m365/m365-threat-safeguard/media/open-suspected-attack.png)

The next alert shows a **Suspected identity theft (pass-the-ticket)**.

![Pass-the-ticket alert.](https://learn.microsoft.com/en-us/training/m365/m365-threat-safeguard/media/pass-ticket-alert.png)

Microsoft Defender for Identity has detected theft of a ticket from a domain administrator to the infiltrated PC. The Defender for Cloud Apps portal shows exactly which resources were accessed using the stolen tickets.

![More information on the pass-the-ticket alert.](https://learn.microsoft.com/en-us/training/m365/m365-threat-safeguard/media/alert-pass-ticket.png)

In the next alert, we see that the stolen credentials were used to run a remote command on the domain controller.

![Alert showing remote code execution attemptl.](https://learn.microsoft.com/en-us/training/m365/m365-threat-safeguard/media/alert-remote-code-execution.png)

Looking into the Activity Log for the alert, we see that the command was to create a new user within the Administrators group.

![Command used to create a new user.](https://learn.microsoft.com/en-us/training/m365/m365-threat-safeguard/media/create-new-user.png)

From all the previous alerts, we suspect that an attacker has:

- Infiltrated a PC.  
- Used the PC to determine IP addresses of other users' PCs, one of which belongs to a domain administrator.  
- Performed an overpass-the-hash attack by stealing the NTLM hash from another user who previously authenticated to the infiltrated PC to access any resource the user has permissions for. (In this case, local admin rights to IP addresses previously exposed)  
- Used the newly stolen credentials to gain access to the domain administrator's PC.  
- Used their access to the domain administrator's PC to steal the identity of the domain administrator.  
- Used the domain administrator's identity to access the domain controller, and created a new user account with domain administrative permissions.

With domain administrative permissions, the attacker has effectively compromised the environment. Now they are free to perform any number of attacks, such as a Skeleton Key attack.  
--------------------------------------------------    
# Integrate with other Microsoft tools

**Completed 100 XP**

*5 minutes*

---

The Microsoft Defender for Identity cloud service runs on Azure infrastructure and is currently deployed in the US, Europe, and Asia. Microsoft Defender for Identity cloud service is connected to Microsoft's intelligent security graph. This enables Microsoft Defender for Identity to integrate with Microsoft Defender for Cloud Apps, as part of a Microsoft Defender XDR monitoring strategy.

Once integrated into Microsoft Defender for Cloud Apps, you're able to see on-premises activities for all the users in your organization. You'll also get advanced insights on your users that combine alerts and suspicious activities across your cloud and on-premises environments. Additionally, policies from Microsoft Defender for Identity appear on the Defender for Cloud Apps policies page. The following screenshot shows Microsoft Defender for Identity reporting within Defender for Cloud Apps.

Microsoft Defender for Identity also enables you to integrate Microsoft Defender for Identity with Microsoft Defender for Endpoint, for an even more complete threat protection solution. While Microsoft Defender for Identity monitors the traffic on your domain controllers, Microsoft Defender for Endpoint monitors your endpoints, together providing a single interface from which you can protect your environment. Once Microsoft Defender for Endpoint and Microsoft Defender for Identity are integrated, you can select on an endpoint to view Microsoft Defender for Identity alerts in the Microsoft Defender for Endpoint portal.

Having this level of insight into system running processes allows an analyst to locate event sequences leading to a compromise of the network. In the screenshot below, there are high severity alerts pointing to malware being installed on the system.

Clicking into the alert verifies that a Pass-The-Hash (PtH) attack occurred using the tool Mimikatz. Under actions for the alert, we can also review a timeline of events surrounding the credential theft.

--------------------------------------------------    
# Summary and knowledge check

**Completed 200 XP**

- 4 minutes

In this module, you learned about the Microsoft Defender for Identity component of Microsoft Defender XDR.

Now that you have completed this module, you should be able to:

- Define the capabilities of Microsoft Defender for Identity.  
- Understand how to configure Microsoft Defender for Identity sensors.  
- Explain how Microsoft Defender for Identity can remediate risks in your environment.

## Check your knowledge

1. Microsoft Defender for Identity requires an on-premises Active Directory environment.  
    - True  
    - False

2. Which of the following describes advanced threats detected by Microsoft Defender for Identity?  
    - Reconnaissance  
    - Vertical movements  
    - Bitcoin mining

3. Which of the following is **not** a supported integration for Microsoft Defender for Identity?  
    - Microsoft Defender for Endpoint  
    - Microsoft Defender for Cloud Apps  
    - Intune

--------------------------------------------------    
# Secure your cloud apps and services with Microsoft Defender for Cloud Apps

## Module Overview

Microsoft Defender for Cloud Apps is a cloud access security broker (CASB) that operates on multiple clouds. It provides rich visibility, control over data travel, and sophisticated analytics to identify and combat cyberthreats across all your cloud services. Learn how to use Defender for Cloud Apps in your organization.

**Duration:** 1 hr 9 min    
**Level:** Beginner    
**Role:** Administrator    
**Products:** Microsoft 365, Microsoft Defender for Cloud Apps

## Learning objectives

At the end of this module, you should be able to:

- Define the Defender for Cloud Apps framework  
- Explain how Cloud Discovery helps you see what's going on in your organization  
- Understand how to use Conditional Access App Control policies to control access to the apps in your organization

## Prerequisites

None

## Units in this module

- Introduction (1 min)  
- Understand the Defender for Cloud Apps Framework (2 min)  
- Explore your cloud apps with Cloud Discovery (2 min)  
- Protect your data and apps with Conditional Access App Control (4 min)  
- Walk through discovery and access control with Microsoft Defender for Cloud Apps (26 min)  
- Classify and protect sensitive information (7 min)  
- Detect Threats (21 min)  
- Module assessment (5 min)  
- Summary (1 min)

## Module assessment

Assess your understanding of this module. Sign in and answer all questions correctly to earn a pass designation on your profile.  
--------------------------------------------------    
# Introduction

Completed 100 XP

*1 minute*

When you move from an on-premises to a cloud-based organization, you increase flexibility, both for employees and the IT team. However, this move also introduces new challenges for keeping your organization secure. To get the full benefit of cloud apps and services, you have to balance supporting access with protecting critical data. Microsoft Defender for Cloud Apps helps you achieve that balance. It provides rich visibility, control over data travel, and sophisticated analytics to identify and combat cyberthreats across all your cloud services.

Suppose you're an administrator for an organization that's moved into the cloud. This module will show you how to use Microsoft Defender for Cloud Apps.

## Learn objectives

When you finish this module, you'll be able to:

- Define the Defender for Cloud Apps framework.  
- Understand how to use Cloud Discovery for visibility in your organization.  
- Explain how to use Conditional Access App Control policies to monitor and control access to your applications.  
- Understand how to classify and protect your information.  
- Understand how to use anomaly detection policies to detect threats in your cloud environment.  
--------------------------------------------------    
# Understand the Defender for Cloud Apps Framework

**Completed 100 XP**

- 2 minutes

Cloud access security broker (CASBs) are defined by Gartner as security policy enforcement points, placed between cloud service consumers and cloud service providers to combine and interject enterprise security policies as cloud-based resources are accessed. CASBs consolidate multiple types of security policy enforcement.

In other words, CASBs are the intermediaries between your users and all of the cloud services they access. CASBs help you to apply monitoring and security controls over your users and data. CASBs for cloud services are like firewalls to corporate networks.

Microsoft Defender for Cloud Apps is a CASB that helps you identify and combat cyberthreats across Microsoft and third-party cloud services. Microsoft Defender for Cloud Apps integrates with Microsoft solutions, providing simple deployment, centralized management, and innovative automation capabilities.

The following graphic shows the flow of information around your organization. You can see how Defender for Cloud Apps functions as an intermediary between apps, data, and users.

![Workflow diagram shows how data flows into and out of Defender for Cloud Apps, cloud apps, and cloud traffic in an organization. Each group is connected by two lines, going opposite directions that represent the inflow and outflow of data.](https://learn.microsoft.com/en-us/training/m365/microsoft-cloud-app-security/media/cloud-middleman.png)

There are four elements to the Defender for Cloud Apps framework:

- **Discover and control the use of Shadow IT**: Identify the cloud apps, IaaS, and PaaS services used by your organization. How many cloud apps do you think are used by your users? The apps you don't know about, on average totaling more than 1,000, are your "Shadow IT". When you know which apps are being used, you'll better understand and control your risk.  
- **Protect your sensitive information anywhere in the cloud**: Understand, classify, and protect sensitive information at rest. To help you avoid accidental data exposure, Defender for Cloud Apps provides data loss prevention (DLP) capabilities that cover the various data leak points that exist in organizations.  
- **Protect against cyberthreats and anomalies**: Detect unusual behavior across apps, users, and potential ransomware. Defender for Cloud Apps combines multiple detection methods, including anomaly, user entity behavioral analytics (UEBA), and rule-based activity detections, to show who is using the apps in your environment, and how they're using them.  
- **Assess the compliance of your cloud apps**: Assess if your cloud apps comply with regulations and industry standards specific to your organization. Defender for Cloud Apps helps you compare your apps and usage against relevant compliance requirements, prevent data leaks to noncompliant apps, and limit access to regulated data.  
--------------------------------------------------    
# Explore your cloud apps with Cloud Discovery

**Completed 100 XP**

- 2 minutes

You can use Cloud Discovery to see what's happening in your network. You'll see both the cloud apps you expect and the ones you don't, signs of Shadow IT, and nonsanctioned apps that might not be compliant with your security and compliance policies. Cloud Discovery analyzes your traffic logs against a catalog of more than 16,000 cloud apps. Cloud Discovery ranks each app and scores it based on more than 80 risk factors to give you visibility into cloud use, Shadow IT, and the risk it poses in your organization.

The Cloud Discovery dashboard provides an at-a-glance overview of what kinds of apps are being used, your open alerts, and the risk levels of the apps in your organization. You can also see who your top app users are and where each app comes from (on an App Headquarters map). You can filter the data collected by Cloud Discovery to generate specific views depending on what interests you most.

## Review the Cloud Discovery Dashboard

Your first step is to get a general picture of your cloud apps. Start at the Cloud Discovery dashboard then move through its elements in the following order to understand what's happening in your organization.

1. Start with the **High-level usage overview** to see the overall cloud app use. You can see the **top users** and **source IP addresses**. Based on this information, identify which users in your organization use cloud apps the most. You'll want to pay attention to these users going forward.  
2. Dive one level deeper to see which category of apps your organization uses most. See how much of this usage is in **Sanctioned** apps.  
3. Go even deeper on the **Discovered apps** tab. See all the apps in a specific category.  
4. Review the risk score for the discovered apps in the **App risk overview**. Each discovered app is assessed against risk factors like security and compliance and regulatory measures. Apps are given a risk score between 1 and 10.  
5. View where discovered apps are located (based on their headquarters) in the **App Headquarters map**.  
6. If you find an app that poses a risk to your organization, you can flag it as **Unsanctioned** in the **Discovered apps** pane.

If your organization is using Microsoft Defender for Endpoint (or a similar solution), any unsanctioned app is automatically blocked.

If you don't have a threat protection solution, you can run a script against the data source to block the app. Then users will see a notification that the application is blocked when they try to access it.  
--------------------------------------------------    
# Protect your data and apps with Conditional Access App Control

Cloud Discovery helps you understand what's happening in your cloud environment after the fact. While this process is important, your primary goal is to stop breaches and leaks in real time, before they put your organization at risk. You also need a way to enable users to bring their own devices to work while still protecting your organization from data leaks and data theft. Microsoft Defender for Cloud Apps integrates with identity providers (IdPs) to protect your data and devices with access and session controls through **Conditional Access App Control**. If you're using Microsoft Entra ID as your IdP, these controls are integrated directly into Defender for Cloud Apps.

Conditional Access App Control lets you monitor and control user app access and sessions in real time. By integrating with Microsoft Entra Conditional Access, it's easy to configure apps to work with Conditional Access App Control. It lets you selectively enforce access and session controls on your organization's apps based on any condition in Conditional Access. You can use conditions that define who (user or group of users), what (which cloud apps), and where (which locations and networks) a Conditional Access policy is applied. After you determine the conditions, you can route users to Defender for Cloud Apps where you protect data with Conditional Access App Control by applying access and session controls.

Microsoft Entra ID includes built-in policies that you can configure for an easy deployment. After you configure the conditions of a Conditional Access policy in Microsoft Entra ID, select **Session** under **Access controls**, and click **Use Conditional Access App Control**. If you choose to **use custom controls**, you'll define them in the Defender for Cloud Apps portal.

You can use access and session policies in the Defender for Cloud Apps portal to further refine filters and set actions to be taken on a user. With the access and session policies, you can:

* **Prevent data exfiltration**: Block the download, cut, copy, and print of sensitive documents on, for example, unmanaged devices.  
* **Protect on download**: Instead of blocking the download of sensitive documents, you can require them to be labeled and protected with Azure Information Protection. This action ensures that the document is protected and that user access is restricted in a potentially risky session.  
* **Prevent upload of unlabeled files**: Enforce the use of labeling. Before a sensitive file is uploaded, distributed, and used by others, it's important to make sure that it has the right label and protection. You can block a file upload until the content is classified.  
* **Monitor user sessions for compliance**: Monitor risky users when they sign in to apps and log their actions from within the session. You can investigate and analyze user behavior to understand where, and under what conditions, to apply session policies in the future.  
* **Block access**: You can block access for specific apps and users depending on several risk factors. For example, you can block a user if they're using a client certificate as a form of device management.  
* **Block custom activities**: Some apps have unique scenarios that carry risk; for example, sending messages with sensitive content in apps like Microsoft Teams or Slack. In these kinds of scenarios, you can scan messages for sensitive content and block them in real time.

For example, let's create a session policy in Microsoft Teams that blocks IM messages containing sensitive content. Assuming we previously created a Conditional Access policy with **Use custom controls** set under **Use Conditional Access App Control**, we start by creating a new session policy in Microsoft Defender for Cloud Apps.

We'll use an existing template for our new session policy. Select the **Block sending of messages based on real-time content inspection** policy template.

Under **Activity source** for the session policy, select **Send Teams message** as the application.

You then enable **Content Inspection**, where you'll define the sensitive information as matching a present expression, a custom expression, or any regular expression. When the expressions are defined, select **Block** under **Actions** to block the message, and to create alerts to notify administrators.

Now, when a user tries to send a sensitive message in Teams, they'll see a notification.  
--------------------------------------------------    
# Walk through discovery and access control with Microsoft Defender for Cloud Apps

**Completed 100 XP**

- 26 minutes

Now that you've learned how Cloud Discovery and Conditional Access App Control work, it's time to see how to implement them in Defender XDR.

This video walks you through how to protect your cloud apps in Microsoft Defender XDR:  
--------------------------------------------------    
# Classify and protect sensitive information

**Completed 100 XP**

- 7 minutes

One of the key elements of the Defender for Cloud Apps framework is protecting your sensitive information. Sensitivity is a subjective phrase, as this can vary from one organization to another.

Here, you'll understand how to find which apps are accessing your data, how to classify which information is sensitive, how to protect it from illegal access, and how to monitor and report on the overall health of your environment.

## What is Information Protection?

An employee might accidentally upload a file to the wrong place. Or they could send confidential information to someone who shouldn't have it. As a result, information could be lost or made accessible to the wrong person. Any lost or wrongfully exposed information can have serious legal, financial, or reputational consequences for your organization. Information is vital to any modern organization, and you want to ensure that it's protected at all times.

To help you, Microsoft Defender for Cloud Apps natively integrates with Azure Information Protection, a cloud-based service that helps classify and protect files and emails across your organization.

> **Note**  
>   
> You have to enable the app connector for Microsoft 365 to take advantage of Azure Information Protection

You enforce information protection with Microsoft Defender for Cloud Apps through phases:

### Phase 1: Discover data

During this phase, you make sure apps are connected to Microsoft Defender for Cloud Apps so it can scan for and classify data, then apply policies and controls. You can do this in two different ways: use an app connector, or use Conditional Access App Control.

### Phase 2: Classify sensitive information

In this phase, you'll do the following:

1. Decide what counts as sensitive in the context of your organization. Microsoft Defender for Cloud Apps includes more than 100 predefined sensitive information types, and default labels in Azure Information Protection. Sensitive information types and labels define how to handle, for example, passport numbers and national/regional identity numbers. You can also use default labels in Azure Information Protection. These labels will be used by Microsoft Defender for Cloud Apps when scanning, to classify information. The labels are:  
    - **Personal**: Data for personal, nonbusiness use only.  
    - **Public**: Data that can be shared for public consumption, such as marketing posters and blog posts.  
    - **General**: Data that can't be shared for public consumption, but can be shared with external partners. For example, project timelines and organizational charts.  
    - **Confidential**: Data that could damage the organization if it's shared with unauthorized people. For example, sales account data and forecasts.  
    - **Highly confidential**: Very sensitive data that will cause serious damage if shared with unauthorized people. For example, customer details, passwords and source code.  
2. Enable Azure Information Protection integration in Microsoft Defender for Cloud Apps by selecting **Automatically scan new files for Azure Information Protection classification labels** in the **Settings** pane:

![Screenshot showing how to configure Azure information protection.](https://learn.microsoft.com/en-us/training/m365/microsoft-cloud-app-security/media/phase-2-classify-sensitive-information.png)

### Phase 3: Protect data

There are different types of policies you can create to detect sensitive information and act accordingly. For example, you can create a **File policy** to scan the content of files in your apps in real time, and for data at rest. File policies let you apply governance actions. You can then automatically:

- Trigger alerts and email notifications.  
- Change sharing access for files.  
- Quarantine files.  
- Remove file or folder permissions.  
- Move files to a trash folder.

To create a file policy:

1. Open Microsoft Defender for Cloud Apps  
2. Select the **Control** pane  
3. Select **Policies > Create policy**  
4. Select **File policy**  
    - When the form that appears, you'll fill in the following fields:

| Field | Description |  
| --- | --- |  
| **Policy severity** | Defines how important the policy is and whether to trigger a notification. The severity of the policy can be customized to quickly identify the risk associated with a policy match. |  
| **Category** | This is an informative label that you assign to the policy to help locate it later. By default, for File policies is DLP. |  
| **Create a filter for the files this policy will act on** | It is used to decide which apps will trigger the policy. Ideally this should be defined to be as narrow as possible to avoid false positives. |  
| **Apply to (1st)** | Select which discovered apps will trigger the policy. There are two choices: · All files excluding selected folders: to apply the policy to all files. · Selected folders: to apply the policy to apps like Box, SharePoint, OneDrive, and Dropbox. |  
| **Apply to (2nd)** | Select which users and groups should be included in this policy. There are three options: · All file owners · File owners from selected user groups · All file owners excluding selected groups |  
| **Content inspection method** | Select how you want files to be inspected. There are two options: · Built-in DLP · Data Classification Services (DCS) Microsoft recommends DCS as this will allow you to use a unified labeling experience across Microsoft 365, Azure Information Protection, and Microsoft Defender for Cloud Apps. |  
| **Governance** | Select which governance actions you want Microsoft Defender for Cloud Apps to perform when a match is detected. |

5. When you're done, select **Create** to create your file policy.

### Phase 4: Monitor and report

Check your dashboard to monitor for alerts and the overall health of your environment. For example, to review file-related alerts, go to the **Alerts** pane, and select **DLP** in the **Category** field.

![Screenshot showing how to monitor for alerts.](https://learn.microsoft.com/en-us/training/m365/microsoft-cloud-app-security/media/phase-4-alerts.png)

You can investigate a file-related alert to better understand what caused it to be triggered. Or you can dismiss an alert that you determine could be ignored. You can also export your alerts to a CSV file for further analysis.  
--------------------------------------------------    
# Detect Threats

**Completed 100 XP**

- 21 minutes

When you understand how to protect data from accidental exposure, the next thing to consider, and one of the elements of the Defender for Cloud Apps framework, is protecting against cyberthreats and anomalies.

Microsoft Defender for Cloud Apps includes out-of-the-box anomaly detection policies that utilize user and entity behavioral analytics (UEBA) and machine learning to provide advanced threat detection across your cloud environment. It's important to note that anomaly detections are nondeterministic by nature. These detections only trigger when there's behavior that deviates from the norm.

Although anomaly detection policies are automatically enabled, Microsoft Defender for Cloud Apps spends the first seven days learning about your environment. It looks at the IP addresses, devices, and locations your users access, identifies which apps and services they use, and calculates the risk score of all of these activities. This process contributes to the baseline, against which your environment and any alerts are compared. The detection policies also use machine learning to profile your users. If Microsoft Defender for Cloud Apps recognizes your users and their normal sign-in patterns, it can help reduce false positive alerts.

Anomalies are detected by scanning user activity and evaluating it for risk. The risk is evaluated by looking at more than 30 different indicators, grouped into the following risk factors:

- Risky IP address  
- Login failures  
- Admin activity  
- Inactive accounts  
- Location  
- Impossible travel  
- Device and user agent  
- Activity rate

Microsoft Defender for Cloud Apps looks at every user session on your cloud and alerts you when something happens that's different from the baseline of your organization, or from the user's regular activity.

## Anomaly detection policy overview

The Microsoft Defender for Cloud Apps anomaly detection policies is configured to detect various security issues. The most popular are:

- **Impossible travel**. Activities from the same user in different locations within a period that's shorter than the expected travel time between the two locations.  
- **Activity from infrequent country**. Activity from a location that wasn't recently or never visited by the user, or by any user in the organization.  
- **Malware detection**. Scans files in your cloud apps and runs suspicious files through Microsoft's threat intelligence engine to determine whether they're associated with known malware.  
- **Ransomware activity**. File uploads to the cloud that might be infected with ransomware.  
- **Activity from suspicious IP addresses**. Activity from an IP address identified as risky by Microsoft Threat Intelligence.  
- **Suspicious inbox forwarding**. Detects suspicious inbox forwarding rules set on a user's inbox.  
- **Unusual multiple file download activities**. Detects multiple file download activities in a single session with respect to the baseline learned, which could indicate an attempted breach.  
- **Unusual administrative activities**. Detects multiple administrative activities in a single session with respect to the baseline learned, which could indicate an attempted breach.

## Configure an anomaly detection policy

Now that you learned about the anomaly detection policies, let's configure a discovery anomaly policy so you can see the steps to set it up and configure it for your environment. A discovery anomaly detection policy looks for unusual increases in cloud application usage. It looks at increases in downloaded data, uploaded data, transactions, and users for each cloud application. Then, each increase is compared to the baseline for the application. The most extreme increases trigger security alerts.

You can set filters to customize how you monitor application usage. Filters include an application filter, selected data views, and a selected start date. You can also set the sensitivity, which enables you to set how many alerts the policy should trigger.

### Fine-tune anomaly detection policies for suppression or surfacing alerts

Although anomaly detections only trigger when something happens outside the norm, they're still susceptible to false positives. Too many false positives can lead to alert fatigue, and you risk missing the important alerts in the noise. To help prevent alert noise, you can fine-tune the detection logic in each policy to include different levels of suppression to address scenarios that can trigger false positive, such as VPN activities.

When creating or editing an anomaly detection policy, you determine its sensitivity according to the type of coverage you need. A higher sensitivity uses stricter detection logic algorithms. This allows you to adapt your detection strategies for each policy.

Before you fine-tune your policies, it helps to understand the options for suppressing an alert. There are three types of suppression:

| Suppression type | Description |  
| --- | --- |  
| **System** | Built-in detections that are always suppressed. |  
| **Tenant** | Common activities based on previous activity in the tenant. For example, suppressing activities from an ISP previously alerted on in your organization. |  
| **User** | Common activities based on previous activity of the specific user. For example, suppressing activities from a location that is commonly used by the user. |

The sensitivity levels affect the suppression types differently:

| Sensitivity Level | Suppression types affected |  
| --- | --- |  
| Low | System, Tenant, and User |  
| Medium | System, and User |  
| High | System Only |

You can also configure whether alerts for activity from infrequent country/region, anonymous IP addresses, suspicious IP addresses, and impossible travel should analyze failed and successful logins, or successful logins.

### Adjust the anomaly detection scope policy to users and groups

Each anomaly detection policy can be independently scoped so that it applies only to the users and groups you want to include and exclude in the policy. For example, you can set the Activity from infrequent country/region detection to ignore a specific user who travels frequently.

To scope an anomaly detection policy:

1. Sign in to the Microsoft Defender Portal through your browser.  
2. In the navigation menu, expand the Cloud apps section, and select **Policies**.  
3. Select **Policy management**, and set the **Type** filter to **Anomaly detection policy**.  
4. Select the policy you want to scope.  
5. Under **Scope**, change the dropdown from the default setting of **All users and groups**, to **Specific users and groups**.  
6. Select **Include** to specify the users and groups for whom this policy applies. Any user or group not selected here won't be considered a threat or generate an alert.  
7. Select **Exclude** to specify users for whom this policy won't apply. Any user selected here won't be considered a threat or generate an alert, even if they're members of groups selected under **Include**.  
8. When you've completed the changes to the scope, select **Update** to commit the change.  
--------------------------------------------------    
# Module assessment

**Completed 200 XP**

- 5 minutes

## Check your knowledge

1. How can you get an at-a-glance overview of the kinds of apps are being used within your organization?  
    - Use Azure Information Protection  
    - Use Conditional Access  
    - Use the Cloud Discovery Dashboard

2. The Defender for Cloud Apps framework includes which of the following?  
    - Discover and control the use of Shadow IT  
    - Block external traffic  
    - Protect Active Directory

3. Which of these is a feature of Conditional Access App Control policies?  
    - Remote access  
    - Require multi-factor authentication  
    - Protect on download

4. How can you ensure that a file is sent into quarantine for review by an administrator?  
    - When creating a file policy, select Quarantine for admin  
    - When creating a file policy, select Put in admin quarantine  
    - When creating a file policy, select Put in review for admin

5. Which anomaly detection policy triggers an alert if the same user credentials originate from two geographically distant locations within a short time?  
    - Impossible travel  
    - Impossible distance  
    - Impossible twins  
--------------------------------------------------    
# Summary

Completed 100 XP

* 1 minute

In this module, you saw how Microsoft Defender for Cloud Apps brings visibility, data controls, and threat protection to your cloud apps. You reviewed the four elements in the Defender for Cloud Apps framework, and you saw how to use Cloud Discovery to find out which apps are being used in your organization. Finally, you looked at how to apply Conditional Access principles to your cloud apps and created an access policy that stops users from sharing sensitive information in Teams IMs.

Now that you have completed this module, you should be able to:

* Define the Defender for Cloud Apps Framework  
* Understand how Cloud Discovery gives you visibility into your organization  
* Explain how Conditional Access App Control policies can monitor and control access to applications  
* Understand how to classify and protect your information  
* Understand how to use anomaly detection policies to detect threats in your cloud environment  
-------------------------
