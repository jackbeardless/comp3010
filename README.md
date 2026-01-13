# BOTSv3 Incident Analysis – COMP3010 Security Operations & Incident Management

**Student:** Jack Beard
**Module:** COMP3010 Security Operations & Incident Management
**Dataset:** Boss of the SOC v3 (BOTSv3)
**Tools:** Splunk Enterprise, Ubuntu Linux

---

## Introduction

A security operations centre (or SOC) is responsible for continuous monitoring, detection, analysis and response to security incidents across an IT infrastructure. Modern SOCS rely a lot on centralised log aggregation and analysis platforms such as splunk, to provide visibility across network, endpoint, cloud and application environments.
This coursework is based on the BOTSv3 dataset which is a realistic simulatied security incident made by the splunk team. BOTSv3 uses a fictional organisation called Frothly which is a brewing comnpany operating a hybrid infrastructure that includes on premise systems , endpoints and cloud services using amazon AWS. The dataset contains a large volume of security relevant logs, including AWS cloudtrail events, s3 access logs, endpoint telemetry and host monitoring data.
The objective of my investigation is to assume the role of a SOC analyst and conduct and incident analysis using Splunks search processing language. The focys is on AWS related security events, with supporting analysis of endpoint data where relevant. By answering a set of Botsv3 questions, this report aims to demonstrate practical log analysis skills, an understanding of cloud security risks, and the ability to relate technical findings to SOC operations and incident handling methodologies. The scope of this investigations is limited to the data provided within the BOTSv3 set.

---

## SOC Roles & Incident Handling Reflection

SOCs typically operate using a tiered analyst model, with responsibilities distributed across Tier 1 (triage and monitoring), Tier 2 (investigation and correlation), and Tier 3 (advanced threat hunting and incident response). This investigations primarily focuses on Tier 2, meaning I will be analysing alerts, correlating events and determining the scope and impact of security incidents.
Throughout the investigation, findings are considered in the context of SOC workflows, including alert escalation, evidence preservation, and communication with stakeholders. EMphasis is placed on understanding not only what occured but also how a SOC would detect, respond to and prevent similar incidents.

---

## Installation & Data Preparation

### Environment Setup

The investigation environment is hosted on an Ubuntu Linux VM configured to run Splunk Enterprise. This setup reflects a common SOC deployment model where analysts interact with splunk through a web interface while aanalysis and indexing are performed on a dedicated Linux server. Ubuntu was selected due to stability and compatability.
Splunk Enterprise is used as the primary SIEM platform for this investigation.

### BOTSv3 Dataset Ingestion

The BOTSv3 dataset is obtained from the official splunk's github repository. The dataset consists of pre indexed logs covering multiple sourcetypes relevant to enterprise security monitoring. Ingestion is performed by following the vendor provided instructions to ensure correct index naming, sourcetype assignment and timestamp extraction.


### Data Validation

Once ingestion is completed, data validation is performed to confirm that logs have been indexed and that key sourcetypes are available for analysis. Validation includes verifying event vounts, confirming the presence of AWS and enpoint related sourcetypes and ensuring that time ranges align with the simulated incident period.
Sucessful validation is critical in a SOC context, as innacurate or incomplete log ingestion can lead to missed detections or delayed incident response. 

Following ingestion, data validation was performed to confirm that the BOTSv3 dataset was sucessfully indexed. An initial search confirmed 2.8Million indexed events. A breakdown of events by sourcetype further verified the presence of key AWS and endpoint sources, including aws:cloudtrail, aws:s3:accesslogs, winhostmon and hardware. This validation step is critical in a SOC environment, as incomplete or missing log sources can result in missed detections.
![Screenshot](https://github.com/jackbeardless/comp3010/blob/main/screenshots/ingestion1.png)
![Screenshot](https://github.com/jackbeardless/comp3010/blob/main/screenshots/ingestion2.png)

---

## Guided Investigation – AWS & Endpoint Analysis

This section answers the selected BOTSv3 200-level guided questions, focusing on AWS-related events with supporting endpoint analysis.

---

### Question 1 – IAM Users Accessing AWS Services

**Objective:** Identify IAM users that accessed AWS services in Frothly’s AWS environment.

**SPL Query:**

```spl
index=botsv3 sourcetype=aws:cloudtrail earliest=0
| search NOT eventName=ConsoleLogin
| stats count by userIdentity.userName
| sort userIdentity.userName
```

**Evidence:**
![Screenshot](https://github.com/jackbeardless/comp3010/blob/main/screenshots/Question1proof.png)

**Answer: bstoll, btun, splunk_access, web_admin**

**SOC Relevance:**
Identifying IAM users that have accessed AWS services is a critical step in SOC monitoring and incidente response. By querying cloudtrail logs for API activity, analysts can detect unusual or unauthorized usuage, such as supicious automation scripts, cromprimised credentials or privilege escalation attempt.

---

### Question 2 – MFA-less AWS API Activity

**Objective:** Identify the field used to alert on AWS API activity without MFA.

**SPL Query:**

```spl
index=botsv3 sourcetype=aws:cloudtrail earliest=0
| search NOT eventName=ConsoleLogin
| eval mfa_used=if(tostring(userIdentity.sessionContext.attributes.mfaAuthenticated)="true", 1, 0)
| where mfa_used=0
| stats count by userIdentity.userName, eventName
| sort userIdentity.userName
```

**Evidence:**
![Screenshot](https://github.com/jackbeardless/comp3010/blob/main/screenshots/question2proof.png)

**Answer: userIdenity.sessionContext.attributes.mfaAuthenticated**

**SOC Relevance:**
Monitoring AWS API activity without MFA is a critical SOC control. MFa provides an additional layer of security beyond passwords or keys, detecting API calls without MFA allows analysts to:
Identify potentially compromised credentials
Trigger immediate alerts for risky access
Ensure compliance with orginizational security policies.

This detection falls within preventive and detective SOC controls, helping analysts reduce the risk of unauthorized access to sensitive cloud resources.

---

### Question 3 – Web Server Processor Information

**Objective:** Identify the processor number used on Frothly web servers.

**SPL Query:**

```spl
index=botsv3 sourcetype=hardware earliest=0
| table host, cpu
| sort host

```

**Evidence:**
![Screenshot](https://github.com/jackbeardless/comp3010/blob/main/screenshots/q3-1.png)
![Screenshot](https://github.com/jackbeardless/comp3010/blob/main/screenshots/q3-2.png)


**Answer:E5-2676**

**SOC Relevance:**
Identifying processor types on servers is critical for SOC operations as part of asset inventory and vulnerability management. Hardware information helps analysts understand the environment, assess potential vulnerabilities, and correlate incidents to affected hardware. Maintaining up to date hardware details is a preventative control that supports incident investigation.

---

### Question 4 – Public S3 Bucket Misconfiguration Event

**Objective:** Identify the event ID of the API call that enabled public S3 bucket access.

**SPL Query:**

```spl
```

**Evidence:**
![Screenshot](https://github.com/jackbeardless/comp3010/blob/main/screenshots/q4-query.png)
![Screenshot](https://github.com/jackbeardless/comp3010/blob/main/screenshots/q4-publicproof.png)


**Answer:**

**SOC Relevance:**

---

### Question 5 – User Responsible for S3 Misconfiguration

**Objective:** Identify the username responsible for making the S3 bucket publicly accessible.

**Answer:**

---

### Question 6 – Public S3 Bucket Name

**Objective:** Identify the name of the S3 bucket that was made publicly accessible.

**Answer:**

---

### Question 7 – File Uploaded to Public S3 Bucket

**Objective:** Identify the text file uploaded while the S3 bucket was publicly accessible.

**SPL Query:**

```spl
```

**Evidence:**
*(Screenshot placeholder)*

**Answer:**

**SOC Relevance:**

---

### Question 8 – Endpoint Operating System Anomaly

**Objective:** Identify the FQDN of the endpoint running a different Windows OS edition.

**SPL Query:**

```spl
```

**Evidence:**
*(Screenshot placeholder)*

**Answer:**

**SOC Relevance:**

---

## Conclusion & Lessons Learned

*(Summarise key findings, SOC lessons learned, and recommendations for improving detection and response.)*

---

## Video Presentation

*(Unlisted YouTube link to the recorded presentation will be embedded here.)*

---

## References

*(IEEE-style references to Splunk documentation, AWS documentation, and BOTSv3 resources.)*
