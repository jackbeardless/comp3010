# BOTSv3 Incident Analysis – COMP3010 Security Operations & Incident Management

**Student:** Jack Beard
**Module:** COMP3010 Security Operations & Incident Management
**Dataset:** Boss of the SOC v3 (BOTSv3)
**Tools:** Splunk Enterprise, Ubuntu Linux

---

## Introduction

A security operations centre (or SOC) is responsible for continuous monitoring, detection, analysis and response to security incidents across an IT infrastructure. Modern SOCS rely a lot on centralised log aggregation and analysis platforms such as Splunk, to provide visibility across network, endpoint, cloud and application environments.
This coursework is based on the BOTSv3 dataset which is a realistic simulatied security incident made by the Splunk team. BOTSv3 uses a fictional organisation called Frothly which is a brewing company operating a hybrid infrastructure that includes on premise systems , endpoints and cloud services using amazon AWS. The dataset contains a large volume of security relevant logs, including AWS cloudtrail events, s3 access logs, endpoint telemetry and host monitoring data.
The objective of my investigation is to assume the role of a SOC analyst and conduct and incident analysis using Splunks search processing language. The focus is on AWS related security events, with supporting analysis of endpoint data where relevant. By answering a set of Botsv3 questions, this report aims to demonstrate practical log analysis skills, an understanding of cloud security risks, and the ability to relate technical findings to SOC operations and incident handling methodologies. The scope of this investigations is limited to the data provided within the BOTSv3 set.

---

## SOC Roles & Incident Handling Reflection

SOCs typically operate using a tiered analyst model, with responsibilities distributed across Tier 1 (triage and monitoring), Tier 2 (investigation and correlation), and Tier 3 (advanced threat hunting and incident response). This investigations primarily focuses on Tier 2, meaning I will be analysing alerts, correlating events and determining the scope and impact of security incidents.
Throughout the investigation, findings are considered in the context of SOC workflows, including alert escalation, evidence preservation, and communication with stakeholders. EMphasis is placed on understanding not only what occured but also how a SOC would detect, respond to and prevent similar incidents.

---

## Installation & Data Preparation

### Environment Setup

The investigation environment is hosted on an Ubuntu Linux VM configured to run Splunk Enterprise. This setup reflects a common SOC deployment model where analysts interact with Splunk through a web interface while aanalysis and indexing are performed on a dedicated Linux server. Ubuntu was selected due to stability and compatability.
Splunk Enterprise is used as the primary SIEM platform for this investigation.

### BOTSv3 Dataset Ingestion

The BOTSv3 dataset is obtained from the official Splunk's github repository. The dataset consists of pre indexed logs covering multiple sourcetypes relevant to enterprise security monitoring. Ingestion is performed by following the vendor provided instructions to ensure correct index naming, sourcetype assignment and timestamp extraction.


### Data Validation

Once ingestion is completed, data validation is performed to confirm that logs have been indexed and that key sourcetypes are available for analysis. Validation includes verifying event vounts, confirming the presence of AWS and endpoint related sourcetypes and ensuring that time ranges align with the simulated incident period.
Sucessful validation is critical in a SOC context, as innacurate or incomplete log ingestion can lead to missed detections or delayed incident response. 

Following ingestion, data validation was performed to confirm that the BOTSv3 dataset was sucessfully indexed. An initial search confirmed 2.8Million indexed events. A breakdown of events by sourcetype further verified the presence of key AWS and endpoint sources, including AWS:cloudtrail, AWS:s3:accesslogs, winhostmon and hardware. This validation step is critical in a SOC environment, as incomplete or missing log sources can result in missed detections.
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
index=botsv3 sourcetype=AWS:cloudtrail earliest=0
| search NOT eventName=ConsoleLogin
| stats count by userIdentity.userName
| sort userIdentity.userName
```

**Evidence:**
![Screenshot](https://github.com/jackbeardless/comp3010/blob/main/screenshots/Question1proof.png)

**Answer: bstoll, btun, Splunk_access, web_admin**

**SOC Relevance:**
Identifying IAM users that access AWS services is a fundamental SOC monitoring activity. By analysing the AWS CloudTrail logs, SOC analysts gain visibility into who is interacting with cloud resources and how frequently. This information helps establish a baseline of normal user behaviour and supports the detection of any anomolies in the activity such as unexpected API usage, comprimised credentials or the abuse of privileged accounts.

In a real SOC environment, this analysis would typically be performed by a Tier 1 analyst as part of routine monitoring or alert triage. Any unknown or high risk IAM users identified would be escalated to Tier 2 for futher investigation, including reviewing access patterns, validating permissions, and determining whether access aligns with the users role. This process supports accountability, access crontrol enforcement, and early detection of cloud based threats.

---

### Question 2 – MFA-less AWS API Activity

**Objective:** Identify the field used to alert on AWS API activity without MFA.

**SPL Query:**

```spl
index=botsv3 sourcetype=AWS:cloudtrail earliest=0
| search NOT eventName=ConsoleLogin
| eval MFA_used=if(tostring(userIdentity.sessionContext.attributes.MFAAuthenticated)="true", 1, 0)
| where MFA_used=0
| stats count by userIdentity.userName, eventName
| sort userIdentity.userName
```

**Evidence:**
![Screenshot](https://github.com/jackbeardless/comp3010/blob/main/screenshots/question2proof.png)

**Answer: userIdenity.sessionContext.attributes.MFAAuthenticated**

**SOC Relevance:**
Monitoring AWS API activity where MFA is not used is a critical detective control in cloud security operations. MFA significantly reduces the risk of credential compromise, and API activity without MFA represents and elevated security risk, particularly for privileged IAM users.

In a SOC context, detection of API calls without MFA would typically trigger an automated alert. A Tier 2 analyst would investigate whether the activity was authorised, assess the sensitivity of the affected resources, and determine whether the credentials may have been compromised. If confirmed as risky or malicious, reponse actions could include rotating access keys, enforcing MFa policies, and auditing IAM perissions. This detection directly supports incident prevention, cloud security posture management and compliance with organisational security standards.

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
Maintaining accurate hardware and system invesntory is and important supporting function of a SOC, particularly for incident scoping and vulnerablitiy management. Indentifying processor information on web servers allows analysts to better understand the infrastructure they are protecting and to correlate incidents with specific assets.

In a real world SOC, this information would be used to assess exposure to hardware specific vulnerablities, support forensic investigations and prioritise patching or mitigation activities. Accurate asset visibility also enables faster incident response by allowing analysts to quickly identify affected systems and their critically within the environment.

---

### Question 4 – Public S3 Bucket Misconfiguration Event

**Objective:** Identify the event ID of the API call that enabled public S3 bucket access.

**SPL Query:**

```spl
index=botsv3 sourcetype=AWS:cloudtrail earliest=0
| search eventName=PutBucketAcl
| table _time, userIdentity.userName, userIdentity.arn, eventName, eventID, requestParameters
| sort _time

```

**Evidence:**
![Screenshot](https://github.com/jackbeardless/comp3010/blob/main/screenshots/q4-query.png)
![Screenshot](https://github.com/jackbeardless/comp3010/blob/main/screenshots/q4-publicproof.png)


**Answer: ab45689d-69cd-41e7-8705-5350402cf7ac**

**SOC Relevance:**
Publicly accessible S3 buckets are a common cause of cloud data exposure incidents. Monitoring for PutBucketAcl events allows SOC analysts to detect when access controls on S3 buckets are modified, potentially exposing sensitive data to the internet.
In a SOC environment, this type of event would usually trigger a high priority alert due to the risk of data leakage. A tier 2 analyst would investigate the context of the change, identify the user responsible, assess wether the change was intentional or accidental and determine the potential impact. Immediate remediation actions would include restricting bucket access, notifying cloud administrators and documenting the incident for audit and compliance purposes.

---

### Question 5 – User Responsible for S3 Misconfiguration

**Objective:** Identify the username responsible for making the S3 bucket publicly accessible.


**EXTRACTED DURING Q4 so no query for me to add**
**Answer: bstoll**

**Evidence:**
![Screenshot](https://github.com/jackbeardless/comp3010/blob/main/screenshots/q5-username.png)

**SOC Relevance:**
Attributing security relevant actions to specific users is a core requirement for SOC investigations. Identifying the user responsible for making an S3 bucket publicly accessible enables accountability and supports root cause analysis.
In a real SOC scenario, this information would be used to assess intent, such as whether the action resulted from human error, misconfiguration, or malicious activity. The SOC may escalate the incident to cloud security or management teams, revoke or adjust the users permissions and implement additional controls or training to prevent recurrence. User attribution is also essential for compliance reporting and post incident reviews.

---

### Question 6 – Public S3 Bucket Name

**Objective:** Identify the name of the S3 bucket that was made publicly accessible.

**Also extracted during q4 analysis so using the same Splunk query**

**Answer: frothlywebcode**

**Evidence**
![Screenshot](https://github.com/jackbeardless/comp3010/blob/main/screenshots/q6-bucketname.png)

**SOC Relevance**
Identifying the specific S3 bucket affected by a misconfiguration is critical for effective incident response. Knowing the bucket name allows SOC analysts to determing what data may have been exposed and to assess the sensitivity and business impact of the incident.
In practice, a SOC would use this information to coordinate remediation actions such as restricting access, reviewing historical access logs, and verifting whether any unauthorised downloads occured. This step is essential for incident containment, impact assessment and regulatory reporting, particularly if sensitive or customer data is involved.

---

### Question 7 – File Uploaded to Public S3 Bucket

**Objective:** Identify the text file uploaded while the S3 bucket was publicly accessible.

**SPL Query:**

```spl
index=botsv3 sourcetype="AWS:s3:accesslogs" "txt"
```

**Evidence:**
![Screenshot](https://github.com/jackbeardless/comp3010/blob/main/screenshots/q7-txt.png)

**Answer:OPEN_BUCKET_PLEASE_FIX.txt**

**SOC Relevance:**
Monitoring files uploaded to publicly accessible S3 buckets is an important paet of cloud threat detection and data protection. The presence of a ".TXT' file uploaded while the bucket was public may indicate unauthorised access, proof of concept exploitation or attempted data manipulation by an external party.
In a SOC environment, this finding would prompt further investigation to determine who uploaded the file, from which IP address and whether additional malicious activity occured. Analysts would also review access logs to identify potential data exfiltration and ensure that no sensitive files were exposed. This analysis supports both incdient adetection and post incident forensic investigation.

---

### Question 8 – Endpoint Operating System Anomaly

**Objective:** Identify the FQDN of the endpoint running a different Windows OS edition.

**SPL Query:**

```spl
index=botsv3 sourcetype="WinHostMon" Type="OperatingSystem" | stats count by OS, host
```

**Evidence:**
![Screenshot](https://github.com/jackbeardless/comp3010/blob/main/screenshots/q8-diffos.png)
![Screenshot](https://github.com/jackbeardless/comp3010/blob/main/screenshots/q8-queryandanswer.png)

**Answer:BSTOLL-L.froth.ly**

**SOC Relevance:**
Indentifying endpoints running a different operating system edition than the baseline is an important SOC function. In enterprise environments, SOC teams maintain expected configurations for endpoints top reduce attack surface and ensure consistent patching and security controls.

A host running an anomalous Windows edition may indicate:
A misconfigured or unmanaged endpoint
A legacy system lacking critical security patches
A potentially unauthorized or rogue device
Increased vulnerability exposure due to unsupported or weaker security features

By analysing endpoint telemetry using sources such as winhostmon, SOC analysts can quickly identify deviations from normal operating system baselines. These anomalies can then be escalated for futher investigation, asset validation, or remediation, reducing the risk of exploitation and improving overall endpoint security posture.
This approach aligns with real world SOC practices focused on continuous monitoring, baseline comparison and early detection of configureation drift.

---

## Conclusion & Lessons Learned

*(Summarise key findings, SOC lessons learned, and recommendations for improving detection and response.)*

---

## Video Presentation

*(Unlisted YouTube link to the recorded presentation will be embedded here.)*

---

## References

*(IEEE-style references to Splunk documentation, AWS documentation, and BOTSv3 resources.)*
