# BOTSv3 Incident Analysis – COMP3010 Security Operations & Incident Management

**Student:** Jack Beard
**Module:** COMP3010 Security Operations & Incident Management
**Dataset:** Boss of the SOC v3 (BOTSv3)
**Tools:** Splunk Enterprise, Ubuntu Linux

---

## Introduction

*(This section will introduce the Security Operations Centre (SOC) context, the BOTSv3 dataset, and the objectives and scope of the investigation.)*

---

## SOC Roles & Incident Handling Reflection

*(This section will reflect on SOC tiered roles (Tier 1–3), incident handling methodologies, and how detection, response, containment, and recovery phases relate to the BOTSv3 investigation.)*

---

## Installation & Data Preparation

### Environment Setup

*(Describe Ubuntu VM setup and Splunk installation.)*

### BOTSv3 Dataset Ingestion

*(Describe ingestion steps followed from the official BOTSv3 repository.)*

### Data Validation

*(Include evidence confirming successful ingestion, such as sourcetype counts.)*

---

## Guided Investigation – AWS & Endpoint Analysis

This section answers the selected BOTSv3 200-level guided questions, focusing on AWS-related events with supporting endpoint analysis.

---

### Question 1 – IAM Users Accessing AWS Services

**Objective:** Identify IAM users that accessed AWS services in Frothly’s AWS environment.

**SPL Query:**

```spl
```

**Evidence:**
*(Screenshot placeholder)*

**Answer:**

**SOC Relevance:**

---

### Question 2 – MFA-less AWS API Activity

**Objective:** Identify the field used to alert on AWS API activity without MFA.

**SPL Query:**

```spl
```

**Evidence:**
*(Screenshot placeholder)*

**Answer:**

**SOC Relevance:**

---

### Question 3 – Web Server Processor Information

**Objective:** Identify the processor number used on Frothly web servers.

**SPL Query:**

```spl
```

**Evidence:**
*(Screenshot placeholder)*

**Answer:**

**SOC Relevance:**

---

### Question 4 – Public S3 Bucket Misconfiguration Event

**Objective:** Identify the event ID of the API call that enabled public S3 bucket access.

**SPL Query:**

```spl
```

**Evidence:**
*(Screenshot placeholder)*

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
