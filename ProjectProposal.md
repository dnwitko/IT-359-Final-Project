# Project Proposal

## Overview 
**Project name:** EscapeContainer  
**Description:** A script that automatically fingerprints a Docker container for common escape vectors and reports exactly which vector would successfully allow a breakout.

**Objectives:**
- Develop a relatively small executable file/script/binary
- Accurately fingerprint common escape vectors
- Generate a comprehensive report based on which specific vectors would allow a breakout

**Success criteria:**  
Running the script will automatically and accurately generate a breakout vulnerability report without unintended consequences.

**Start Date:** August 27th, 2026  
**End Date:** December 5th, 2026  
  
## Stakeholders 
**Sponsor designation:** An confidential bank will commission Rapid7 for an internal infrastructure audit, who will use our tool [2].

### **Stakeholder list:**  

**Bank**
- **CISO (Chief Info Security Officer):** Allocates funding and oversees the project.
- **DevSecOps Lead:** Coordinates the infrastructure teams and provides subject matter expertise.
- **Internal System Administrator(s):** Provides isolated test environments and baseline containers.

**Rapid7**
- **Penetration Testing Lead:** Oversees project delivery, scope adherence, and final presentation of the vulnerabilities.
- **Security Consultant/Pentester:** Deploys our fingerprinting tool. Essentially the main user of the product.

**Development Team:**
- **Developers:** Ensures the tool works correctly and acts as a point of contact for Rapid7. Maintains transparency with other stakeholders.

## Scope Management 
**In-scope items:**  
- Automatic fingerprinting of common Docker misconfigurations and vulnerabilities
- Generating a final text (.txt) breakout report

**Out-of-scope items:** 
- Active exploitation of the host system running the container
- Testing on production environments
- Automatic remediation of vulnerabilities

### **Project assumptions and constraints:**  
**Assumptions:**  
- Access to an isolated Docker container
- Docker configurations are fairly standard
- Vulnerable sample containers work as intended

**Constraints:**  
- Time constraints
- Unknown breakout techniques/vulnerabilities

## Timeline 
1. **Project Proposal/Plan** - Submitted by August 27, 2026
2. **Research and Attack Vector Discovery** - Completed by middle of September.
3. **Core Fingerprinting Script** - Functional by middle of October.
4. **Reporting Engine** - Functional by first week of November.
5. **Testing** - Fully completed by last week of November.
6. **Submit Project** - Submitted during first week of December.

 ## Risk Management 
- Scope Creep (Checking too many attack vectors)
  - Impact: High
  - Probability: Medium
  - Remediation: Limiting the scope to a list of top 3-5 most common misconfigurations.
- False Positives/Negatives in Report
  - Impact: High
  - Probability: Medium
  - Remediation: Troubleshooting report engine using known secure and insecure containers to identify bugs.

 ## Resources 
**Budget Allocation:**  
We will need a $0.00 budget to complete this project, since we are using open-source software. 

**Required Tools and Technology:**  
- Docker Desktop
- Python 3.0 / Bash
- Virtualization Software (VirtualBox, VMware, etc.)
- Sample Docker containers for testing [1]

**Project Dependencies:**
- **docker (version 7.1.0):** Python library for the Docker Engine API to interface with containers.
- **colorama (version 0.4.6, optional):** Makes terminal output prettier for the final report.

## Communication  
**Meeting Cadence and Reporting Frequency:**  
We will plan to meet and report progress at least once per week with each other.  

**Communication Channels:**  
Discord, Microsoft Teams, Microsoft Outlook

## Action Items  
- Meeting with Stakeholders regularly to hear their comments on requirements.
- Provision a Linux VM for safe Docker testing.
- Compile a list of the specific Docker escape vectors the tool will check for.

## References  
[1] - Google Gemini  
[2] - Rapid7: https://www.rapid7.com/services/penetration-testing/
