# CSE241 – Security of Information Systems  
## Assignment (01) – Answers  
**Spring 2026 | Dr. Islam Moursy**

---

## 1.1 [20 POINTS] – CIA Triad for a Student Information System (SIS)

A Student Information System (SIS) allows students to authenticate using a University Student Number (USN) and a card to access their academic records and account services.

### Confidentiality

**Definition (Lecture 2):** Preserving authorized restrictions on information access and disclosure, including protecting personal privacy and proprietary information.

| # | Example | Importance |
|---|---------|------------|
| 1 | A student's grades, GPA, and academic transcript must only be accessible to that student, their assigned academic advisor, and authorized registrar staff. Unauthorized exposure to other students, faculty, or external parties would violate personal privacy. | **High** – Grade data is sensitive personal information. Unauthorized disclosure could harm a student's reputation and violates applicable data protection requirements. |
| 2 | The USN–card combination (authentication credentials) must be kept confidential. If another party obtains a student's USN and clones or steals their card, they can impersonate the student and access all linked services (financial aid, enrollment records, etc.). | **High** – Credential disclosure undermines the entire authentication mechanism, potentially exposing all other protected data and enabling identity theft. |

---

### Integrity

**Definition (Lecture 2):** Guarding against improper information modification or destruction, including ensuring information nonrepudiation and authenticity.

| # | Example | Importance |
|---|---------|------------|
| 1 | Course registration records must accurately reflect only the courses a student actually enrolled in. An attacker who can modify enrollment data could add or drop courses on behalf of a student without their consent, affecting degree completion requirements or financial aid eligibility. | **High** – Falsified enrollment data directly impacts a student's academic standing, financial aid, and graduation. Even minor errors (e.g., a wrong section number) can have significant academic consequences. |
| 2 | Grades and examination scores stored in the SIS must not be alterable by students or unauthorized personnel. If a student could change their own grade (or if grades were corrupted by a technical fault), the academic record would be meaningless and the university's credibility would be compromised. | **High** – Academic grade integrity is fundamental to the value of the institution's degrees. Unauthorized modification constitutes fraud and can have legal consequences. |

---

### Availability

**Definition (Lecture 2):** Ensuring timely and reliable access to and use of information by authorized users.

| # | Example | Importance |
|---|---------|------------|
| 1 | The SIS must be accessible during critical periods such as course registration windows, exam result releases, and tuition payment deadlines. A Denial-of-Service (DoS) attack or system failure during registration could prevent students from enrolling in required courses, leading to delayed graduation or financial penalties. | **High** – Registration deadlines are time-sensitive and non-negotiable. Downtime during these windows has a direct, measurable impact on all students. |
| 2 | The card-based authentication infrastructure (card readers, authentication servers) must remain operational at all times. If the authentication system goes offline, students are entirely locked out of the SIS – they cannot view grades, submit requests, or access any account services. | **Moderate to High** – While brief outages are disruptive, extended outages (e.g., during end-of-semester periods) can be operationally critical. Redundancy mechanisms (clustering, failover) are warranted. |

---

## 1.2 [20 POINTS] – Security Flaw and Corrected Code

### (a) Security Flaw

The code applies the logic of **checking for failure** (checking if the return value equals `ERROR_ACCESS_DENIED`) and treating every *other* return value as a success. This is a violation of the **Fail-Safe Defaults** design principle (Lecture 2).

The flaw is:

- `IsAccessAllowed(...)` can return many values beyond just `ERROR_ACCESS_DENIED` and a success code. For example, it can return error codes such as `ERROR_INSUFFICIENT_BUFFER`, `ERROR_INVALID_PARAMETER`, `ERROR_NOT_ENOUGH_MEMORY`, or any other unexpected error.
- All those non-`ERROR_ACCESS_DENIED` return values fall into the `else` branch, which grants access.
- Therefore, **any unexpected error or system fault is silently interpreted as permission being granted**, which is the opposite of a secure default.

**In summary:** The code denies access only in one specific known failure case but **grants access by default** for all other outcomes, including unexpected errors. According to the Fail-Safe Defaults principle, access should be **denied by default** and only granted when explicitly confirmed.

---

### (b) Corrected Code

The fix is to check for the **explicit success condition** and deny access in all other cases (including unexpected errors). This ensures that a failed or ambiguous result never inadvertently grants access.

```c
DWORD dwRet = IsAccessAllowed(...);
if (dwRet == ERROR_SUCCESS) {
    // Security check explicitly passed.
    // Proceed with granting access.
} else {
    // Security check failed OR returned an unexpected error.
    // Default to denying access – fail-safe.
    // Inform user that access is denied.
}
```

**Why this is correct:** This implementation embodies the **Fail-Safe Defaults** principle: the default action is *denial*. Access is granted only when the function *explicitly* returns `ERROR_SUCCESS`. Any unexpected error, resource exhaustion, invalid parameter, or other non-success return value results in access being denied, preventing privilege escalation through error conditions.

---

## 1.3 [10 POINTS] – Attack Tree: Gaining Access to the Contents of a Physical Safe

```
Goal: Gain Access to Contents of Physical Safe [OR]
│
├── 1. Open the Safe Without the Combination/Key [OR]
│   ├── 1.1 Crack the Combination [OR]
│   │   ├── 1.1.1 Observe owner entering combination (shoulder surfing)
│   │   ├── 1.1.2 Obtain combination from written note (social engineering / theft)
│   │   └── 1.1.3 Try all combinations (brute-force attack)
│   ├── 1.2 Pick the Lock [OR]
│   │   ├── 1.2.1 Use lock-picking tools on mechanical lock
│   │   └── 1.2.2 Exploit worn or faulty lock mechanism
│   └── 1.3 Bypass the Electronic Lock [OR]
│       ├── 1.3.1 Replay recorded electronic signal
│       └── 1.3.2 Exploit software vulnerability in digital lock
│
├── 2. Obtain Legitimate Credentials [OR]
│   ├── 2.1 Steal the physical key or access card
│   ├── 2.2 Coerce the owner to open the safe (threat / extortion)
│   └── 2.3 Impersonate an authorized person to obtain credentials
│
├── 3. Physically Defeat the Safe [OR]
│   ├── 3.1 Cut or drill through the safe body
│   ├── 3.2 Apply thermite or torch to burn through
│   └── 3.3 Remove the entire safe and open it elsewhere [AND]
│       ├── 3.3.1 Safe is not bolted to floor/wall
│       └── 3.3.2 Attacker has transport capability
│
└── 4. Exploit the Environment [OR]
    ├── 4.1 Bribe or compromise an insider who knows the combination
    └── 4.2 Access safe during a period it is left open (e.g., after owner use)
```

---

## 1.4 [15 POINTS] – Attack Tree: Disclosure of Proprietary Secrets

The root node represents the ultimate adversarial goal. The tree models **physical, social engineering, and technical** attack vectors using both AND-nodes and OR-nodes. Leaf nodes (attack initiation points) are numbered and marked with **[LEAF]**.

```
ROOT: Disclose Proprietary Secrets [OR]
│
├── A. Physical Attacks [OR]
│   ├── A1. Breach Perimeter Fence [OR]
│   │   ├── [LEAF-1]  Cut or climb the perimeter fence at night
│   │   └── [LEAF-2]  Ram vehicle through perimeter gate
│   │
│   ├── A2. Bypass Front Gate [OR]
│   │   ├── [LEAF-3]  Tailgate (piggyback) an authorized employee
│   │   └── [LEAF-4]  Present forged visitor credentials to the gate guard
│   │
│   ├── A3. Break Into Headquarters Building [OR]
│   │   ├── [LEAF-5]  Pick or force lock on a building entrance
│   │   └── [LEAF-6]  Smash window to gain building access
│   │
│   └── A4. Steal Physical Storage Media [AND]
│       ├── [LEAF-7]  Gain access to an office or server room
│       └── [LEAF-8]  Remove unencrypted hard drives, USB sticks, or printed documents
│
├── B. Social Engineering Attacks [OR]
│   ├── B1. Phishing [OR]
│   │   ├── [LEAF-9]  Send targeted spear-phishing email to employee to harvest VPN credentials
│   │   └── [LEAF-10] Send phishing link that installs credential-stealing malware
│   │
│   ├── B2. Pretexting / Impersonation [OR]
│   │   ├── [LEAF-11] Pose as IT support to trick employee into revealing password
│   │   └── [LEAF-12] Impersonate a vendor/contractor to gain physical access to network services building
│   │
│   └── B3. Insider Threat [OR]
│       ├── [LEAF-13] Bribe or blackmail a trusted employee to exfiltrate documents
│       └── [LEAF-14] Recruit a disgruntled employee to leak data voluntarily
│
└── C. Technical Attacks [OR]
    ├── C1. Attack via Internet-Facing Web Server [OR]
    │   ├── [LEAF-15] Exploit web application vulnerability (SQL injection) to extract database records
    │   └── [LEAF-16] Upload a web shell via an unpatched file-upload vulnerability
    │
    ├── C2. Attack via Dial-Up Server [AND]
    │   ├── [LEAF-17] War-dial to discover the dial-up number
    │   └── [LEAF-18] Brute-force credentials on dial-up server to gain access to Network Services LAN
    │
    ├── C3. Intercept Network Traffic [AND]
    │   ├── [LEAF-19] Gain access to network segment (physical or remote)
    │   └── [LEAF-20] Perform packet sniffing / man-in-the-middle attack to capture unencrypted data
    │
    └── C4. Bypass Firewall [OR]
        ├── [LEAF-21] Exploit misconfigured firewall rule to reach internal LAN
        └── [LEAF-22] Use covert channel (e.g., DNS tunneling) to exfiltrate data through the firewall
```

**Tree Statistics:**
- Total leaf nodes: **22** (exceeds the required 15)
- Attack categories covered: Physical (leaves 1–8), Social Engineering (leaves 9–14), Technical (leaves 15–22)
- Node types used: OR-nodes (alternatives, attacker chooses one path) and AND-nodes (all sub-conditions required)

---

## 1.5 [15 POINTS] – E-Commerce Security Incident Analysis

**Scenario:** An attacker exploits a known software bug in a web server, gains access, and deletes all product databases.

---

### (a) Primary Asset(s) Involved

Using the terminology from Lecture 2 (A Model for Information Security – System Resources):

- **Data / Database:** The product database is the primary asset. It constitutes critical business data whose loss directly disrupts operations and revenue.
- **Software:** The web server software is a secondary asset; it is the vehicle through which the attack was carried out.

> *"Any system resource that users and owners wish to protect, including hardware, software, data, communication facilities and networks."* — Lecture 2

---

### (b) The Vulnerability

> **Definition (Lecture 2):** A weakness in an information system, system security procedures, internal controls, or implementation that could be exploited or triggered by a threat through an adversary.

**Identified Vulnerability:** A **known, unpatched software bug** in the web server software. The company failed to apply available security patches, leaving a documented weakness actively exploitable by any attacker who is aware of the bug.

---

### (c) The Threat

> **Definition (Lecture 2):** Any circumstance or event with the potential to adversely impact organizational operations, assets, individuals, or other organizations through an information system via unauthorized access, destruction, disclosure, modification of information, and/or denial of service.

**Identified Threat:** An **external malicious attacker** (adversary / threat agent) who is capable of exploiting web server vulnerabilities. The threat specifically manifests as the potential for *unauthorized access leading to data destruction*.

---

### (d) The Attack and Its Category

> **Definition (Lecture 2):** Any kind of malicious activity that attempts to collect, disrupt, deny, degrade, or destroy information system resources or the information itself.

**Identified Attack:** The attacker exploited the known bug to gain unauthorized access to the web server, then executed commands to **delete all product databases**.

**Attack Category (Lecture 2 classification):**

| Dimension | Classification | Justification |
|-----------|---------------|---------------|
| Passive vs. Active | **Active Attack** | The attacker altered system resources (deleted the database) and affected system operation — not merely observing. |
| Insider vs. Outsider | **Outsider Attack** | The attacker initiated the attack from outside the organization's security perimeter. |
| Threat Consequence | **Disruption** (Availability) + **Destruction** (Integrity) | The deletion caused loss of availability (data inaccessible) and loss of integrity (data destroyed). The specific attack actions are **Incapacitation** (disabling the database) and **Corruption** (adversely modifying/destroying data). |

---

### (e) A Countermeasure That Could Have Helped and Its Category

> **Definition (Lecture 2):** A device or technique that has as its objective the impairment of the operational effectiveness of undesirable or adversarial activity, or the prevention of espionage, sabotage, theft, or unauthorized access.

**Recommended Countermeasure:** **Timely patch management and vulnerability remediation** — The company should have applied the available patch for the known web server vulnerability before it was exploited.

**Countermeasure Categories (Lecture 2):**

| Dimension | Category | Justification |
|-----------|----------|---------------|
| Function | **Technical Control** | Patch management involves deploying software updates — a technical/logical mechanism. |
| Type | **Preventive Control** | Applying the patch would have *prevented* the attack from occurring in the first place by eliminating the vulnerability. |

**Additional Countermeasure:** Regular **data backups** stored securely off-site would constitute a **Technical, Recovery Control** — while it would not prevent the attack, it would allow the organization to restore the deleted product database and resume operations, minimizing the impact of the incident.

---

*End of Assignment (01) Answers*
