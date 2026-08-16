# PowerShell STIG Remediations — Microsoft Windows 11

Automated remediation of DISA STIG controls on Windows 11 using PowerShell,
verified through SCAP Compliance Checker re-scan.

Each script remediates a single STIG rule, is idempotent, and is paired with a
before-and-after scan to confirm the control actually took effect rather than
assuming the registry write succeeded.

---

## Results

| | |
|---|---|
| **Benchmark** | Microsoft Windows 11 STIG, `<VxRx>` |
| **Scan tool** | SCAP Compliance Checker `<version>` |
| **Target** | Windows 11 `<edition/build>`, `<domain-joined or standalone>` |
| **Controls remediated** | 10 |
| **Compliance before** | `<XX>%` |
| **Compliance after** | `<XX>%` |
| **Open findings closed** | `<XX>` |

---

## Method

1. **Baseline.** Run a SCAP Compliance Checker scan against the Windows 11 STIG
   benchmark to establish the starting compliance percentage and enumerate open
   findings.
2. **Triage.** Review open findings in DISA STIG Viewer. Read each rule's Check
   Text and Fix Text, and record the STIG ID, Vulnerability ID, severity (CAT
   level), and associated CCI.
3. **Author.** Write a PowerShell script implementing the Fix Text. Scripts set
   the underlying registry value or local policy directly so they are
   repeatable and can run unattended.
4. **Apply.** Execute the script in an elevated session against the target
   system.
5. **Verify.** Re-run the SCAP scan and confirm the finding moves from Open to
   Not a Finding. A rule is only considered remediated after the re-scan
   confirms it.
6. **Document.** Record the before-and-after result and note any control that
   required manual intervention or could not be automated.

This is the same detect, assess, remediate, re-validate loop used for
continuous monitoring under RMF. Scan results feed control status; anything
that cannot be remediated becomes a documented risk decision rather than a
silent gap.

---

## Scripts

| Script | STIG ID | Vuln ID | CAT | Control enforced |
|---|---|---|---|---|
| `WN11-AC-000005.ps1` | WN11-AC-000005 | V-253297 | II | Account lockout duration set to 15 minutes or greater |
| `WN11-AC-000010.ps1` | WN11-AC-000010 | V-253298 | II | Account lockout threshold set to three or fewer invalid logon attempts |
| `WN11-AU-000083.ps1` | WN11-AU-000083 | `<verify>` | II | Object Access auditing enabled (advanced audit policy subcategory) |
| `WN11-AU-000500.ps1` | WN11-AU-000500 | V-253337 | II | Application event log size set to 32768 KB or greater |
| `WN11-CC-000038.ps1` | WN11-CC-000038 | V-253358 | II | WDigest Authentication disabled to prevent plaintext credential storage in memory |
| `WN11-CC-000066.ps1` | WN11-CC-000066 | V-253367 | II | Command line data included in process creation events |
| `WN11-CC-000315.ps1` | WN11-CC-000315 | V-253411 | I | Windows Installer "Always install with elevated privileges" disabled |
| `WN11-SO-000030.ps1` | WN11-SO-000030 | V-253437 | II | Audit policy using subcategories enabled |
| `WN11-SO-000070.ps1` | WN11-SO-000070 | V-253444 | II | Machine inactivity limit set to 15 minutes, locking the session |
| `WN11-UR-000010.ps1` | WN11-UR-000010 | V-253479 | II | "Access Credential Manager as a trusted caller" user right assigned to no groups or accounts |

Vulnerability IDs and severities are tied to a specific STIG release. Confirm
against the benchmark version listed above before citing them.

---

## Why these controls

The set covers four distinct control families rather than ten variations on one
theme:

- **Account policy** (AC-000005, AC-000010) — brute-force resistance. Maps to
  NIST SP 800-53 AC-7, Unsuccessful Logon Attempts.
- **Audit configuration** (AU-000083, AU-000500, CC-000066, SO-000030) — ensures
  the events a SIEM depends on are actually generated and retained. Without
  subcategory auditing enabled and adequate log sizing, detection content has
  nothing to query. Maps to the AU family.
- **Credential and privilege protection** (CC-000038, CC-000315, UR-000010) —
  removes plaintext credential exposure, blocks a well-known privilege
  escalation path, and restricts a sensitive user right.
- **Session protection** (SO-000070) — enforces workstation lock on inactivity.

---

## Usage

Run in an elevated PowerShell session on the target system.

```powershell
# Single control
.\WN11-CC-000038.ps1

# All controls in this repo
Get-ChildItem -Filter 'WN11-*.ps1' | ForEach-Object { & $_.FullName }
```

Test in a lab before applying to any production or accredited system. Several
of these controls change authentication and audit behavior and should go
through normal configuration management and change control first.

---

## Environment

- Windows 11 virtual machine, VMware Workstation
- DISA STIG Viewer
- SCAP Compliance Checker
- PowerShell 5.1

---

## Related

- [Vulnerability Management Program Implementation](https://github.com/malcolmtyronebell/Vulnerability-Management-Program-Implementation)
  — credentialed Tenable/Nessus scanning, risk-based prioritization, remediation
  coordination, and closure validation.
