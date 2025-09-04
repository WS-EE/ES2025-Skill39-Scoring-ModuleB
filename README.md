# Marking Script for EuroSkills 2025 – Skill39 (Module B)

## Prerequisites

- Target machines have **OpenSSH** server enabled and the **admin public key** installed.
- Default SSH key at `C:\Marking\ModuleB`  
  _(You can override per aspect via `DefaultSshKey`, or per step via `SshKey`.)_

## Run
AD users import checks
```powershell
PS > .\ADUserChecker.ps1
```

AD users import checks example output
```powershell
Mismatched UPN for antonio.hall. Actual: antonio.hallsd@skillsnet.dk, Expected: antonio.hall@skillsnet.dk
Mismatched last name for andrew.clements. Actual: Clementssd, Expected: Clements
Mismatched first name for alexander.valencia. Actual: Alexanderas, Expected: Alexander
User with SAMAccountName annette.morris not found in AD.
Mismatched job title for chelsea.raymond. Actual: 23, Expected: Rural practice surveyor
Mismatched department for chelsea.raymond. Actual: Finance232323, Expected: Finance
Mismatched job title for charles.ibarra. Actual: Chartered public finance accountantsdsd, Expected: Chartered public finance accountant
Users are located in these OUs:
OU=Development,OU=Users,OU=Skills,DC=skillsnet,DC=dk: 305
OU=Tech,OU=Users,OU=Skills,DC=skillsnet,DC=dk: 357
OU=Contractors,OU=Users,OU=Skills,DC=skillsnet,DC=dk: 343
OU=Finance,OU=Users,OU=Skills,DC=skillsnet,DC=dk: 339
OU=Employees,OU=Users,OU=Skills,DC=skillsnet,DC=dk: 319
OU=Sales,OU=Users,OU=Skills,DC=skillsnet,DC=dk: 336
```

All tests
```powershell
PS > .\ModuleB.ps1
```

`Aspect` accepts `B2`, `B2.M4`, or `B2M4`.
No `-Aspect` = run everything.

All aspects within a sub-criterion
```powershell
PS> .\ModuleB.ps1 -Aspect B2
PS> .\ModuleB.ps1 -Aspect B4
```

A single aspect
```powershell
PS> .\ModuleB.ps1 -Aspect B3.M1
PS> .\ModuleB.ps1 -Aspect B5.J1
```

What you will see for each step:
```powershell
----------------------------------------------------------
Testing aspect B1.M3
RAS: Firewall is configured to block TCP/8080 + WinRM

[1/2] RTR-CPH: TCP/8080 is blocked
Expected: TCP/8080 is listed
Actual  :
----- OUTPUT START -----
Filter Information for Interface INET
------------------------------------------------------------------

Fragment checking is Disabled.
No input filters configured.

Filter Type           : OUTPUT
Default Action        : FORWARD

    Src Addr       Src Mask         Dst Addr       Dst Mask      Proto  Src Port  Dst Port
------------------------------------------------------------------------------------------
        0.0.0.0         0.0.0.0         0.0.0.0         0.0.0.0    TCP       0    8080
        0.0.0.0         0.0.0.0         0.0.0.0         0.0.0.0    TCP       0    5986
        0.0.0.0         0.0.0.0         0.0.0.0         0.0.0.0    TCP       0    5987
No demand-dial filters configured.
-----  OUTPUT END  -----
Result: PASS

[2/2] RTR-CPH: WINRM is blocked
Expected: TCP/5985 is listed
Actual  :
----- OUTPUT START -----
Filter Information for Interface INET
------------------------------------------------------------------

Fragment checking is Disabled.
No input filters configured.

Filter Type           : OUTPUT
Default Action        : FORWARD

    Src Addr       Src Mask         Dst Addr       Dst Mask      Proto  Src Port  Dst Port
------------------------------------------------------------------------------------------
        0.0.0.0         0.0.0.0         0.0.0.0         0.0.0.0    TCP       0    8080
        0.0.0.0         0.0.0.0         0.0.0.0         0.0.0.0    TCP       0    5986
        0.0.0.0         0.0.0.0         0.0.0.0         0.0.0.0    TCP       0    5987
No demand-dial filters configured.
-----  OUTPUT END  -----
Result: FAIL
```

At the end of the aspect
```powershell
Score: 1/2 (automated steps only)
Please mark now aspect B1.M3
Move to the next aspect? [y/n]:
```

* Automated steps: executed over SSH (or locally), compared to `Expected`, scored. Assessment can be done alternatively with regex using `PassIf`.
* Manual steps: show banner + `Expected` (and optional `Instructions`), not executed, not scored.

---

## Core Function: `Test-AspectSteps`
Runs one aspect consisting of one or more steps.

**Parameters**
- `Aspect` – Aspect ID, e.g. `B3.M1`.
- `Description` – Human-readable aspect description.
- `Steps` – Array of step dictionaries (see below).
- `Defaults` (can be overridden per step):
  - `DefaultUser` – SSH username (default: `Administrator`)
  - `DefaultSshKey` – SSH private key path (default: `C:\Marking\ModuleB`)
  - `DefaultJumpUser` – SSH proxy username (default: `Administrator`)
  - `DefaultIp` – Default target host for all steps in this aspect
  - `DefaultManual` – If set, all steps default to manual (can override per step)
  - `DefaultLocal` – If set, all steps run on the local machine (can override per step)

**Step Dictionary**

| Key            | Type        | Meaning                                                                             |
| -------------- | ----------- | ----------------------------------------------------------------------------------- |
| `Name`         | string      | Step name shown in console                                                          |
| `Cmd`          | string      | Command to execute                                                |
| `Expected`     | string      | Expected value/regex                               |
| `PassIf`       | scriptblock | Custom predicate. Receives actual output as `param($o)` and returns `$true/$false`. |
| `Ip`           | string      | Override host for this step                                                         |
| `User`         | string      | Override SSH user for this step                                                     |
| `SshKey`       | string      | Override SSH key path for this step                                                 |
| `JumpIp`       | string      | SSH jump/proxy host (optional)                                                      |
| `JumpUser`     | string      | Override jump user                                                                  |
| `Local`        | bool        | Force local execution for this step                                                 |
| `Manual`       | bool        | Mark this step as manual (not executed, not scored)                                 |
| `Instructions` | string      | Shown for manual steps to guide the expert                                          |


## Protection

Encrypt and Decrypt files:
```
# Encrypt
PS > EncryptDecryptFile.ps1 -FilePath .\ModuleB.ps1 -Password "EuroSkills2025" -Action encrypt

# Decrypt
PS > EncryptDecryptFile.ps1 -FilePath .\ModuleB.ps1.encrypted -Password "EuroSkills2025" -Action decrypt

```