# Marking Script for EuroSkills 2025 – Skill39 (Module B)

## Prerequisites

- Target machines have **OpenSSH** server enabled and the **admin public key** installed.
- Default SSH key at `C:\Marking\ModuleB`  
  _(You can override per aspect via `DefaultSshKey`, or per step via `SshKey`.)_

## Run
`Aspect` accepts `B2`, `B2.M4`, or `B2M4`.
No `-Aspect` = run everything.

All tests
```powershell
PS > .\ModuleB.ps1
```

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
[1/2] IPv4 ping
Expected: True
Actual  : True
Result  : PASS
```

At the end of the aspect
```powershell
Score   : 1/2 (automated steps only)
Please mark now aspect B1.M1
Move to the next aspect? [y/n]
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
