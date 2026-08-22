pattern_id: AP-EXEC-001
tactic: Execution
technique_id: T1059.009
technique: Command and Scripting Interpreter: Cloud API

precondition:
  - Attacker possesses credentials or other authentication material
    with sufficient permissions to invoke the required cloud APIs

action:
  - Attacker uses cloud APIs through CLI, Cloud Shell,
    PowerShell modules, SDKs, or similar interfaces

postcondition:
  - Attacker performs unauthorized actions against cloud resources

evidence:
  - APT29
  - Pacu
  - ShinyHunters
  - TeamTNT

source:
  type: MITRE ATT&CK
  technique: T1059.009