import os
from openai import OpenAI
import base64
from google import genai
from openai import types
import json
import textwrap
from typing import Any, Dict

SYSTEM_PROMPT = """
Role:
You are a malware-intent auditor for software update code snippets.

Global Rules:
1) Judge by visible behavior, not names/comments.
2) If critical behavior is missing from snippet, do not assume it exists.
3) Distinguish malicious logic from dual-use/admin utility context.
4) Prefer conservative labeling when evidence is incomplete.
5) Output JSON only.
6) Do not infer unseen project context; judge only from code visible in the snippet.
"""

STEP1_PROMPT = """
Task:
Given the code snippet, detect primary intent category.

Code:
{code_snippet}

Decision Flow:
1) Benign Filter:
- If behavior matches normal utility/installer/updater/admin function with no malicious indicators -> Benign.

2) Ambiguity Filter:
- Dangerous APIs/tools alone (e.g., subprocess, cryptography, base64, keyboard hooks) without harmful workflow -> Undetermined.
- Bare connectivity alone is ambiguous -> Undetermined.

3) Malicious Intent Match (pick one primary type):
- Type A InfoStealer: collects sensitive data (credentials/tokens/keys/cookies/etc).
- Type B Backdoor/RAT: remote control channel + command/session handling.
- Type C Ransomware: encryption used to deny access (not just normal crypto helper).
- Type D Wiper: destructive deletion/overwrite at harmful scope.
- Type E Clipper: clipboard wallet replacement.
- Type F File Infector: injects/patches other files.
- Type G Logic Bomb: trigger condition tied to malicious payload.
- Type H Keylogger: active key capture with stealth/collection intent.
- Type I Builder: generates malware artifacts.
- Type J Dropper/Downloader: payload delivery chain intent.
- Type K System Interference: disrupts normal system usability.
- Type L Worm:
  - L-File/Device Worm: self-replication/infection across files, removable media, archives, or shared folders/devices.
  - L-Network Worm: self-propagation across network hosts.
- Type M High-Impact: clearly harmful logic not covered above.

Type D vs Type K Disambiguation (MANDATORY):
- Type D (Wiper) requires explicit destructive intent against existing meaningful targets (e.g., user/system files, disks, partitions, backups, DB/data stores), with irreversible damage actions such as delete/overwrite/corrupt/format.
- Type K (System Interference) covers disruption/resource-abuse behavior that degrades usability without clear targeted irreversible wiping semantics (e.g., infinite file spam, process kill loops, startup abuse, CPU/disk exhaustion, lock-screen nuisance).
- If code mainly creates junk files or repeatedly overwrites newly-created/random files, classify as Type K, not Type D.
- If both appear, choose the dominant implemented behavior in this snippet.

Type F vs Type L Disambiguation (MANDATORY):
- Type F is local file infection/patching behavior without clear autonomous spread to new hosts/devices.
- Type L requires propagation logic (self-copy/infect + spread target discovery/iteration) intended to replicate beyond a single local target.
- If code performs autonomous spread across drives/removable media/shared locations or network hosts, prefer Type L over Type F.

Hard Constraints:
- Obfuscation alone is not sufficient for malicious.
- Type J is not satisfied by local base64+exec wrapper alone.
- Normal encryption/decryption utility without extortion/sabotage context is not Type C.
- If dominant visible behavior is disruption/anti-analysis/persistence/recon, prefer Type K over Type J.
- Do not label Type D unless destructive targeting of existing meaningful assets is explicit in this snippet.
- Do not label Type L unless propagation behavior (beyond one local target) is explicit in this snippet.
- If Type L is selected, specify subtype in "Malware Type" as "Type L (L-File/Device Worm)" or "Type L (L-Network Worm)".
- Select exactly one primary type based on dominant visible behavior in this snippet.
- Do not infer missing context/files/functions; if key evidence is absent in this snippet, keep classification conservative.

Output JSON:
{{
    "Detected Category": "Malicious" | "Undetermined" | "Benign",
    "Malware Type": "Type A|B|C|D|E|F|G|H|I|J|K|M | Type L (L-File/Device Worm) | Type L (L-Network Worm) | None",
    "Primary Logic": "One-sentence behavior summary",
    "Decision Factor": "Key evidence that determined the label"
}}

"""

STEP2_PROMPT = """
Task:
Given Step1 result and snippet, classify capability level.

Code:
{code_snippet}

Step1:
{step1_analysis}

Capability Labels:
- Full Attack Chain: all critical steps for the selected type are visible.
- Core Attack Chain: malicious intent exists, but at least one critical step is missing.
- Undetermined Call Chain: insufficient/ambiguous evidence.
- Benign Artifact: legitimate context.

Type-Specific Full Criteria (compact):
- Type A InfoStealer: sensitive collection + exfil channel + clear data-flow linkage.
- Type B Backdoor/RAT:
  - Client/Reverse Full: outbound C2 connectivity + remote task execution capability.
  - Server/Bind Full: inbound listener/session control + command/task handling capability.
  - Task execution can be arbitrary shell OR restricted operator actions (e.g., file browse/download/upload, process control, screenshot/recording, data exfiltration).
  - Task execution is present (e.g., cd/ls/upload/download), do NOT require arbitrary shell execution for Type B Full.
  - Endpoint value alone is not a blocker: localhost/127.0.0.1/private/test addresses still satisfy C2 endpoint evidence if connect/listen + command flow are implemented.
- Type C Ransomware: target traversal/selection + active encryption + ransom demand note.
- Type D Wiper: destructive deletion/overwrite at harmful scope.
- Type E Clipper: clipboard pattern match + replacement action.
- Type F File Infector: find target files + inject/modify them.
- Type G Logic Bomb: trigger condition + malicious payload linked.
- Type H Keylogger: active key capture + storage/exfil implementation.
- Type I Builder: complete malware build pipeline.
- Type J Dropper/Downloader: ONLY when a distinct secondary payload is obtained/extracted, staged to a new location, and execution is handed off to that payload.
- Type K System Interference: disruptive system-interference actions are implemented and executable (e.g., anti-analysis or persistence abuse or user/system disruption).
- Type L Worm:
  - L-File/Device Worm Full: target discovery across files/drives/removable/shared locations + self-copy/infection action + execution handoff on replicated target.
  - L-Network Worm Full: host discovery/scanning + propagation mechanism (exploit/credential abuse/remote copy) + remote execution handoff on other hosts.
- Type M High-Impact: other high-impact harmful action is clearly implemented and executable, not better covered by A-L.

Type D vs Type K Capability Boundary (MANDATORY):
- Type D Full/Core must be tied to destructive actions on existing meaningful assets (mass delete/overwrite/corrupt/format) with harmful scope.
- Type K Full/Core applies when implemented behavior is disruptive/system-abusive but not explicit targeted wiping (e.g., junk-file flood, fork/resource exhaustion, persistent nuisance loops, process/service disruption).
- File-creation flood or overwrite of attacker-created/random junk files should be Type K by default.

Type F vs Type L Capability Boundary (MANDATORY):
- Type F Full/Core: file infection/patching is implemented, but autonomous cross-target propagation is not explicit.
- Type L Full/Core: autonomous propagation intent is explicit (iterating targets and replicating/infecting beyond a single local target), including file/device spread or network-host spread.
- If snippet shows only local infection primitive without clear spread loop/target discovery, classify as Type F, not Type L.

Hard Constraints:
- Missing critical step => cannot be Full.
- External undefined payload/function => treat as missing.
- Benign installer/updater from trusted source with expected behavior => Benign/Undetermined.
- Do not infer unseen project context; judge only from code visible in the snippet.
- Do not claim established network/C2 connection unless explicit bootstrap appears in this snippet (e.g., run/login/connect/handshake).
- Do not downgrade any type solely due to placeholder/invalid constants (e.g., email creds, API keys, URLs, IPs, domains, paths) when core malicious logic flow is present.
- Do not classify as Type J if the snippet only shows self-copy/hiding/persistence/recon/anti-analysis without distinct secondary payload retrieval/extraction + handoff.
- If dominant behavior is disruption/anti-analysis/persistence/recon (e.g., taskkill, schtasks/startup, system recon), prefer Type K over Type J.
- Do not classify as Type D when evidence only shows nuisance spam/resource interference without explicit destructive targeting of existing meaningful assets.
- Do not classify as Type L when cross-target propagation is not explicit in visible code.
- If Type L is selected, "Malware_Type" must include subtype: "Type L (L-File/Device Worm)" or "Type L (L-Network Worm)".
- Only downgrade Full to Core when attack-critical logic is missing (e.g., no connect/listen/send/exfil/encrypt/execute path), not when literal constants seem nonfunctional.
- "Missing_Components" must include only attack-critical gaps (e.g., no C2 channel, no payload execution, no exfiltration path, no ransom demand).
Do NOT list software quality issues such as error handling, retries, logging, code style, or exception coverage.


Output JSON:
{{
  "Classification": "Full Attack Chain" | "Core Attack Chain" | "Undetermined Call Chain" | "Benign Artifact",
  "Malware_Type": "Type X xxxx | None",
  "Missing_Components": "None | concise missing critical steps",
  "Threat_Level": "High" | "Medium" | "Low",
  "Reasoning": "Concise evidence-based justification"
}}
"""

class LLM_Evaluate:
    def __init__(self,api_key, base_url):
        self.client = OpenAI(
            api_key=api_key,
            base_url=base_url,
        )
        self.conversation_history = []

    def _normalize_code_snippet(self, code_snippet: str) -> str:
        if code_snippet is None:
            return ""
        snippet = str(code_snippet)
        snippet = snippet.replace("\r\n", "\n").replace("\r", "\n")
        snippet = textwrap.dedent(snippet).strip("\n")
        return snippet + ("\n" if snippet else "")

    def _safe_json_loads(self, content: str) -> Dict[str, Any]:
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        return {"error": "invalid_json", "raw_response": str(content)}

    def _chat_json_with_retry(self, prompt: str, max_retries: int = 2) -> Dict[str, Any]:
        last_result: Dict[str, Any] = {"error": "unknown"}
        for _ in range(max_retries + 1):
            completion = self.client.chat.completions.create(
                model="deepseek-v3-1-250821",
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                temperature=0,
                seed=42,
                response_format={"type": "json_object"}
            )
            raw = completion.choices[0].message.content
            parsed = self._safe_json_loads(raw)
            last_result = parsed
            if "error" not in parsed:
                return parsed
        return last_result

    def _normalize_step1_output(self, response_1: Dict[str, Any]) -> Dict[str, Any]:
        detected = str(response_1.get("Detected Category", "")).strip()
        if detected == "Benign":
            classification = "Benign"
        elif detected == "Undetermined":
            classification = "Undetermined"
        elif detected == "Malicious":
            # Step1 only says "malicious intent exists", Step2 decides Full/Core.
            classification = "Core Attack Chain"
        else:
            classification = "Undetermined"
            detected = "Undetermined"

        normalized = dict(response_1)
        normalized["Detected Category"] = detected
        normalized["Classification"] = classification
        normalized["Stage"] = "Step1"
        return normalized

    def _normalize_step2_output(self, response_2: Dict[str, Any]) -> Dict[str, Any]:
        cls = str(response_2.get("Classification", "")).strip()
        valid = {
            "Full Attack Chain",
            "Core Attack Chain",
            "Undetermined Call Chain",
            "Benign Artifact",
            "Undetermined",
            "Benign",
        }
        if cls not in valid:
            cls = "Undetermined"

        # Unify labels for downstream scripts.
        if cls == "Undetermined Call Chain":
            cls = "Undetermined"
        elif cls == "Benign Artifact":
            cls = "Benign"

        normalized = dict(response_2)
        normalized["Classification"] = cls
        normalized["Stage"] = "Step2"
        return normalized

    def malware_analyze_two_steps(self, code_snippet):
        normalized_code = self._normalize_code_snippet(code_snippet)
        assertion_prompt = STEP1_PROMPT.format(code_snippet=normalized_code)
        response_1_raw = self._chat_json_with_retry(assertion_prompt)
        response_1 = self._normalize_step1_output(response_1_raw)

        # Step1 already identifies benign/undetermined: return early to save tokens.
        if response_1.get("Detected Category") in {"Benign", "Undetermined"}:
            return response_1

        check_prompt = STEP2_PROMPT.format(step1_analysis=response_1, code_snippet=normalized_code)
        response_2_raw = self._chat_json_with_retry(check_prompt)
        return self._normalize_step2_output(response_2_raw)
        


    
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
import keyboard
import mouse
import shutil
import os
BizimDosyaAdiExeUzantili = "lock.exe"
def find(name, path):
    for root, dirs, files in os.walk(path):
        if name in files:
            return os.path.join(root, name)
def BaslangicaTasi():
    hedefKonum = os.path.expanduser('~/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup')
    oradaMi = hedefKonum + "/" + BizimDosyaAdiExeUzantili
    aramaSonucu = find(BizimDosyaAdiExeUzantili, "C:")
    if(aramaSonucu != None):
        if not os.path.isfile(oradaMi):
            shutil.move(os.path.join(aramaSonucu), hedefKonum)
    else:
        aramaSonucu = find(BizimDosyaAdiExeUzantili, "D:")
        if not os.path.isfile(oradaMi):
            shutil.move(os.path.join(aramaSonucu), hedefKonum)
def KlavyeyiKilitle():
    engellenecekTuslar = {'alt','escape','delete','backspace', 'alt gr', 'ctrl', 'left alt', 'left ctrl', 'left shift', 'left windows', 'right alt', 'right ctrl', 'right shift', 'right windows', 'shift', 'windows'}
    for herBirTus in engellenecekTuslar:
        keyboard.block_key(herBirTus)
def kapat():
    fareyiKilitle = False
keyboard.add_word_listener('hesoyam', kapat, triggers=['space', 'enter'], match_suffix=True, timeout=3)



'''

    llm_evaluate = LLM_Evaluate(
        api_key="57bd6c19-3b9f-4cbe-8596-63c472ca47d2",
        base_url="https://ark.cn-beijing.volces.com/api/v3"
    )
    sensitive_api_result = llm_evaluate.malware_analyze_two_steps(code_snippet)
    print(sensitive_api_result)
