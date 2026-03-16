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
Given the Step1 result and the same code snippet, assess the capability level of the detected behavior and output a single JSON object.
Inputs:
- Code Snippet: {code_snippet}
- Step1 Analysis: {step1_analysis}

Capability Labels:
- Full Attack Chain: all critical steps for the selected type are visible and at least one malicious behavior is executable.
- Core Attack Chain: malicious intent exists, but at least one critical step is missing.
- Undetermined Call Chain: evidence for a coherent malicious chain is insufficient or ambiguous.
- Benign Artifact: Behavior is consistent with legitimate/non-malicious context.


High-Priority Rules(MANDATORY):
1) 1) Missing any critical attack step OR having no reachable code path to the malicious behavior even when this script/binary is executed => CANNOT be "Full Attack Chain".
   - Manual execution of the script/binary by a user/operator counts as a valid execution path.
   - The absence of auto-start/persistence/cron/etc. alone MUST NOT be used to downgrade from "Full Attack Chain" to "Core Attack Chain" when the malicious logic is fully implemented and reachable.
2) External/undefined payloads or functions MUST be treated as missing; they do not count as implemented.
3) Judge ONLY from visible code in this snippet; do NOT infer unseen project context or hidden C2.
4) Do NOT downgrade Full to Core just because constants/endpoints/creds look fake or placeholder if the malicious flow is otherwise complete.
5) “Missing_Components” MUST list only attack-critical gaps (e.g., no C2 channel, no payload execution, no exfil path, no ransom demand); 
6）Do NOT mention code quality issues (logging, error handling, retries, style, etc.).

Type-Specific Full Criteria (summary):
Use the primary type inferred in Step1, and apply these as a checklist for Full vs Core:

- Type A InfoStealer: sensitive data collection + exfiltration channel + clear data-flow linkage between the two.

- Type B Backdoor/RAT:
  - Client/Reverse: outbound C2 connectivity + remote task/command execution capability.
  - Server/Bind: inbound listener/session control + command/task handling/response capability.
  - For Type B "Full Attack Chain", it is sufficient that EITHER a Client/Reverse pattern OR a Server/Bind pattern is fully implemented; both are NOT required in the same snippet.
  - Task execution can be arbitrary shell OR restricted operator actions (e.g., file browse/download/upload, process control, screenshot/recording, data exfiltration).
  - Task execution is present (e.g., cd/ls/upload/download), do NOT require arbitrary shell execution for Type B Full.
  - Endpoint value alone is not a blocker: localhost/127.0.0.1/private/test addresses still satisfy C2 endpoint evidence if connect/listen + command flow are implemented.
  If Type B applies, set "Malware_Type" as:
  - "Type B (Client/Reverse)" OR
  - "Type B (Server/Bind)".
  
- Type C Ransomware: target traversal/selection + active encryption + ransom demand note.

- Type D Wiper: Destructive delete/overwrite/corrupt/format operations against existing meaningful assets at harmful scope.
Nuisance disruption or junk-file flood without clear destructive targeting => prefer Type K.

- Type E Clipper: clipboard/wallet pattern match + replacement/modification action.

- Type F File Infector: find/choose target files + inject/modify them.
No explicit autonomous cross-target spread (otherwise see Type L).

- Type G Logic Bomb:  Trigger condition + linked malicious payload that executes when condition holds.

- Type H Keylogger: active key capture + storage and/or exfiltration implementation.

- Type I Builder: complete malware build pipeline.

- Type J Dropper/Downloader: DISTINCT secondary payload is obtained or extracted, staged to a new location, AND execution is handed off to that payload.
  Self-copy/hiding/persistence/recon/anti-analysis alone are NOT Type J.

- Type K System Interference: Disruptive/system-abusive behavior (e.g., resource exhaustion, process/service disruption, anti-analysis, persistence abuse, nuisance loops) that degrades normal usability.
  For Type K to be Full:
  - At least one disruptive action is visible, AND
  - At least one visible execution path can trigger it (top-level statements also count as a path).
  
- Type L Worm:
  - L-File/Device Worm Full: target discovery across files/drives/removable/shared locations + self-copy/infection action + execution handoff on replicated target.
  - L-Network Worm Full: host discovery/scanning + propagation mechanism (exploit/credential abuse/remote copy) + remote execution handoff on other hosts.
  Local infection primitive without explicit spread loop => classify as Type F, not Type L.
  If Type L applies, set "Malware_Type" as:
  - "Type L (L-File/Device Worm)" OR
  - "Type L (L-Network Worm)".
  
- Type M High-Impact: other high-impact harmful action is clearly implemented or executable, not better covered by A-L.

Additional Constraints:
- Benign installer/updater from a trusted source with expected behavior => usually "Benign Artifact" or "Undetermined Call Chain".
- Do NOT classify as Type D when only nuisance spam/resource interference appears without explicit destructive targeting of existing meaningful assets.
- Do NOT classify as Type L when cross-target propagation is not explicit in this snippet.

Output JSON (STRICT, single object, no extra text):
{{
  "Classification": "Full Attack Chain" | "Core Attack Chain" | "Undetermined Call Chain" | "Benign Artifact",
  "Malware_Type": "Type X xxxx" | "Type L (L-File/Device Worm)" | "Type L (L-Network Worm)" | "None",
  "Missing_Components": "None" | "Concise description of missing critical steps",
  "Threat_Level": "High" | "Medium" | "Low",
  "Reasoning": "Concise evidence-based justification referencing visible code and the applied rules."
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
                # seed=42,
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
    code_dir = "/home/lxy/lxy_codes/mal_update_detect/joern_output/multiple_commits/"
    arg = "crypto-clipper,0,dfe2b,NEW@<module>@main.py_slice.py"
    repo_path = os.path.join(code_dir,arg.split(",")[0])
    slice_path=""
    for slice_dir in os.listdir(repo_path):
        if arg.split(',')[1] == slice_dir.split('_')[0] and arg.split(',')[2] == slice_dir.split('_')[1]:
            slice_path = os.path.join(repo_path,slice_dir)
    code_path = os.path.join(slice_path,"taint_slices_methods",arg.split(',')[3])
    
    # code_path = "/home/lxy/lxy_codes/mal_update_detect/joern_output/benign_dataset/networking_tools/ECommerceCrawlers/45_88038_8b579/taint_slices_methods/NEW@<module>@DianpingCrawler_dazhong.py_slice.py"
    with open(code_path, "r") as f:
        code_snippet = f.read()
    llm_evaluate = LLM_Evaluate(
        api_key="57bd6c19-3b9f-4cbe-8596-63c472ca47d2",
        base_url="https://ark.cn-beijing.volces.com/api/v3"
    )
    sensitive_api_result = llm_evaluate.malware_analyze_two_steps(code_snippet)
    with open(os.path.join(code_path.replace(".py", "_result.json")), "w") as f:
        json.dump(sensitive_api_result, f, indent=4)
    print(sensitive_api_result)
