import openai
import json
import textwrap
from typing import Dict, Any
from pydantic import BaseModel, Field
import os

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
Given the code snippet, detect primary intent category AND infer its role within a larger repository.

Code:
{code_snippet}

Analysis Steps:
1) Context Inference:
   - Identify the code's likely role (utility, installer, updater, payload, etc.)
   - Infer required input sources, environment variables, or upstream dependencies
   - Note any missing context needed for full understanding

2) Intent Classification:
   - Benign Filter:
     If behavior matches normal utility/installer/updater/admin function with no malicious indicators -> Benign.

   - Ambiguity Filter:
     Dangerous APIs/tools alone (e.g., subprocess, cryptography, base64, keyboard hooks) without harmful workflow -> Undetermined.
     Bare connectivity alone is ambiguous -> Undetermined.

   - Malicious Intent Detection:
     Focus on observable harmful behaviors rather than predefined categories:
     - Data theft/exfiltration: unauthorized collection or transmission of sensitive data
     - Remote control: establishing unauthorized command/control channels
     - Destruction: deleting, corrupting, or encrypting data for harmful purposes
     - Persistence: unauthorized modification of system startup/config
     - Surveillance: capturing keystrokes, screenshots, clipboard, or other user activity
     - Lateral movement: unauthorized spreading to other systems or files
     - Payload delivery: downloading/executing unauthorized code
     - System disruption: degrading system availability or functionality

Hard Constraints:
- Obfuscation alone is not sufficient for malicious.
- Dangerous tools used in legitimate admin/utility context are not malicious.
- Do not infer missing context/files/functions; if key evidence is absent, keep classification conservative.
- Base judgment on observable behavior patterns, not specific attack type labels.

Output JSON:
{{
    "Detected Category": "Malicious" | "Undetermined" | "Benign",
    "Primary Logic": "One-sentence behavior summary",
    "Key Behaviors": ["list of observable malicious behaviors if any"],
    "Decision Factor": "Key evidence that determined the label",
    "Inferred Context": "Description of inferred role, missing dependencies, and calling environment"
}}
"""

STEP2_PROMPT = """
Task:
You are a Low-Level Systems Analyst. Extract atomic operations (API calls, logic branches, data flows).
Focus on physical actions rather than business logic. Trace how data moves from an input to a sensitive output.

Code:
{code_snippet}

Inferred Context:
{inferred_context}

Instructions:
1) List each atomic operation in execution order
2) Identify data sources (inputs, network reads, file reads)
3) Identify data transformations (encoding, encryption, string manipulation)
4) Identify data sinks (network sends, file writes, process execution)
5) Trace the complete data flow path if one exists

Output:
Provide a detailed sequence of atomic behaviors and data flow analysis as plain text.
"""

STEP3_PROMPT = """
Task:
You are a Senior Cyber Security Researcher. Map the extracted behavior sequence to the MITRE ATT&CK framework.
Evaluate the potential harm if these actions are executed in sequence. Do not jump to conclusions; focus on technical capabilities.

Extracted Behaviors:
{behaviors}

Inferred Context:
{inferred_context}

Detected Category:
{detected_category}

Instructions:
1) Map each behavior to relevant MITRE ATT&CK tactics and techniques
2) Evaluate the threat potential when behaviors are combined
3) Identify any indicators of specific attack patterns

Output:
Provide the threat mapping analysis as plain text, referencing MITRE ATT&CK techniques where applicable.
"""

STEP4_PROMPT = """
Task:
You are a Malicious Code Auditor. Synthesize all previous reasoning steps to assess the capability level of the detected behavior.
Focus on attack chain completeness and output a single JSON object.

Original Code:
{code_snippet}

Inferred Context:
{inferred_context}

Detected Category:
{detected_category}

Key Behaviors:
{key_behaviors}

Extracted Behaviors:
{behaviors}

Threat Mapping:
{threat_mapping}

Capability Labels:
- Full Attack Chain: ALL critical steps for the malicious behavior are visible and executable.
- Core Attack Chain: malicious intent exists, but at least one critical step is missing.
- Undetermined Call Chain: evidence for a coherent malicious chain is insufficient or ambiguous.
- Benign Artifact: Behavior is consistent with legitimate/non-malicious context.

Full Attack Chain Criteria (MANDATORY - STRICT):
"Full" requires that ALL critical steps for the observed malicious behavior are implemented in visible code.
Missing ANY critical step => MUST be "Core Attack Chain", NOT "Full".

Critical Step Requirements by Behavior Pattern:

1) Data Theft/Exfiltration (collecting sensitive data):
   - Sensitive data collection is NOT enough for Full
   - REQUIRES: exfiltration channel (network send, remote upload, email, etc.)
   - Writing collected data to local file ONLY => Core, NOT Full
   - Full needs: collection + exfiltration + clear data-flow linkage between them

2) Remote Control/Backdoor/C2:
   - C2 connection alone is NOT enough for Full
   - REQUIRES: command/task execution capability
   - Full needs: outbound/inbound connection + command handling + task execution
   - Local shell open without C2 => Core
   - C2 connect without command execution => Core

3) Payload Delivery/Dropper:
   - Download/stage payload is NOT enough for Full
   - REQUIRES: execution handoff to the payload
   - Full needs: payload obtain + stage to location + execute

4) Destructive Actions (delete/overwrite/encrypt):
   - Destructive capability is NOT enough for Full
   - REQUIRES: target selection/traversal + destructive action
   - Single file delete without traversal => Core

5) Surveillance (keylogging, screenshots, clipboard):
   - Capture capability is NOT enough for Full
   - REQUIRES: storage AND/OR exfiltration of captured data
   - Capture + local file write only => Core

6) Worm/Propagation:
   - Local infection is NOT enough for Full
   - REQUIRES: target discovery + self-copy + execution handoff on new target
   - Without spread loop => Core

Universal Rules (MANDATORY):
1) External/undefined functions or payloads MUST be treated as missing - they do NOT count as implemented
2) Judge ONLY from visible code; do NOT infer unseen project context
3) Manual execution by user counts as valid execution path
4) Do NOT downgrade Full to Core just because endpoints/creds look fake if flow is complete
5) "Missing_Components" MUST list only attack-critical gaps
6) Do NOT mention code quality issues

Output JSON (STRICT, single object, no extra text):
{{
  "Classification": "Full Attack Chain" | "Core Attack Chain" | "Undetermined Call Chain" | "Benign Artifact",
  "Attack Flow": "Brief description of Source -> Transform -> Sink if applicable",
  "Missing_Components": "None" | "Concise description of missing critical steps",
  "Threat_Level": "High" | "Medium" | "Low",
  "Reasoning": "Concise evidence-based justification referencing visible code and attack chain analysis."
}}
"""


class CodeSliceIntegrityAnalyzer:
    def __init__(self, api_key, base_url="https://ark.cn-beijing.volces.com/api/v3"):
        self.client = openai.OpenAI(api_key=api_key, base_url=base_url)
        self.model = "deepseek-v3-1-250821"

    def analyze(self, code_slice):
        print("--- Initiating Multi-Stage Reasoning Chain ---")

        normalized_code = self._normalize_code_snippet(code_slice)

        # Stage 1: Intent Classification + Context Reconstruction
        step1_result = self._step_context_classification(normalized_code)
        step1_normalized = self._normalize_step1_output(step1_result)
        print("[Step 1] Intent Classification Complete.")

        # Early exit for Benign/Undetermined
        if step1_normalized.get("Detected Category") in {"Benign", "Undetermined"}:
            print("[Early Exit] No malicious intent detected.\n")
            return {"Step1": step1_normalized}

        # Stage 2: Atomic Behavior & Data Flow Extraction
        behaviors = self._step_behavior_extraction(
            normalized_code,
            step1_normalized.get("Inferred Context", "")
        )
        print("[Step 2] Behavioral Chain Extracted.")

        # Stage 3: Threat Mapping (MITRE ATT&CK Alignment)
        threat_mapping = self._step_threat_mapping(
            behaviors,
            step1_normalized.get("Inferred Context", ""),
            step1_normalized.get("Detected Category", "Malicious")
        )
        print("[Step 3] Threat Patterns Mapped.")

        # Stage 4: Capability Assessment & Final Verdict
        step4_result = self._step_final_verdict(
            normalized_code,
            step1_normalized.get("Inferred Context", ""),
            step1_normalized.get("Detected Category", "Malicious"),
            step1_normalized.get("Key Behaviors", []),
            behaviors,
            threat_mapping
        )
        step4_normalized = self._normalize_step4_output(step4_result)
        print("[Step 4] Capability Assessment Finished.\n")

        return {
            "Step1": step1_normalized,
            "Step2": behaviors,
            "Step3": threat_mapping,
            "Step4": step4_normalized
        }

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

    def _call_llm(self, system_prompt, user_content):
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ],
            temperature=0.1
        )
        return response.choices[0].message.content or ""

    def _chat_json_with_retry(self, prompt: str, max_retries: int = 2) -> Dict[str, Any]:
        last_result: Dict[str, Any] = {"error": "unknown"}
        for _ in range(max_retries + 1):
            completion = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                temperature=0,
                response_format={"type": "json_object"}
            )
            raw = completion.choices[0].message.content or ""
            parsed = self._safe_json_loads(raw)
            last_result = parsed
            if "error" not in parsed:
                return parsed
        return last_result

    def _normalize_step1_output(self, response: Dict[str, Any]) -> Dict[str, Any]:
        detected = str(response.get("Detected Category", "")).strip()
        if detected not in {"Benign", "Undetermined", "Malicious"}:
            detected = "Undetermined"

        normalized = dict(response)
        normalized["Detected Category"] = detected
        normalized["Stage"] = "Step1"

        if "Key Behaviors" not in normalized:
            normalized["Key Behaviors"] = []

        return normalized

    def _normalize_step4_output(self, response: Dict[str, Any]) -> Dict[str, Any]:
        cls = str(response.get("Classification", "")).strip()
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

        if cls == "Undetermined Call Chain":
            cls = "Undetermined"
        elif cls == "Benign Artifact":
            cls = "Benign"

        normalized = dict(response)
        normalized["Classification"] = cls
        normalized["Stage"] = "Step4"
        return normalized

    def _step_context_classification(self, code: str) -> Dict[str, Any]:
        prompt = STEP1_PROMPT.format(code_snippet=code)
        return self._chat_json_with_retry(prompt)

    def _step_behavior_extraction(self, code: str, context: str) -> str:
        user_content = STEP2_PROMPT.format(
            code_snippet=code,
            inferred_context=context
        )
        return self._call_llm(SYSTEM_PROMPT, user_content)

    def _step_threat_mapping(self, behaviors: str, context: str, detected_category: str) -> str:
        user_content = STEP3_PROMPT.format(
            behaviors=behaviors,
            inferred_context=context,
            detected_category=detected_category
        )
        return self._call_llm(SYSTEM_PROMPT, user_content)

    def _step_final_verdict(self, code: str, context: str, detected_category: str,
                            key_behaviors: list, behaviors: str, threat_mapping: str) -> Dict[str, Any]:
        key_behaviors_str = json.dumps(key_behaviors) if isinstance(key_behaviors, list) else str(key_behaviors)
        user_content = STEP4_PROMPT.format(
            code_snippet=code,
            inferred_context=context,
            detected_category=detected_category,
            key_behaviors=key_behaviors_str,
            behaviors=behaviors,
            threat_mapping=threat_mapping
        )
        return self._chat_json_with_retry(user_content)


# --- Example Usage ---
if __name__ == "__main__":
    code_dir = "/home/lxy/lxy_codes/mal_update_detect/joern_output/multiple_commits/"
    arg = "1stMalware,10,3a1e0,NEW@<module>@main.py_slice.py"
    repo_path = os.path.join(code_dir,arg.split(",")[0])
    slice_path=""
    for slice_dir in os.listdir(repo_path):
        if arg.split(',')[1] == slice_dir.split('_')[0] and arg.split(',')[2] == slice_dir.split('_')[1]:
            slice_path = os.path.join(repo_path,slice_dir)
    code_path = os.path.join(slice_path,"taint_slices_methods",arg.split(',')[3])
    
    with open(code_path, "r") as f:
        code_snippet = f.read()

    analyzer = CodeSliceIntegrityAnalyzer(api_key="57bd6c19-3b9f-4cbe-8596-63c472ca47d2")
    report = analyzer.analyze(code_snippet)
    print(json.dumps(report, indent=2, ensure_ascii=False))
