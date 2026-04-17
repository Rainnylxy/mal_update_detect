import json
import os
import textwrap
from typing import Any, Dict, Iterable, List, Set

from openai import OpenAI


SYSTEM_PROMPT = """
Role:
You are a malware slice auditor for software supply-chain investigations.

Core Principles:
1) Use only evidence visible in the provided code slice.
2) Never treat undefined functions/modules/payloads as implemented behavior.
3) Separate observed facts from inferred intent.
4) Prefer "Undetermined" when critical evidence is missing.
5) Output valid JSON only.
"""


CAPABILITY_ATOMS = [
    "anti_analysis_or_evasion",
    "builder_generate_artifact",
    "capture_input",
    "clipboard_read",
    "clipboard_write",
    "collect_sensitive_data",
    "destroy_or_overwrite_data",
    "discover_targets",
    "disrupt_system",
    "display_ransom_or_coercion",
    "download_or_extract_payload",
    "encrypt_or_lock_data",
    "execute_code_or_command",
    "handoff_execution",
    "modify_other_files",
    "modify_startup_or_persistence",
    "network_connect",
    "network_listen",
    "network_send",
    "receive_remote_task",
    "remote_propagation",
    "scan_or_discover_hosts",
    "self_replicate_or_infect",
    "trigger_condition",
    "write_local_artifact",
    "write_payload_to_disk",
]


STEP0_PROMPT = """
Task:
Extract structured evidence from the code slice. Do not classify it yet.

Code:
{code_snippet}

Allowed Capability Atoms:
{capability_atoms}

Instructions:
1) Report only behavior that is directly visible in this slice.
2) If a behavior depends on an undefined function/module/payload, mark it as partial or put it under Undefined Dependencies.
3) Use capability atoms only from the allowed list.
4) Distinguish data sources, sensitive sinks, execution paths, and missing dependencies.
5) Keep evidence short, technical, and tied to visible code.

Output JSON:
{{
  "Slice Summary": "Short factual summary of visible behavior",
  "Entrypoints": [
    {{
      "name": "function or top-level block",
      "reachability": "reachable|conditional|unclear",
      "evidence": "Why execution can reach it from this slice"
    }}
  ],
  "Capability Evidence": [
    {{
      "capability": "one of allowed capability atoms",
      "status": "visible|partial",
      "evidence": "Visible fact supporting this capability",
      "line_hint": "Approximate line or code region"
    }}
  ],
  "Sources": [
    {{
      "kind": "argv|env|file_read|network_read|clipboard|keyboard|browser_store|system_info|other",
      "detail": "What is read",
      "line_hint": "Approximate line or code region"
    }}
  ],
  "Sinks": [
    {{
      "kind": "network_send|file_write|process_exec|startup_modification|clipboard_write|other",
      "detail": "What is written/sent/executed",
      "line_hint": "Approximate line or code region"
    }}
  ],
  "Data Flows": [
    {{
      "source": "Source description",
      "sink": "Sink description",
      "linkage": "clear|partial|none",
      "evidence": "How data appears to move in visible code"
    }}
  ],
  "Undefined Dependencies": [
    {{
      "name": "function/module/payload/variable name",
      "kind": "function|module|payload|variable|other",
      "impact": "critical|non_critical",
      "reason": "Why missing context matters"
    }}
  ],
  "Benign Signals": ["Observable signals supporting benign or admin-tool interpretation"],
  "Malicious Signals": ["Observable signals supporting malicious interpretation"],
  "Unknowns": ["Missing context or ambiguity that blocks certainty"]
}}
"""


STEP1_PROMPT = """
Task:
Using the structured evidence and the same code slice, determine whether the slice is malicious, benign, or still undetermined.
Choose one primary malware type only when the visible evidence supports it.

Code:
{code_snippet}

Evidence JSON:
{evidence_json}

Malware Type Options:
- Type A InfoStealer
- Type B Backdoor/RAT
- Type C Ransomware
- Type D Wiper
- Type E Clipper
- Type F File Infector
- Type G Logic Bomb
- Type H Keylogger
- Type I Builder
- Type J Dropper/Downloader
- Type K System Interference
- Type L (L-File/Device Worm)
- Type L (L-Network Worm)
- Type M High-Impact
- None

Rules:
1) Base the decision on the evidence JSON first, code second.
2) Dangerous APIs alone are not malicious.
3) If the slice shows harmful capability but key context is missing, "Malicious" is allowed for intent, but keep uncertainty explicit.
4) If visible evidence equally supports benign admin/update behavior, prefer "Undetermined" over "Malicious".
5) Do not invent evidence that is not in the code or the evidence JSON.

Output JSON:
{{
  "Detected Category": "Malicious" | "Undetermined" | "Benign",
  "Malware Type": "Type A|Type B|Type C|Type D|Type E|Type F|Type G|Type H|Type I|Type J|Type K|Type M|Type L (L-File/Device Worm)|Type L (L-Network Worm)|None",
  "Primary Logic": "One-sentence summary of visible behavior",
  "Decision Factor": "Main evidence that drove the label",
  "Key Evidence": ["Short evidence points copied from the evidence JSON"],
  "Competing Benign Hypothesis": "Best benign explanation if any, otherwise None",
  "Uncertainty": "Main uncertainty that could change the verdict, otherwise None"
}}
"""


STEP2_PROMPT = """
Task:
Given the code slice, the structured evidence, and the Step1 intent result, assess capability completeness.

Code:
{code_snippet}

Evidence JSON:
{evidence_json}

Step1 Result:
{step1_json}

Capability Labels:
- Full Attack Chain
- Core Attack Chain
- Undetermined Call Chain
- Benign Artifact

Strict Rules:
1) "Full Attack Chain" requires all critical steps to be visibly implemented in this slice.
2) Undefined critical dependencies count as missing, not implemented.
3) Manual execution by a user counts as a valid execution path if the malicious behavior is otherwise reachable.
4) If harmful workflow is incomplete but intent is still visible, use "Core Attack Chain".
5) If harmful workflow itself is ambiguous or too incomplete, use "Undetermined Call Chain".
6) Prefer evidence-based chain descriptions over family lore.

Type-Specific Full Checklists:
- Type A: collect_sensitive_data + network_send + a clear/partial data flow between them.
- Type B: (network_connect OR network_listen) + receive_remote_task + execute_code_or_command.
- Type C: discover_targets + encrypt_or_lock_data + display_ransom_or_coercion.
- Type D: discover_targets + destroy_or_overwrite_data.
- Type E: clipboard_read + clipboard_write.
- Type F: discover_targets + modify_other_files.
- Type G: trigger_condition + visible harmful payload action.
- Type H: capture_input + (write_local_artifact OR network_send).
- Type I: builder_generate_artifact.
- Type J: download_or_extract_payload + write_payload_to_disk + handoff_execution.
- Type K: disrupt_system + at least one reachable or conditional execution path.
- Type L (L-File/Device Worm): discover_targets + self_replicate_or_infect + handoff_execution.
- Type L (L-Network Worm): scan_or_discover_hosts + remote_propagation + handoff_execution.
- Type M: clearly harmful high-impact action visibly implemented and reachable.

Output JSON:
{{
  "Classification": "Full Attack Chain" | "Core Attack Chain" | "Undetermined Call Chain" | "Benign Artifact",
  "Malware_Type": "Type A|Type B|Type C|Type D|Type E|Type F|Type G|Type H|Type I|Type J|Type K|Type M|Type L (L-File/Device Worm)|Type L (L-Network Worm)|None",
  "Satisfied_Requirements": ["Checklist items visibly satisfied"],
  "Missing_Components": "None" | "Critical missing steps",
  "Threat_Level": "High" | "Medium" | "Low",
  "Reasoning": "Short evidence-based explanation"
}}
"""


TYPE_REQUIREMENTS = {
    "Type A": {"collect_sensitive_data", "network_send"},
    "Type B": {"receive_remote_task", "execute_code_or_command"},
    "Type C": {"discover_targets", "encrypt_or_lock_data", "display_ransom_or_coercion"},
    "Type D": {"discover_targets", "destroy_or_overwrite_data"},
    "Type E": {"clipboard_read", "clipboard_write"},
    "Type F": {"discover_targets", "modify_other_files"},
    "Type G": {"trigger_condition"},
    "Type H": {"capture_input"},
    "Type I": {"builder_generate_artifact"},
    "Type J": {"download_or_extract_payload", "write_payload_to_disk", "handoff_execution"},
    "Type K": {"disrupt_system"},
    "Type L (L-File/Device Worm)": {"discover_targets", "self_replicate_or_infect", "handoff_execution"},
    "Type L (L-Network Worm)": {"scan_or_discover_hosts", "remote_propagation", "handoff_execution"},
}


TYPE_ALIASES = {
    "Type A": "Type A",
    "Type B": "Type B",
    "Type C": "Type C",
    "Type D": "Type D",
    "Type E": "Type E",
    "Type F": "Type F",
    "Type G": "Type G",
    "Type H": "Type H",
    "Type I": "Type I",
    "Type J": "Type J",
    "Type K": "Type K",
    "Type L (L-File/Device Worm)": "Type L (L-File/Device Worm)",
    "Type L (L-Network Worm)": "Type L (L-Network Worm)",
    "Type M": "Type M",
}


class LLM_Evaluate_V3:
    def __init__(self, api_key: str, base_url: str, model: str = "deepseek-v3-1-250821"):
        self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.model = model

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
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0,
                response_format={"type": "json_object"},
            )
            raw = completion.choices[0].message.content or ""
            parsed = self._safe_json_loads(raw)
            last_result = parsed
            if "error" not in parsed:
                return parsed
        return last_result

    def _normalize_string_list(self, value: Any) -> List[str]:
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        if value in (None, ""):
            return []
        return [str(value).strip()]

    def _normalize_object_list(self, value: Any) -> List[Dict[str, Any]]:
        if not isinstance(value, list):
            return []
        normalized: List[Dict[str, Any]] = []
        for item in value:
            if isinstance(item, dict):
                normalized.append({str(k): v for k, v in item.items()})
        return normalized

    def _normalize_evidence_output(self, response: Dict[str, Any]) -> Dict[str, Any]:
        normalized = dict(response)
        normalized["Slice Summary"] = str(response.get("Slice Summary", "")).strip()
        normalized["Entrypoints"] = self._normalize_object_list(response.get("Entrypoints"))
        normalized["Capability Evidence"] = self._normalize_object_list(response.get("Capability Evidence"))
        normalized["Sources"] = self._normalize_object_list(response.get("Sources"))
        normalized["Sinks"] = self._normalize_object_list(response.get("Sinks"))
        normalized["Data Flows"] = self._normalize_object_list(response.get("Data Flows"))
        normalized["Undefined Dependencies"] = self._normalize_object_list(response.get("Undefined Dependencies"))
        normalized["Benign Signals"] = self._normalize_string_list(response.get("Benign Signals"))
        normalized["Malicious Signals"] = self._normalize_string_list(response.get("Malicious Signals"))
        normalized["Unknowns"] = self._normalize_string_list(response.get("Unknowns"))
        normalized["Stage"] = "Evidence"
        return normalized

    def _normalize_step1_output(self, response: Dict[str, Any]) -> Dict[str, Any]:
        detected = str(response.get("Detected Category", "")).strip()
        if detected not in {"Malicious", "Undetermined", "Benign"}:
            detected = "Undetermined"

        malware_type = self._normalize_malware_type(response.get("Malware Type"))
        normalized = dict(response)
        normalized["Detected Category"] = detected
        normalized["Malware Type"] = malware_type
        normalized["Key Evidence"] = self._normalize_string_list(response.get("Key Evidence"))
        normalized["Primary Logic"] = str(response.get("Primary Logic", "")).strip()
        normalized["Decision Factor"] = str(response.get("Decision Factor", "")).strip()
        normalized["Competing Benign Hypothesis"] = str(response.get("Competing Benign Hypothesis", "")).strip() or "None"
        normalized["Uncertainty"] = str(response.get("Uncertainty", "")).strip() or "None"
        normalized["Stage"] = "Step1"
        return normalized

    def _normalize_step2_output(self, response: Dict[str, Any]) -> Dict[str, Any]:
        cls = str(response.get("Classification", "")).strip()
        valid = {
            "Full Attack Chain",
            "Core Attack Chain",
            "Undetermined Call Chain",
            "Benign Artifact",
        }
        if cls not in valid:
            cls = "Undetermined Call Chain"

        normalized = dict(response)
        normalized["Classification"] = cls
        normalized["Malware_Type"] = self._normalize_malware_type(response.get("Malware_Type"))
        normalized["Satisfied_Requirements"] = self._normalize_string_list(response.get("Satisfied_Requirements"))
        normalized["Missing_Components"] = str(response.get("Missing_Components", "")).strip() or "None"
        normalized["Threat_Level"] = str(response.get("Threat_Level", "")).strip() or "Low"
        normalized["Reasoning"] = str(response.get("Reasoning", "")).strip()
        normalized["Stage"] = "Step2"
        return normalized

    def _normalize_malware_type(self, malware_type: Any) -> str:
        raw = str(malware_type or "None").strip()
        if raw in TYPE_ALIASES:
            return TYPE_ALIASES[raw]
        compact = raw.split("|", 1)[0].strip()
        return TYPE_ALIASES.get(compact, "None")

    def _extract_evidence(self, code_snippet: str) -> Dict[str, Any]:
        prompt = STEP0_PROMPT.format(
            code_snippet=code_snippet,
            capability_atoms=", ".join(CAPABILITY_ATOMS),
        )
        return self._normalize_evidence_output(self._chat_json_with_retry(prompt))

    def _classify_intent(self, code_snippet: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
        prompt = STEP1_PROMPT.format(
            code_snippet=code_snippet,
            evidence_json=json.dumps(evidence, ensure_ascii=False, indent=2),
        )
        return self._normalize_step1_output(self._chat_json_with_retry(prompt))

    def _assess_capability(
        self,
        code_snippet: str,
        evidence: Dict[str, Any],
        step1: Dict[str, Any],
    ) -> Dict[str, Any]:
        prompt = STEP2_PROMPT.format(
            code_snippet=code_snippet,
            evidence_json=json.dumps(evidence, ensure_ascii=False, indent=2),
            step1_json=json.dumps(step1, ensure_ascii=False, indent=2),
        )
        raw = self._chat_json_with_retry(prompt)
        normalized = self._normalize_step2_output(raw)
        return self._post_validate_final_assessment(evidence, step1, normalized)

    def _visible_capabilities(self, evidence: Dict[str, Any], status: str = "visible") -> Set[str]:
        capabilities: Set[str] = set()
        for item in evidence.get("Capability Evidence", []):
            cap = str(item.get("capability", "")).strip()
            cap_status = str(item.get("status", "")).strip()
            if cap in CAPABILITY_ATOMS and cap_status == status:
                capabilities.add(cap)
        return capabilities

    def _has_reachable_path(self, evidence: Dict[str, Any]) -> bool:
        for item in evidence.get("Entrypoints", []):
            reachability = str(item.get("reachability", "")).strip()
            if reachability in {"reachable", "conditional"}:
                return True
        return False

    def _has_data_flow(self, evidence: Dict[str, Any], linkage_levels: Iterable[str]) -> bool:
        allowed = set(linkage_levels)
        for item in evidence.get("Data Flows", []):
            linkage = str(item.get("linkage", "")).strip()
            if linkage in allowed:
                return True
        return False

    def _has_critical_unknown(self, evidence: Dict[str, Any]) -> bool:
        for item in evidence.get("Undefined Dependencies", []):
            if str(item.get("impact", "")).strip() == "critical":
                return True
        return False

    def _type_full_requirements_met(self, malware_type: str, evidence: Dict[str, Any]) -> bool:
        visible = self._visible_capabilities(evidence, status="visible")

        if malware_type == "Type A":
            return TYPE_REQUIREMENTS["Type A"].issubset(visible) and self._has_data_flow(evidence, {"clear", "partial"})
        if malware_type == "Type B":
            network_ok = "network_connect" in visible or "network_listen" in visible
            return network_ok and TYPE_REQUIREMENTS["Type B"].issubset(visible)
        if malware_type == "Type C":
            return TYPE_REQUIREMENTS["Type C"].issubset(visible)
        if malware_type == "Type D":
            return TYPE_REQUIREMENTS["Type D"].issubset(visible)
        if malware_type == "Type E":
            return TYPE_REQUIREMENTS["Type E"].issubset(visible)
        if malware_type == "Type F":
            return TYPE_REQUIREMENTS["Type F"].issubset(visible)
        if malware_type == "Type G":
            payload_caps = {
                "execute_code_or_command",
                "destroy_or_overwrite_data",
                "encrypt_or_lock_data",
                "network_send",
                "handoff_execution",
            }
            return "trigger_condition" in visible and bool(payload_caps & visible)
        if malware_type == "Type H":
            return "capture_input" in visible and bool({"write_local_artifact", "network_send"} & visible)
        if malware_type == "Type I":
            return "builder_generate_artifact" in visible
        if malware_type == "Type J":
            return TYPE_REQUIREMENTS["Type J"].issubset(visible)
        if malware_type == "Type K":
            return "disrupt_system" in visible and self._has_reachable_path(evidence)
        if malware_type in {
            "Type L (L-File/Device Worm)",
            "Type L (L-Network Worm)",
        }:
            return TYPE_REQUIREMENTS[malware_type].issubset(visible)
        if malware_type == "Type M":
            high_impact_caps = {
                "destroy_or_overwrite_data",
                "encrypt_or_lock_data",
                "execute_code_or_command",
                "disrupt_system",
                "network_send",
                "handoff_execution",
            }
            return bool(high_impact_caps & visible) and self._has_reachable_path(evidence)
        return False

    def _post_validate_final_assessment(
        self,
        evidence: Dict[str, Any],
        step1: Dict[str, Any],
        step2: Dict[str, Any],
    ) -> Dict[str, Any]:
        result = dict(step2)
        malware_type = result.get("Malware_Type") or step1.get("Malware Type") or "None"
        malware_type = self._normalize_malware_type(malware_type)
        result["Malware_Type"] = malware_type

        if result["Classification"] == "Benign Artifact" and step1.get("Detected Category") == "Malicious":
            result["Classification"] = "Undetermined Call Chain"
            if result.get("Missing_Components") == "None":
                result["Missing_Components"] = "Intent and completeness disagree; evidence is not strong enough for benign"

        if result["Classification"] == "Full Attack Chain":
            if malware_type == "None":
                result["Classification"] = "Undetermined Call Chain"
                result["Missing_Components"] = "No stable malware type selected for a full-chain claim"
            elif self._has_critical_unknown(evidence):
                if not self._type_full_requirements_met(malware_type, evidence):
                    result["Classification"] = "Core Attack Chain"
                    result["Missing_Components"] = "Critical behavior depends on undefined or external components"
            elif not self._type_full_requirements_met(malware_type, evidence):
                result["Classification"] = "Core Attack Chain"
                result["Missing_Components"] = "Visible slice does not satisfy all full-chain requirements"

        if result["Classification"] == "Core Attack Chain" and step1.get("Detected Category") == "Benign":
            result["Classification"] = "Undetermined Call Chain"
            if result.get("Missing_Components") == "None":
                result["Missing_Components"] = "Intent and capability assessment disagree"

        if result["Classification"] == "Undetermined Call Chain" and step1.get("Detected Category") == "Benign":
            result["Threat_Level"] = "Low"

        result["Post_Validation"] = "applied"
        return result

    def malware_analyze_three_steps(self, code_snippet: str) -> Dict[str, Any]:
        normalized_code = self._normalize_code_snippet(code_snippet)
        evidence = self._extract_evidence(normalized_code)
        step1 = self._classify_intent(normalized_code, evidence)
        step2 = self._assess_capability(normalized_code, evidence, step1)
        return {
            "Evidence": evidence,
            "Step1": step1,
            "Step2": step2,
        }

    def malware_analyze(self, code_snippet: str, return_trace: bool = False) -> Dict[str, Any]:
        result = self.malware_analyze_three_steps(code_snippet)
        if return_trace:
            return result
        return result["Step2"]


if __name__ == "__main__":
    code_dir = "/home/lxy/lxy_codes/mal_update_detect/joern_output/multiple_commits/"
    arg = "crypto-clipper,0,dfe2b,NEW@<module>@main.py_slice.py"
    repo_path = os.path.join(code_dir, arg.split(",")[0])
    slice_path = ""
    for slice_dir in os.listdir(repo_path):
        if arg.split(",")[1] == slice_dir.split("_")[0] and arg.split(",")[2] == slice_dir.split("_")[1]:
            slice_path = os.path.join(repo_path, slice_dir)
    code_path = os.path.join(slice_path, "taint_slices_methods", arg.split(",")[3])

    with open(code_path, "r", encoding="utf-8") as f:
        code_snippet = f.read()

    llm_evaluate = LLM_Evaluate_V3(
        api_key="57bd6c19-3b9f-4cbe-8596-63c472ca47d2",
        base_url="https://ark.cn-beijing.volces.com/api/v3",
    )
    result = llm_evaluate.malware_analyze(code_snippet, return_trace=True)
    out_path = os.path.join(slice_path, f"{os.path.basename(code_path)}_v3.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(json.dumps(result, ensure_ascii=False, indent=2))
