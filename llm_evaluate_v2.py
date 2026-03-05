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
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    ec,
    padding as asymmetric_padding,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
class ECC:
        return serialized_public_key
class RSA:
    def decrypt_data(self, encrypted_data):
        unencrypted_data = self._private_key.decrypt(
            encrypted_data, self._get_padding()
        )
        return unencrypted_data
        return serialized_public_key
import sqlite3
import logging
def create_connection():
    try:
        connection = sqlite3.connect("data.db")
        return connection
    except Exception as err:
        raise err
def create_tables():
    connection = create_connection()
    cursor = connection.cursor()
    statistics_table = """CREATE TABLE IF NOT EXISTS `statistics` (`client_id` VARCHAR(100) NOT NULL,`platform` VARCHAR(75) DEFAULT NULL,`architecture` VARCHAR(75) DEFAULT NULL,`ip_address` VARCHAR(75) DEFAULT NULL,`mac_address` VARCHAR(75) DEFAULT NULL,`device_name` VARCHAR(75) DEFAULT NULL,`username` VARCHAR(75) DEFAULT NULL,`is_admin` BOOLEAN DEFAULT NULL DEFAULT NULL, `created_time` TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (`client_id`));"""
    cursor.execute(statistics_table)
    bitcoin_details = """CREATE TABLE IF NOT EXISTS `bitcoin_details` (`client_id` VARCHAR(100) NOT NULL,`wallet_address` VARCHAR(1000) NOT NULL,`public_key` VARCHAR(1000) NOT NULL,`wif_private_key` VARCHAR(1000) NOT NULL, `created_time` TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (`client_id`,`wallet_address`));"""
    cursor.execute(bitcoin_details)
    payment_details = """CREATE TABLE IF NOT EXISTS `payment_details` (`client_id` VARCHAR(100) NOT NULL,`payee_address` VARCHAR(1000) NOT NULL,`is_decrypted` BOOLEAN NOT NULL, `created_time` TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (`client_id`));"""
    cursor.execute(payment_details)
    connection.commit()
    connection.close()
def insert_statistics_to_database(statistics):
    try:
        logger.info("Inserting statistics into database")
        connection = create_connection()
        cursor = connection.cursor()
        statistics_insert_query = "INSERT INTO `statistics` (client_id, platform, architecture, ip_address, mac_address, device_name, username, is_admin) VALUES (:client_id, :platform, :architecture, :ip_address, :mac_address, :device_name, :username, :is_admin);"
        cursor.execute(statistics_insert_query, statistics)
        connection.commit()
        connection.close()
    except sqlite3.IntegrityError as err:
        logger.error(f"{err}: Client ID already present")
def insert_bitcoin_details_to_database(
    client_id, wallet_address, wif_encoded_private_key, public_key
    connection = create_connection()
    cursor = connection.cursor()
    bitcoin_details_insert_query = "INSERT INTO `bitcoin_details` (client_id, wallet_address, public_key, wif_private_key) VALUES (?, ?, ?, ?);"
    cursor.execute(
        [client_id, wallet_address, public_key, wif_encoded_private_key],
    )
    connection.commit()
    connection.close()
def get_bitcoin_wallet_id_database(client_id):
    connection = create_connection()
    cursor = connection.cursor()
    wallet_query = "SELECT wallet_address FROM `bitcoin_details` where client_id = ?;"
    result = cursor.execute(wallet_query, [client_id])
    id = result.fetchone()
    connection.close()
    if id is not None:
        return id[0]
def insert_payment_details_into_database(client_id, payee_wallet_address):
    connection = create_connection()
    cursor = connection.cursor()
    payment_details_insert_query = "INSERT INTO `payment_details`(client_id, payee_address, is_decrypted) VALUES (?, ?, ?)"
    cursor.execute(
        payment_details_insert_query, [client_id, payee_wallet_address, True]
    )
    connection.commit()
    connection.close()
import hashlib
import logging
import blockcypher
from asymmetric_encryption import ECC
from db import (
    insert_bitcoin_details_to_database,
    get_bitcoin_wallet_id_database,
    insert_payment_details_into_database,
)
def sha256(data):
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()
def ripemd160(data):
    ripemd160 = hashlib.new("ripemd160")
    ripemd160.update(data)
    return ripemd160.hexdigest()
def b58encode(data):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    b58_string = ""
    leading_zeros = len(data) - len(data.lstrip("0"))
    address_int = int(data, 16)
    while address_int > 0:
        digit = address_int % 58
        digit_char = alphabet[digit]
        b58_string = digit_char + b58_string
        address_int //= 58
    ones = leading_zeros // 2
    for _ in range(ones):
        b58_string = "1" + b58_string
    return b58_string
def generate_bitcoin_wallet_address(public_key):
    hashed_public_key_hex = ripemd160(bytes.fromhex(sha256(public_key)))
    key_with_network_byte = f"00{hashed_public_key_hex}"
    checksum = sha256(bytes.fromhex(sha256(bytes.fromhex(key_with_network_byte))))
    address_in_hex_format = f"{key_with_network_byte}{checksum[:8]}"
    wallet_address = b58encode(address_in_hex_format)
    return wallet_address
def encode_private_key_in_wif(private_key):
    private_key_in_hex = private_key.hex()
    network_byte = "80"
    first_four_bytes_of_checksum = sha256(
        bytes.fromhex(sha256(bytes.fromhex(f"{network_byte}{private_key_in_hex}")))
    )[0:8]
    key_in_hex = f"{network_byte}{private_key_in_hex}{first_four_bytes_of_checksum}"
    key_in_wif = b58encode(key_in_hex)
    return key_in_wif
def generate_bitcoin_address(client_id):
    logger.info(f"Generating bitcoin payment addresses for {client_id}")
    cipher = ECC()
    serialized_private_key = cipher.private_key
    serialized_public_key = cipher.public_key
    wallet_address = get_bitcoin_wallet_id_database(client_id)
    if wallet_address:
        return wallet_address
    wallet_address = generate_bitcoin_wallet_address(serialized_public_key)
    wif_encoded_private_key = encode_private_key_in_wif(serialized_private_key)
    insert_bitcoin_details_to_database(
        serialized_public_key.decode(),
    )
    logger.info(f"Successfully inserted bitcoin details for {client_id}")
    return wallet_address
def verify_payment(client_id, assigned_wallet_address, payee_wallet_address):
    if not assigned_wallet_address == get_bitcoin_wallet_id_database(client_id):
        logger.error("Given wallet address does not match with assigned wallet address")
        return None
    address_details = blockcypher.get_address_overview(assigned_wallet_address)
    if address_details.get("balance") > 5328:
        insert_payment_details_into_database(client_id, payee_wallet_address)
        return True
    return True  # For testing
import logging
import random
from flask import Flask, request, json, Response
from werkzeug import exceptions
from utils import process_request
from db import create_tables
def initialise():
    return process_request(request, "initialise")
def decrypt():
    return process_request(request, "decrypt")
import logging
import requests
import ipaddress
import random
from asymmetric_encryption import RSA
from base64 import b64encode, b64decode
from payment import verify_payment, generate_bitcoin_address
from db import insert_statistics_to_database
from validation import validate_decryption_request, validate_initialisation_request
def decrypt_rsa_data(encrypted_key):
    logger.info("Decrypting RSA data")
    cipher = RSA()
    unencrypted_local_private_key = b"".join(
        [cipher.decrypt_data(key_part) for key_part in encrypted_key]
    )
    payload = {"key": b64encode(unencrypted_local_private_key).decode("ascii")}
    logger.info(f"Returning Payload: {payload}")
    return payload
def unpack_decrypt_request(request_parameters):
    client_id = request_parameters.get("client_id")
    private_key = [b64decode(part) for part in request_parameters.get("private_key")]
    assigned_wallet_address = b64decode(
        request_parameters.get("assigned_wallet_address")
    ).decode()
    payee_wallet_address = b64decode(
        request_parameters.get("payee_wallet_address")
    ).decode()
    return client_id, private_key, assigned_wallet_address, payee_wallet_address
def unpack_initialise_request(request_parameters):
    client_id = request_parameters.get("client_id")
    statistics = request_parameters.get("statistics")
    return client_id, statistics
def format_and_insert_statistics_to_database(client_id, statistics, request):
    statistics["client_id"] = client_id
    if request.headers.getlist("X-Forwarded-For"):
        ip = ipaddress.ip_address(request.headers.getlist("X-Forwarded-For")[0])
    else:
        ip = ipaddress.ip_address(request.remote_addr)
    statistics["ip_address"] = str(ip)
    insert_statistics_to_database(statistics)
def process_request(request, request_type):
    parameters = request.get_json()
    if request_type == "initialise" and validate_initialisation_request(parameters):
        client_id, statistics = unpack_initialise_request(parameters)
        wallet_id = generate_bitcoin_address(client_id)
        format_and_insert_statistics_to_database(client_id, statistics, request)
        return {"client_id": client_id, "wallet_id": wallet_id}
    elif request_type == "decrypt" and validate_decryption_request(parameters):
        client_id, private_key, assigned_wallet_address, payee_wallet_address = unpack_decrypt_request(parameters)
        if verify_payment(client_id, assigned_wallet_address, payee_wallet_address):
            return decrypt_rsa_data(private_key)
import logging
from cerberus import Validator
from werkzeug.exceptions import BadRequest
initialisation_parameters = {
}
decryption_parameters = {
}
def validate_decryption_request(parameters):
    logger.info("Validating decrypt parameters")
    decryption_validator = Validator(decryption_parameters)
    result = decryption_validator.validate(parameters)
    if result:
        return True
    logger.error("Validation Failed: {0}".format(decryption_validator.errors))
    raise BadRequest
def validate_initialisation_request(parameters):
    logger.info("Validating initialisation parameters")
    initialisation_validator = Validator(initialisation_parameters)
    result = initialisation_validator.validate(parameters)
    if result:
        return True
    logger.error("Validation Failed: {0}".format(initialisation_validator.errors))
    raise BadRequest


'''

    llm_evaluate = LLM_Evaluate(
        api_key="57bd6c19-3b9f-4cbe-8596-63c472ca47d2",
        base_url="https://ark.cn-beijing.volces.com/api/v3"
    )
    sensitive_api_result = llm_evaluate.malware_analyze_two_steps(code_snippet)
    print(sensitive_api_result)
