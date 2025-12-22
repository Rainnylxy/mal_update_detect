import json
import datetime

class FormatterUtils:
    @staticmethod
    def format_log_entry(timestamp: datetime.datetime, keystroke: str) -> str:
        return f"{timestamp.isoformat()} - Keystroke: {keystroke}"

    @staticmethod
    def format_json(data: dict) -> str:
        try:
            return json.dumps(data, indent=4)
        except (TypeError, ValueError) as e:
            raise ValueError(f"Failed to format data as JSON: {e}")

    @staticmethod
    def parse_json(json_string: str) -> dict:
        try:
            return json.loads(json_string)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse JSON string: {e}")

    @staticmethod
    def format_timestamp() -> str:
        return datetime.datetime.now().isoformat()
