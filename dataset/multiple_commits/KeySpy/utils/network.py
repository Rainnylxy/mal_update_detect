import requests
from requests.exceptions import RequestException, Timeout
import logging

class NetworkUtils:
    def __init__(self):
        self.logger = logging.getLogger("NetworkUtils")

    def check_connectivity(self, url="http://www.google.com", timeout=5) -> bool:
        try:
            response = requests.get(url, timeout=timeout)
            self.logger.info(f"Network connectivity check to {url}: {response.status_code}")
            return response.status_code == 200
        except (RequestException, Timeout) as e:
            self.logger.warning(f"Connectivity check failed: {e}")
            return False

    def send_post_request(self, url: str, data: dict, headers: dict = None, timeout=10):
        try:
            response = requests.post(url, json=data, headers=headers, timeout=timeout)
            response.raise_for_status()
            self.logger.info(f"POST request to {url} successful: {response.status_code}")
            return response.json()
        except (RequestException, Timeout) as e:
            self.logger.error(f"Failed POST request to {url}: {e}")
            raise
