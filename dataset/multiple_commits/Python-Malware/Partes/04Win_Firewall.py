import subprocess

try:
    subprocess.check_call('netsh.exe advfirewall set allprofiles state off')
except:
    print 'UUID != 0'
