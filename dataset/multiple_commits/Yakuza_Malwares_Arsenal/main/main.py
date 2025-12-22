
""" This is the main file of the Yakuza Pentest Arsenal project
        All submodule's used and combined in this project.

        List of submodules:
            1. YoutubeDL
            2. EmailBomber


Author: Davood.Yakuza
---
Develop Start Date: 11/3/2024 => 14 aban 1403
Develop End Date:

"""

# Step 0: append the current path to sys.path
from pathlib import Path
import sys

projectRoot = Path(__file__).resolve().parent.parent
sys.path.append(str(projectRoot))

# Step 1: Importing Section
import YoutubeDL.YtDl as YoutbuteDL
import EmailBomber.email_bomb as EmailBomb

from miscs.colors import fColors, bColors
from miscs.string_format import stringFormat


# Step 2: Define FUnction to give option from the user
def option_chooser():
    options = f""" {fColors.GREEN}
        Available Module's:
    
            [1] Youtube Downloader
            [2] Email Bomber
        
            [0] Exit 
    """

    print(options)
    option  = int(input(fColors.LIGHT_YELLOW + "[?] Choose Module :$ "))

    if option == 0:
        print(fColors.RED + "[-] Exiting the Yakuza Pentest Arsenal, Goodbye and GoodLuck")
        exit()

    return option

# Step 3: Define the main launcher function
def launcher():
    option = option_chooser()

    if option == 1:
        YoutbuteDL.launcher()

    elif option == 2:
        EmailBomb.launcher()

    else:
        print(fColors.RED + "[-] Invalid Sub Module")

# Main Execution
if __name__ == '__main__':
    launcher()
