#!/usr/bin/python3
from shutil import which
from os import system,getuid
from colorama import Fore

intro ="""
###############################################################################
#                                                                             #  
#                                                                             #  
#                                                                             #  
#                           REVERSE SHELL GENERATOR                           #      
#                               BY ERUSHA SANDUSHAN                           #
#                                                                             #          
#                                                                             #
#                                                                             #  
#                                                                             #  
############################################################################### 
"""

if getuid() == 0: # Checking Permissions
    print(Fore.GREEN+"\n[*] Installing requirements\n")
    system("pip3 install -r requirements.txt")
    if which('netcat') == None:
        system('apt-get install netcat')
    if which('ncat') == None:
        system('apt-get install ncat')
    if which('openssl') == None:
        system('apt-get install openssl')
    print("\n Installing Revers-Shell-Generator.\n"+Fore.RESET)
    system("cp Reverse-Shell-Generator.py /usr/sbin/reverseshellgenerator && chmod +x /usr/sbin/reverseshellgenerator") # Copying Tool For PATH
    print(intro)
    print(Fore.GREEN + "\n\n[*] Finished.")
    print("\n[+] Run "+Fore.BLUE+"reverseshellgenerator "+Fore.RESET+" to start the Reverse Shell Generator")
