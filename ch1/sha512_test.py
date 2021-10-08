import re
from urllib import urlopen
from passlib.hash import sha512_crypt
from time import sleep


def crack_sha(url, salt, crypt_pass):
    try:
         passwd_lst = urlopen(url).read().decode('utf-8')
         for word in passwd_lst.split('\n'):
             # Default SHA-512 uses 5,000 rounds according to docs
             hash_word = sha512_crypt.encrypt(word, salt=salt, rounds=5000)
             guess = hash_word[12:] # I want the portion after the $6$<salt>$ prefix to compare against target password
             if guess == crypt_pass:
                 print "[+] Found password: " + word
                 return
         print "[-] No match found in dictionary."
         return
    except Exception as e:
        print e

# For testing purposes/simplicity, I'm hardcoding the encrypted portion rather than cutting it out of shadow
_crypt_pass = "NyXj0YofkK14MpRwFHvXQW0yvUid.slJtgxHE2EuQqgD74S/GaGGs5VCnqeC.bS0MzTf/EFS3uspQMNeepIAc."
prefix = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/"
url_lst = [
    prefix + "Common-Credentials/10-million-password-list-top-1000000.txt",
    # I was originally going to run against multiple url lists, but after success using this one I decided
    # Keep it as is for now
]

regex = re.compile("(root\W)\s([a-zA-Z0-9]{8,}\W)") # This will pull the username and salt out of shadow
with open ('fake_shadow_file.txt', 'r') as shadow_file:
    for expression in shadow_file.readlines():
        if re.findall(regex, expression): # Just making sure my regex skills are on point...
            target_line = re.match(regex, expression)
            _user, _salt = target_line.group(1).strip(':'), target_line.group(2).strip(':') # Split those 2 fields
            print "[*] Cracking password for the " + _user.upper() + " account...\n"
            sleep(3)
            for item in url_lst: # See comment above for 'url_lst'
                _url = item
                crack_sha(_url, _salt, _crypt_pass)
        else:
            print "[-] Skipping undesired account..."
            # I already cracked this account in my other program using default crypt.method so I don't care