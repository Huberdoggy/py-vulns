import crypt
import hashlib
from urllib import urlopen


def test_pass(crypt_pass, account_name):
    if account_name != str('root'):
        salt = crypt_pass[:2]  # The first 2 chars in the encryped word we're feeding the function (corresponds to
        # the field one from my fake /etc/shadow file. This param satisfies the default/weak Crypt.METHOD
        with open('dictionary.txt', 'r') as dictFile:
            for word in dictFile.readlines():
                word = word.strip('\n')  # eliminate the EOL returns
                crypt_word = crypt.crypt(word, salt)  # Will take in the plain English 'word' and we pass it 2 chars
                # from our hashed pass field (i.e '1', as 2nd param for crypt.crypt) to generate a hashed string
                if crypt_word == crypt_pass:
                    print "[+] Found Password: " + word + "\n"
                    return
            # default else if word list is exhausted..
            print "[-] Password NOT found.\n"
            return
    else:  # We are targeting the 'root' user pass hash
        salt = crypt_pass[:13]  # changing the salt to correspond to 13 chars in field 1
        hash_obj_5 = hashlib.sha512()
        hash_obj_5.update(salt.encode())
        sha_512_hash = hash_obj_5.hexdigest()
        try:  # I need a REALLY big wordlist ....
            url_pt1 = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
            url_pt2 = "Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"
            passwd_lst = urlopen(url_pt1 + url_pt2).read().decode('utf-8')
            for password in passwd_lst.split('\n'):
                password = password.encode('utf-8')
                guess = hashlib.sha512(bytes(password)).hexdigest()
                # password = password.encode('utf-8') # Ensure each individual passwd is passed as UTF-8 NOT unicode
                # crypt_word = crypt.crypt(password, "$6${}".format(salt))
                # This will force SHA512 hashing (i.e $6$ shorthand)
                # print crypt_word
                # guess = crypt_word[3:16] # This cuts the newly generated hash between the '$6$' and trailing '$'
                if guess == sha_512_hash:
                    print "[+] Found password: " + password
                    break
                else:
                    print "[-] No match " + str(sha_512_hash) + " against " + str(guess)
        except Exception as e:
            print e


with open('fake_shadow_file.txt') as pass_file:
    for line in pass_file.readlines():
        if ":" in line:
            user = line.split(":")[0]  # Field zero holds our usernames
            _crypt_pass = line.split(":")[1].strip()  # stores field after username - the hashed pass
            if user == 'root':
                print "[*] Cracking password for the " + user.upper() + " account...\n"
            else:
                print "[*] Cracking password for: " + user + "\n"
            test_pass(_crypt_pass, user)
