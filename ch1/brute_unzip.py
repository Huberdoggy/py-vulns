import zipfile, optparse
from urllib import urlopen


def extract_file(_z_file, password):
    try:
        _z_file.extractall(pwd=password)  # feed 'password' param from each word/line in Seclist
        return password
    except:
        return # since main will continue for each word in dict, this will just prevent terminal output


parser = optparse.OptionParser("usage: %prog -f <zipfile>")
parser.add_option('-f', dest='zname', type='string', help='specify zip file')
(options, args) = parser.parse_args()
if options.zname == None:
    print parser.usage
    exit(0)
else:
    zname = options.zname
    z_file = zipfile.ZipFile(zname)
    url_pt1 = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
    url_pt2 = "Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"
    pass_lst = urlopen(url_pt1 + url_pt2).read().decode('utf-8')
    count = 0
    for _password in pass_lst.split('\n'):
        count += 1
        guess = extract_file(z_file, _password) # store the return value...
        if guess:
            print "[+] Found password = {}".format(guess) + " in " + str(count) + " attempts"
            exit(0)
        else:
            print "[-] No password. Number of attempts: " + str(count)