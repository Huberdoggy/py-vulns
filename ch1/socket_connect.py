import socket, re

def ret_banner(ip, port):
    try:
        socket.setdefaulttimeout(2)  # in seconds
        s = socket.socket()  # instantiate new socket, assigned to 's' variable
        s.connect((ip, port)) # Accepts a tuple argument (attempt to connect to my custom ssh port)
        banner = s.recv(1024)  # provide buffer-size arg -> will return first 1024 bytes
        return banner
    except Exception as e:
        print "[-] Error = " + str(e)
        return False


def check_version(banner): # Simulate a fake vuln check if condition ID's banner version >= 2.0, call it good
    pattern = re.compile("[A-Z]{3}\W2\.[0-5]")
    match = pattern.search(banner)
    if match:
        print "[+] Match FOUND in provided banner: {}".format(match.group())
        strip_reg = re.compile("[^2]")
        new_pattern = strip_reg.sub("", banner)
        new_pattern = int(new_pattern)
        return new_pattern


while True:
    ask_ip = raw_input("Enter the ip of the target machine: ")
    if ask_ip != "":
        if ask_ip == "q":
            break
        else:
            ask_port = raw_input("Enter the port number to identify SSH banner info: ")
            if ask_port == "q":
                break
            elif ask_port == "":
                print "Please enter something..."
            else:
                ask_port = int(ask_port)
                banner = ret_banner(ask_ip, ask_port)
                if banner:
                    print "[+] Successfully identified SSH version runningg on target => {}".format(banner)
                    is_version_greater = check_version(banner)
                    if is_version_greater >= 2:
                        print "[+] SSH is secure with version of at least: {}".format(is_version_greater)
    else:
        print "Please enter something..."
        continue
