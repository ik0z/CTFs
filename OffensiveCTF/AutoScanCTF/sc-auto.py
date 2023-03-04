#!/usr/bin/python3
import os,requests,sys,time
from termcolor import colored, cprint
import socket as sock
import os , sys ,os.path,signal,subprocess,random,requests , shutil,termcolor , platform,ipaddress
from sys import platform
from datetime import datetime



#--------- status 
info = termcolor.colored("[!]",'cyan')
oka = termcolor.colored("[+]",'green')
good = termcolor.colored("[✔]",'green',attrs=['bold'])
opn = termcolor.colored("[Discovery all open ports]",'green')
fai = termcolor.colored("[X]",'red')
err = termcolor.colored("[?]",'yellow')
inpu = termcolor.colored("$",'magenta')
kaz = termcolor.colored("ENG. Khaled",'red')

#----------------- functions 
#--- python scanner port -- This code is copy from internet  
import threading
from queue import Queue
import time
import socket
# a print_lock is what is used to prevent "double" modification of shared variables.
# this is used so while one thread is using a variable, others cannot access
# it. Once done, the thread releases the print_lock.
# to use it, you want to specify a print_lock per thing you wish to print_lock.
def pythsc():
    print_lock = threading.Lock()

    ipadd1 = ipadd

    cprint("\n---------------------------------------------------",'cyan',attrs=['bold'])
    cprint("          Python Ports scanner                        ",'cyan',attrs=['bold'])
    cprint("       {}      ".format(opn))
    cprint("\n---------------------------------------------------",'cyan',attrs=['bold'])
    def portscan(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            con = s.connect((ipadd1,port))
            with print_lock:
                if port == 80 :
                    print("{} ".format(oka),port,"      HTTP")
                elif port == 443 :
                    print("{} ".format(oka),port,"      HTTPs")
                elif port == 21 :
                    print("{} ".format(oka),port,"      FTP")
                elif port == 22 :
                    print("{} ".format(oka),port,"      SSH")
                elif port == 445 :
                    print("{} ".format(oka),port,"      SMB")
                elif port == 53 :
                    print("{} ".format(oka),port,"      DNS")
                elif port == 3389 :
                    print("{} ".format(oka),port,"      RDP") 
                elif port == 111 :
                    print("{} ".format(oka),port,"      NFS") 

                else :
                    print("{} ".format(oka),port)   
            con.close()
        except:
            pass


    # The threader thread pulls an worker from the queue and processes it
    def threader():
        while True:
            # gets an worker from the queue
            worker = q.get()
            # Run the example job with the avail worker in queue (thread)
            portscan(worker)
            # completed with the job
            q.task_done()


    # Create the queue and threader 
    q = Queue()

    # how many threads are we going to allow for
    for x in range(100):
        t = threading.Thread(target=threader)
        # classifying as a daemon, so they will die when the main dies
        t.daemon = True
        # begins, must come after daemon definition
        t.start()


    start = time.time()

    # 100 jobs assigned.
    for worker in range(1,10024):
        q.put(worker)

    # wait until the thread terminates.
    q.join()

#--- end 
#--- Gobuster func
def gobust(ipadd,pro):
    print("[1] Common   list")
    print("[2] Big      list")
    list_da = input("{} default [Big] $> ".format(info))
    cprint("\n{} Gobuster result :".format(oka))
    cprint("---------------------------------------------------",'cyan')
    #http
    if pro == 1 : 
        if list_da == 1 :
            os.system("gobuster dir -u http://{}/  -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -q".format(ipadd))
        elif list_da == 2 :
            os.system("gobuster dir -u http://{}/  -w /usr/share/wordlists/dirb/big.txt  -q".format(ipadd))
        else :
            os.system("gobuster dir -u http://{}/  -w /usr/share/wordlists/dirb/big.txt  -q".format(ipadd))
    #https
    if pro == 2 : 
        if list_da == 1 :
            os.system("gobuster dir -u https://{}/  -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -q".format(ipadd))
        elif list_da == 2 :
            os.system("gobuster dir -u https://{}/  -w /usr/share/wordlists/dirb/big.txt -q".format(ipadd))
        else :
            os.system("gobuster dir -u https://{}/  -w /usr/share/wordlists/dirb/big.txt -q".format(ipadd))
    cprint("\n---------------------------------------------------",'cyan')

#--- Handling with CTRL+C 
def signal_handler(signal, frame):
    cprint("\n Goodbye",'grey',attrs=['bold'])
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

#--- ping Online or offline 
def pinip():
    try :
        response = subprocess.run(["ping", "-c 1", "{}".format(ipadd)], capture_output=True)
    except :
        response = os.system("ping -c 1 " + ipadd)
    if response.returncode == 0 or response==0:
        cprint('{} '.format(good)+ipadd+' is up!')
        return 0
    else:
        cprint('{} '.format(fai)+ipadd+' is down!','red',attrs=['bold'])
        return 1

#----- check port 
def posc(ipadd,port):
    create_socket = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
    destination = (ipadd,port)
    result = create_socket.connect_ex(destination)
    if result == 0:
        print('\n')
        cprint("="*60,'cyan',attrs=['bold'])
        print("{} Port is open : {}".format(oka,port))
        return 1
    else:
        print('\n')
        print("{} Close : {}".format(fai,port))
        return 0
    create_socket.close()
#----- logo 
def logome():
    cprint("""
  _                   
 | |       /\         
 | | __   /  \    ____
 | |/ /  / /\ \  |_  /
 |   <  / ____ \  / /     
 |_|\_\/_/    \_\/___|    Version 1.0.0                              
{} | CTF Auto scanner
    """.format(kaz),'cyan',attrs=['bold'])


#------ start execute script from here :) 
try : 
    logome()
    ipadd = input("└─{} Enter IP address :".format(inpu))
    while True : 
        if pinip()== 0 :
            #cprint("\n---------------------------------------------------",'cyan',attrs=['bold'])
            print('\n')
            cprint("="*60,'cyan',attrs=['bold'])
            cprint("{} Nmap Simple scanning ...".format(info))
            print('\n')
            cprint("-"*60,'cyan',attrs=['bold'])
            os.system("sudo nmap -sV "+ipadd)
            cprint("Run $sudo nmap -sV -sC -A {} ?[N/y]".format(ipadd),'yellow')
            nmad = input(">")
            while True :
                if  nmad == 'y' :
                        
                    print('\n')
                    cprint("="*60,'cyan',attrs=['bold'])
                    cprint("{} Nmap Scaning ...".format(info))
                    print('\n')
                    cprint("="*60,'cyan',attrs=['bold'])
                    os.system("sudo nmap -sV -sC -A "+ipadd)
                    print('\n')
                    cprint("="*60,'cyan',attrs=['bold'])
                    break
                else :
                    break
            if posc(ipadd,80) == 1 :
                print('\n')
                cprint("="*60,'cyan',attrs=['bold'])
                cprint("{} HTTP Gobuster BF".format(oka),attrs=['bold'])
                print('\n')
                cprint("="*60,'cyan',attrs=['bold'])
                gobust(ipadd,1)
            elif posc(ipadd,443)==1 :
                cprint("-"*60,'cyan',attrs=['bold'])
                cprint("{} HTTPs Gobuster BF".format(oka),attrs=['bold'])
                print('\n')
                cprint("="*60,'cyan',attrs=['bold'])
                gobust(ipadd,2)
            #gobust(ipadd)
            if posc(ipadd,445)==1:
                print('\n')
                cprint("="*60,'cyan',attrs=['bold'])
                cprint("{} SMB was detected !".format(oka),attrs=['bold'])
                print('\n')
                cprint("="*60,'cyan',attrs=['bold'])
                os.system("nmap --script smb-enum-shares.nse -p445 "+ipadd)
                cprint("-"*30,'cyan',attrs=['bold'])
            if posc(ipadd,445)==1:
                print('\n')
                cprint("="*60,'cyan',attrs=['bold'])
                cprint("{} FTP was detected !".format(oka),attrs=['bold'])
                print('\n')
                cprint("="*60,'cyan',attrs=['bold'])
                os.system("nmap --script ftp-anon.nse,ftp-bounce.nse,ftp-syst.nse,tftp-enum.nse -p21 "+ipadd)
            if posc(ipadd,3389)==1:
                print('\n')
                cprint("="*60,'cyan',attrs=['bold'])
                cprint("{} RDP was detected !".format(oka),attrs=['bold'])
                print('\n')
                cprint("="*60,'cyan',attrs=['bold'])
                os.system("nmap -p 3389 --script rdp-* "+ipadd)
            if posc(ipadd,111)==1 :
                print('\n')
                cprint("="*60,'cyan',attrs=['bold'])
                cprint("{} NFS was detected !".format(oka),attrs=['bold'])
                print('\n')
                cprint("="*60,'cyan',attrs=['bold'])
                os.system("nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount "+ipadd)
            else :
                print("\n")
                cprint("="*60,'cyan',attrs=['bold'])
                cprint("\n {} Nothing more :( !".format(fai),attrs=['bold'])

            pythsc()
            break
        else :
            cprint("{} Check The OpenVPN or IP Address".format(err),attrs=['bold'])
            print('\n')
            askre = input("└─> {}  retry ? Yes [Enter] / No [x] ".format(info))
            if askre.lower()=='x' :
                break
            elif askre=='' : 
                pass  
            else : 
                cprint("{} Invalid input ".format(err),attrs=['bold']) 

except Exception():
    cprint("{} Error was found ".format(err),attrs=['bold']) 

#------------ End  

print('\n',info,' Finished see ya :$')

