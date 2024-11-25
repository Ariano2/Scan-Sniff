from subprocess import call
def run_packet_sniffer():
    call(['python','packet_sniffer.py'])
def run_port_scanner():
    call(['python','port_scanner.py'])
def run_password_generator():
    call(['python','password_generator.py'])
while(True):
    print("\n\nWelcome to Network Scanner Project\n")
    control=int(input("Enter 1 to sniff out packets\nEnter 2 to scan the ports\nEnter 3 to generate passwords\nEnter 4 to exit\nInput: "))
    if control==1:
        run_packet_sniffer()
    elif control==2:
        run_port_scanner()
    elif control==3:
        run_password_generator()
    elif control==4:
        exit()
    else:
        print("Invalid Input please retry!")
    check=input("\nEnter y or Y to continue operations: ")
    if check!='y' and check!='Y':
        break