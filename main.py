from subprocess import call
def run_packet_sniffer():
    call(['python','packet_sniffer.py'])
def run_port_scanner():
    call(['python','port_scanner.py'])
while(True):
    print("\n\nWelcome to Scan+Sniff Project\n")
    control=int(input("Enter 1 to sniff out packets\nEnter 2 to scan the ports\nInput: "))
    if control==1:
        run_packet_sniffer()
    if control==2:
        run_port_scanner()
    check=input("\nEnter y or Y to continue operations: ")
    if check!='y' and check!='Y':
        break