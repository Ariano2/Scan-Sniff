import socket,threading
from datetime import datetime
try:
    host="localhost"
    host_ip=socket.gethostbyname(host)
    print(host)
    print(host_ip)
except socket.gaierror:
    print("Host Could Not be Found!")
    exit(1)

threads=[]
open_ports={}

def check_ports(ip,port,delay,open_ports):
    try:
        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(delay)
        result=sock.connect_ex((ip,port))
        if result==0:
            # port is open
            open_ports[port]='open'
    except socket.gaierror:
        print("Host Could Not be Found!")
    except socket.error:
        print("Socket Error Encountered while connecting to server!")
def scanning_ports(host_ip,delay,file_reference):
    for port in range (0,65535):
        thread=threading.Thread(target=check_ports,args=(host_ip,port,delay,open_ports))
        threads.append(thread)

    for i in range (0,65535):
        threads[i].start()

    for i in range (0,65535):
        threads[i].join()
    file_reference.write("\n\nOpen Ports are:")
    print("Open Ports are:\n")
    for key,value in open_ports.items():
        print(str(key))
        file_reference.write("\n"+str(key))

file_reference=open("port_scan_results.txt","w")
file_reference.write("Host - "+host+"\n")
file_reference.write("IP - "+host_ip+"\n")
start_time=datetime.now()
print("Start Time: {}".format(start_time))
file_reference.write("\nScan Initiated At: {}\n".format(start_time))
print("\n")
scanning_ports(host_ip,0.001,file_reference)
end_time=datetime.now()
print("\n")
print("End Time: {}".format(end_time))
file_reference.write("\n\nScan Completed At: {}\n".format(end_time))
total_time=end_time-start_time
print("\n")
print("Total Time: {}".format(total_time))
file_reference.write("\nScan Duration: {}".format(total_time))

