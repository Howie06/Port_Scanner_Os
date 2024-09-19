import sys
import threading
from queue import Queue
from scapy.all import *
import socket
import logging
from scapy.layers.inet import IP, ICMP
from concurrent.futures import ThreadPoolExecutor, as_completed

# 阻止scapy的报错信息
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)



def port_scan(ip, port, open_ports):
    try:
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.2)  
        sock.connect((ip, port))  
        open_ports.put(port)  
        sock.close()  
    except:
        pass  



def analyze_os(ip, port):
    try:
        ans = sr1(IP(dst=ip) / ICMP(id=RandShort()), timeout=1, retry=2, verbose=0)

        if ans:  
            ttl = ans[IP].ttl  

            
            if ttl <= 64:
                os_guess = "Linux or Unix"
            elif ttl == 108:
                os_guess = "Window2000"
            elif ttl == 107:
                os_guess = "win NT"
            elif ttl == 127:
                os_guess = "win9x"
            elif ttl == 252:
                os_guess = "Solaris"
            elif ttl == 128:
                os_guess = "Windows"
            else:
                os_guess = "Unix"

           
            print(f"{ip}, port open: {port}, TTL: {ttl}, OS: {os_guess}")

    except Exception as e:
        pass 



def port_scan_all(ip):
    open_ports = Queue()  

    # 用 ThreadPoolExecutor 创建一个有50个threads的 pool
    with ThreadPoolExecutor(max_workers=50) as executor:
        # 将所有的扫描端口的task提交到thread pool里
        futures = [executor.submit(port_scan, ip, port, open_ports) for port in range(1, 65536)]

        # 等待所有的threads完成
        for future in as_completed(futures):
            pass

    open_port_list = []  
    while not open_ports.empty():
        open_port_list.append(open_ports.get())

    return open_port_list


# 检测os和检测端口的main function
def main():
    if len(sys.argv) == 2:  # 如果有target IP地址
        ip_target = sys.argv[1]

        # 开始检测端口并获得开放端口
        open_ports = port_scan_all(ip_target)

        # 分析每一个开放端口的TTL来猜测OS
        for port in open_ports:
            analyze_os(ip_target, port)

    else:  # 如果没能找到 Target Ip
        print("Correct usage: script, IP address target")
        sys.exit(0)


# 执行 main function
if __name__ == "__main__":
    main()