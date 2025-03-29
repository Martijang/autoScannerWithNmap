#Thank you for some of my friends that helped me to learn python-nmap.

import nmap
import sys
import requests
import pyfiglet
import random

ran = random.randint(1,3)
host = sys.argv

nvd_api = "https://services.nvd.nist.gov/rest/json/cves/2.0"
nm = nmap.PortScanner()

def print_banner():
    if ran == 1:
        f1 = pyfiglet.figlet_format("AUTOMATIC", font="slant")
        print(f1)
    elif ran == 2:
        f2 = pyfiglet.figlet_format("I LOV3 YOU", font="block")
        print(f2)
    elif ran == 3:
        f3 = pyfiglet.figlet_format("What a great day")
        print(f3)


def check_arg():
    #Now, this is the hardest one, haha
    if len(host) < 2:
        print("Please enter a ip example: 'python <filename.py> <IP>'")
        sys.exit(1)


def scan_version():
    user_input = input("Enter ports to scan (e.g., 22-80): ")
    
    check_arg()#Idk why but I have to do this for better cuz interprinter won't shut up
    
    target_ip = sys.argv[1]
    
    nm.scan(hosts=target_ip, arguments=f'-p {user_input} -sV')
    
    vulnerabilities = []
    
    for host in nm.all_hosts():
        print(f"\033[34m[INFO]\033[0mHost: {host}")
        print(f"\033[34m[INFO]\033[0mState: {nm[host].state()}")
        
        for proto in nm[host].all_protocols():
            print(f"\033[34m[INFO]\033[0mProtocol: {proto}")
            for port in nm[host][proto]:
                state = nm[host][proto][port]['state']
                service = nm[host][proto][port]['name']
                product = nm[host][proto][port].get('product', 'Unknown')
                version = nm[host][proto][port].get('version', 'Unknown')
                print(f"\033[32m[RESULT]\033[0mPort: {port} | State: {state} | Service: {service} | Product: {product} | Version: {version}")

                if product != 'Unknown' and version != 'Unknown':
                    vulnerabilities.append((product, version))
    
    for product, version in vulnerabilities:
        try:
            params = {
                "keywordSearch": f"{product} {version}",
                "resultPerPage": 5
            }
            response = requests.get(nvd_api, params=params, timeout=10)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if "result" in data and "CVE_Items" in data["result"]:
                        cve_items = data["result"]["CVE_Items"]
                        if cve_items:
                            print(f"\n\033[34m[INFO]\033[0mFound CVE(s) for {product} {version}:")
                            for item in cve_items:
                                cve_id = item["cve"]["CVE_data_meta"]["ID"]
                                description = item["cve"]["description"]["description_data"][0]["value"]
                                print(f"- {cve_id}: {description}")
                        else:
                            print(f"\033[34m[INFO]\033[0mNo known CVEs found for {product} {version}.")
                    else:
                        print(f"\033[33m[WARN]\033[0mNo CVE data found for {product} {version}.")
                except ValueError as ve:
                    print(f"\033[31[ERROR]\033[0m: Invalid JSON format in response for {product} {version}: {ve}")
            elif response.status_code == 404:
                print(f"\033[33m[WARN]\033[0mA current version might not have a vulnerabilites for {product} {version} because: {response.status_code}")
            else:
                print(f"\033[31m[ERROR]\033[0merror: Unable to fetch CVE data from NVD. Status code: {response.status_code}")
        except Exception as e:
            print(f"\033[31m[ERROR]\033[0merror:while checking CVEs for {product} {version}: {e}")

def get_OS_version():

    target_ip = sys.argv[1]
    nm.scan(hosts=target_ip, arguments='-O')
    print(f"\033[34m[INFO]\033[0mTarget: {target_ip}")
    print(f"\033[34m[INFO]\033[0mState: {nm[target_ip].state()}")

    try:
     if 'osmatch' in nm[target_ip]:
       print(f"\033[34m[INFO]\033[0mDeteced OS: {nm[target_ip]['osmatch']}")
       for os_info in nm[target_ip]['osmatch']:
         os_in = os_info['name']
         print(f"\033[34m[INFO]D\033[0mdetected info: {os_in}")#Ik ik, the result looks shitty?Cuz I didn't find any documentation for -O option.. please forgive me
     else:
       print("\033[33[WARN]\033[0mOS not deteced: it might happen because of firewall.")
    except Exception as e:
        print(f"\033[31m[ERROR]\033[0merror deteced while scanning:{e}")

def scan_all():
    target_ip = sys.argv[1]
    nm.scan(hosts=target_ip, arguments='-p- -T4 --open -Pn')
    print(f"\033[34m[INFO]\033[0mTarget: {target_ip}")
    print(f"\033[34m[INFO]\033[0mState: {nm[target_ip].state()}")
    try:
        if 'hostnames' in nm[target_ip]:
         print(f"\033[34m[INFO]\033[0mHostnames: {nm[target_ip]['hostnames']}")
        for proto in nm[target_ip].all_protocols():
         print(f"\033[34m[INFO]\033[0mUsing protocol: {proto}")
        for port in nm[target_ip][proto]:
         state = nm[target_ip][proto][port]['state']
         print(f"\033[34m[INFO]\033[0m port: {port} | State: {state}")
    except Exception as e:
        print(f"\033[31m[ERROR]\033[0merror: while scanning all ports: {e}")

def stealth_scan():
    target_ip = sys.argv[1]
    nm.scan(hosts=target_ip, arguments='-sS -f -p- -D RND:5')
    print(f"\033[34m[INFO]\033[0mTarget: {target_ip}")
    print(f"\033[34m[INFO]\033[0mState: {nm[target_ip].state()}")
    try:
        if 'hostnames' in nm[target_ip]:
         print(f"\033[34m[INFO]\033[0m Hostnames: {nm[target_ip]['hostnames']}")
        for proto in nm[target_ip].all_protocols():
         print(f"\033[34m[INFO]\033[0mUsing protocol: {proto}")
        for port in nm[target_ip][proto]:
         state = nm[target_ip][proto][port]['state']
         print(f"\033[34m[INFO]\033[0mport: {port} | State: {state}")
    except Exception as e:
        print(f"\033[31m[ERROR]\033[0merror: while scanning all ports: {e}")   

def print_help():
    print("""Usage:
                scan all: scanning all ports(no ping scan)
                scan ver: scanning target service version and search for vulnerabilities (testing)
                stealth scan: scanning all ports as -sS (stealth scan) and -f, with -D (makes a lot of fake IPs)WARN: this might take a longggg time
                scan OS: scanning OS
                
                EDIT: for 'scan ver' you may scan a multiple ports by eg: 80,20,10 < like this""")

def main():
    check_arg()
    print_banner()
    while True:
        user_input = input("Please enter a module>")

        if user_input == "help":
            print_help()
        elif user_input == "scan ver":
            scan_version()
        elif user_input == "scan OS":
            get_OS_version()
        elif user_input == "scan all":
            scan_all()
        elif user_input == "stealth scan":
            print("\033[33m[WARN]\033[0mTime: This might take a long time")
            stealth_scan()
        elif user_input == "exit":
            print("\033[34m[INFO]\033[0mExiting, goodbye!")
            sys.exit()
        else:
            print("\033[31m[ERROR]\033[0m Error: invalid command")


if __name__ == "__main__":
    main()
