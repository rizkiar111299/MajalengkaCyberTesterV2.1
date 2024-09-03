import argparse
import logging
from modules import info_gathering, web_crawler, security_tests, report_generator, port_scanner
from tqdm import tqdm
from colorama import init, Fore, Style
from tabulate import tabulate

# Initialize colorama
init(autoreset=True)

def display_info(info):
    table = [[key, value] for key, value in info.items()]
    print(Fore.CYAN + Style.BRIGHT + tabulate(table, headers=["Key", "Value"], tablefmt="grid"))

def display_vulnerabilities(vulnerabilities):
    if vulnerabilities:
        table = [[vuln[0], vuln[1], vuln[2], vuln[3]] for vuln in vulnerabilities]
        print(Fore.RED + Style.BRIGHT + tabulate(table, headers=["URL", "Type", "Payload", "Method"], tablefmt="grid"))
    else:
        print(Fore.GREEN + "No vulnerabilities found.")

def display_open_ports(open_ports):
    if open_ports:
        table = [[port] for port in open_ports]
        print(Fore.YELLOW + Style.BRIGHT + tabulate(table, headers=["Open Ports"], tablefmt="grid"))
    else:
        print(Fore.GREEN + "No open ports found.")

def display_links(links):
    if links:
        table = [[link] for link in links]
        print(Fore.BLUE + Style.BRIGHT + tabulate(table, headers=["Links"], tablefmt="grid"))
    else:
        print(Fore.GREEN + "No links found.")

def main():
    parser = argparse.ArgumentParser(description="Web Security Tester Tool")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--depth", type=int, default=3, help="Depth of crawling")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # Header
    header = f"""
{Fore.MAGENTA + Style.BRIGHT}
	   .---------       `---------.      `.-://::.``---  .----------------`    
   sddddddddd:      oddddddddd/    .+yddmmmmmdhsddd` +dddddddddddddddd:    
   :+smmdymmmd.    /mmhhmmmdo+-  `odmmmdho++oydmmmd` ommh++ymmmms++dmm:    
     -mmh.dmmmy`  .dmd.smmmd`    smmmmh-      .yddd` omms  ommmm:  hmm:    
     -mmh :mmmmo `hmm/ smmmd`   -mmmmd.        `---  /ss+  ommmm:  oss-    
     -mmh  +mmmm:smms  smmmd`   /mmmmh                     ommmm-          
     -mmh   ymmmdmmh`  smmmd`   -mmmmd.        .hs/-       ommmm-          
     .mmh   `hmmmmd.   smmmd`    smmmmh:`    `:hmmm/       ommmm-          
   :osmmdoo. -dmmm/  +ohmmmmoo-  `ommmmmdysoyhmmmd/     -oohmmmmsoo`       
   ommmmmmm:  /mms   dmmmmmmmm/    .+ydmmmmmmmdy/`      /mmmmmmmmmd`       
   .-------`   --`   ---------`      ``.-::-..`         `---------- 
	<=- Majalengka Cyber Tester -=>
{Style.RESET_ALL}
{Fore.WHITE + Style.BRIGHT}
Usage:
  python main.py <url> [--verbose] [--depth <n>]

Options:
  --verbose        Enable verbose output
  --depth <n>      Depth of crawling (default: 3)
{Style.RESET_ALL}
    """
    print(header)

    url = args.url
    depth = args.depth

    print(Fore.CYAN + Style.BRIGHT + f"Starting security tests for {url}")

    # Step 1: Information Gathering
    print(Fore.YELLOW + "Step 1: Information Gathering")
    info = info_gathering.gather_info(url)
    display_info(info)
    print(Fore.GREEN + "Information Gathering Completed")

    # Step 2: Port Scanning
    print(Fore.YELLOW + "Step 2: Port Scanning")
    host = url.replace("http://", "").replace("https://", "").split('/')[0]
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 8080]
    open_ports = port_scanner.scan_ports(host, common_ports)
    display_open_ports(open_ports)
    print(Fore.GREEN + "Port Scanning Completed")

    # Step 3: Web Crawling
    print(Fore.YELLOW + "Step 3: Web Crawling")
    links = web_crawler.crawl(url, depth)
    display_links(links)
    print(Fore.GREEN + "Web Crawling Completed")

    # Step 4: Security Tests
    print(Fore.YELLOW + "Step 4: Security Tests")
    vulnerabilities = security_tests.run_tests(url, links)
    display_vulnerabilities(vulnerabilities)
    print(Fore.GREEN + "Security Tests Completed")

    # Step 5: Generate Report
    print(Fore.YELLOW + "Step 5: Generating Report")
    report_generator.generate_report(url, info, vulnerabilities, open_ports)
    print(Fore.GREEN + "Report Generated Successfully")

if __name__ == "__main__":
    main()