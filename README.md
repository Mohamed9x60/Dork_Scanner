# Dork Scanner  

**Author**: Mohamed Fouad  

## Overview  
Dork Scanner is a professional vulnerability detection tool designed to identify vulnerable websites using specific Google dorks. The tool automates the process of discovering websites that may be susceptible to various critical vulnerabilities. It supports multiple scanning features, making it a valuable resource for penetration testers and cybersecurity professionals.  

---

## Features  

### [+] Vulnerabilities Detected:
The tool detects the following vulnerabilities:  

1. **Local File Inclusion (LFI):**  
   - **Description:** Allows attackers to include and execute files from the server, potentially accessing sensitive data.  
   - **Severity:** High - Can expose confidential files or credentials.  

2. **Cross-Site Scripting (XSS):**  
   - **Description:** Enables attackers to inject malicious scripts into web pages viewed by users.  
   - **Severity:** Medium to High - Can lead to data theft or session hijacking.  

3. **SQL Injection (SQLi):**  
   - **Description:** Allows attackers to execute malicious SQL queries to manipulate databases.  
   - **Severity:** Critical - May lead to full database compromise.  

4. **Remote File Inclusion (RFI):**  
   - **Description:** Enables attackers to remotely include malicious files in a web server.  
   - **Severity:** High - Can lead to server compromise or malware deployment.  

5. **Command Injection:**  
   - **Description:** Allows attackers to execute arbitrary commands on the server.  
   - **Severity:** Critical - Can result in full control over the server.  

6. **Open Redirect:**  
   - **Description:** Redirects users to malicious websites without their consent.  
   - **Severity:** Medium - Can be used in phishing attacks or spreading malware.  

---

## Preloaded Dorks  
The tool includes a files Dorks , which contains multiple ready-to-use dork . These dorks have been preconfigured to target specific vulnerabilities and can be used directly to scan websites.  

---

## Installation  

1. **Clone the Repository:**  
   ```bash
   git clone https://github.com/Mohamed9x60/Dork_Scanner.git
   cd Dork_Scanner
   ```

2. **Install Dependencies:**  
   Use the `requirements.txt` file to install all required dependencies.  
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Tool:**  
   Execute the tool using the following command:  
   ```bash
   python Dork_Scanner.py
   ```

---

## Usage  
1. **Load a Dork File:**  
   Choose a dork file from the `Dorks` directory.  

2. **Start Scanning:**  
   Use the tool to scan websites for vulnerabilities based on the selected dork file.  

3. **View Results:**  
   Detected vulnerabilities will be displayed in a structured format, along with severity levels.  
  

---

## Note  
**For Educational and Ethical Use Only:**  
This tool is intended for use by cybersecurity professionals to secure their systems and identify potential vulnerabilities. Misuse of this tool for illegal purposes is strictly prohibited.  

---  

**Developed: Mohamed Fouad**
