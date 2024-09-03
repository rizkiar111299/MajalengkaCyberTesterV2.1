import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging
import re
import time

# Configure logging
logging.basicConfig(level=logging.WARNING)  # Set to WARNING to reduce verbosity

# List of common WAF header patterns
WAF_PATTERNS = {
    'Cloudflare': ['cf-ray', 'cf-cache-status'],
    'Akamai': ['akamai'],
    'Sucuri': ['sucuri'],
    'Incapsula': ['incapsula'],
    'F5 BigIP': ['bigipserver'],
    'AWS WAF': ['x-amz-cf-id'],
    'Barracuda': ['barra'],
    'DenyAll': ['denyall'],
    'Imperva': ['imperva'],
    'Palo Alto': ['x-paloalto'],
    'Radware': ['rdwr'],
    'FortiWeb': ['fortiwaf', 'fortiweb'],
}

def detect_waf(headers, content):
    detected_wafs = []
    for waf, patterns in WAF_PATTERNS.items():
        for pattern in patterns:
            if any(pattern.lower() in header.lower() for header in headers) or pattern.lower() in content.lower():
                detected_wafs.append(waf)
                break
    return detected_wafs

def gather_info(url):
    info = {}
    try:
        logging.debug(f"Sending request to {url}")
        start_time = time.time()
        
        # Verify SSL certificate and handle exceptions
        try:
            response = requests.get(url, verify=True)
        except requests.exceptions.SSLError:
            logging.warning(f"SSL verification failed for {url}. Trying with verification disabled.")
            response = requests.get(url, verify=False)
        
        response_time = time.time() - start_time

        info['status_code'] = response.status_code
        info['headers'] = dict(response.headers)  # Convert to standard dictionary
        info['content_type'] = response.headers.get('Content-Type', 'unknown')
        info['content_length'] = len(response.content)
        info['response_time'] = response_time

        logging.debug(f"Response received: {response.status_code}")

        # Parse the HTML content
        soup = BeautifulSoup(response.text, 'html.parser')

        # Extract meta tags
        meta_tags = {}
        for meta in soup.find_all('meta'):
            if 'name' in meta.attrs and 'content' in meta.attrs:
                meta_tags[meta.attrs['name'].lower()] = meta.attrs['content']
        info['meta_tags'] = meta_tags

        # Extract internal and external links
        internal_links = set()
        external_links = set()
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            full_url = urljoin(url, href)
            if urlparse(full_url).netloc == urlparse(url).netloc:
                internal_links.add(full_url)
            else:
                external_links.add(full_url)
        info['internal_links'] = list(internal_links)
        info['external_links'] = list(external_links)

        # Check for common technologies
        technologies = {
            'Google Analytics': bool(re.search(r'www\.google-analytics\.com/analytics\.js', response.text)),
            'jQuery': bool(re.search(r'jquery', response.text, re.IGNORECASE)),
            'Bootstrap': bool(re.search(r'bootstrap', response.text, re.IGNORECASE))
        }
        info['technologies'] = technologies

        # Detect WAF
        wafs = detect_waf(response.headers, response.text)
        info['wafs'] = wafs

    except Exception as e:
        info['error'] = str(e)
        logging.error(f"Error gathering info: {e}")

    return info

def print_info(info):
    if 'error' in info:
        print(f"Error: {info['error']}")
        return

    print("\nInformation gathered:")
    
    print("\n--- General Information ---")
    print(f"Status Code: {info['status_code']}")
    print(f"Content Type: {info['content_type']}")
    print(f"Content Length: {info['content_length']} bytes")
    print(f"Response Time: {info['response_time']:.2f} seconds")
    
    print("\n--- Headers ---")
    for key, value in info['headers'].items():
        print(f"{key}: {value}")

    print("\n--- Meta Tags ---")
    for key, value in info['meta_tags'].items():
        print(f"{key}: {value}")

    print("\n--- Internal Links ---")
    for link in info['internal_links']:
        print(f"- {link}")

    print("\n--- External Links ---")
    for link in info['external_links']:
        print(f"- {link}")

    print("\n--- Detected Technologies ---")
    for tech, found in info['technologies'].items():
        status = "Found" if found else "Not Found"
        print(f"{tech}: {status}")

    print("\n--- Detected WAFs ---")
    if info['wafs']:
        for waf in info['wafs']:
            print(f"- {waf}")
    else:
        print("No WAF detected")
