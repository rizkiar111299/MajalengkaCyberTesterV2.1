import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def crawl(url, depth=5, aggressive=True):
    visited = set()
    links = set()
    folders = set()
    files = set()
    lock = threading.Lock()

    def _crawl(url, current_depth):
        if url in visited or current_depth > depth:
            return set()
        with lock:
            visited.add(url)
        
        try:
            logging.info(f"Crawling: {url} (Depth: {current_depth})")
            response = requests.get(url, timeout=10)
            response.raise_for_status()  # Raise an HTTPError on bad status
            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract links using BeautifulSoup
            new_links = set()
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                full_url = urljoin(url, href)
                if urlparse(full_url).netloc == urlparse(url).netloc:  # Filter only internal links
                    with lock:
                        if full_url not in visited:
                            links.add(full_url)
                            new_links.add((full_url, current_depth + 1))
                            if is_folder(full_url):
                                folders.add(full_url)
                            else:
                                files.add(full_url)

            # Check for directory listing by looking for common patterns
            if is_directory_listing(response.text):
                for listing_link in extract_links_from_directory_listing(response.text, url):
                    full_url = urljoin(url, listing_link)
                    if urlparse(full_url).netloc == urlparse(url).netloc:  # Filter only internal links
                        with lock:
                            if full_url not in visited:
                                links.add(full_url)
                                new_links.add((full_url, current_depth + 1))
                                if is_folder(full_url):
                                    folders.add(full_url)
                                else:
                                    files.add(full_url)

            # Aggressive mode: Extract additional info and deeper analysis
            if aggressive:
                extract_and_log_sensitive_info(soup, url)

            return new_links

        except requests.HTTPError as e:
            if e.response.status_code == 404:
                logging.warning(f"404 Not Found: {url}")
            else:
                logging.error(f"HTTP error: {e} - URL: {url}")
            return set()
        except requests.RequestException as e:
            logging.error(f"Error crawling {url}: {e}")
            return set()

    with ThreadPoolExecutor(max_workers=20 if aggressive else 10) as executor:  # Increase max_workers in aggressive mode
        futures = {executor.submit(_crawl, url, 0): url}
        while futures:
            for future in as_completed(futures):
                new_links = future.result()
                if new_links:
                    for new_url, new_depth in new_links:
                        if new_url not in visited:
                            futures[executor.submit(_crawl, new_url, new_depth)] = new_url
                del futures[future]

    logging.info(f"Total folders found: {len(folders)}")
    for folder in folders:
        logging.info(f"Folder: {folder}")

    logging.info(f"Total files found: {len(files)}")
    for file in files:
        logging.info(f"File: {file}")

    files_and_folders = [{"name": item, "type": "folder" if item in folders else "file", "size": "N/A"} for item in folders.union(files)]
    return links, files_and_folders

def is_directory_listing(html):
    """
    Check if the HTML content looks like a directory listing.
    """
    directory_listing_patterns = [
        r'Index of /',  # Common directory listing title
        r'<title>Index of',  # Common directory listing title
        r'<a href="[^"]*">[^<]*</a>'  # Links in a directory listing
    ]
    for pattern in directory_listing_patterns:
        if re.search(pattern, html, re.IGNORECASE):
            return True
    return False

def extract_links_from_directory_listing(html, base_url):
    """
    Extract links from directory listing page.
    """
    soup = BeautifulSoup(html, 'html.parser')
    links = []
    for link in soup.find_all('a', href=True):
        href = link.get('href')
        if not href.startswith('?') and not href.startswith('#'):
            full_url = urljoin(base_url, href)
            links.append(full_url)
    return links

def is_folder(url):
    """
    Determine if a URL is a folder or a file.
    """
    parsed_url = urlparse(url)
    path = parsed_url.path
    return path.endswith('/') or not re.search(r'\.[a-zA-Z0-9]+$', path)

def extract_and_log_sensitive_info(soup, url):
    """
    Extract and log sensitive information from the page.
    """
    # Example: Extract email addresses
    emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', soup.text))
    if emails:
        logging.info(f"Found emails on {url}: {emails}")

    # Example: Extract phone numbers
    phone_numbers = set(re.findall(r'\+?\d[\d -]{8,}\d', soup.text))
    if phone_numbers:
        logging.info(f"Found phone numbers on {url}: {phone_numbers}")

    # Example: Extract any other sensitive information based on patterns
    sensitive_patterns = [
        r'\bpassword\b',
        r'\bsecret\b',
        r'\btoken\b',
        r'\bkey\b'
    ]
    for pattern in sensitive_patterns:
        matches = set(re.findall(pattern, soup.text, re.IGNORECASE))
        if matches:
            logging.info(f"Found sensitive info on {url}: {matches}")

