import re
import urllib.parse
import socket
from datetime import datetime
import whois

def is_ip(url):
    # Check if URL uses an IP address
    match = re.match(r'(http[s]?://)?(\d{1,3}\.){3}\d{1,3}', url)
    return 1 if match else 0

def count_subdomains(url):
    domain = urllib.parse.urlparse(url).netloc
    return domain.count('.')

def has_at_symbol(url):
    return 1 if '@' in url else 0

def has_hyphen(url):
    domain = urllib.parse.urlparse(url).netloc
    return 1 if '-' in domain else 0

def uses_https(url):
    return 1 if url.startswith('https') else 0

def count_double_slash(url):
    return url.count('//')

def get_url_length(url):
    return len(url)

def suspicious_words(url):
    words = ['login', 'secure', 'account', 'update', 'banking', 'confirm', 'verify']
    return any(word in url.lower() for word in words)

def domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            return -1
        today = datetime.now()
        age = (today - creation_date).days
        return age
    except:
        return -1

def extract_features(url):
    domain = urllib.parse.urlparse(url).netloc

    features = [
        is_ip(url),
        count_subdomains(url),
        has_at_symbol(url),
        has_hyphen(url),
        uses_https(url),
        count_double_slash(url),
        get_url_length(url),
        suspicious_words(url),
        domain_age(domain)
    ]
    return features

# Example usage
if __name__ == "__main__":
    test_url = input("Enter a URL to extract features: ")
    features = extract_features(test_url)
    print("Extracted Features:", features)
