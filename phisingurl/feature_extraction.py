import re
import tldextract

def extract(url):
    """
    Extracts numerical features from a given URL for phishing detection.
    """
    features = []

    # Count special characters in the URL
    features.append(url.count('.'))  # Number of dots
    features.append(url.count('-'))  # Number of hyphens
    features.append(url.count('_'))  # Number of underscores
    features.append(url.count('/'))  # Number of slashes
    features.append(url.count('?'))  # Number of question marks

    # Check if URL contains 'https' (secure)
    features.append(1 if url.startswith("https") else 0)

    # Extract domain name information
    domain_info = tldextract.extract(url)
    features.append(len(domain_info.domain))  # Length of domain name

    return features