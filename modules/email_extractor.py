# modules/email_extractor.py

import re
import requests

def extract_emails(domain):
    emails = set()
    
    urls_to_check = [
        f"http://{domain}",
        f"https://{domain}",
        f"http://{domain}/contact",
        f"https://{domain}/contact-us",
        f"https://{domain}/about",
        f"https://{domain}/about-us"
    ]
    
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }

    for url in urls_to_check:
        try:
            response = requests.get(url, timeout=4, headers=headers)
            if response.status_code == 200:
                found = re.findall(email_pattern, response.text, re.IGNORECASE)
                for email in found:
                    email_lower = email.lower()
                    if not any(email_lower.endswith(ext) for ext in ['.png', '.jpg', '.jpeg', '.gif', '.js', '.css']):
                        emails.add(email_lower)
        except requests.RequestException:
            continue

    return sorted(list(emails))