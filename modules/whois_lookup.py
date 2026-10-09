# modules/whois_lookup.py

import whois
import requests

def get_whois(domain):
    try:
        w = whois.whois(domain)
        output = []

        if w.domain_name:
            if isinstance(w.domain_name, list):
                output.append(f"Domain Name: {w.domain_name[0]}")
            else:
                output.append(f"Domain Name: {w.domain_name}")
                
        if w.registrar:
            output.append(f"Registrar: {w.registrar}")
        if w.creation_date:
            creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            output.append(f"Creation Date: {creation}")
        if w.expiration_date:
            expiration = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            output.append(f"Expiration Date: {expiration}")
        if w.emails:
            if isinstance(w.emails, list):
                output.append(f"Registrant Emails: {', '.join(set(w.emails))}")
            else:
                output.append(f"Registrant Email: {w.emails}")
        if hasattr(w, 'dnssec') and w.dnssec:
            output.append(f"DNSSEC: {w.dnssec}")

        if output:
            return '\n'.join(output)
    except Exception:
        pass

    try:
        response = requests.get(f"https://api.hackertarget.com/whois/?q={domain}", timeout=5)
        if response.status_code == 200 and "error" not in response.text.lower():
            return response.text
    except Exception:
        pass

    return "No WHOIS info found."
