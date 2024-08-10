from flask import Flask, request, jsonify, render_template
import re
import dns.resolver
import requests
from urllib.parse import urlparse
import tldextract

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('enscan.html')

def is_valid_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

def email_domain_check(email):
    if not is_valid_email(email):
        return {"error": "Invalid email format"}
    
    domain = email.split('@')[1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        result = {
            "email": email,
            "domain": domain,
            "mx_records": [str(mx.exchange) for mx in mx_records],
            "valid": True,
            "domain_status": "Active",
            "definitions": {
                "MX": "Mail exchange record - maps a domain to a list of mail servers for that domain."
            }
        }
        return result
    except dns.resolver.NoAnswer:
        return {
            "email": email,
            "domain": domain,
            "valid": False,
            "error": "Domain does not exist.",
            "domain_status": "Inactive or Error",
            "definitions": {
                "MX": "Mail exchange record - maps a domain to a list of mail servers for that domain."
            }
        }
    except Exception as e:
        return {
            "email": email,
            "domain": domain,
            "valid": False,
            "error": f"Error: {str(e)}",
            "domain_status": "Inactive or Error",
            "definitions": {
                "MX": "Mail exchange record - maps a domain to a list of mail servers for that domain."
            }
        }

def classify_url(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        final_url = response.url
        parsed_url = urlparse(final_url)
        extracted = tldextract.extract(final_url)
        
        classification = "safe"
        risk_score = 0.1
        details = {
            "is_phishing": False,
            "is_onion": False,
            "is_shortener": False,
            "is_fake": False,
            "http_https_status": parsed_url.scheme
        }

        if extracted.suffix == 'onion':
            classification = "onion"
            risk_score = 0.8
            details["is_onion"] = True

        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co']
        if parsed_url.netloc in shorteners:
            classification = "shortener"
            risk_score = 0.5
            details["is_shortener"] = True

        if 'login' in parsed_url.path.lower() and parsed_url.scheme != 'https':
            classification = "potential phishing"
            risk_score = 0.7
            details["is_phishing"] = True

        result = {
            "url": url,
            "final_url": final_url,
            "classification": classification,
            "risk_score": risk_score,
            "details": details,
            "definitions": {
                "classification": "The classification of the URL based on its characteristics.",
                "risk_score": "A numerical value representing the risk level of the URL.",
                "is_phishing": "Indicates if the URL is potentially used for phishing.",
                "is_onion": "Indicates if the URL belongs to the Tor network (onion domain).",
                "is_shortener": "Indicates if the URL is a shortened link.",
                "http_https_status": "Shows whether the URL uses HTTP or HTTPS."
            }
        }
        return result
    except Exception as e:
        return {
            "url": url,
            "error": f"Unable to classify URL: {str(e)}",
            "definitions": {
                "classification": "The classification of the URL based on its characteristics.",
                "risk_score": "A numerical value representing the risk level of the URL.",
                "is_phishing": "Indicates if the URL is potentially used for phishing.",
                "is_onion": "Indicates if the URL belongs to the Tor network (onion domain).",
                "is_shortener": "Indicates if the URL is a shortened link.",
                "http_https_status": "Shows whether the URL uses HTTP or HTTPS."
            }
        }

def dns_enumeration(domain):
    results = {}
    valid_record_types = ['A', 'AAAA', 'NS', 'MX', 'TXT', 'SOA', 'PTR']
    for record_type in valid_record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results[record_type] = [str(record) for record in answers]
        except dns.resolver.NoAnswer:
            results[record_type] = "Domain does not exist."
        except dns.resolver.Timeout:
            results[record_type] = "DNS query timed out."
        except Exception as e:
            results[record_type] = f"Error: {str(e)}"
    
    results["definitions"] = {
        "A": "Address record - maps a domain to an IPv4 address.",
        "AAAA": "Address record - maps a domain to an IPv6 address.",
        "NS": "Name server record - specifies authoritative DNS servers for the domain.",
        "MX": "Mail exchange record - maps a domain to a list of mail servers for that domain.",
        "TXT": "Text record - holds arbitrary text information.",
        "SOA": "Start of Authority record - provides information about the DNS zone.",
        "PTR": "Pointer record - maps an IP address to a domain name."
    }
    return results

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.json
    input_value = data.get('input', '').strip()

    if '@' in input_value:
        result = email_domain_check(input_value)
    elif urlparse(input_value).scheme in ['http', 'https']:
        result = classify_url(input_value)
    else:
        result = dns_enumeration(input_value)
    
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
