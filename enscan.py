from flask import Flask, request, jsonify, render_template, Blueprint
import re
import dns.resolver
import requests
from urllib.parse import urlparse
import tldextract
import concurrent.futures
import whois
from datetime import datetime
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

enscan = Blueprint('enscan', __name__, template_folder='templates')

@enscan.route('/')
def index():
    return render_template('enscan.html')

def is_valid_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

def get_domain_info(domain):
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": w.creation_date.strftime("%Y-%m-%d") if isinstance(w.creation_date, datetime) else str(w.creation_date),
            "expiration_date": w.expiration_date.strftime("%Y-%m-%d") if isinstance(w.expiration_date, datetime) else str(w.expiration_date),
        }
    except Exception as e:
        logging.error(f"Error fetching domain info for {domain}: {str(e)}")
        return {"error": f"Unable to fetch domain information: {str(e)}"}

def email_domain_check(email):
    logging.info(f"Checking email: {email}")
    if not is_valid_email(email):
        return {"error": "Invalid email format"}
    
    domain = email.split('@')[1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        domain_info = get_domain_info(domain)
        
        result = {
            "email": email,
            "domain": domain,
            "mx_records": [str(mx.exchange) for mx in mx_records],
            "valid": True,
            "domain_status": "Active",
            "domain_info": domain_info,
            "definitions": {
                "MX": "Mail exchange record - maps a domain to a list of mail servers for that domain.",
                "Registrar": "The company that manages the registration of the domain.",
                "Creation Date": "The date when the domain was first registered.",
                "Expiration Date": "The date when the domain registration will expire if not renewed."
            }
        }
        return result
    except dns.resolver.NoAnswer:
        logging.warning(f"No MX records found for domain: {domain}")
        return {
            "email": email,
            "domain": domain,
            "valid": False,
            "error": "No MX records found for domain.",
            "domain_status": "Inactive or Error",
            "definitions": {
                "MX": "Mail exchange record - maps a domain to a list of mail servers for that domain."
            }
        }
    except Exception as e:
        logging.error(f"Error checking email {email}: {str(e)}")
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
    logging.info(f"Classifying URL: {url}")
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
            "http_https_status": parsed_url.scheme,
            "content_type": response.headers.get('Content-Type', 'Unknown'),
            "server": response.headers.get('Server', 'Unknown'),
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

        domain_info = get_domain_info(extracted.registered_domain)

        result = {
            "url": url,
            "final_url": final_url,
            "classification": classification,
            "risk_score": risk_score,
            "details": details,
            "domain_info": domain_info,
            "definitions": {
                "classification": "The classification of the URL based on its characteristics.",
                "risk_score": "A numerical value representing the risk level of the URL.",
                "is_phishing": "Indicates if the URL is potentially used for phishing.",
                "is_onion": "Indicates if the URL belongs to the Tor network (onion domain).",
                "is_shortener": "Indicates if the URL is a shortened link.",
                "http_https_status": "Shows whether the URL uses HTTP or HTTPS.",
                "content_type": "The MIME type of the content returned by the server.",
                "server": "The web server software used by the website."
            }
        }
        return result
    except Exception as e:
        logging.error(f"Error classifying URL {url}: {str(e)}")
        return {
            "url": url,
            "error": f"Unable to classify URL: {str(e)}",
            "definitions": {
                "classification": "The classification of the URL based on its characteristics.",
                "risk_score": "A numerical value representing the risk level of the URL.",
                "is_phishing": "Indicates if the URL is potentially used for phishing.",
                "is_onion": "Indicates if the URL belongs to the Tor network (onion domain).",
                "is_shortener": "Indicates if the URL is a shortened link.",
                "http_https_status": "Shows whether the URL uses HTTP or HTTPS.",
                "content_type": "The MIME type of the content returned by the server.",
                "server": "The web server software used by the website."
            }
        }

def dns_query(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(record) for record in answers]
    except dns.resolver.NoAnswer:
        return "No records found."
    except dns.resolver.Timeout:
        return "DNS query timed out."
    except Exception as e:
        return f"Error: {str(e)}"

def dns_enumeration(domain):
    logging.info(f"Performing DNS enumeration for domain: {domain}")
    results = {}
    valid_record_types = ['A', 'AAAA', 'NS', 'MX', 'TXT', 'SOA', 'PTR', 'CNAME']
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(valid_record_types)) as executor:
        future_to_record_type = {executor.submit(dns_query, domain, record_type): record_type for record_type in valid_record_types}
        for future in concurrent.futures.as_completed(future_to_record_type):
            record_type = future_to_record_type[future]
            results[record_type] = future.result()
    
    domain_info = get_domain_info(domain)
    results["domain_info"] = domain_info
    
    results["definitions"] = {
        "A": "Address record - maps a domain to an IPv4 address.",
        "AAAA": "Address record - maps a domain to an IPv6 address.",
        "NS": "Name server record - specifies authoritative DNS servers for the domain.",
        "MX": "Mail exchange record - maps a domain to a list of mail servers for that domain.",
        "TXT": "Text record - holds arbitrary text information.",
        "SOA": "Start of Authority record - provides information about the DNS zone.",
        "PTR": "Pointer record - maps an IP address to a domain name.",
        "CNAME": "Canonical Name record - maps an alias domain name to a true domain name."
    }
    return results

@enscan.route('/api/scan', methods=['POST'])
def scan():
    logging.debug("Received request to /api/scan")
    try:
        data = request.json
        input_value = data.get('input', '').strip()

        if not input_value:
            return jsonify({"error": "Empty input provided"}), 400

        logging.info(f"Received scan request for input: {input_value}")

        if '@' in input_value:
            result = email_domain_check(input_value)
        elif urlparse(input_value).scheme in ['http', 'https']:
            result = classify_url(input_value)
        else:
            result = dns_enumeration(input_value)
        
        logging.info(f"Scan completed for input: {input_value}")
        return jsonify(result)
    except Exception as e:
        logging.error(f"Error in scan: {str(e)}")
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

@enscan.route('/test', methods=['GET'])
def test():
    return jsonify({"message": "Test successful"}), 200

def create_app():
    app = Flask(__name__)
    app.register_blueprint(enscan)
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)