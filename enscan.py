from flask import Flask, request, jsonify,render_template
import os
import re
import dns.resolver
import requests
import whois
import ssl
from urllib.parse import urlparse
import tldextract

app = Flask(__name__)

# Path to the directory containing enscan.html
HTML_FILE_DIRECTORY = os.path.join(os.path.dirname(__file__), 'DNS')

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
        return {
            "email": email,
            "domain": domain,
            "mx_records": [str(mx.exchange) for mx in mx_records],
            "valid": True,
            "domain_status": "Active"
        }
    except Exception as e:
        return {
            "email": email,
            "domain": domain,
            "valid": False,
            "error": f"Error: {str(e)}",
            "domain_status": "Inactive or Error"
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

        return {
            "url": url,
            "final_url": final_url,
            "classification": classification,
            "risk_score": risk_score,
            "details": details
        }
    except Exception as e:
        return {
            "url": url,
            "error": f"Unable to classify URL: {str(e)}"
        }

def dns_enumeration(domain):
    results = {}
    valid_record_types = ['A', 'AAAA', 'NS', 'MX', 'TXT', 'SOA', 'PTR', 'CNAME', 'SRV', 'CAA', 'HINFO', 'NAPTR']
    
    for record_type in valid_record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results[record_type] = [str(rdata) for rdata in answers]
        except dns.resolver.NoAnswer:
            results[record_type] = []
        except Exception as e:
            results[record_type] = [f"Error: {str(e)}"]
    
    filtered_results = {rtype: rdata for rtype, rdata in results.items() if rdata}
    
    return {
        "domain": domain,
        "dns_records": filtered_results,
        "description": "Detailed DNS record information including various record types."
    }

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return {
            "domain": domain,
            "whois_info": {
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "creation_date": w.creation_date,
                "expiration_date": w.expiration_date,
                "name_servers": w.name_servers,
                "status": w.status,
                "updated_date": w.updated_date,
                "domain_age": (w.expiration_date - w.creation_date).days if w.creation_date and w.expiration_date else "Unknown"
            }
        }
    except Exception as e:
        return {
            "domain": domain,
            "error": f"Unable to retrieve WHOIS info: {str(e)}"
        }

def ip_geolocation(ip):
    try:
        response = requests.get(f'https://geolocation-db.com/json/{ip}&position=true')
        data = response.json()
        return {
            "ip": ip,
            "geolocation": {
                "country": data.get("country_name", "Unknown"),
                "state": data.get("state", "Unknown"),
                "city": data.get("city", "Unknown"),
                "latitude": data.get("latitude", "Unknown"),
                "longitude": data.get("longitude", "Unknown"),
                "ISP": data.get("ISP", "Unknown")
            }
        }
    except Exception as e:
        return {
            "ip": ip,
            "error": f"Unable to retrieve IP geolocation: {str(e)}"
        }

def ssl_certificate_info(domain):
    try:
        conn = ssl.create_connection((domain, 443))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        sock = context.wrap_socket(conn, server_hostname=domain)
        cert = sock.getpeercert()
        return {
            "domain": domain,
            "ssl_certificate": {
                "issuer": dict(cert.get('issuer')),
                "subject": dict(cert.get('subject')),
                "not_before": cert.get('notBefore'),
                "not_after": cert.get('notAfter'),
                "version": cert.get('version'),
                "serial_number": cert.get('serialNumber')
            }
        }
    except Exception as e:
        return {
            "domain": domain,
            "error": f"Unable to retrieve SSL certificate info: {str(e)}"
        }

@app.route('/api/scan', methods=['POST'])
def scan_endpoint():
    try:
        data = request.json
        if not data or 'input' not in data:
            return jsonify({"error": "Invalid input"}), 400

        input_data = data['input']

        if '@' in input_data:
            result = email_domain_check(input_data)
        elif re.match(r'^\d+\.\d+\.\d+\.\d+$', input_data) or re.match(r'^[0-9a-fA-F:]+$', input_data):
            result = ip_geolocation(input_data)
        elif input_data.startswith(('http://', 'https://')):
            result = classify_url(input_data)
        elif '.' in input_data:
            dns_result = dns_enumeration(input_data)
            whois_result = whois_lookup(input_data)
            ssl_result = ssl_certificate_info(input_data)
            
            result = {
                "domain": input_data,
                "dns_records": dns_result.get("dns_records", {}),
                "whois_info": whois_result.get("whois_info", {}),
                "ssl_certificate": ssl_result.get("ssl_certificate", {}),
                "description": "Combined DNS, WHOIS, and SSL certificate information."
            }
        else:
            result = {"error": "Invalid input type"}

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
