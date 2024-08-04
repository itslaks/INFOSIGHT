from flask import Flask, render_template, request, jsonify
import re
import dns.resolver
import requests
from urllib.parse import urlparse
import tldextract

app = Flask(__name__)

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
            "valid": True
        }
    except:
        return {
            "email": email,
            "domain": domain,
            "valid": False,
            "error": "No MX records found or unable to resolve domain"
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
            "is_fake": False
        }

        # Check for onion domains
        if extracted.suffix == 'onion':
            classification = "onion"
            risk_score = 0.8
            details["is_onion"] = True

        # Check for URL shorteners
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co']
        if parsed_url.netloc in shorteners:
            classification = "shortener"
            risk_score = 0.5
            details["is_shortener"] = True

        # Basic phishing check (this is oversimplified and should be more comprehensive in a real application)
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
    except:
        return {
            "url": url,
            "error": "Unable to classify URL"
        }

def dns_enumeration(domain):
    results = {}
    record_types = ['A', 'AAAA', 'NS', 'MX', 'TXT']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results[record_type] = [str(rdata) for rdata in answers]
        except:
            results[record_type] = []
    
    return {
        "domain": domain,
        "dns_records": results
    }

@app.route('/')
def index():
    return render_template('enscan.html')

@app.route('/api/scan', methods=['POST'])
def scan_endpoint():
    try:
        data = request.json
        if not data or 'input' not in data:
            return jsonify({"error": "Invalid input"}), 400

        input_data = data['input']

        if '@' in input_data:
            result = email_domain_check(input_data)
        elif input_data.startswith(('http://', 'https://')):
            result = classify_url(input_data)
        else:
            result = dns_enumeration(input_data)

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)