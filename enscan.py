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
import socket

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

def dns_query(domain, record_type):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['8.8.8.8', '8.8.4.4']  # Google's public DNS servers
    resolver.timeout = 5
    resolver.lifetime = 5
    
    try:
        answers = resolver.resolve(domain, record_type)
        return [str(record) for record in answers]
    except dns.resolver.NoAnswer:
        return "No records found."
    except dns.exception.Timeout:
        return "DNS query timed out."
    except dns.resolver.NXDOMAIN:
        return "Domain does not exist."
    except dns.resolver.NoNameservers:
        return "No nameservers available."
    except Exception as e:
        return f"Error: {str(e)}"

def dns_enumeration(domain):
    logging.info(f"Performing DNS enumeration for domain: {domain}")
    results = {}
    valid_record_types = ['A', 'AAAA', 'NS', 'MX', 'TXT', 'SOA', 'CNAME']
    
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

        result = dns_enumeration(input_value)
        
        logging.info(f"Scan completed for input: {input_value}")
        return jsonify(result)
    except Exception as e:
        logging.error(f"Error in scan: {str(e)}")
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

def create_app():
    app = Flask(__name__)
    app.register_blueprint(enscan)
    return app

if __name__ == '__main__':
    socket.setdefaulttimeout(100)
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)