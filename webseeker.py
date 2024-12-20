from flask import Flask, Blueprint, request, render_template, jsonify
import requests
import socket
import subprocess
import time
import logging
import dns.resolver
import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import ssl
import json
import re  # Import regex module for URL validation

# Create the Flask app
app = Flask(__name__)

# Create the blueprint
webseeker = Blueprint('webseeker', __name__, template_folder='templates')

# Configure logging
logging.basicConfig(level=logging.INFO)

# API Keys (Consider using environment variables for security)
VIRUSTOTAL_API_KEY = 'd1cd837730b014a8cc8b9aef3ebcb85ab179be6067604ada94dc8fe7b6c25f57'
IPINFO_API_KEY = '8e6847c71ee1d7'
IPSTACK_API_KEY = 'c1d88d8306f550aa1c80c6a617872ac9'

VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/urls'
VIRUSTOTAL_ANALYSIS_URL = 'https://www.virustotal.com/api/v3/analyses/'

# Nmap scan type definitions
SCAN_TYPES = {
    'quick_scan': '-T4 -F',
    'intense_scan': '-T4 -A -v',
    'ping_scan': '-sn',
    'service_version_scan': '-sV',
    'os_detection_scan': '-O',
    'syn_scan': '-sS',
    'udp_scan': '-sU',
    'full_port_scan': '-p-',
    'script_scan': '-sC'
}

# Blacklist Checking API
BLACKLIST_CHECK_API = "https://checkurl.phishtank.com/checkurl/"

# Route for homepage
@webseeker.route('/')
def index():
    return render_template('webseeker.html', scan_types=SCAN_TYPES)

# Start scan route
@webseeker.route('/start_scan', methods=['GET'])
def start_scan():
    try:
        url = request.args.get('url')
        scans = request.args.getlist('scans[]')

        if not url:
            return jsonify({'error': 'URL is required'}), 400

        if not scans:
            return jsonify({'error': 'At least one scan type is required'}), 400

        if not is_valid_domain(url):
            return jsonify({'error': 'Invalid URL format'}), 400

        results = {
            'response_time': get_url_response_time(url),
            'blacklist_check': check_url_blacklist(url),
            'virustotal': scan_with_virustotal(url),
            'whois': get_whois_info(url),
            'ssl': get_ssl_info(url),
            'web_content': scrape_web_content(url)
        }

        ip_address = get_ip_address(url)
        if ip_address:
            results['nslookup'] = get_ip_info(ip_address)
            results['ipstack'] = get_ip_info_ipstack(ip_address)
            results['dns_records'] = get_dns_records(url)

            nmap_results = {}
            for scan_type in scans:
                if scan_type in SCAN_TYPES:
                    nmap_results[scan_type] = run_nmap_scan(ip_address, scan_type)
                else:
                    logging.warning(f"Unsupported scan type: {scan_type}")
            results['nmap'] = nmap_results
        else:
            results['nslookup'] = {'error': 'Failed to resolve IP address'}
            results['nmap'] = {'error': 'Unable to perform Nmap scan without a valid IP address'}

        # Format the results in a user-friendly way
        formatted_results = {k: json.dumps(v, indent=2) if isinstance(v, dict) else v for k, v in results.items()}
        
        return jsonify(formatted_results)

    except Exception as e:
        logging.error(f"Error occurred: {str(e)}", exc_info=True)
        return jsonify({'error': 'An unexpected error occurred', 'details': str(e)}), 500

# Run Nmap scan
def run_nmap_scan(ip_address, scan_type):
    try:
        command = f"nmap {SCAN_TYPES[scan_type]} {ip_address}"
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout, stderr = process.communicate()
        output = stdout.decode() + stderr.decode()  # Combine stdout and stderr
        return {'status': 'completed', 'output': output}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}

# Check if URL is a valid domain
def is_valid_domain(url):
    # Simple regex for validating domain names
    pattern = re.compile(
        r'^(?:http(s)?://)?(?:www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$'
    )
    return pattern.match(url) is not None

# Get URL response time
def get_url_response_time(url):
    try:
        start_time = time.time()
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return {'response_time': round((time.time() - start_time) * 1000, 2)}  # in milliseconds
    except requests.RequestException as e:
        return {'error': f"Failed to fetch response time: {str(e)}"}

# Check if URL is in a blacklist
def check_url_blacklist(url):
    try:
        response = requests.post(BLACKLIST_CHECK_API, data={'url': url}, timeout=10)
        return response.json()
    except requests.RequestException as e:
        return {'error': f'Blacklist check failed: {str(e)}'}

# Scan URL with VirusTotal
def scan_with_virustotal(url):
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    data = {'url': url}
    try:
        response = requests.post(VIRUSTOTAL_URL, headers=headers, data=data, timeout=10)
        response.raise_for_status()

        analysis_id = response.json().get('data', {}).get('id')
        if not analysis_id:
            return {'error': 'Error fetching analysis ID'}

        return poll_virustotal_analysis(analysis_id, headers)
    except requests.RequestException as e:
        logging.error(f"VirusTotal request failed: {e}")
        return {'error': f'VirusTotal request failed: {e}'}

# Poll VirusTotal for analysis results
def poll_virustotal_analysis(analysis_id, headers):
    analysis_url = f"{VIRUSTOTAL_ANALYSIS_URL}/{analysis_id}"
    for _ in range(10):  # Poll for 30 seconds total (10 x 3 seconds)
        time.sleep(3)
        try:
            response = requests.get(analysis_url, headers=headers, timeout=10)
            response.raise_for_status()
            analysis_result = response.json()

            if analysis_result.get('data', {}).get('attributes', {}).get('status') == 'completed':
                return optimize_results(analysis_result)
        except requests.RequestException as e:
            logging.error(f"VirusTotal analysis request failed: {e}")
            return {'error': f'VirusTotal analysis request failed: {e}'}

    return {'error': 'Analysis timed out or failed to complete'}

# Optimize VirusTotal results
def optimize_results(results):
    stats = results.get('data', {}).get('attributes', {}).get('stats', {})
    last_analysis_results = results.get('data', {}).get('attributes', {}).get('last_analysis_results', {})

    positives = [f"{engine}: {engine_result['category']}" for engine, engine_result in last_analysis_results.items() if engine_result['category'] == 'malicious']

    return {
        'stats': stats,
        'malicious_results': positives if positives else 'No malicious results'
    }

# Get WHOIS information
def get_whois_info(url):
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        return {k: str(v) for k, v in w.items() if v}  # Convert all values to strings
    except Exception as e:
        return {'error': f"WHOIS lookup failed: {e}"}

# Get SSL certificate information
def get_ssl_info(url):
    try:
        hostname = urlparse(url).netloc
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert()

        return {
            'subject': dict(x[0] for x in cert['subject']),
            'issuer': dict(x[0] for x in cert['issuer']),
            'version': cert['version'],
            'serialNumber': cert['serialNumber'],
            'notBefore': cert['notBefore'],
            'notAfter': cert['notAfter']
        }
    except Exception as e:
        return {'error': f"SSL info retrieval failed: {str(e)}"}

# Scrape web content
def scrape_web_content(url):
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        return {
            'title': soup.title.string if soup.title else 'No title found',
            'description': soup.find('meta', attrs={'name': 'description'})['content'] if soup.find('meta', attrs={'name': 'description'}) else 'No description found',
            'content': soup.get_text()
        }
    except Exception as e:
        return {'error': f"Web content scraping failed: {str(e)}"}

# Get IP address from URL
def get_ip_address(url):
    try:
        hostname = urlparse(url).netloc
        return socket.gethostbyname(hostname)
    except socket.error as e:
        return {'error': f"IP address lookup failed: {str(e)}"}

# Get IP information from IPinfo
def get_ip_info(ip_address):
    try:
        response = requests.get(f'https://ipinfo.io/{ip_address}/json?token={IPINFO_API_KEY}', timeout=10)
        return response.json()
    except requests.RequestException as e:
        return {'error': f'IPinfo request failed: {str(e)}'}

# Get IP information from IPStack
def get_ip_info_ipstack(ip_address):
    try:
        response = requests.get(f'http://api.ipstack.com/{ip_address}?access_key={IPSTACK_API_KEY}', timeout=10)
        return response.json()
    except requests.RequestException as e:
        return {'error': f'IPStack request failed: {str(e)}'}

# Get DNS records
def get_dns_records(url):
    try:
        domain = urlparse(url).netloc
        answers = dns.resolver.resolve(domain, 'A')
        return {'records': [str(answer) for answer in answers]}
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
        return {'error': f'DNS lookup failed: {str(e)}'}

# Register blueprint
app.register_blueprint(webseeker)

if __name__ == '__main__':
    app.run(debug=True)
