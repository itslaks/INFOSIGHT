from flask import Flask, Blueprint, request, render_template, jsonify
import requests
import socket
import re
import subprocess
import time
import logging
import shutil
import threading

# Create the Flask app
app = Flask(__name__)

# Create the blueprint
webseeker = Blueprint('webseeker', __name__, template_folder='templates')

# Configure logging
logging.basicConfig(level=logging.INFO)

# VirusTotal configuration
VIRUSTOTAL_API_KEY = 'd1cd837730b014a8cc8b9aef3ebcb85ab179be6067604ada94dc8fe7b6c25f57'
VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/urls'
VIRUSTOTAL_ANALYSIS_URL = 'https://www.virustotal.com/api/v3/analyses/'

# IPinfo configuration
IPINFO_API_KEY = '8e6847c71ee1d7'

# Nmap scan type definitions
SCAN_TYPES = {
    'intense_scan': '-T4 -A -v',
    'ping_scan': '-sn',
    'quick_scan_plus': '-sV -T4 -O -F --version-light',
    'regular_scan': '-sS -sV',
    'quick_scan': '-T4 -F',
    'tcp_connect_scan': '-sT',
    'syn_scan': '-sS',
    'udp_scan': '-sU',
    'service_version_scan': '-sV',
    'os_detection_scan': '-O'
}

# Route to render the Web Seeker page
@webseeker.route('/')
def index():
    return render_template('webseeker.html', scan_types=SCAN_TYPES)

# Route to handle scan requests
@webseeker.route('/start_scan', methods=['GET'])
def start_scan():
    url = request.args.get('url')
    scans = request.args.get('scans', '').split(',')

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    if not scans:
        return jsonify({'error': 'At least one scan type is required'}), 400

    results = {}
    ip_address = None

    # VirusTotal scan
    virustotal_results = scan_with_virustotal(url)
    results['virustotal'] = virustotal_results

    # NSLOOKUP
    if is_valid_domain(url):
        ip_address = get_ip_address(url)
        if ip_address:
            results['nslookup'] = get_ip_info(ip_address)
        else:
            results['nslookup'] = {'error': 'Failed to resolve IP address'}
    else:
        results['nslookup'] = {'error': 'Invalid domain'}

    # Nmap scan
    if ip_address:
        nmap_results = run_nmap_scan(ip_address, scans)
        results['nmap'] = nmap_results
    else:
        results['nmap'] = {'error': 'Unable to perform Nmap scan without valid IP address'}

    return jsonify(results)

# VirusTotal Functions
def scan_with_virustotal(url):
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }

    data = {'url': url}
    try:
        response = requests.post(VIRUSTOTAL_URL, headers=headers, data=data, timeout=10)
        response.raise_for_status()
        logging.info(f"VirusTotal POST response status: {response.status_code}")
        logging.info(f"VirusTotal POST response text: {response.text}")

        result = response.json()
        analysis_id = result.get('data', {}).get('id')

        if not analysis_id:
            return {'error': 'Error fetching analysis ID'}

        analysis_url = f"{VIRUSTOTAL_ANALYSIS_URL}/{analysis_id}"

        for _ in range(10):
            time.sleep(3)

            analysis_response = requests.get(analysis_url, headers=headers, timeout=10)
            logging.info(f"VirusTotal GET response status: {analysis_response.status_code}")
            logging.info(f"VirusTotal GET response text: {analysis_response.text}")
            analysis_response.raise_for_status()

            analysis_result = analysis_response.json()
            status = analysis_result.get('data', {}).get('attributes', {}).get('status')

            if status == 'completed':
                return optimize_results(analysis_result)

        return {'error': 'Analysis timed out or failed to complete'}
    except requests.HTTPError as http_err:
        logging.error(f"HTTP error occurred: {http_err}")
        return {'error': f'HTTP error occurred: {http_err}'}
    except requests.RequestException as req_err:
        logging.error(f"Request error occurred: {req_err}")
        return {'error': f'Request error occurred: {req_err}'}
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return {'error': f'Unexpected error occurred: {e}'}

def optimize_results(results):
    if 'error' in results:
        return results['error']

    stats = results.get('data', {}).get('attributes', {}).get('stats', {})
    last_analysis_results = results.get('data', {}).get('attributes', {}).get('last_analysis_results', {})

    positives = []
    negatives = []

    for engine, result in last_analysis_results.items():
        if result['category'] == 'malicious':
            positives.append(f"{engine}: {result['result']}")
        else:
            negatives.append(f"{engine}: {result['result']}")

    return {
        'malicious': stats.get('malicious', 0),
        'suspicious': stats.get('suspicious', 0),
        'harmless': stats.get('harmless', 0),
        'undetected': stats.get('undetected', 0),
        'positives': positives,
        'negatives': negatives
    }

# NSLOOKUP Functions
def is_valid_domain(domain):
    regex = re.compile(
        r'^(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)$', re.IGNORECASE)
    return re.match(regex, domain) is not None

def get_ip_address(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return None

def get_ip_info(ip_address):
    url = f"https://ipinfo.io/{ip_address}/json?token={IPINFO_API_KEY}"
    try:
        response = requests.get(url, timeout=10)
        logging.info(f"IPInfo response status: {response.status_code}")
        logging.info(f"IPInfo response text: {response.text}")
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logging.error(f"IPInfo request failed: {str(e)}")
        return {'error': f'IPInfo request failed: {str(e)}'}

# Nmap Functions
def is_nmap_available():
    return shutil.which('nmap') is not None

def run_nmap_scan(ip_address, scan_types):
    if not is_nmap_available():
        return {"error": "Nmap is not available on this system. Please install Nmap and ensure it's in your system PATH."}

    results = {}
    for scan_type in scan_types:
        if scan_type in SCAN_TYPES:
            result = run_single_nmap_scan(ip_address, scan_type)
            results[scan_type] = result

    return results

def run_single_nmap_scan(ip_address, scan_type):
    try:
        command = ["nmap"]
        command.extend(SCAN_TYPES[scan_type].split())
        command.append(ip_address)

        logging.info(f"Running command: {' '.join(command)}")

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        def kill_process():
            if process.poll() is None:
                process.kill()
                logging.error(f"Process killed due to timeout for IP: {ip_address}, scan type: {scan_type}")

        # Set a timer to kill the process after 300 seconds (5 minutes)
        timer = threading.Timer(300, kill_process)
        timer.start()

        output, error = process.communicate()

        # Cancel the timer if the process completed before timeout
        timer.cancel()

        if process.returncode != 0:
            logging.error(f"Nmap command failed with return code {process.returncode}. Error: {error}")
            if "Npcap" in error:
                return {"error": "Nmap requires Npcap to be installed and properly configured. Please visit https://npcap.com to download and install the latest version of Npcap."}
            return {"error": f"Nmap command failed. Error: {error}"}
        if not output.strip():
            logging.error("No output from nmap command")
            return {"error": "No output from nmap command"}

        logging.info(f"Nmap scan completed successfully for IP: {ip_address}, scan type: {scan_type}")
        return {"result": output}
    except subprocess.SubprocessError as e:
        logging.error(f"Subprocess error: {e}")
        return {"error": f"Subprocess error: {e}"}
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return {"error": f"Unexpected error occurred: {e}"}

# Error Handlers
@webseeker.errorhandler(404)
def page_not_found(e):
    logging.error(f"404 Error: {e}")
    return jsonify({'error': 'Page not found'}), 404

@webseeker.errorhandler(500)
def internal_server_error(e):
    logging.error(f"500 Error: {e}")
    return jsonify({'error': 'Internal server error'}), 500

# Register the blueprint
app.register_blueprint(webseeker, url_prefix='/webseeker')

if __name__ == '__main__':
    app.run(debug=True)