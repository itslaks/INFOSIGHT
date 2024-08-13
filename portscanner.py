from flask import Flask, request, jsonify, Blueprint,  render_template
import subprocess
import time
import ipaddress
import traceback
import logging

app = Flask(__name__)

portscanner = Blueprint('portscanner', __name__, template_folder='templates')

# Configure logging
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

SCAN_TYPES = {
    'intense_scan': '-T4 -A -v',
    'quick_scan': '-T4 -F',
    'ping_scan': '-sn',
    'service_version_detection': '-sV',
    'OS_detection': '-O',
    'TCP_connect_scan': '-sT',
    'SYN_scan': '-sS',
    'UDP_scan': '-sU',
    'Aggressive_scan': '-A',
    'Traceroute': '--traceroute',
    'Idle_scan': '-sI',
    'FIN_scan': '-sF',
    'NULL_scan': '-sN',
    'XMAS_scan': '-sX',
    'Window_scan': '-sW',
    'Maimon_scan': '-sM',
    'SCTP_INIT_scan': '-sY',
    'SCTP_COOKIE_ECHO_scan': '-sZ',
    'IP_protocol_scan': '-sO',
    'Slow_scan': '-T0',
}

@portscanner.route('/')
def index():
    return render_template('portscanner.html', scan_types=SCAN_TYPES)

@portscanner.route('/scan', methods=['POST'])
def scan():
    data = request.json
    ip_address = data.get('ip_address')
    scan_types = [data.get('scan_types')] if isinstance(data.get('scan_types'), str) else data.get('scan_types', [])

    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        app.logger.error(f"Invalid IP address: {ip_address}")
        return jsonify({"error": "Invalid IP address"}), 400

    if not scan_types:
        app.logger.error("No scan types selected")
        return jsonify({"error": "No scan types selected"}), 400

    app.logger.info(f"Received scan request for IP: {ip_address}, Types: {scan_types}")

    results = run_nmap_scan(ip_address, scan_types)

    if 'error' in results:
        return jsonify(results), 500

    return jsonify(results)

def run_nmap_scan(ip_address, scan_types):
    try:
        command = ["nmap"]

        for scan_type in scan_types:
            if scan_type in SCAN_TYPES:
                command.extend(SCAN_TYPES[scan_type].split())

        # Check and skip OS detection if Npcap is not available
        if 'OS_detection' in scan_types:
            if 'os_detection' in SCAN_TYPES:
                command.remove('-O')

        command.append(ip_address)

        app.logger.info(f"Running command: {' '.join(command)}")

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        timeout = 6000
        start_time = time.time()
        while process.poll() is None:
            if time.time() - start_time > timeout:
                process.kill()
                app.logger.error(f"Process killed due to timeout for IP: {ip_address}")
                return {"error": "Nmap scan timed out after 10 minutes"}
            time.sleep(0.1)

        output, error = process.communicate()

        app.logger.info(f"Nmap output: {output}")
        app.logger.info(f"Nmap error: {error}")

        if process.returncode != 0:
            app.logger.error(f"Nmap command failed with return code {process.returncode}. Error: {error}")
            return {"error": f"Nmap command failed with return code {process.returncode}. Error: {error}"}
        if not output.strip():
            app.logger.error("No output from nmap command")
            return {"error": "No output from nmap command"}

        app.logger.info(f"Nmap scan completed successfully for IP: {ip_address}")
        return {"result": output}
    except subprocess.SubprocessError as e:
        app.logger.error(f"Subprocess error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return {"error": f"A subprocess error occurred: {str(e)}"}
    except Exception as e:
        app.logger.error(f"Exception occurred: {str(e)}")
        app.logger.error(traceback.format_exc())
        return {"error": f"An unexpected error occurred: {str(e)}"}

if __name__ == '__main__':
    app.run(debug=True)
