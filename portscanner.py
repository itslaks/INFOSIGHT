from flask import Flask, request, jsonify, Blueprint, render_template, Response, stream_with_context
import subprocess
import time
import ipaddress
import traceback
import logging
import threading
import queue

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

    def generate():
        for result in run_nmap_scan(ip_address, scan_types):
            yield f"data: {result}\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream')

def run_nmap_scan(ip_address, scan_types):
    try:
        command = ["nmap", "-v"]  # Add verbose flag for more detailed output

        for scan_type in scan_types:
            if scan_type in SCAN_TYPES:
                command.extend(SCAN_TYPES[scan_type].split())

        # Check and skip OS detection if Npcap is not available
        if 'OS_detection' in scan_types:
            if 'os_detection' in SCAN_TYPES:
                command.remove('-O')

        command.append(ip_address)

        app.logger.info(f"Running command: {' '.join(command)}")

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)

        output_queue = queue.Queue()
        
        def enqueue_output(out, queue):
            for line in iter(out.readline, ''):
                queue.put(line)
            out.close()

        t = threading.Thread(target=enqueue_output, args=(process.stdout, output_queue))
        t.daemon = True
        t.start()

        timeout = 600  # 10 minutes
        start_time = time.time()
        
        while True:
            try:
                line = output_queue.get_nowait()
                yield app.json.dumps({"progress": line.strip()})
            except queue.Empty:
                if process.poll() is not None:
                    break
                if time.time() - start_time > timeout:
                    process.kill()
                    app.logger.error(f"Process killed due to timeout for IP: {ip_address}")
                    yield app.json.dumps({"error": "Nmap scan timed out after 10 minutes"})
                    return
                time.sleep(0.1)

        if process.returncode != 0:
            app.logger.error(f"Nmap command failed with return code {process.returncode}.")
            yield app.json.dumps({"error": f"Nmap command failed with return code {process.returncode}."})
        else:
            yield app.json.dumps({"result": "Scan completed successfully"})

    except subprocess.SubprocessError as e:
        app.logger.error(f"Subprocess error: {str(e)}")
        app.logger.error(traceback.format_exc())
        yield app.json.dumps({"error": f"A subprocess error occurred: {str(e)}"})
    except Exception as e:
        app.logger.error(f"Exception occurred: {str(e)}")
        app.logger.error(traceback.format_exc())
        yield app.json.dumps({"error": f"An unexpected error occurred: {str(e)}"})

app.register_blueprint(portscanner, url_prefix='/portscanner')

if __name__ == '__main__':
    app.run(debug=True)