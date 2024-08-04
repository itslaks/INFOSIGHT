from flask import Blueprint, request, render_template, jsonify
import requests
import time
import logging

filescanner = Blueprint('filescanner', __name__, template_folder='templates')


VIRUSTOTAL_API_KEY = '5d0e2769a6d70bb561d0ddb24a4d05020dfe1aaccbde61879be7d50e289b82f1'

@filescanner.route('/')
def index():
    return render_template('filescanner.html')

@filescanner.route('/upload', methods=['POST'])
def upload_file():
    file = request.files.get('file')
    if file:
        try:
            upload_response = scan_file(file)
            if 'data' in upload_response and 'id' in upload_response['data']:
                analysis_id = upload_response['data']['id']
                result = get_analysis_result(analysis_id)
                return jsonify(result)
            else:
                return jsonify({'error': 'Failed to upload file'}), 400
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    return jsonify({'error': 'No file uploaded'}), 400

def scan_file(file):
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    files = {'file': (file.filename, file.stream, file.content_type)}
    
    response = requests.post(url, headers=headers, files=files)
    response.raise_for_status()  # Raise an exception for bad status codes
    return response.json()

def get_analysis_result(analysis_id):
    url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    
    max_attempts = 10
    for attempt in range(max_attempts):
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            result = response.json()
            
            if result['data']['attributes']['status'] == 'completed':
                return result
            
            time.sleep(20)  # Wait for 20 seconds before trying again
        except requests.RequestException as e:
            return {'error': 'Failed to get analysis result'}

    return {'error': 'Analysis timed out'}