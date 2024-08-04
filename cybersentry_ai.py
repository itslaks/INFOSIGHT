# cybersentry_ai.py

import json
from flask import Blueprint, render_template, request, jsonify
import google.generativeai as genai

# Create a blueprint
cybersentry_ai = Blueprint('cybersentry_ai', __name__, template_folder='templates')

# Load responses from JSON file
def load_responses():
    try:
        with open('responses.json', 'r') as file:
            return json.load(file)
    except Exception as e:
        print(f"Error loading responses: {e}")
        return []

responses = load_responses()

# Configure Gemini API
genai.configure(api_key='AIzaSyDtouj7zKLoZG_-GWaIw-ectFb3RFrECtU')
model = genai.GenerativeModel('gemini-1.5-flash-latest')

def simple_match(query, responses):
    query = query.lower().strip()
    for response in responses:
        if 'question' in response and query in response['question'].lower():
            return response.get('answer')
    return None

def get_gemini_response(query):
    try:
        response = model.generate_content(query)
        return response.text
    except Exception as e:
        print(f"Error fetching response from Gemini API: {e}")
        return None

@cybersentry_ai.route('/')
def index():
    return render_template('cybersentry_AI.html')

@cybersentry_ai.route('/ask', methods=['POST'])
def ask():
    try:
        question = request.json['question']
        print(f"Received question: {question}")  # Debugging line
        
        answer = simple_match(question, responses)
        print(f"JSON answer: {answer}")  # Debugging line
        
        if answer:
            return jsonify({'answer': answer, 'source': 'JSON'})
        else:
            print("No match found in JSON, trying Gemini API")  # Debugging line
            gemini_answer = get_gemini_response(question)
            if gemini_answer:
                return jsonify({'answer': gemini_answer, 'source': 'Gemini'})
            else:
                return jsonify({'answer': "I'm sorry, I don't have an answer for that question.", 'source': 'Default'})
    except Exception as e:
        print(f"Error in /ask route: {e}")
        return jsonify({'error': str(e)}), 500
