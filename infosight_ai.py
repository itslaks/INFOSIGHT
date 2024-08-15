import logging
import time
from flask import Flask, request, jsonify, render_template, Blueprint
import google.generativeai as genai
from google.api_core import retry

app = Flask(__name__)

# Create a blueprint
infosight_ai = Blueprint('infosight_ai', __name__, template_folder='templates')

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# API Key for Gemini model
GENAI_API_KEY = "AIzaSyDhVqSVp2bR7saU4RwPDYC4QkAkWqtRsL8"

# Configure Gemini model
genai.configure(api_key=GENAI_API_KEY)
model = genai.GenerativeModel('gemini-1.5-flash')

@infosight_ai.route('/')
def index():
    # Add the necessary context or parameters here if needed
    return render_template('infosight_ai.html') 

@infosight_ai.route('/generate', methods=['POST'])
def generate():
    try:
        data = request.json
        query = data.get('query')

        if not query:
            return jsonify({"error": "No query provided"}), 400

        logging.info(f"Received query: {query}")
        response_data = {}

        if query.startswith('/text'):
            text_query = query.replace('/text', '').strip()
            logging.info(f"Processing /text command with query: {text_query}")
            generated_text = generate_text(text_query)
            if generated_text:
                response_data['generatedText'] = format_text_as_points(generated_text)
                logging.info("Text generated successfully")
            else:
                response_data['error'] = "Unable to generate text. Please try again later."
                logging.warning("Failed to generate text")

        elif query.startswith('/pic'):
            image_prompt = query.replace('/pic', '').strip()
            logging.info(f"Processing /pic command with prompt: {image_prompt}")
            response_data['imagePrompt'] = image_prompt

        elif query.startswith('/imagine'):
            text_query = query.replace('/imagine', '').strip()
            logging.info(f"Processing /imagine command with query: {text_query}")
            generated_text = generate_text(text_query)
            if generated_text:
                response_data['generatedText'] = format_text_as_points(generated_text)
                logging.info("Text generated successfully")
            else:
                response_data['error'] = "Unable to generate text. Please try again later."
                logging.warning("Failed to generate text")
            response_data['imagePrompt'] = text_query

        logging.info(f"Sending response: {response_data}")
        return jsonify(response_data)
    
    except Exception as e:
        error_msg = f"Error processing request: {str(e)}"
        logging.error(error_msg)
        return jsonify({"error": error_msg}), 500

@retry.Retry(predicate=retry.if_exception_type(Exception))
def generate_text_with_retry(prompt):
    try:
        logging.debug(f"Generating text for prompt: {prompt}")
        response = model.generate_content(prompt)
        logging.debug(f"Generated text: {response.text}")
        return response.text
    except genai.types.generation_types.BlockedPromptException as e:
        error_msg = f"Blocked prompt: {str(e)}"
        logging.error(error_msg)
        return None
    except Exception as e:
        error_msg = f"Error generating text: {str(e)}"
        logging.error(error_msg)
        raise  # Re-raise the exception to trigger the retry

def generate_text(prompt):
    max_retries = 5
    for attempt in range(max_retries):
        try:
            result = generate_text_with_retry(prompt)
            if result is not None:
                return result
            logging.warning(f"Attempt {attempt + 1} failed, retrying...")
        except Exception as e:
            if attempt == max_retries - 1:
                logging.error(f"Failed to generate text after {max_retries} attempts: {str(e)}")
                return None
            logging.warning(f"Attempt {attempt + 1} failed: {str(e)}, retrying...")
            time.sleep(2 ** attempt)  # Exponential backoff
    return None

def format_text_as_points(text):
    points = text.split('. ')
    formatted_points = "<ul>" + "".join(f"<li>{point.strip()}</li>" for point in points if point) + "</ul>"
    return formatted_points

if __name__ == '__main__':
    app.run(debug=True)