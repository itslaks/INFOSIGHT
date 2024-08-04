from flask import Flask, request, jsonify, render_template, Blueprint
from flask_cors import CORS
from transformers import BlipForConditionalGeneration, BlipProcessor
import torch
from PIL import Image
import io
import time

app = Flask(__name__, template_folder='templates')
CORS(app)

snapspeak_ai = Blueprint('snapspeak_ai', __name__, template_folder='templates')

# Load the pre-trained model and processor globally
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model = BlipForConditionalGeneration.from_pretrained("Salesforce/blip-image-captioning-large").to(device)
processor = BlipProcessor.from_pretrained("Salesforce/blip-image-captioning-large")

gen_kwargs = {"max_length": 150, "num_beams": 8}

@snapspeak_ai.route('/')
def index():
    return render_template('snapspeak.html')

@snapspeak_ai.route('/api/predict/', methods=['POST'])
def generate_description():
    try:
        start_time = time.time()
        file = request.files['file']
        image = Image.open(io.BytesIO(file.read())).convert("RGB")

        pixel_values = processor(images=image, return_tensors="pt").pixel_values.to(device)

        with torch.no_grad():
            output_ids = model.generate(pixel_values, **gen_kwargs)
        
        caption = processor.decode(output_ids[0], skip_special_tokens=True)

        processing_time = time.time() - start_time

        return jsonify({
            'data': [caption],
            'time': processing_time
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)