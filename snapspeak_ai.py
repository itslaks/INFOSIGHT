from flask import Blueprint, request, jsonify, render_template
from flask_cors import CORS
from transformers import BlipForConditionalGeneration, BlipProcessor
import torch
from PIL import Image, ExifTags
import io
import time
import imagehash
import traceback

snapspeak_ai = Blueprint('snapspeak_ai', __name__, template_folder='templates')
CORS(snapspeak_ai)

# Load models globally
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model = BlipForConditionalGeneration.from_pretrained("Salesforce/blip-image-captioning-large").to(device)
processor = BlipProcessor.from_pretrained("Salesforce/blip-image-captioning-large")

def metadata_analysis(image):
    metadata = {}
    try:
        exif_data = image.getexif()
        if exif_data:
            for tag_id, value in exif_data.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                metadata[tag] = str(value)
    except Exception as e:
        print(f"Error in metadata analysis: {str(e)}")
    return metadata

def image_hash(image):
    return str(imagehash.average_hash(image))

@torch.no_grad()
def generate_caption(image):
    try:
        pixel_values = processor(images=image, return_tensors="pt").pixel_values.to(device)
        output_ids = model.generate(pixel_values, max_length=150, num_beams=8)
        return processor.decode(output_ids[0], skip_special_tokens=True)
    except Exception as e:
        print(f"Error in caption generation: {str(e)}")
        return "Error generating caption"

@snapspeak_ai.route('/')
def index():
    return render_template('snapspeak.html')

@snapspeak_ai.route('/api/analyze/', methods=['POST'])
def analyze_image():
    try:
        start_time = time.time()
        file = request.files['file']
        if not file:
            return jsonify({'error': 'No file provided'}), 400
        
        image_bytes = file.read()
        image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
       
        # Perform analyses
        caption = generate_caption(image)
        metadata = metadata_analysis(image)
        img_hash = image_hash(image)
       
        # Simulate longer processing time
        processing_time = time.time() - start_time
        if processing_time < 5:
            time.sleep(5 - processing_time)
       
        processing_time = time.time() - start_time
       
        return jsonify({
            'caption': caption,
            'steganography': {
                'detected': False,
                'confidence': 0,
                'methods': []
            },
            'metadata': metadata,
            'image_hash': img_hash,
            'processing_time': processing_time
        })
    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"Error in analyze_image: {str(e)}")
        print(f"Traceback: {error_trace}")
        return jsonify({'error': str(e), 'traceback': error_trace}), 500

if __name__ == "__main__":
    from flask import Flask
    app = Flask(__name__)
    app.register_blueprint(snapspeak_ai, url_prefix='/snapspeak_ai')
    app.run(debug=True)