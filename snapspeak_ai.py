from flask import Blueprint, request, jsonify, render_template
from flask_cors import CORS
from transformers import BlipForConditionalGeneration, BlipProcessor
import torch
from PIL import Image
from PIL.ExifTags import TAGS
import io
import time
import imagehash
import traceback
import warnings
from collections import Counter
import cv2
import numpy as np

warnings.filterwarnings("ignore", category=FutureWarning, message=".*clean_up_tokenization_spaces.*")

# Set the transformers logging level to ERROR to suppress other warnings
from transformers import logging
logging.set_verbosity_error()

snapspeak_ai = Blueprint('snapspeak_ai', __name__, template_folder='templates')
CORS(snapspeak_ai)

# Load models globally
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model = BlipForConditionalGeneration.from_pretrained("Salesforce/blip-image-captioning-large").to(device)
processor = BlipProcessor.from_pretrained("Salesforce/blip-image-captioning-large")

# Load face detection model
face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')

def format_metadata(metadata):
    formatted_metadata = {}
    for key, value in metadata.items():
        if value:
            formatted_metadata[key] = str(value)
    return formatted_metadata

def metadata_analysis(image):
    try:
        exif_data = {}
        info = image.getexif()
        if info:
            for tag_id, value in info.items():
                tag = TAGS.get(tag_id, tag_id)
                if isinstance(value, bytes):
                    value = value.decode(errors='replace')
                exif_data[tag] = str(value)
        
        # Add some basic image information
        exif_data['Format'] = image.format
        exif_data['Mode'] = image.mode
        exif_data['Size'] = f"{image.width}x{image.height}"
        
        return format_metadata(exif_data)
    except Exception as e:
        print(f"Error in metadata analysis: {str(e)}")
        return {}

def image_hash(image):
    return str(imagehash.average_hash(image))

@torch.no_grad()
def generate_caption(image):
    try:
        pixel_values = processor(images=image, return_tensors="pt").pixel_values.to(device)
        output_ids = model.generate(pixel_values, max_length=50, num_beams=4)
        return processor.decode(output_ids[0], skip_special_tokens=True)
    except Exception as e:
        print(f"Error in caption generation: {str(e)}")
        return "Error generating caption"

def color_analysis(image):
    if image.mode != 'RGB':
        image = image.convert('RGB')
    colors = Counter(image.getdata())
    most_common_colors = colors.most_common(5)
    formatted_colors = [f'#{r:02x}{g:02x}{b:02x}' for (r, g, b) in [color for color, count in most_common_colors]]
    return formatted_colors

def detect_faces(image):
    try:
        # Convert PIL Image to OpenCV format
        opencv_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
        gray = cv2.cvtColor(opencv_image, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))
        return len(faces)
    except Exception as e:
        print(f"Error in face detection: {str(e)}")
        return 0

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
        image = Image.open(io.BytesIO(image_bytes))
       
        # Perform analyses
        caption = generate_caption(image)
        metadata = metadata_analysis(image)
        img_hash = image_hash(image)
        colors = color_analysis(image)
        face_count = detect_faces(image)
       
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
            'dominant_colors': colors,
            'face_count': face_count,
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
