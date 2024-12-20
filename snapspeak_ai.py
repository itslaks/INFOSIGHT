from flask import Blueprint, request, jsonify, render_template
from flask_cors import CORS
from transformers import BlipForConditionalGeneration, BlipProcessor, logging
import torch
from PIL import Image, ImageStat
from PIL.ExifTags import TAGS
import io
import time
import imagehash
import traceback
import warnings
from collections import Counter
import cv2
import numpy as np
from scipy.stats import skew, kurtosis

warnings.filterwarnings("ignore", category=FutureWarning, message=".clean_up_tokenization_spaces.")
logging.set_verbosity_error()

snapspeak_ai = Blueprint('snapspeak_ai', __name__, template_folder='templates')
CORS(snapspeak_ai)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model = BlipForConditionalGeneration.from_pretrained("Salesforce/blip-image-captioning-large").to(device)
processor = BlipProcessor.from_pretrained("Salesforce/blip-image-captioning-large")

face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
eye_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_eye.xml')

def format_metadata(metadata):
    return {key: str(value) for key, value in metadata.items() if value}

def metadata_analysis(image):
    try:
        exif_data = {}
        info = image.getexif()
        if info:
            for tag_id, value in info.items():
                tag = TAGS.get(tag_id, tag_id)
                if isinstance(value, bytes):
                    try:
                        value = value.decode('utf-8')
                    except UnicodeDecodeError:
                        value = value.hex()
                exif_data[tag] = str(value)
        
        exif_data.update({
            'Format': image.format,
            'Mode': image.mode,
            'Size': f"{image.width}x{image.height}",
            'Format': image.format,
            'Is Animated': getattr(image, 'is_animated', False),
            'Frames': getattr(image, 'n_frames', 1),
        })
        
        return format_metadata(exif_data)
    except Exception as e:
        print(f"Error in metadata analysis: {str(e)}")
        return {}

def image_hash(image):
    return {
        'average_hash': str(imagehash.average_hash(image)),
        'phash': str(imagehash.phash(image)),
        'dhash': str(imagehash.dhash(image)),
        'whash': str(imagehash.whash(image))
    }

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
    try:
        image = image.convert('RGB')
        colors = Counter(image.getdata())
        most_common = colors.most_common(10)
        return {
            'most_common': [f'#{r:02x}{g:02x}{b:02x}' for (r, g, b), _ in most_common],
            'color_count': len(colors),
            'percentage': [(f'#{r:02x}{g:02x}{b:02x}', count / (image.width * image.height) * 100) for (r, g, b), count in most_common]
        }
    except Exception as e:
        print(f"Error in color analysis: {str(e)}")
        return {}

def detect_faces_and_eyes(image):
    try:
        opencv_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
        gray = cv2.cvtColor(opencv_image, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))
        eyes = eye_cascade.detectMultiScale(gray)
        return {
            'face_count': len(faces),
            'eye_count': len(eyes),
            'face_locations': faces.tolist(),
            'eye_locations': eyes.tolist()
        }
    except Exception as e:
        print(f"Error in face and eye detection: {str(e)}")
        return {'face_count': 0, 'eye_count': 0, 'face_locations': [], 'eye_locations': []}

def image_statistics(image):
    try:
        stat = ImageStat.Stat(image)
        return {
            'extrema': stat.extrema,
            'count': stat.count,
            'sum': stat.sum,
            'sum2': stat.sum2,
            'mean': stat.mean,
            'median': stat.median,
            'rms': stat.rms,
            'var': stat.var,
            'stddev': stat.stddev
        }
    except Exception as e:
        print(f"Error in image statistics: {str(e)}")
        return {}

def calculate_image_moments(image):
    try:
        gray = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2GRAY)
        moments = cv2.moments(gray)
        hu_moments = cv2.HuMoments(moments)
        return {
            'moments': {key: value for key, value in moments.items()},
            'hu_moments': hu_moments.flatten().tolist()
        }
    except Exception as e:
        print(f"Error in calculating image moments: {str(e)}")
        return {}

def analyze_image_histogram(image):
    try:
        hist = image.histogram()
        return {
            'histogram': hist,
            'histogram_stats': {
                'mean': np.mean(hist),
                'std': np.std(hist),
                'skewness': skew(hist),
                'kurtosis': kurtosis(hist)
            }
        }
    except Exception as e:
        print(f"Error in analyzing image histogram: {str(e)}")
        return {}

@snapspeak_ai.route('/')
def index():
    return render_template('snapspeak.html')

@snapspeak_ai.route('/api/analyze/', methods=['POST'])
def analyze_image():
    try:
        start_time = time.time()
        file = request.files.get('file')
        if not file:
            return jsonify({'error': 'No file provided'}), 400
        
        image_bytes = file.read()
        image = Image.open(io.BytesIO(image_bytes))
       
        # Perform comprehensive analyses
        caption = generate_caption(image)
        metadata = metadata_analysis(image)
        img_hash = image_hash(image)
        colors = color_analysis(image)
        faces_and_eyes = detect_faces_and_eyes(image)
        stats = image_statistics(image)
        moments = calculate_image_moments(image)
        histogram = analyze_image_histogram(image)
       
        processing_time = time.time() - start_time
       
        return jsonify({
            'caption': caption,
            'metadata': metadata,
            'image_hash': img_hash,
            'color_analysis': colors,
            'face_and_eye_detection': faces_and_eyes,
            'image_statistics': stats,
            'image_moments': moments,
            'histogram_analysis': histogram,
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
    app.run(host='0.0.0.0', port=5000, debug=False)