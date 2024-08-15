import os
from flask import Flask, render_template, jsonify, Blueprint
import speech_recognition as sr
import pygame
from gtts import gTTS
from time import time
import threading
import signal
import numpy as np

# Create a blueprint
lana_ai = Blueprint('lana_ai', __name__, template_folder='templates')

# API key
GOOGLE_API_KEY = 'AIzaSyB0Uc1lxcWlvXP3kTb2jbpiAY91QgRyK9U'

# Initialize APIs
from google.generativeai import configure, GenerativeModel

configure(api_key=GOOGLE_API_KEY)
model = GenerativeModel('gemini-pro')
pygame.mixer.init()

# Define constants
RECORDING_PATH = "audio/recording.wav"
RESPONSE_PATH = "audio/response.mp3"
PROMPT_TEMPLATE = "You are Lana, Boss human assistant. You are witty and full of personality. Your answers should be limited to 3 lines short sentences.\nBoss: {user_input}\nLana: "

# Initialize Flask app
app = Flask(__name__)
is_listening = False
thread = None
latest_transcription = ""
latest_response = ""
conversation_lock = threading.Lock()
stop_event = threading.Event()

# New variables for audio visualization
audio_data = np.array([])

def log(message: str):
    """Print and write to status.txt"""
    print(message)
    with open("status.txt", "a") as f:
        f.write(message + "\n")

def request_gemini(prompt: str) -> str:
    """Generate content using the Gemini model"""
    response = model.generate_content(prompt)
    return response.text

def transcribe_audio() -> str:
    """Transcribe audio using Google's speech recognition"""
    recognizer = sr.Recognizer()
    with sr.AudioFile(RECORDING_PATH) as source:
        audio = recognizer.record(source)

    try:
        return recognizer.recognize_google(audio)
    except sr.UnknownValueError:
        log("Google Speech Recognition could not understand audio")
        return ""
    except sr.RequestError as e:
        log(f"Could not request results from Google Speech Recognition service; {e}")
        return ""

def record_audio() -> str:
    """Record audio using speech_recognition"""
    global audio_data
    recognizer = sr.Recognizer()
    with sr.Microphone() as source:
        log("Listening...")
        recognizer.adjust_for_ambient_noise(source, duration=1)
        audio = recognizer.listen(source, timeout=5, phrase_time_limit=10)

    with open(RECORDING_PATH, "wb") as f:
        f.write(audio.get_wav_data())
    log("Done recording")
    
    # Update audio_data for visualization
    audio_data = np.frombuffer(audio.get_raw_data(), dtype=np.int16)
    
    return "Recording complete"

def listen_and_respond():
    global latest_transcription, latest_response
    while not stop_event.is_set():
        try:
            # Record audio
            record_audio()

            # Check if stop event is set
            if stop_event.is_set():
                break

            # Transcribe audio
            words = transcribe_audio()
            if not words:
                continue

            # Update latest transcription immediately
            with conversation_lock:
                latest_transcription = words

            # Get response from Gemini
            prompt = PROMPT_TEMPLATE.format(user_input=words)
            response = request_gemini(prompt)

            # Update latest response immediately
            with conversation_lock:
                latest_response = response

            # Convert response to audio and play it
            tts = gTTS(response)
            tts.save(RESPONSE_PATH)
            sound = pygame.mixer.Sound(RESPONSE_PATH)
            sound.play()
            pygame.time.wait(int(sound.get_length() * 1000))

        except Exception as e:
            log(f"An error occurred: {e}")

        # Check if stop event is set after each iteration
        if stop_event.is_set():
            break

    log("Listening thread stopped")

@lana_ai.route('/')
def index():
    return render_template('lana.html')

@lana_ai.route('/start_listening', methods=['POST'])
def start_listening():
    global is_listening, thread, latest_transcription, latest_response, stop_event
    if not is_listening:
        is_listening = True
        latest_transcription = ""
        latest_response = ""
        stop_event.clear()
        thread = threading.Thread(target=listen_and_respond)
        thread.start()
        return jsonify({"status": "success", "message": "Listening started"})
    else:
        return jsonify({"status": "error", "message": "Already listening"})

@lana_ai.route('/stop_listening', methods=['POST'])
def stop_listening():
    global is_listening, stop_event, thread
    if is_listening:
        is_listening = False
        stop_event.set()
        if thread:
            thread.join(timeout=5)  # Wait for the thread to finish
        return jsonify({"status": "success", "message": "Listening stopped"})
    else:
        return jsonify({"status": "error", "message": "Not currently listening"})

@lana_ai.route('/process_audio', methods=['POST'])
def process_audio():
    global latest_transcription, latest_response, audio_data
    with conversation_lock:
        if latest_transcription or latest_response:
            response = {
                "status": "success",
                "user_transcript": latest_transcription,
                "response": latest_response,
                "audio_data": audio_data.tolist()  # Convert numpy array to list for JSON serialization
            }
            latest_transcription = ""
            latest_response = ""
            return jsonify(response)
    return jsonify({"status": "error", "message": "No new transcription available"})

if __name__ == '__main__':
    app.register_blueprint(lana_ai, url_prefix='/lana_ai')
    app.run(debug=True)