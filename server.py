import os
import logging
from flask import Flask, render_template, redirect, url_for, session
from infocrypt import infocrypt
from cybersentry_ai import cybersentry_ai
from lana_ai import lana_ai
from osint import osint
from portscanner import portscanner
from webseeker import webseeker
from filescanner import filescanner
from infosight_ai import infosight_ai
from snapspeak_ai import snapspeak_ai
from enscan import enscan

# Initialize Flask app
app = Flask(__name__, template_folder='static')
app.secret_key = 'your_secret_key_here'  # Set a secret key for session management
logging.basicConfig(level=logging.DEBUG)

# Register blueprints
app.register_blueprint(infocrypt, url_prefix='/infocrypt')
app.register_blueprint(cybersentry_ai, url_prefix='/cybersentry_ai')
app.register_blueprint(lana_ai, url_prefix='/lana_ai')
app.register_blueprint(osint, url_prefix='/osint')
app.register_blueprint(portscanner, url_prefix='/portscanner')
app.register_blueprint(webseeker, url_prefix='/webseeker')
app.register_blueprint(filescanner, url_prefix='/filescanner')
app.register_blueprint(infosight_ai, url_prefix='/infosight_ai')
app.register_blueprint(snapspeak_ai, url_prefix='/snapspeak_ai')
app.register_blueprint(enscan, url_prefix='/enscan')

@app.route('/')
def login():
    return render_template('login.html')

@app.route('/login_success')
def login_success():
    # This route should be called after successful login
    session['logged_in'] = True
    return redirect(url_for('landing_page'))

@app.route('/landing')
def landing_page():
    return render_template('landingpage.html')

@app.route('/homepage')
def homepage():
    return render_template('homepage.html')

if __name__ == '__main__':
    app.run(debug=True)