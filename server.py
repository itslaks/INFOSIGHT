import os
import logging
from flask import Flask, render_template
from infocrypt import infocrypt
from cybersentry_ai import cybersentry_ai
from lana_ai import lana_ai
from osint import osint
from portscanner import portscanner
from webseeker import webseeker
from filescanner import filescanner
from infosight_ai import infosight_ai
from snapspeak_ai import snapspeak_ai

# Initialize Flask app
app = Flask(__name__)
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
@app.route('/')
def home():
    return render_template('new.html')

if __name__ == '__main__':
    app.run(debug=True)
