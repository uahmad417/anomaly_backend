import configparser
from flask import Flask, redirect, url_for


app = Flask(__name__)

config = configparser.ConfigParser()
config.read('config.ini')

from project.data.views import anomaly_bp
app.register_blueprint(anomaly_bp,url_prefix='/data/')

@app.route('/')
def root():
    return redirect(url_for('anomaly.index'))