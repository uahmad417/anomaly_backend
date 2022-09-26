import configparser
from flask import Flask


app = Flask(__name__)

from project.data.views import anomaly_bp
app.register_blueprint(anomaly_bp,url_prefix='/data/')

def readConfig():
    global config
    config = configparser.ConfigParser()
    config.read('config.ini')

@app.route('/')
def root():
    return 'This is root Path'