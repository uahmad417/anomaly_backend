from sys import prefix
from flask import Flask


app = Flask(__name__)

from project.data.views import anomaly_bp
app.register_blueprint(anomaly_bp,url_prefix='/data/')

@app.route('/')
def root():
    return 'This is root Path '