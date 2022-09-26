from flask import Blueprint

anomaly_bp = Blueprint('anomaly',__name__)

@anomaly_bp.route('/')
def index():
    return 'This is an example app'