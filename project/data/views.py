from flask import Blueprint
from elasticsearch import Elasticsearch
import configparser

anomaly_bp = Blueprint('anomaly',__name__)

from project import config
es = Elasticsearch(hosts=config['ElasticServer']['host'])
import project.data.analyzer as analyzer

@anomaly_bp.route('/',methods=['GET'])
def index(): 
    ip_list = analyzer.source_ips()
    return ip_list

@anomaly_bp.route('/<int:id>/', methods=['GET'])
def attacker_chain(id):
    return analyzer.web_activity(id)
