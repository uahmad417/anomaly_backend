from flask import Blueprint
from elasticsearch import Elasticsearch
import configparser

anomaly_bp = Blueprint('anomaly',__name__)

from project import config
es = Elasticsearch(hosts=config['ElasticServer']['host'])
sysmon_index = config['ElasticServer']['sysmon_index']
scapy_index = config['ElasticServer']['scapy_index']
import project.data.analyzer as analyzer

@anomaly_bp.route('/',methods=['GET'])
def index(): 
    ip_list = analyzer.source_ips()
    return ip_list

@anomaly_bp.route('/<string:ip>/', methods=['GET'])
def attacker_chain(ip):
    return analyzer.web_activity(ip)
