from flask import Blueprint
from elasticsearch import Elasticsearch
import project.data.queries as queries
import configparser


anomaly_bp = Blueprint('anomaly',__name__)

from project import config
es = Elasticsearch(hosts=config['ElasticServer']['host'])

def source_ips():
    response = es.search(index='dvwa_http', body = queries.query_source_ips)
    data = {id:response['aggregations']['by_ips']['buckets'][id] for id,_ in enumerate(response['aggregations']['by_ips']['buckets'])}
    return data

def web_activity(id):
    anomaly_json = {'web':[],'process':[],'file':[],'network':[]}
    ip_list = source_ips()
    response = es.search(index='dvwa_http', body=queries.query_webpages%ip_list[id]['key'], scroll='5m')
    scroll_id = response['_scroll_id']
    while True:
        for entry in response['hits']['hits']:
            anomaly_json['web'].append(entry['_source'])
        if len(response['hits']['hits']) < 20:
            break
        response = es.scroll(scroll='5m',scroll_id=scroll_id)
    return anomaly_json

@anomaly_bp.route('/',methods=['GET'])
def index(): 
    ip_list = source_ips()
    return ip_list

@anomaly_bp.route('/<int:id>/', methods=['GET'])
def attacker_chain(id):
    return web_activity(id)
