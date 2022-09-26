from flask import Blueprint
from elasticsearch import Elasticsearch
import project.data.queries as queries
from project import config

anomaly_bp = Blueprint('anomaly',__name__)

es = Elasticsearch(hosts=config['ElasticServer']['host'])

def source_ips():
    response = es.search(index='dvwa_http', body = queries.query_source_ips)
    data = {id:response['aggregations']['by_ips']['buckets'][id] for id,_ in enumerate(response['aggregations']['by_ips']['buckets'])}
    return data

@anomaly_bp.route('/',methods=['GET'])
def index(): 
    data = source_ips()
    return data

@anomaly_bp.route('/<int:id>/', methods=['GET'])
def chain(id):
    anomaly_json = {'web':[]}
    data = source_ips()
    response = es.search(index='dvwa_http', body=queries.query_webpages%response['aggregations']['by_ips']['buckets'][id], scroll='5m')
    scroll_id = response['_scroll_id']
    while True:
        for entry in response['hits']['hits']:
            anomaly_json['web'].append(entry['_source'])
        if len(response['hits']['hits']) < 20:
            break
        response = es.scroll(scroll='5m',scroll_id=scroll_id)
    return anomaly_json
