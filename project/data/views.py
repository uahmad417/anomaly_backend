from crypt import methods
from flask import Blueprint
from elasticsearch import Elasticsearch
import project.data.queries as queries
import json

anomaly_bp = Blueprint('anomaly',__name__)

es = Elasticsearch(hosts='http://localhost:9200')

@anomaly_bp.route('/',methods=['GET'])
def index():
    response = es.search(index='dvwa_http', body = queries.query_source_ips)
    data = {id:response['aggregations']['by_ips']['buckets'][id] for id,_ in enumerate(response['aggregations']['by_ips']['buckets'])} 
    return data

@anomaly_bp.route('/<int:id>/', methods=['GET'])
def chain(id):
    return