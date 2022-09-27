from concurrent.futures import process
from flask import Blueprint
from elasticsearch import Elasticsearch
import project.data.queries as queries
import configparser
import requests
import json

anomaly_bp = Blueprint('anomaly',__name__)

from project import config
es = Elasticsearch(hosts=config['ElasticServer']['host'])

def source_ips():
    response = es.search(index='dvwa_http', body = queries.query_source_ips)
    data = {id:response['aggregations']['by_ips']['buckets'][id] for id,_ in enumerate(response['aggregations']['by_ips']['buckets'])}
    return data

def web_activity(id):
    global anomaly_json
    anomaly_json = {'web':[],'process':[],'file':[],'network':[]}
    ip_list = source_ips()
    response = es.search(index='dvwa_http', body=queries.query_webpages%ip_list[id]['key'], scroll='5m')
    scroll_id = response['_scroll_id']
    while True:
        if len(response['hits']['hits']) == 0:
            break
        for entry in response['hits']['hits']:
            anomaly_json['web'].append(entry['_source'])
            if entry['_source']['Method'] == 'POST' and 'exec' in entry['_source']['Path']:
                command_injection(entry['_source']['Payload'][3:-14])
        response = es.scroll(scroll='5m',scroll_id=scroll_id)
    return anomaly_json

def command_injection(payload):
    sysmon_response = es.search(index='dvwa_sysmon_2',body=queries.query_command_injection%requests.utils.unquote(payload.replace('+','%20')))
    sysmon_event = {}
    for entry in sysmon_response['hits']['hits'][0]['_source']['Event']['EventData']['Data']:
        sysmon_event.update(entry)
    anomaly_json['process'].append(sysmon_event)
    process_id = anomaly_json['process'][-1]['ProcessId']
    #file_creation(process_id)
    #network_connections(process_id)
    chain(process_id)

def chain(process_id):
    sysmon_response = es.search(index='dvwa_sysmon_2',body=queries.query_child_pids%process_id)
    if 'ProcessId' in json.dumps(sysmon_response):
        hits = sysmon_response['hits']['total']['value']
        child_pids = [record['_source']['Event']['EventData']['Data'][1]['ProcessId'] for record in sysmon_response['hits']['hits']]
        while True:
            if len(child_pids) != 0:
                current_process_id = child_pids.pop(0)
                store_process(current_process_id)
                sysmon_response = es.search(index='dvwa_sysmon_2',body=queries.query_child_pids%current_process_id)
                if 'ProcessId' in json.dumps(sysmon_response):
                    hits = sysmon_response['hits']['total']['value']
                    child_pids = child_pids + [record['_source']['Event']['EventData']['Data'][1]['ProcessId'] for record in sysmon_response['hits']['hits']]
            else:
                break


def store_process(current_process_id):
    sysmon_response = es.search(index='dvwa_sysmon_2',body=queries.query_pid%current_process_id)
    sysmon_event = {}
    for entry in sysmon_response['hits']['hits'][0]['_source']['Event']['EventData']['Data']:
        sysmon_event.update(entry)
    anomaly_json['process'].append(sysmon_event)

def file_creation(process_id):
    return
def network_connections(process_id):
    return


@anomaly_bp.route('/',methods=['GET'])
def index(): 
    ip_list = source_ips()
    return ip_list

@anomaly_bp.route('/<int:id>/', methods=['GET'])
def attacker_chain(id):
    return web_activity(id)
