import sys
from time import time
import project.data.queries as queries
import json
import requests

from project.data.views import es

def source_ips():
    response = es.search(index='dvwa_http', body = queries.query_source_ips)
    #data = response['aggregations']['by_ips']['buckets']
    data = {entry['key']: entry['doc_count'] for entry in response['aggregations']['by_ips']['buckets']}
    #data = {id:response['aggregations']['by_ips']['buckets'][id] for id,_ in enumerate(response['aggregations']['by_ips']['buckets'])}
    return data

def web_activity(ip):
    global anomaly_json
    global timeline_json
    anomaly_json = {'web':[],'process':[],'file':[],'network':[]}
    timeline_json = []
    response = es.search(index='dvwa_http', body=queries.query_webpages%ip, scroll='5m')
    scroll_id = response['_scroll_id']
    while True:
        if len(response['hits']['hits']) == 0:
            break
        for entry in response['hits']['hits']:
            anomaly_json['web'].append(entry['_source'])
            timeline_json.append(entry['_source'])
            if entry['_source']['Method'] == 'POST' and 'exec' in entry['_source']['Path']:
                command_injection(entry['_source']['Payload'][3:-14])
        response = es.scroll(scroll='5m',scroll_id=scroll_id)
        timeline_json = sorted(timeline_json, key=lambda record:record['UtcTime'])
    return timeline_json

def command_injection(payload):
    sysmon_process_response = es.search(index='dvwa_sysmon_2',body=queries.query_command_injection%requests.utils.unquote(payload.replace('+','%20')))
    sysmon_event = {}
    for entry in sysmon_process_response['hits']['hits'][0]['_source']['Event']['EventData']['Data']:
        sysmon_event.update(entry)
    anomaly_json['process'].append(sysmon_event)
    timeline_json.append(sysmon_event)
    process_id = anomaly_json['process'][-1]['ProcessId']
    file_creation(process_id)
    network_connections(process_id)
    chain(process_id)

def chain(process_id):
    sysmon_process_response = es.search(index='dvwa_sysmon_2',body=queries.query_child_pids%process_id)
    if 'ProcessId' in json.dumps(sysmon_process_response):
        hits = sysmon_process_response['hits']['total']['value']
        child_pids = [record['_source']['Event']['EventData']['Data'][1]['ProcessId'] for record in sysmon_process_response['hits']['hits']]
        while True:
            if len(child_pids) != 0:
                current_process_id = child_pids.pop(0)
                store_process(current_process_id)
                file_creation(current_process_id)
                sysmon_process_response = es.search(index='dvwa_sysmon_2',body=queries.query_child_pids%current_process_id)
                if 'ProcessId' in json.dumps(sysmon_process_response):
                    hits = sysmon_process_response['hits']['total']['value']
                    child_pids = child_pids + [record['_source']['Event']['EventData']['Data'][1]['ProcessId'] for record in sysmon_process_response['hits']['hits']]
            else:
                break


def store_process(current_process_id):
    sysmon_process_response = es.search(index='dvwa_sysmon_2',body=queries.query_pid%current_process_id)
    sysmon_event = {}
    for entry in sysmon_process_response['hits']['hits'][0]['_source']['Event']['EventData']['Data']:
        sysmon_event.update(entry)
    anomaly_json['process'].append(sysmon_event)
    timeline_json.append(sysmon_event)

def file_creation(process_id):
    sysmon_file_response = es.search(index='dvwa_sysmon_2',body=queries.query_file_creation%process_id)
    if 'ProcessId' in json.dumps(sysmon_file_response):
        hits = sysmon_file_response['hits']['total']['value']
        for record in range(hits):
            sysmon_event = {}
            for entry in sysmon_file_response['hits']['hits'][record]['_source']['Event']['EventData']['Data']:
                sysmon_event.update(entry)
            anomaly_json['file'].append(sysmon_event)
            timeline_json.append(sysmon_event)

def network_connections(process_id):
    sysmon_network_response = es.search(index='dvwa_sysmon_2',body=queries.query_network_connect%process_id)
    if 'ProcessId' in json.dumps(sysmon_network_response):
        hits = sysmon_network_response['hits']['total']['value']
        for record in range(hits):
            sysmon_event = {}
            for entry in sysmon_network_response['hits']['hits'][record]['_source']['Event']['EventData']['Data']:
                sysmon_event.update(entry)
            anomaly_json['network'].append(sysmon_event)
            timeline_json.append(sysmon_event)