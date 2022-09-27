import os,sys,xmltodict,json
import Evtx.Evtx as evtx
from elasticsearch import Elasticsearch
from elasticsearch import ElasticsearchException

def upload_sysmon_evtx():
    try:
        global client
        client = Elasticsearch(hosts='http://localhost:9200')
        with evtx.Evtx('dvwa.evtx') as open_logs:
            events = list(open_logs.records())
            count = len(events)
            for record in events:
                json_log = json.loads(json.dumps(xmltodict.parse(record.xml())))
                event_data = json_log['Event']['EventData']['Data']
                for i in event_data:
                    i[i.pop('@Name')] = i.pop('#text')
                client.index(index='dvwa_sysmon',body=json.dumps(json_log))
                print('successfully uploaded to ELK')
    except ElasticsearchException as err:
        print('Error occured: '+str(err))

def upload_scapy():
    with open('dvwa.json') as scappy_logs_file:
        scappy_logs = scappy_logs_file.readlines()
        for record in scappy_logs:
            client.index(index='dvwa_http',body=record.strip())
    
if __name__=='__main__':
    upload_sysmon_evtx()
    upload_scapy()

