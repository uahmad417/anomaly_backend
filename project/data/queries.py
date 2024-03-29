query_source_ips = '{"query": {"bool": {"must": [{"wildcard": {"Path": {"value": "*dvwa*"}}}]}}, "aggs": {"by_ips": {"terms": {"field": "SourceIP.keyword","size": 100}}}}'

query_webpages = '{"size": 20,"query": {"bool": {"must_not": [{"wildcard": {"Path": {"value": "*.js"}}},{"wildcard": {"Path": {"value": "*.png"}}},{"wildcard": {"Path": {"value": "*.ico"}}},{"wildcard": {"Path": {"value": "*.css"}}}],"must": [{"match": {"SourceIP": "%s"}}]}}}'

query_command_injection=r'{"query": {"bool": {"must": [{"wildcard": {"Event.EventData.Data.ParentImage": {"value": "*http*"}}},{"wildcard": {"Event.EventData.Data.Image": {"value": "*cmd.exe"}}},{"match_phrase": {"Event.EventData.Data.CommandLine": "%s\""}}]}}}'

query_child_pids = '{"query": {"bool": {"must": [{"match": {"Event.EventData.Data.ParentProcessId": "%s"}}], "filter": [{"term": {"Event.System.EventID.#text": "1"}}]}}, "_source": ["Event.EventData.Data.ParentProcessId", "Event.EventData.Data.ParentImage", "Event.EventData.Data.ProcessId","Event.EventData.Data.Image", "Event.EventData.Data.CommandLine","Event.EventData.Data.RuleName"]}'

query_pid = '{"query": {"bool": {"must": [{"match": {"Event.EventData.Data.ProcessId": "%s"}}], "filter": [{"term": {"Event.System.EventID.#text": "1"}}]}}}'

query_file_creation = '{"query": {"bool": {"must": [{"match": {"Event.EventData.Data.ProcessId": "%s"}}], "filter": [{"term": {"Event.System.EventID.#text": "11"}}]}}}'

query_network_connect =  '{"query": {"bool": {"must": [{"match": {"Event.EventData.Data.ProcessId": "%s"}}], "filter": [{"term": {"Event.System.EventID.#text": "3"}}]}}}'
query_dns =  '{"query": {"bool": {"must": [{"match": {"Event.EventData.Data.ProcessId": "%s"}}], "filter": [{"term": {"Event.System.EventID.#text": "22"}}]}}}'