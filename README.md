# Description

This is the backend for the anomaly detection model.
It has two endpoints:  

* `/data` gives a listing of all the ips that have interacted with the honepot. It returns a json response in which the keys are different ids assigned to the ips. The value of each id is another dictionary consisting of the ip and count. The count is how often the ip appears in the data. This is only determined by the web activity of the ip and does not necessarily mean that the attack originated from the ip was more presistent.

* `/data/<id>` gives the entire chain of events originating from id assigned to an ip. It returns a json response in which the keys are `process`, `network`, `file` and `web`. The chaining of adversery activity is achieved by using the process chaining algorithm, in other words by chaining process creation events.

  * `process` includes all the process related information
  * `file` if a process creates any files these are included under the file key
  * `network` includes all network connections launched by a process
  * `web` includes all the web activity of the attacker

# How it works

The backend builds its json response by retrieving data from elasticsearch. As such different queries have been desisgned to retrieve relevant data from elasticsearch. These queries are presesnt in `.\project\data\queries.py`.  

It is required that elasticsearch has both sysmon and scapy data for this to work properly

# Sample Data

A sample scapy and sysmon data has been included in `.\sample data\` which can be uploaded to elastic to check how the backend works. simply run the script `.\sample data\upload_to_elastic.py`
