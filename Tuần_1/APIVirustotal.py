import urllib.request
import json
import sys

hash_value = sys.argv[1]
vt_url = "https://www.virustotal.com/vtapi/v2/file/report"
api_key = "12b324a57e12d701bd0c291298daae9943a0ab32e9b22179f572739aae717f2c"
parameters = {'apikey':api_key,'resource':hash_value}
encoded_parameters = urllib.parse.urlencode(parameters).encode('utf-8')
request =urllib.request.Request(vt_url,encoded_parameters)
response = urllib.request.urlopen(request)
json_response = json.loads(response.read().decode('utf-8'))

if json_response['response_code']:
    detections =json_response['positives']
    total = json_response['total']
    scan_results =json_response['scans']
    print("Detection: %s/%s" % (detections,total))
    print("VirusTotal Results:")
    for av_name, av_data in scan_results.items():
        print("/t%s ==> %s" % (av_name,av_data['result']))
else:
    print("No AV Detections For: %s" % hash_value)