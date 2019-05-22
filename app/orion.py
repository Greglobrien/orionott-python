from botocore.vendored import requests
import botocore.config
import json
import time
from xml.etree import ElementTree
import io
import boto3
import logging
import os

# pulled from Environment Varibales in Lambda -- default is: ERROR
log_level = os.environ['LOG_LEVEL']
log_level = log_level.upper()  ## set log level to upper case
# works with AWS Logger: https://stackoverflow.com/questions/10332748/python-logging-setlevel
logger = logging.getLogger()
level = logging.getLevelName(log_level)
logger.setLevel(level)


def login(url):
    login = url + "/rest/api/auth/login"
    username = '''{"user":{"username":"%s","password":"%s"}}''' % \
               (os.environ['ORION_SERVER_USER'], os.environ['ORION_SERVER_PASS'])
    content = {"Content-Type": "application/json"}

    r = requests.post(login, data=username, headers=content)
    debug = "func login url: %s, func login json: %s" %(r.url, r.json())
    logger.debug(debug)
    cookie = r.json()['data']['cookies']
    return cookie

def live_summary(url, headers, cookie):
    get = url
    get3 = get + "/rest/api/content/live/summary"
    got3 = requests.get(get3, headers=headers, cookies=cookie)
    live_names = []
    debug = "func live_summary url: %s, func live_summary json: %s" % (got3.url, got3.json())
    logger.debug(debug)
    for obj in got3.json()['data']['contentRunSummaries']:
        #print(obj['run']['id'], obj['content']['name'], obj['content']['id'])
        live_names.append([obj['content']['name'], obj['content']['id']])
    return live_names

def live_alerts(url, time, assetId, headers, cookie):
    ## https://stackoverflow.com/questions/5998245/get-current-time-in-milliseconds-in-python
    timenow = int(round(time.time() * 1000))
    start_time = timenow - (3600 * 1000)  ## 10 min at the moment
    orion_time = "fromTime=%s&toTime=%s" % (start_time, timenow)
    test_time = "fromTime=1558031395902&toTime=1558031995902"

    get13 = url + "/rest/api/reports/liveAlerts/xml" \
            "?%s&severity=[Critical]&assets=[%s]" % (orion_time, assetId)

    c = requests.get(get13, headers=headers, cookies=cookie)
    #print(c.url)  ## for testing only
    #print(c.content)  ## for testing only
    tree = ElementTree.fromstring(c.content)
    #print(ElementTree.dump(tree))  ## should print "structure of" xml not lines

    test_tree1 = tree.find('Alerts')

    orion_alert_list = []

    for item in test_tree1.iter():
        assetName = item.get('assetName')
        description = item.get('description')
        alertNumberType = item.get('number')
        time = item.get('time')
        variant = item.get('variant')

        if assetName:
            test = '''{"time": "%s", "assetName": "%s", "alertNumberType": "%s", "variant": "%s", "description": "%s"}''' % \
                   (time, assetName, alertNumberType, variant, description)
            # test2 = json.loads(test) ## Possibly Not Necessary, but checks json validity
            # print("Json", test2)
            orion_alert_list.append(test)
    return orion_alert_list

def bigstring(orion_stuff):
    new_file = io.StringIO()
    for k,v in orion_stuff.items():
         #print(k,v)
        for orion_row in v:
            #print(orion_row)
            new_file.write(orion_row)
            new_file.write('\n')
    return new_file

def save_to_bucket(s3_r, bucket_name, filename, body_text):
    ## pulled from Environment Varibales in Lambda
    bucket = s3_r.Bucket(bucket_name)
    path = filename
    data = body_text.getvalue()

    bucket.put_object(
        ACL='private',
        ContentType='application/json',
        Key=path,
        Body=data,
    )

    return {
        "statusCode": 200,
        "filename": path
    }


def lambda_handler(event, context):
    base_url = os.environ['ORION_SERVER']

    cookies = login(base_url)
    header = {"Content-Type": "application/json"}
    orion_names = live_summary(base_url, header, cookies)

    orion_alert_list = {}
    for name in orion_names:
        # print(name[1])
        alerts_from_id = live_alerts(base_url, time, name[1], header, cookies)
        if alerts_from_id:
            orion_alert_list[name[0]] = alerts_from_id
    s3_resource = boto3.resource('s3', 'us-west-2', config=botocore.config.Config(s3={'addressing_style': 'path'}))
    #s3_resource = boto3.resource('s3')

    finished_file = bigstring(orion_alert_list)

    t = time.time()
    t_str = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(t))
    filename = "Orion_%s.json" % (t_str)
    if finished_file:
        bucket = os.environ['DESTINATION_BUCKET']
        saved_to_bucket = save_to_bucket(s3_resource, bucket, filename, finished_file)
        logger.info(saved_to_bucket)