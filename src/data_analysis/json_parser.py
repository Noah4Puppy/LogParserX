

import json



def json_extract_log_field(json_file):
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    result = []
    for item in data:
        log_Field = item.get('logField', [])
        log_item = {
            'logId': item.get('logId', ''),
            'logField': log_Field,
        }
        result.append(log_item)
    return result

def get_key_words(result, key_words):
    new_result = []
    for item in result:
        result_ = []
        for key_item in item['logField']:
            if key_item['key'] in key_words:
                result_.append(key_item)
        if result_:
            new_item = {
                'logId': item['logId'],
                'logField': result_
            }
            new_result.append(new_item)

    return new_result

key_words = [
    "startTime",
    "endTime",
    "opType",
    "srcAddress",
    "destAddress",
    "srcPort",
    "destPort",
    "srcMacAddress",
    "destMacAddress",
    "srcUserName",
    "UserId",
    "srcHostName",
    "taskName",
    "sessionId",
    "requestUrl",
    "loginType",
    "fileMd5",
    "dnsType",
    "srcProcessCmd",
    "appName"
]

json_path = r"d:/Competition_Xihu/Resources/LogParserX/data/dataset.json"
res = json_extract_log_field(json_file=json_path)
res2 = get_key_words(result=res, key_words=key_words)

print(f"res1={len(res)}")
print(f"res2={len(res2)}")