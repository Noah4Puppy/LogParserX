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
    s = set()
    for item in result:
        result_ = []
        for key_item in item['logField']:
            if key_item['key'] in key_words:
                result_.append(key_item)
            if key_item['key'] not in s and key_item['key'] not in key_words:
                s.add(key_item['key'])
        if result_:
            new_item = {
                'logId': item['logId'],
                'logField': result_
            }
            new_result.append(new_item)

    return new_result, s

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
print(len(key_words))
json_path = r"data/dataset.json"
res = json_extract_log_field(json_file=json_path)
res2, s = get_key_words(result=res, key_words=key_words)

print(f"res1={len(res)}")
print(f"res2={len(res2)}")
print(f"s={len(s)}")