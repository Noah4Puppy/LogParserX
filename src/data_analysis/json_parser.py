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

# 统计有key的日志条数 和 所有不重复key的列表
def get_unique_key_value(json_file):
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    unique_key = set()
    new_result = []
    for item in data:
        log_Field = item.get('logField', [])
        unique_logField = []
        for tag_item in log_Field:
            if tag_item["key"] != "":
                unique_logField.append(tag_item)
                unique_key.add(tag_item["key"])

        if unique_logField != []:
            log_item = {
                'logId': item.get('logId', ''),
                'unique_logField': unique_logField,
            }
            new_result.append(log_item)
    return new_result, unique_key


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

json_path = r"data/dataset.json"
key_list_path = r"src/data_analysis/temp/key_list.txt"
res = json_extract_log_field(json_file=json_path)
res2 = get_key_words(result=res, key_words=key_words)
res3, unique_key = get_unique_key_value(json_file=json_path)
print(f"res1={len(res)}")
print(f"res2={len(res2)}")
print(f"res3={len(res3)}")
# print(f"unique_key_list={unique_key}")

if unique_key:
    with open(key_list_path, "w", encoding="utf-8")as f:
        f.write('\n'.join(list(unique_key)))
    print(f"write successfully to {key_list_path}!")
