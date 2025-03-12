import re
import json
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

# Optimized patterns
patterns = {
    "date": r"\b[A-Za-z]{3}\s{1,2}\d{1,2}\s\d{4}\s\d{2}:\d{2}:\d{2}\b",
    "hostname": r"(?<=:\d{2}) ([a-zA-Z0-9._-]+)",
    "client_port": r"客户端端口/(\d+)",
    "HTTPS_code": r"HTTP/S响应码/(\d+)",
    "attack_feature": r"攻击特征串/([^,]+)",
    "trigger_rule": r"触发规则/(\d+)",
    "unique_visit_id": r"访问唯一编号/(\d+)",
    "country": r"国家/(\w+)",
    "event": r"事件/([^,]+)",
    "threat": r"威胁/(\w+)"
}

def match_date(text):
    compiled_re = _compile_regex(patterns['date'])
    match = compiled_re.search(text)
    results = []
    if match:
        date = match.group(0)
        results.append({"key": "", "value": date})
    return results

def match_hostname(text):
    compiled_re = _compile_regex(patterns['hostname'])
    match = compiled_re.search(text)
    results = []
    if match:
        hostname = match.group(1)
        results.append({"key": "", "value": hostname})
    return results

def match_client_port(text):
    compiled_re = _compile_regex(patterns['client_port'])
    match = compiled_re.search(text)
    results = []
    if match:
        client_port = match.group(1)
        results.append({"key": "客户端端口", "value": client_port})
    return results

def match_HTTPS_code(text):
    compiled_re = _compile_regex(patterns['HTTPS_code'])
    match = compiled_re.search(text)
    results = []
    if match:
        HTTPS_code = match.group(1)
        results.append({"key": "HTTP/S响应码", "value": HTTPS_code})
    return results

def match_attack_feature(text):
    compiled_re = _compile_regex(patterns['attack_feature'])
    match = compiled_re.search(text)
    results = []
    if match:
        attack_feature = match.group(1)
        results.append({"key": "攻击特征串", "value": attack_feature})
    return results

def match_trigger_rule(text):
    compiled_re = _compile_regex(patterns['trigger_rule'])
    match = compiled_re.search(text)
    results = []
    if match:
        trigger_rule = match.group(1)
        results.append({"key": "触发规则", "value": trigger_rule})
    return results

def match_unique_visit_id(text):
    compiled_re = _compile_regex(patterns['unique_visit_id'])
    match = compiled_re.search(text)
    results = []
    if match:
        unique_visit_id = match.group(1)
        results.append({"key": "访问唯一编号", "value": unique_visit_id})
    return results

def match_country(text):
    compiled_re = _compile_regex(patterns['country'])
    match = compiled_re.search(text)
    results = []
    if match:
        country = match.group(1)
        results.append({"key": "国家", "value": country})
    return results

def match_event(text):
    compiled_re = _compile_regex(patterns['event'])
    match = compiled_re.search(text)
    results = []
    if match:
        event = match.group(1)
        results.append({"key": "事件", "value": event})
    return results

def match_threat(text):
    compiled_re = _compile_regex(patterns['threat'])
    match = compiled_re.search(text)
    results = []
    if match:
        threat = match.group(1)
        results.append({"key": "威胁", "value": threat})
    return results

def get_components(log_text):
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_threat(log_text))
    results.extend(match_event(log_text))
    results.extend(match_client_port(log_text))
    results.extend(match_HTTPS_code(log_text))
    results.extend(match_attack_feature(log_text))
    results.extend(match_trigger_rule(log_text))
    results.extend(match_unique_visit_id(log_text))
    results.extend(match_country(log_text))
    return results

if __name__ == '__main__':
    log_text = "<178>Oct 31 20:34:13 10.50.81.59 DBAppWAF: 发生时间/2024-10-31 20:34:09,威胁/高,事件/通用代码注入攻击,请求方法/POST,URL地址/hostname/index?id=1,POST数据/username=%27%3Btop%5B%27ale%27%2B%27rt%27%5D%28top%5B%27doc%27%2B%27ument%27%5D%5B%27dom%27%2B%27ain%27%5D%29%3B//&password=password\n\n,服务器IP/10.50.81.5,主机名/hostname,服务器端口/8000,客户端IP/10.24.2.13,客户端端口/57640,客户端环境/User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.89 Safari/537.36,标签/代码注入攻击,动作/阻断,HTTP/S响应码/403,攻击特征串/%27%3Btop%5B%27ale%27%2B%27rt%27%5D%28top%5B%27doc%27%2B%27ument%27%5D%5B%27dom%27%2B%27ain%27%5D%29%3B//,触发规则/12032010,访问唯一编号/7431917130176530899,国家/LAN,省/,市/,XFF_IP/"
    res = get_components(log_text)
    json_data = json.dumps(res, ensure_ascii=False)
    print(json_data)