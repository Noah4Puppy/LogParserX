import re
import json
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

# Optimized Patterns
patterns = {
    "date": r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\b",
    "hostname": r"主机名/([a-zA-Z0-9._-]+)",
    "event": r"事件/([^,]+)",
    "client_ip": r"客户端IP/(\d+\.\d+\.\d+\.\d+)",
    "user_agent": r"客户端环境/([^,]+)",
    "http_response_code": r"HTTP/S响应码/(\d+)",
    "attack_signature": r"攻击特征串/([^,]+)",
    "trigger_rule": r"触发规则/(\d+)",
    "unique_id": r"访问唯一编号/(\d+)",
    "country": r"国家/([^,]+)"
}

def match_date(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['date'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        date = match.group(0)
        results.append({"key": "", "value": date})
    return results

def match_hostname(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['hostname'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        hostname = match.group(1)
        results.append({"key": "", "value": hostname})
    return results

def match_event(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['event'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        event = match.group(1)
        results.append({"key": "事件", "value": event})
    return results

def match_client_ip(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['client_ip'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        client_ip = match.group(1)
        results.append({"key": "客户端IP", "value": client_ip})
    return results

def match_user_agent(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['user_agent'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        user_agent = match.group(1)
        results.append({"key": "客户端环境", "value": user_agent})
    return results

def match_http_response_code(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['http_response_code'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        http_response_code = match.group(1)
        results.append({"key": "HTTP/S", "value": f"响应码/{http_response_code}"})
    return results

def match_attack_signature(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['attack_signature'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        attack_signature = match.group(1)
        results.append({"key": "攻击特征串", "value": attack_signature})
    return results

def match_trigger_rule(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['trigger_rule'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        trigger_rule = match.group(1)
        results.append({"key": "触发规则", "value": trigger_rule})
    return results

def match_unique_id(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['unique_id'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        unique_id = match.group(1)
        results.append({"key": "访问唯一编号", "value": unique_id})
    return results

def match_country(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['country'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        country = match.group(1)
        results.append({"key": "国家", "value": country})
    return results

def get_components(log_text: str) -> list:
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_event(log_text))
    results.extend(match_client_ip(log_text))
    results.extend(match_user_agent(log_text))
    results.extend(match_http_response_code(log_text))
    results.extend(match_attack_signature(log_text))
    results.extend(match_trigger_rule(log_text))
    results.extend(match_unique_id(log_text))
    results.extend(match_country(log_text))
    return results

if __name__ == '__main__':
    log_text = f"""<178>Dec  5 12:45:01 10.50.81.60 DBAppWAF: 发生时间/2024-12-05 12:44:58,威胁/中,事件/SQL注入,请求方法/POST,URL地址/hostname/api/login,POST数据/username=admin&password=123456,服务器IP/10.50.81.6,主机名/hostname,服务器端口/8080,客户端IP/10.50.35.139,客户端端口/12955,客户端环境/Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36,标签/SQL注入,动作/阻断,HTTP/S响应码/403,攻击特征串/union,触发规则/11060007,访问唯一编号/7433263817181626369,国家/LAN,省/,市/,XFF_IP/"""
    res = get_components(log_text)
    json_data = json.dumps(res, ensure_ascii=False)
    print(json_data)