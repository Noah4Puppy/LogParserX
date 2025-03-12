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
    "threat": r"威胁/([中高低]+)",
    "request_method": r"请求方法/([A-Z]+)",
    "server_ip": r"服务器IP/(\d+\.\d+\.\d+\.\d+)",
    "hostname_full": r"主机名/(\d+\.\d+\.\d+\.\d+:\d+)",
    "client_env": r"客户端环境/((?:\S|\s)+)",
    "http_response_code": r"HTTP/S响应码/(\d+)",
    "attack_feature": r"攻击特征串/((?:\S|\s)+)",
    "trigger_rule": r"触发规则/(\d+)"
}

def match_date(log_text: str) -> list:
    regex = _compile_regex(patterns['date'])
    match = regex.search(log_text)
    results = []
    if match:
        date = match.group(0)
        results.append({"key": "", "value": date})
    return results

def match_hostname(log_text: str) -> list:
    regex = _compile_regex(patterns['hostname'])
    match = regex.search(log_text)
    results = []
    if match:
        hostname = match.group(1)
        results.append({"key": "", "value": hostname})
    return results

def match_threat(log_text: str) -> list:
    regex = _compile_regex(patterns['threat'])
    match = regex.search(log_text)
    results = []
    if match:
        threat = match.group(1)
        results.append({"key": "威胁", "value": threat})
    return results

def match_request_method(log_text: str) -> list:
    regex = _compile_regex(patterns['request_method'])
    match = regex.search(log_text)
    results = []
    if match:
        request_method = match.group(1)
        results.append({"key": "请求方法", "value": request_method})
    return results

def match_server_ip(log_text: str) -> list:
    regex = _compile_regex(patterns['server_ip'])
    match = regex.search(log_text)
    results = []
    if match:
        server_ip = match.group(1)
        results.append({"key": "服务器IP", "value": server_ip})
    return results

def match_hostname_full(log_text: str) -> list:
    regex = _compile_regex(patterns['hostname_full'])
    match = regex.search(log_text)
    results = []
    if match:
        hostname_full = match.group(1)
        results.append({"key": "主机名", "value": hostname_full})
    return results

def match_client_env(log_text: str) -> list:
    regex = _compile_regex(patterns['client_env'])
    match = regex.search(log_text)
    results = []
    if match:
        client_env = match.group(1)
        results.append({"key": "客户端环境", "value": client_env})
    return results

def match_http_response_code(log_text: str) -> list:
    regex = _compile_regex(patterns['http_response_code'])
    match = regex.search(log_text)
    results = []
    if match:
        http_response_code = match.group(1)
        results.append({"key": "HTTP/S响应码", "value": http_response_code})
    return results

def match_attack_feature(log_text: str) -> list:
    regex = _compile_regex(patterns['attack_feature'])
    match = regex.search(log_text)
    results = []
    if match:
        attack_feature = match.group(1)
        results.append({"key": "攻击特征串", "value": attack_feature})
    return results

def match_trigger_rule(log_text: str) -> list:
    regex = _compile_regex(patterns['trigger_rule'])
    match = regex.search(log_text)
    results = []
    if match:
        trigger_rule = match.group(1)
        results.append({"key": "触发规则", "value": trigger_rule})
    return results

def get_components(log_text: str) -> list:
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_threat(log_text))
    results.extend(match_request_method(log_text))
    results.extend(match_server_ip(log_text))
    results.extend(match_hostname_full(log_text))
    results.extend(match_client_env(log_text))
    results.extend(match_http_response_code(log_text))
    results.extend(match_attack_feature(log_text))
    results.extend(match_trigger_rule(log_text))
    return results

if __name__ == '__main__':
    log_text = f"""<178>Dec 20 10:20:30 10-50-86-12 DBAppWAF: 发生时间/2024-12-20 10:20:15,威胁/中,事件/检测SQL注入,请求方法/POST,URL地址/10.50.109.90:31003/api/v1/data,POST数据/user=admin&password=123456,服务器IP/10.50.109.90,主机名/10.50.109.90:31003,服务器端口/31003,客户端IP/10.50.24.198,客户端端口/45678,客户端环境/user=admin&password=123456,标签/SQL注入,动作/警告,HTTP/S响应码/403,攻击特征串/user=admin&password=123456,触发规则/10190001,访问唯一编号/7438514603676449994,国家/局域网,省/未知,市/未知,XFF_IP/"""
    res = get_components(log_text)
    json_data = json.dumps(res, ensure_ascii=False)
    print(json_data)