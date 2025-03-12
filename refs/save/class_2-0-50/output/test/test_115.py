import re
import json
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

# Optimized patterns
patterns = {
    "date": r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\b",
    "hostname": r"主机名/([a-zA-Z0-9._-]+)",
    "request_method": r"请求方法/(\w+)",
    "url_address": r"URL地址/([^,]+)",
    "server_ip": r"服务器IP/(\d+\.\d+\.\d+\.\d+)",
    "server_port": r"服务器端口/(\d+)",
    "client_port": r"客户端端口/(\d+)",
    "action": r"动作/(\w+)",
    "trigger_rule": r"触发规则/(\d+)"
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

def match_request_method(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['request_method'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        request_method = match.group(1)
        results.append({"key": "请求方法", "value": request_method})
    return results

def match_url_address(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['url_address'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        url_address = match.group(1)
        results.append({"key": "URL地址", "value": url_address})
    return results

def match_server_ip(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['server_ip'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        server_ip = match.group(1)
        results.append({"key": "服务器IP", "value": server_ip})
    return results

def match_server_port(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['server_port'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        server_port = match.group(1)
        results.append({"key": "服务器端口", "value": server_port})
    return results

def match_client_port(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['client_port'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        client_port = match.group(1)
        results.append({"key": "客户端端口", "value": client_port})
    return results

def match_action(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['action'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        action = match.group(1)
        results.append({"key": "动作", "value": action})
    return results

def match_trigger_rule(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['trigger_rule'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        trigger_rule = match.group(1)
        results.append({"key": "触发规则", "value": trigger_rule})
    return results

def get_components(log_text: str) -> list:
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_request_method(log_text))
    results.extend(match_url_address(log_text))
    results.extend(match_server_ip(log_text))
    results.extend(match_server_port(log_text))
    results.extend(match_client_port(log_text))
    results.extend(match_action(log_text))
    results.extend(match_trigger_rule(log_text))
    return results

if __name__ == '__main__':
    log_text = f"""<178>Dec 20 10:25:42 10-50-86-12 DBAppWAF: 发生时间/2024-12-20 10:25:32,威胁/中,事件/检测SQL注入,请求方法/POST,URL地址/10.50.109.90/login.php?action=login&username=admin&password=123456,POST数据/password=123456,服务器IP/10.50.109.90,主机名/10.50.109.90,服务器端口/80,客户端IP/10.50.24.198,客户端端口/51255,客户端环境/Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36,标签/SQL注入,动作/警告,HTTP/S响应码/200,攻击特征串/password=123456,触发规则/10110001,访问唯一编号/7438514758295273318,国家/局域网,省/未知,市/未知,XFF_IP/"""
    res = get_components(log_text)
    json_data = json.dumps(res, ensure_ascii=False)
    print(json_data)