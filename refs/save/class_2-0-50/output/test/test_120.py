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
    "threat": r"威胁/([^\s,]+)",
    "server_ip": r"服务器IP/(\d+\.\d+\.\d+\.\d+)",
    "server_port": r"服务器端口/(\d+)",
    "client_ip": r"客户端IP/(\d+\.\d+\.\d+\.\d+)",
    "action": r"动作/([^\s,]+)",
    "http_response_code": r"HTTP/S响应码/(\d+)",
    "trigger_rule": r"触发规则/(\d+)",
    "country": r"国家/([^\s,]+)"
}

def match_date(log_text):
    compiled_re = _compile_regex(patterns['date'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        date = match.group(0)
        results.append({"key": "", "value": date})
    return results

def match_hostname(log_text):
    compiled_re = _compile_regex(patterns['hostname'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        hostname = match.group(1)
        results.append({"key": "", "value": hostname})
    return results

def match_threat(log_text):
    compiled_re = _compile_regex(patterns['threat'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        threat = match.group(1)
        results.append({"key": "威胁", "value": threat})
    return results

def match_server_ip(log_text):
    compiled_re = _compile_regex(patterns['server_ip'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        server_ip = match.group(1)
        results.append({"key": "服务器IP", "value": server_ip})
    return results

def match_server_port(log_text):
    compiled_re = _compile_regex(patterns['server_port'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        server_port = match.group(1)
        results.append({"key": "服务器端口", "value": server_port})
    return results

def match_client_ip(log_text):
    compiled_re = _compile_regex(patterns['client_ip'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        client_ip = match.group(1)
        results.append({"key": "客户端IP", "value": client_ip})
    return results

def match_action(log_text):
    compiled_re = _compile_regex(patterns['action'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        action = match.group(1)
        results.append({"key": "动作", "value": action})
    return results

def match_http_response_code(log_text):
    compiled_re = _compile_regex(patterns['http_response_code'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        http_response_code = match.group(1)
        results.append({"key": "HTTP/S响应码", "value": http_response_code})
    return results

def match_trigger_rule(log_text):
    compiled_re = _compile_regex(patterns['trigger_rule'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        trigger_rule = match.group(1)
        results.append({"key": "触发规则", "value": trigger_rule})
    return results

def match_country(log_text):
    compiled_re = _compile_regex(patterns['country'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        country = match.group(1)
        results.append({"key": "国家", "value": country})
    return results

def get_components(log_text):
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_threat(log_text))
    results.extend(match_server_ip(log_text))
    results.extend(match_server_port(log_text))
    results.extend(match_client_ip(log_text))
    results.extend(match_action(log_text))
    results.extend(match_http_response_code(log_text))
    results.extend(match_trigger_rule(log_text))
    results.extend(match_country(log_text))
    return results

if __name__ == '__main__':
    log_text = f"""<178>Oct 15 07:45:22 10.50.81.60 DBAppWAF: 发生时间/2024-10-15 07:45:22,威胁/中,事件/SQL注入,请求方法/POST,URL地址/10.50.81.60:8000/admin/login.php?username=admin&password=123456,POST数据/username=admin&password=123456,服务器IP/10.50.81.6,主机名/10.50.81.60:8000,服务器端口/8000,客户端IP/10.20.170.23,客户端端口/43789,客户端环境/Mozilla/5.0 [en] (X11, U; DBAPPSecurity 21.4.3),标签/SQL注入(语法/语义分析),动作/阻断,HTTP/S响应码/403,攻击特征串//admin/login.php?username=admin&password=123456,触发规则/13100002,访问唯一编号/7425393358323843207,国家/LAN,省/,市/,XFF_IP/"""
    res = get_components(log_text)
    json_data = json.dumps(res, ensure_ascii=False)
    print(json_data)