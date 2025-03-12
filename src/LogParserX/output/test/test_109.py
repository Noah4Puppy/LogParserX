import re
import json
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

# Optimized patterns
patterns = {
    "date": r"\b[A-Za-z]{3}\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2}\b",
    "hostname": r"(?<=:\d{2}) ([a-zA-Z0-9._-]+)",
    "event": r"事件/([^,]+)",
    "request_method": r"请求方法/([^,]+)",
    "url_address": r"URL地址/([^,]+)",
    "server_ip": r"服务器IP/([^,]+)",
    "client_port": r"客户端端口/(\d+)",
    "tag": r"标签/([^,]+)",
    "http_response_code": r"HTTP/S响应码/(\d+)",
    "unique_id": r"访问唯一编号/(\d+)"
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

def match_event(text):
    compiled_re = _compile_regex(patterns['event'])
    match = compiled_re.search(text)
    results = []
    if match:
        event = match.group(1)
        results.append({"key": "事件", "value": event})
    return results

def match_request_method(text):
    compiled_re = _compile_regex(patterns['request_method'])
    match = compiled_re.search(text)
    results = []
    if match:
        request_method = match.group(1)
        results.append({"key": "请求方法", "value": request_method})
    return results

def match_url_address(text):
    compiled_re = _compile_regex(patterns['url_address'])
    match = compiled_re.search(text)
    results = []
    if match:
        url_address = match.group(1)
        results.append({"key": "URL地址", "value": url_address})
    return results

def match_server_ip(text):
    compiled_re = _compile_regex(patterns['server_ip'])
    match = compiled_re.search(text)
    results = []
    if match:
        server_ip = match.group(1)
        results.append({"key": "服务器IP", "value": server_ip})
    return results

def match_client_port(text):
    compiled_re = _compile_regex(patterns['client_port'])
    match = compiled_re.search(text)
    results = []
    if match:
        client_port = match.group(1)
        results.append({"key": "客户端端口", "value": client_port})
    return results

def match_tag(text):
    compiled_re = _compile_regex(patterns['tag'])
    match = compiled_re.search(text)
    results = []
    if match:
        tag = match.group(1)
        results.append({"key": "标签", "value": tag})
    return results

def match_http_response_code(text):
    compiled_re = _compile_regex(patterns['http_response_code'])
    match = compiled_re.search(text)
    results = []
    if match:
        http_response_code = match.group(1)
        results.append({"key": "HTTP/S响应码", "value": http_response_code})
    return results

def match_unique_id(text):
    compiled_re = _compile_regex(patterns['unique_id'])
    match = compiled_re.search(text)
    results = []
    if match:
        unique_id = match.group(1)
        results.append({"key": "访问唯一编号", "value": unique_id})
    return results

def get_components(log_text):
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_event(log_text))
    results.extend(match_request_method(log_text))
    results.extend(match_url_address(log_text))
    results.extend(match_server_ip(log_text))
    results.extend(match_client_port(log_text))
    results.extend(match_tag(log_text))
    results.extend(match_http_response_code(log_text))
    results.extend(match_unique_id(log_text))
    return results

if __name__ == '__main__':
    log_text = f"""<178>Oct 21 10:00:12 10-50-86-13 DBAppWAF: 发生时间/2024-10-21 09:59:58,威胁/低,事件/检测SQL注入攻击,请求方法/POST,URL地址/10.50.109.3/api/login,POST数据/username=admin&password=123456,服务器IP/10.50.109.3,主机名/10.50.109.3,服务器端口/8080,客户端IP/10.50.86.36,客户端端口/45678,客户端环境/Mozilla/5.0 [en] (X11, U; DBAPPSecurity 21.4.3),标签/SQL注入,动作/阻断,HTTP/S响应码/403,攻击特征串/UNION SELECT,触发规则/10350001,访问唯一编号/7428041536381654218,国家/局域网,省/未知,市/未知,XFF_IP/"""
    res = get_components(log_text)
    json_data = json.dumps(res, ensure_ascii=False)
    print(json_data)