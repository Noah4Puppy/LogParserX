import re
import json
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

# Optimized patterns
patterns = {
    "date": r"\b(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\b",
    "hostname": r"主机名/(\S+)",
    "request_method": r"请求方法/(\w+)",
    "url_address": r"URL地址/(\S+)",
    "hostname_full": r"主机名/(\S+)",
    "client_ip": r"客户端IP/(\d+\.\d+\.\d+\.\d+)",
    "client_port": r"客户端端口/(\d+)",
    "http_response_code": r"HTTP/S响应码/(\d+)",
    "trigger_rule": r"触发规则/(\d+)",
    "country": r"国家/(\S+)"
}

def match_date(log_text):
    compiled_re = _compile_regex(patterns['date'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        date = match.group(1)
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

def match_request_method(log_text):
    compiled_re = _compile_regex(patterns['request_method'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        request_method = match.group(1)
        results.append({"key": "请求方法", "value": request_method})
    return results

def match_url_address(log_text):
    compiled_re = _compile_regex(patterns['url_address'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        url_address = match.group(1)
        results.append({"key": "URL地址", "value": url_address})
    return results

def match_hostname_full(log_text):
    compiled_re = _compile_regex(patterns['hostname_full'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        hostname_full = match.group(1)
        results.append({"key": "主机名", "value": hostname_full})
    return results

def match_client_ip(log_text):
    compiled_re = _compile_regex(patterns['client_ip'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        client_ip = match.group(1)
        results.append({"key": "客户端IP", "value": client_ip})
    return results

def match_client_port(log_text):
    compiled_re = _compile_regex(patterns['client_port'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        client_port = match.group(1)
        results.append({"key": "客户端端口", "value": client_port})
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
    results.extend(match_request_method(log_text))
    results.extend(match_url_address(log_text))
    results.extend(match_hostname_full(log_text))
    results.extend(match_client_ip(log_text))
    results.extend(match_client_port(log_text))
    results.extend(match_http_response_code(log_text))
    results.extend(match_trigger_rule(log_text))
    results.extend(match_country(log_text))
    return results

if __name__ == '__main__':
    log_text = f"""<178>Dec 20 10:22:30 10-50-86-13 DBAppWAF: 发生时间/2024-12-20 10:22:29,威胁/中,事件/检测SQL注入(语义分析),请求方法/GET,URL地址/10.50.109.91:31005/vb/?routestring=ajax/render/widget_sql,GET数据/query=SELECT+*+FROM+users+WHERE+username='admin'+AND+password='12345',服务器IP/10.50.109.91,主机名/10.50.109.91:31005,服务器端口/31005,客户端IP/10.50.24.198,客户端端口/50001,客户端环境/Python-requests/2.25.1,标签/SQL注入,动作/警告,HTTP/S响应码/403,攻击特征串/SELECT * FROM users WHERE username='admin' AND password='12345',触发规则/10130001,访问唯一编号/7438514908622274731,国家/局域网,省/未知,市/未知,XFF_IP/"""
    res = get_components(log_text)
    json_data = json.dumps(res, ensure_ascii=False)
    print(json_data)