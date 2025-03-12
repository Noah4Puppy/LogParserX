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
    "threat": r"威胁/(中|低|高)",
    "request_method": r"请求方法/(GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE|CONNECT)",
    "url": r"URL地址/([^,]+)",
    "server_ip": r"服务器IP/(\d+\.\d+\.\d+\.\d+)",
    "server_port": r"服务器端口/(\d+)",
    "attack_feature": r"攻击特征串/([^,]+)",
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

def match_threat(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['threat'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        threat = match.group(1)
        results.append({"key": "威胁", "value": threat})
    return results

def match_request_method(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['request_method'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        request_method = match.group(1)
        results.append({"key": "请求方法", "value": request_method})
    return results

def match_url(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['url'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        url = match.group(1)
        results.append({"key": "URL地址", "value": url})
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

def match_attack_feature(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['attack_feature'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        attack_feature = match.group(1)
        results.append({"key": "攻击特征串", "value": attack_feature})
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
    results.extend(match_threat(log_text))
    results.extend(match_request_method(log_text))
    results.extend(match_url(log_text))
    results.extend(match_server_ip(log_text))
    results.extend(match_server_port(log_text))
    results.extend(match_attack_feature(log_text))
    results.extend(match_trigger_rule(log_text))
    return results

if __name__ == '__main__':
    log_text = f"""<178>Nov 22 10:25:42 10-50-86-13 DBAppWAF: 发生时间/2024-11-22 10:25:30,威胁/低,事件/检测SQL注入攻击,请求方法/POST,URL地址/10.50.109.3/api/v1/login,POST数据/username=admin&password=123456,服务器IP/10.50.109.3,主机名/10.50.109.3,服务器端口/8080,客户端IP/10.50.86.36,客户端端口/58495,客户端环境/Mozilla/5.0 [en] (X11, U; DBAPPSecurity 21.4.3),标签/通用防护,动作/告警,HTTP/S响应码/403,攻击特征串/api/v1/login?username=admin&password=123456,触发规则/10350001,访问唯一编号/7428040655914406787,国家/局域网,省/未知,市/未知,XFF_IP/"""
    res = get_components(log_text)
    json_data = json.dumps(res, ensure_ascii=False)
    print(json_data)