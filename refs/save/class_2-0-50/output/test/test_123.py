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
    "key_value": r"""
        (?:                        # 起始分隔符检测
        (?<=[;:,=(\-])|       # 关键修正：添加冒号:和连字符-作为合法分隔符
        ^)
        \s*                        # 允许前置空格
        (?P<key>                   # 键名规则
            (?![\d\-])             # 不能以数字或连字符开头
            [\w\s.-]+              # 允许字母/数字/空格/点/连字符
        )
        \s*=\s*                    # 等号两侧允许空格
        (?P<value>                 # 值部分
            (?:                   
                (?!\s*[,;)=\-])    # 排除前置分隔符（新增-）
                [^,;)=\-]+         # 基础匹配（新增排除-）
            )+
        )
        (?=                        # 截断预查
            \s*[,;)=\-]|           # 分隔符（新增-）
            \s*$|                  # 字符串结束
            (?=\S+\s*=)            # 后面紧跟新键（含空格键名）
        )
    """,
    "ip_port": r"(\d+\.\d+\.\d+\.\d+):(\d+)",
    "http_response_code": r"HTTP/S响应码/(\d+)",
    "trigger_rule": r"触发规则/(\d+)"
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

def match_key_value(text):
    compiled_re = _compile_regex(patterns['key_value'], re.VERBOSE)
    matches = compiled_re.findall(text)
    results = []
    for key, value in matches:
        results.append({"key": key.strip(), "value": value.strip()})
    return results

def match_ip_port(text):
    compiled_re = _compile_regex(patterns['ip_port'])
    matches = compiled_re.findall(text)
    results = []
    for ip, port in matches:
        results.append({"key": "服务器IP", "value": ip})
        results.append({"key": "服务器端口", "value": port})
    return results

def match_http_response_code(text):
    compiled_re = _compile_regex(patterns['http_response_code'])
    match = compiled_re.search(text)
    results = []
    if match:
        http_response_code = match.group(1)
        results.append({"key": "HTTP/S响应码", "value": http_response_code})
    return results

def match_trigger_rule(text):
    compiled_re = _compile_regex(patterns['trigger_rule'])
    match = compiled_re.search(text)
    results = []
    if match:
        trigger_rule = match.group(1)
        results.append({"key": "触发规则", "value": trigger_rule})
    return results

def get_components(log_text):
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_key_value(log_text))
    results.extend(match_ip_port(log_text))
    results.extend(match_http_response_code(log_text))
    results.extend(match_trigger_rule(log_text))
    return results

if __name__ == '__main__':
    log_text = f"""<178>Dec 20 10:25:32 10-50-86-12 DBAppWAF: 发生时间/2024-12-20 10:25:25,威胁/低,事件/检测恶意软件,请求方法/POST,URL地址/10.50.109.90:31000/api/v1/login,POST数据/user=admin&password=123456,服务器IP/10.50.109.90,主机名/10.50.109.90:31000,服务器端口/31000,客户端IP/10.50.24.198,客户端端口/50001,客户端环境/curl/7.54.0,标签/恶意软件,动作/警告,HTTP/S响应码/401,攻击特征串/curl,触发规则/10503000,访问唯一编号/7438514852787699739,国家/局域网,省/未知,市/未知,XFF_IP/"""
    res = get_components(log_text)
    json_data = json.dumps(res, ensure_ascii=False)
    print(json_data)