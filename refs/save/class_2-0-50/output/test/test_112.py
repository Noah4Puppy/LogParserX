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
    "user_agent": r"Mozilla/5\.0\s*\([^)]+\)\s*(?:AppleWebKit/[\d\.]+\s*\([^)]+\)\s*Chrome/[\d\.]+\s*Safari/[\d\.]+|[\w\s]+/[\d\.]+)",
    "https_code": r"HTTP/S响应码/(\d+)",
    "attack_feature": r"攻击特征串/([^,]+)",
    "trigger_rule": r"触发规则/(\d+)",
    "unique_visit_id": r"访问唯一编号/(\d+)",
    "country": r"国家/(\w+)"
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
    matches = compiled_re.finditer(text)
    results = []
    for match in matches:
        key = match.group('key').strip()
        value = match.group('value').strip()
        if key or value:
            results.append({"key": key, "value": value})
    return results

def match_ip_port(text):
    compiled_re = _compile_regex(patterns['ip_port'])
    matches = compiled_re.findall(text)
    results = []
    for ip, port in matches:
        results.append({"key": "服务器IP", "value": ip})
        results.append({"key": "服务器端口", "value": port})
    return results

def match_user_agent(text):
    compiled_re = _compile_regex(patterns['user_agent'])
    match = compiled_re.search(text)
    results = []
    if match:
        user_agent = match.group(0)
        results.append({"key": "客户端环境", "value": user_agent})
    return results

def match_https_code(text):
    compiled_re = _compile_regex(patterns['https_code'])
    match = compiled_re.search(text)
    results = []
    if match:
        https_code = match.group(1)
        results.append({"key": "HTTP/S响应码", "value": https_code})
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

def get_components(log_text):
    results = []

    # Extract date
    results.extend(match_date(log_text))

    # Extract hostname
    results.extend(match_hostname(log_text))

    # Extract key-value pairs
    results.extend(match_key_value(log_text))

    # Extract IP and port
    results.extend(match_ip_port(log_text))

    # Extract user agent
    results.extend(match_user_agent(log_text))

    # Extract HTTP response code
    results.extend(match_https_code(log_text))

    # Extract attack feature
    results.extend(match_attack_feature(log_text))

    # Extract trigger rule
    results.extend(match_trigger_rule(log_text))

    # Extract unique visit ID
    results.extend(match_unique_visit_id(log_text))

    # Extract country
    results.extend(match_country(log_text))

    return results

if __name__ == '__main__':
    log_text = f"""<178>Aug 15 10:15:22 192.168.19.40 DBAppWAF: 发生时间/2024-08-15 10:15:19,威胁/中,事件/SQL注入,请求方法/POST,URL地址/59.202.175.9:9031/jinhua/api/user/login?username=admin&password=123456,POST数据/,服务器IP/59.202.175.9,主机名/59.202.175.9:9031,服务器端口/9031,客户端IP/10.44.58.134,客户端端口/52890,客户端环境/Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36,标签/SQL注入,动作/阻断,HTTP/S响应码/403,攻击特征串/abc123def456ghi789,触发规则/18010102,访问唯一编号/7402888116246734200,国家/LAN,省/,市/,XFF_IP/"""
    res = get_components(log_text)
    json_data = json.dumps(res, ensure_ascii=False)
    print(json_data)