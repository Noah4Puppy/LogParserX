import re
import json
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

# Optimized patterns
patterns = {
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
    "date": r"\b[A-Za-z]{3}\s{1,2}\d{1,2}\s\d{4}\s\d{2}:\d{2}:\d{2}\b",
    "hostname": r"(?<=:\d{2}) ([a-zA-Z0-9._-]+)*(?=\s)",
    "pid": r"([a-zA-Z0-9_-]+)\[(\d+)\]",
    "ip_port": r"(\d+\.\d+\.\d+\.\d+)(?:\((\d+)\))?",
    "user_agent": r"Mozilla/5\.0\s*\([^)]+\)\s*(?:AppleWebKit/[\d\.]+\s*\([^)]+\)\s*Chrome/[\d\.]+\s*Safari/[\d\.]+|[\w\s]+/[\d\.]+)",
    "label": r"标签/([\w\s]+)",
    "action": r"动作/([\w\s]+)",
    "request_method": r"请求方法/([\w]+)",
    "server_port": r"服务器端口/(\d+)",
    "client_ip": r"客户端IP/(\d+\.\d+\.\d+\.\d+)",
    "client_port": r"客户端端口/(\d+)",
    "client_env": r"客户端环境/([\w\s\.\[\]\(\);-]+)"
}

def match_key_value(log_text: str) -> list:
    regex = _compile_regex(patterns['key_value'], re.VERBOSE)
    matches = regex.finditer(log_text)
    results = []
    for match in matches:
        results.append({"key": match.group('key').strip(), "value": match.group('value').strip()})
    return results

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

def match_pid(log_text: str) -> list:
    regex = _compile_regex(patterns['pid'])
    match = regex.search(log_text)
    results = []
    if match:
        pid = match.group(0)
        results.append({"key": "", "value": pid})
    return results

def match_ip_port(log_text: str) -> list:
    regex = _compile_regex(patterns['ip_port'])
    matches = regex.findall(log_text)
    results = []
    for ip, port in matches:
        if port:
            results.append({"key": "服务器IP", "value": ip})
            results.append({"key": "服务器端口", "value": port})
    return results

def match_user_agent(log_text: str) -> list:
    regex = _compile_regex(patterns['user_agent'])
    match = regex.search(log_text)
    results = []
    if match:
        user_agent = match.group(0)
        results.append({"key": "客户端环境", "value": user_agent})
    return results

def match_label(log_text: str) -> list:
    regex = _compile_regex(patterns['label'])
    match = regex.search(log_text)
    results = []
    if match:
        label = match.group(1)
        results.append({"key": "标签", "value": label})
    return results

def match_action(log_text: str) -> list:
    regex = _compile_regex(patterns['action'])
    match = regex.search(log_text)
    results = []
    if match:
        action = match.group(1)
        results.append({"key": "动作", "value": action})
    return results

def match_request_method(log_text: str) -> list:
    regex = _compile_regex(patterns['request_method'])
    match = regex.search(log_text)
    results = []
    if match:
        request_method = match.group(1)
        results.append({"key": "请求方法", "value": request_method})
    return results

def match_server_port(log_text: str) -> list:
    regex = _compile_regex(patterns['server_port'])
    match = regex.search(log_text)
    results = []
    if match:
        server_port = match.group(1)
        results.append({"key": "服务器端口", "value": server_port})
    return results

def match_client_ip(log_text: str) -> list:
    regex = _compile_regex(patterns['client_ip'])
    match = regex.search(log_text)
    results = []
    if match:
        client_ip = match.group(1)
        results.append({"key": "客户端IP", "value": client_ip})
    return results

def match_client_port(log_text: str) -> list:
    regex = _compile_regex(patterns['client_port'])
    match = regex.search(log_text)
    results = []
    if match:
        client_port = match.group(1)
        results.append({"key": "客户端端口", "value": client_port})
    return results

def match_client_env(log_text: str) -> list:
    regex = _compile_regex(patterns['client_env'])
    match = regex.search(log_text)
    results = []
    if match:
        client_env = match.group(1)
        results.append({"key": "客户端环境", "value": client_env})
    return results

def get_components(log_text: str) -> list:
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_key_value(log_text))
    results.extend(match_pid(log_text))
    results.extend(match_ip_port(log_text))
    results.extend(match_user_agent(log_text))
    results.extend(match_label(log_text))
    results.extend(match_action(log_text))
    results.extend(match_request_method(log_text))
    results.extend(match_server_port(log_text))
    results.extend(match_client_ip(log_text))
    results.extend(match_client_port(log_text))
    results.extend(match_client_env(log_text))
    return results

if __name__ == '__main__':
    log_text = f"""<178>Oct 22 10:15:42 10-50-86-13 DBAppWAF: 发生时间/2024-10-22 10:15:30,威胁/中,事件/检测SQL注入,请求方法/POST,URL地址/10.50.109.3/login.php?username=admin' OR '1'='1,POST数据/password=123456,服务器IP/10.50.109.3,主机名/10.50.109.3,服务器端口/80,客户端IP/10.50.86.36,客户端端口/43321,客户端环境/Mozilla/5.0 [en] (X11, U; DBAPPSecurity 21.4.3),标签/SQL注入,动作/阻断,HTTP/S响应码/403,攻击特征串/admin' OR '1'='1,触发规则/10191001,访问唯一编号/7428041106882827328,国家/局域网,省/未知,市/未知,XFF_IP/"""
    res = get_components(log_text)
    json_data = json.dumps(res, ensure_ascii=False)
    print(json_data)