```python
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
    "hostname": r"(?<=:\d{2}) ([a-zA-Z0-9._-]+)",
    "pid": r"([a-zA-Z0-9_-]+)\[(\d+)\]",
    "ip_port": r"(\d+\.\d+\.\d+\.\d+):(\d+)",
    "session": r"session (\d+)",
    "function": r"(?!%%.*)([a-zA-Z0-9_-]+)\((.*?)\)",
    "web_port": r"(\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3})",
    "slash": r"([^,/]+)\/([^,]+)",
    "user_agent": r"Mozilla/5\.0\s*\([^)]+\)\s*(?:AppleWebKit/[\d\.]+\s*\([^)]+\)\s*Chrome/[\d\.]+\s*Safari/[\d\.]+|[\w\s]+/[\d\.]+)",
    "http_response_code": r"HTTP/S响应码/(\d+)",
    "web_attack": r"WEB攻击~([^~]+)~([^~]*)~([中高低]+)",
    "sys_attack": r"系统告警~+([^~]*)~+([^~]*)~+([中高低]+)~+(\d+)",
    "json_str": r'''
        "([^"]+)"            # 键
        \s*:\s*              # 分隔符
        (                    # 值
            "(?:\\"|[^"])*"  # 字符串（支持转义）
            |\[.*?\]         # 数组
            |-?\d+           # 整数
            |-?\d+\.\d+      # 浮点数
            |true|false|null # 布尔/空值
        )''',
    "key_words": r"\b(root|system\-logind|systemd|APT|run\-parts|URL地址|发生时间|服务器IP|服务器端口|主机名|攻击特征串|触发规则|访问唯一编号|国家|事件|局域网|LAN|请求方法|标签|动作|威胁|POST数据|省|HTTP/S响应码)\b"
}

def match_key_value(log_text: str) -> list:
    regex = _compile_regex(patterns['key_value'], re.VERBOSE)
    matches = regex.finditer(log_text)
    results = []
    for match in matches:
        key = match.group('key').strip()
        value = match.group('value').strip()
        results.append({"key": key, "value": value})
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
        results.append({"key": "服务器IP", "value": ip})
        results.append({"key": "服务器端口", "value": port})
    return results

def match_session(log_text: str) -> list:
    regex = _compile_regex(patterns['session'])
    match = regex.search(log_text)
    results = []
    if match:
        session = match.group(1)
        results.append({"key": "session", "value": session})
    return results

def match_function(log_text: str) -> list:
    regex = _compile_regex(patterns['function'])
    matches = regex.findall(log_text)
    results = []
    for func, args in matches:
        results.append({"key": func, "value": args})
    return results

def match_web_port(log_text: str) -> list:
    regex = _compile_regex(patterns['web_port'])
    matches = regex.findall(log_text)
    results = []
    for web_port in matches:
        results.append({"key": "WebPort", "value": web_port})
    return results

def match_slash(log_text: str) -> list:
    regex = _compile_regex(patterns['slash'])
    matches = regex.findall(log_text)
    results = []
    for key, value in matches:
        results.append({"key": key, "value": value})
    return results

def match_user_agent(log_text: str) -> list:
    regex = _compile_regex(patterns['user_agent'])
    match = regex.search(log_text)
    results = []
    if match:
        user_agent = match.group(0)
        results.append({"key": "客户端环境", "value": user_agent})
    return results

def match_http_response_code(log_text: str) -> list:
    regex = _compile_regex(patterns['http_response_code'])
    match = regex.search(log_text)
    results = []
    if match:
        http_response_code = match.group(1)
        results.append({"key": "HTTP/S响应码", "value": http_response_code})
    return results

def match_web_attack(log_text: str) -> list:
    regex = _compile_regex(patterns['web_attack'])
    match = regex.search(log_text)
    results = []
    if match:
        attack_type = match.group(1)
        attack_info = match.group(2)
        threat_level = match.group(3)
        results.append({"key": "攻击类型", "value": attack_type})
        results.append({"key": "攻击信息", "value": attack_info})
        results.append({"key": "威胁等级", "value": threat_level})
    return results

def match_sys_attack(log_text: str) -> list:
    regex = _compile_regex(patterns['sys_attack'])
    match = regex.search(log_text)
    results = []
    if match:
        attack_type = match.group(1)
        attack_info = match.group(2)
        threat_level = match.group(3)
        rule_id = match.group(4)
        results.append({"key": "攻击类型", "value": attack_type})
        results.append({"key": "攻击信息", "value": attack_info})
        results.append({"key": "威胁等级", "value": threat_level})
        results.append({"key": "规则ID", "value": rule_id})
    return results

def match_json_str(log_text: str) -> list:
    regex = _compile_regex(patterns['json_str'], re.VERBOSE)
    matches = regex.findall(log_text)
    results = []
    for key, value in matches:
        results.append({"key": key, "value": value})
    return results

def match_key_words(log_text: str) -> list:
    regex = _compile_regex(patterns['key_words'])
    matches = regex.findall(log_text)
    results = []
    for key in matches:
        results.append({"key": key, "value": key})
    return results

def get_components(log_text: str) -> list:
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_pid(log_text))
    results.extend(match_ip_port(log_text))
    results.extend(match_session(log_text))
    results.extend(match_function(log_text))
    results.extend(match_web_port(log_text))
    results.extend(match_slash(log_text))
    results.extend(match_user_agent(log_text))
    results.extend(match_http_response_code(log_text))
    results.extend(match_web_attack(log_text))
    results.extend(match_sys_attack(log_text))
    results.extend(match_json_str(log_text))
    results.extend(match_key_value(log_text))
    results.extend(match_key_words(log_text))
    return results

if __name__ == '__main__':
    log_text = "<178>Oct 21 09:54:46 10-50-86-12 DBAppWAF: 发生时间/2024-10-21 09:54:40,威胁/高,事件/检测XSS攻击,请求方法/GET,URL地址/10.50.109.2/photos/search.php?dosearch=true&query=\"\>\<script>alert(document.cookie)\</script>\",POST数据/,服务器IP/10.50.109.2,主机名/10.50.109.2,服务器端口/80,客户端IP/10.50.86.35,客户端端口/58262,客户端环境/Mozilla/5.0 [en] (X11, U; DBAPPSecurity 21.4.3),标签/通用防护,动作/告警,HTTP/S响应码/301,攻击特征串/\"\>\<script>alert(document.cookie)\</script>\",触发规则/10240000,访问唯一编号/7428041484838900913,国家/局域网,省/未知,市/未知,XFF_IP/,"
    res = get_components(log_text)
    json_data = json.dumps(res, ensure_ascii=False)
    print(json_data)
```
This code defines a set of functions to match various patterns in the log text and extract the required fields. The `get_components` function combines the results from all these functions and returns a list of dictionaries containing the key-value pairs. The main block demonstrates how to use the `get_components` function and prints the results in JSON format.