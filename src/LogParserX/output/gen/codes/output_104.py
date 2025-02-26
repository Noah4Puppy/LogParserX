```python
import re
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
            [\w\s.-]*              # 允许字母/数字/空格/点/连字符
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
    "ip_port": r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})",
    "session": r"session (\d+)",
    "function": r"(?!%%.*)([a-zA-Z0-9_-]+)\((.*?)\)",
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
        )
    ''',
    "target_keys": r"""
        ^\s*                    # 开头可能存在的空格
        ({})                    # 捕获目标键（类型|Host|解析域名）
        \s*:\s*                 # 冒号及两侧空格
        (.+?)                   # 非贪婪捕获值
        \s*$                    # 结尾可能存在的空格
    """.format('|'.join({'类型', 'Host', '解析域名'})),
    "keywords": r"\b(root|system\-logind|systemd|APT|run\-parts|URL地址|发生时间|服务器IP|服务器端口|主机名|攻击特征串|触发规则|访问唯一编号|国家|事件|局域网|LAN|请求方法|标签|动作|威胁|POST数据|省|HTTP/S响应码)\b"
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
        results.append({"key": "hostname", "value": hostname})
    return results

def match_pid(log_text: str) -> list:
    regex = _compile_regex(patterns['pid'])
    match = regex.search(log_text)
    results = []
    if match:
        pid = match.group(2)
        results.append({"key": "pid", "value": pid})
    return results

def match_ip_port(log_text: str) -> list:
    regex = _compile_regex(patterns['ip_port'])
    matches = regex.findall(log_text)
    results = []
    for ip, port in matches:
        results.append({"key": f"{ip}:{port}", "value": f"{ip}:{port}"})
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

def match_web_attack(log_text: str) -> list:
    regex = _compile_regex(patterns['web_attack'])
    matches = regex.findall(log_text)
    results = []
    for attack_type, details, severity in matches:
        results.append({"key": "WEB攻击", "value": f"{attack_type}~{details}~{severity}"})
    return results

def match_sys_attack(log_text: str) -> list:
    regex = _compile_regex(patterns['sys_attack'])
    matches = regex.findall(log_text)
    results = []
    for attack_type, details, severity, count in matches:
        results.append({"key": "系统告警", "value": f"{attack_type}~{details}~{severity}~{count}"})
    return results

def match_json_str(log_text: str) -> list:
    regex = _compile_regex(patterns['json_str'], re.VERBOSE)
    matches = regex.findall(log_text)
    results = []
    for key, value in matches:
        results.append({"key": key, "value": value})
    return results

def match_target_keys(log_text: str) -> list:
    regex = _compile_regex(patterns['target_keys'], re.VERBOSE)
    matches = regex.finditer(log_text)
    results = []
    for match in matches:
        key = match.group(1).strip()
        value = match.group(2).strip()
        results.append({"key": key, "value": value})
    return results

def match_keywords(log_text: str) -> list:
    regex = _compile_regex(patterns['keywords'])
    matches = regex.findall(log_text)
    results = []
    for keyword in matches:
        results.append({"key": keyword, "value": keyword})
    return results

def get_components(log_text: str) -> list:
    results = []
    results.extend(match_date(log_text))
    results.extend(match_key_value(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_pid(log_text))
    results.extend(match_ip_port(log_text))
    results.extend(match_session(log_text))
    results.extend(match_function(log_text))
    results.extend(match_web_attack(log_text))
    results.extend(match_sys_attack(log_text))
    results.extend(match_json_str(log_text))
    results.extend(match_target_keys(log_text))
    results.extend(match_keywords(log_text))
    return results

if __name__ == '__main__':
    log_text = "<178>Aug 15 11:23:08 10-50-86-12 DBAppWAF: 发生时间/2024-08-15 11:22:58,威胁/中,事件/阻止携带异常HTTP版本号的请求,请求方法/OPTIONS,URL地址//,POST数据/,服务器IP/10.50.109.79,主机名/,服务器端口/2105,客户端IP/10.20.170.22,客户端端口/34448,客户端环境/,标签/协议限制,动作/告警,HTTP/S响应码/0,攻击特征串/RTSP/1.0,触发规则/11010102,访问唯一编号/7403201528594620508,国家/局域网,省/未知,市/未知,XFF_IP/"
    res = get_components(log_text)
    print(res)
```
```