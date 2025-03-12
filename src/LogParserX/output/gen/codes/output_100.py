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
    "hostname": r"(?<=:\d{2}) ([a-zA-Z0-9._-]+)*(?=\s)",
    "pid": r"([a-zA-Z0-9_-]+)\[(\d+)\]",
    "ip_port": r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})",
    "session": r"session (\d+)",
    "function": r"(?!%%.*)([a-zA-Z0-9_-]+)\((.*?)\)",
    "HTTPS_code": r"HTTP/S响应码/(\d+)",
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
    """.format('|'.join({'类型', 'Host'})),
    "fangkuohao": r"\[(\d+)\]",
    "key_words": r"\b(root|system\-logind|systemd|APT|run\-parts|URL地址|发生时间|服务器IP|服务器端口|主机名|攻击特征串|触发规则|访问唯一编号|国家|事件|局域网|LAN|请求方法|标签|动作|威胁|POST数据|省|HTTP/S响应码)\b"
}

# Define functions to match patterns
def match_key_value(log_text):
    compiled_re = _compile_regex(patterns['key_value'], re.VERBOSE)
    matches = compiled_re.finditer(log_text)
    results = []
    for match in matches:
        key = match.group('key').strip()
        value = match.group('value').strip()
        results.append({"key": key, "value": value})
    return results

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
        hostname = match.group(1).strip()
        results.append({"key": "", "value": hostname})
    return results

def match_pid(log_text):
    compiled_re = _compile_regex(patterns['pid'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        pid = match.group(2).strip()
        results.append({"key": "", "value": pid})
    return results

def match_ip_port(log_text):
    compiled_re = _compile_regex(patterns['ip_port'])
    matches = compiled_re.finditer(log_text)
    results = []
    for match in matches:
        ip = match.group(1).strip()
        port = match.group(2).strip()
        results.append({"key": "服务器IP", "value": ip})
        results.append({"key": "服务器端口", "value": port})
    return results

def match_session(log_text):
    compiled_re = _compile_regex(patterns['session'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        session = match.group(1).strip()
        results.append({"key": "session", "value": session})
    return results

def match_function(log_text):
    compiled_re = _compile_regex(patterns['function'])
    matches = compiled_re.finditer(log_text)
    results = []
    for match in matches:
        function = match.group(1).strip()
        args = match.group(2).strip()
        results.append({"key": function, "value": args})
    return results

def match_HTTPS_code(log_text):
    compiled_re = _compile_regex(patterns['HTTPS_code'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        code = match.group(1).strip()
        results.append({"key": "HTTP/S响应码", "value": code})
    return results

def match_web_attack(log_text):
    compiled_re = _compile_regex(patterns['web_attack'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        attack_type = match.group(1).strip()
        attack_info = match.group(2).strip()
        threat_level = match.group(3).strip()
        results.append({"key": "WEB攻击类型", "value": attack_type})
        results.append({"key": "WEB攻击信息", "value": attack_info})
        results.append({"key": "威胁等级", "value": threat_level})
    return results

def match_sys_attack(log_text):
    compiled_re = _compile_regex(patterns['sys_attack'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        attack_type = match.group(1).strip()
        attack_info = match.group(2).strip()
        threat_level = match.group(3).strip()
        count = match.group(4).strip()
        results.append({"key": "系统告警类型", "value": attack_type})
        results.append({"key": "系统告警信息", "value": attack_info})
        results.append({"key": "威胁等级", "value": threat_level})
        results.append({"key": "次数", "value": count})
    return results

def match_json_str(log_text):
    compiled_re = _compile_regex(patterns['json_str'], re.VERBOSE)
    matches = compiled_re.finditer(log_text)
    results = []
    for match in matches:
        key = match.group(1).strip()
        value = match.group(2).strip()
        results.append({"key": key, "value": value})
    return results

def match_target_keys(log_text):
    compiled_re = _compile_regex(patterns['target_keys'], re.VERBOSE)
    matches = compiled_re.finditer(log_text)
    results = []
    for match in matches:
        key = match.group(1).strip()
        value = match.group(2).strip()
        results.append({"key": key, "value": value})
    return results

def match_fangkuohao(log_text):
    compiled_re = _compile_regex(patterns['fangkuohao'])
    matches = compiled_re.finditer(log_text)
    results = []
    for match in matches:
        number = match.group(1).strip()
        results.append({"key": "方括号内数字", "value": number})
    return results

def match_key_words(log_text):
    compiled_re = _compile_regex(patterns['key_words'])
    matches = compiled_re.finditer(log_text)
    results = []
    for match in matches:
        keyword = match.group(0).strip()
        results.append({"key": keyword, "value": keyword})
    return results

def get_components(log_text):
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_pid(log_text))
    results.extend(match_ip_port(log_text))
    results.extend(match_session(log_text))
    results.extend(match_function(log_text))
    results.extend(match_HTTPS_code(log_text))
    results.extend(match_web_attack(log_text))
    results.extend(match_sys_attack(log_text))
    results.extend(match_json_str(log_text))
    results.extend(match_target_keys(log_text))
    results.extend(match_fangkuohao(log_text))
    results.extend(match_key_words(log_text))
    results.extend(match_key_value(log_text))
    return results

if __name__ == '__main__':
    log_text = "<178>Oct 14 06:46:19 10.50.81.59 DBAppWAF: 发生时间/2024-10-14 06:46:18,威胁/中,事件/协议违规,请求方法/GET,URL地址/10.50.81.59:8000/index.php?GLOBALS[SKIN]=../../../../../../../../../winnt/win.ini%00,POST数据/,服务器IP/10.50.81.5,主机名/10.50.81.59:8000,服务器端口/8000,客户端IP/10.20.170.22,客户端端口/34687,客户端环境/Mozilla/5.0 [en] (X11, U; DBAPPSecurity 21.4.3),标签/协议违规,动作/阻断,HTTP/S响应码/403,攻击特征串//index.php?GLOBALS[SKIN]=../../../../../../../../../winnt/win.ini\\x00,触发规则/11010015,访问唯一编号/7425395334018236552,国家/LAN,省/,市/,XFF_IP/"
    res = get_components(log_text)
    json_data = json.dumps(res, ensure_ascii=False)
    print(json_data)
```
```