import re
import json
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

# Optimized patterns
patterns = {
    "key_value_p": r"""
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
    "date_p": r"\b[A-Za-z]{3}\s{1,2}\d{1,2}\s\d{4}\s\d{2}:\d{2}:\d{2}\b",
    "hostname_p": r"(?<=:\d{2}) ([a-zA-Z0-9._-]+)*(?=\s)",
    "pid_p": r"([a-zA-Z0-9_-]+)\[(\d+)\]",
    "ip_port_p": r"(\d+\.\d+\.\d+\.\d+)\s+port\s+(\d+)",
    "session_p": r"session (\d+)",
    "function_p": r"(?!%%.*)([a-zA-Z0-9_-]+)\((.*?)\)",
    "WebPort_p": r"(\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3})",
    "slash_pattern": r"([^,/]+)\/([^,]+)",
    "user_agent_p": r"Mozilla/5\.0\s*\([^)]+\)\s*(?:AppleWebKit/[\d\.]+\s*\([^)]+\)\s*Chrome/[\d\.]+\s*Safari/[\d\.]+|[\w\s]+/[\d\.]+)",
    "HTTPS_code_p": r"HTTP/S响应码/(\d+)",
    "web_attack_p": r"WEB攻击~([^~]+)~([^~]*)~([中高低]+)",
    "sys_attack_p": r"系统告警~+([^~]*)~+([^~]*)~+([中高低]+)~+(\d+)",
    "json_str_p": r'''
        "([^"]+)"            # 键
        \s*:\s*              # 分隔符
        (                    # 值
            "(?:\\"|[^"])*"  # 字符串（支持转义）
            |\[.*?\]         # 数组
            |-?\d+           # 整数
            |-?\d+\.\d+      # 浮点数
            |true|false|null # 布尔/空值
        )''',
    "segment_p": r"""
        ^\s*                    # 开头可能存在的空格
        ({})                    # 捕获目标键（类型|Host|解析域名）
        \s*:\s*                 # 冒号及两侧空格
        (.+?)                   # 非贪婪捕获值
        \s*$                    # 结尾可能存在的空格
    """.format('|'.join({'类型', 'Host'})),
    "fangkuohao_p": r"\[(\d+)\]",
    "key_words_p": r"\b(root|system\-logind|systemd|APT|run\-parts|URL地址|发生时间|服务器IP|服务器端口|主机名|攻击特征串|触发规则|访问唯一编号|国家|事件|局域网|LAN|请求方法|标签|动作|威胁|POST数据|省|HTTP/S响应码)\b"
}

def match_key_value_pairs(log_text):
    compiled_re = _compile_regex(patterns['key_value_p'], re.VERBOSE)
    matches = compiled_re.finditer(log_text)
    results = []
    for match in matches:
        key = match.group('key').strip()
        value = match.group('value').strip()
        results.append({"key": key, "value": value})
    return results

def match_date(log_text):
    compiled_re = _compile_regex(patterns['date_p'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        date = match.group(0)
        results.append({"key": "", "value": date})
    return results

def match_hostname(log_text):
    compiled_re = _compile_regex(patterns['hostname_p'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        hostname = match.group(1)
        results.append({"key": "", "value": hostname})
    return results

def match_pid(log_text):
    compiled_re = _compile_regex(patterns['pid_p'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        pid = match.group(0)
        results.append({"key": "", "value": pid})
    return results

def match_ip_port(log_text):
    compiled_re = _compile_regex(patterns['ip_port_p'])
    matches = compiled_re.finditer(log_text)
    results = []
    for match in matches:
        ip = match.group(1)
        port = match.group(2)
        results.append({"key": "IP", "value": ip})
        results.append({"key": "Port", "value": port})
    return results

def match_session_id(log_text):
    compiled_re = _compile_regex(patterns['session_p'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        session_id = match.group(1)
        results.append({"key": "Session ID", "value": session_id})
    return results

def match_function_call(log_text):
    compiled_re = _compile_regex(patterns['function_p'])
    matches = compiled_re.finditer(log_text)
    results = []
    for match in matches:
        function_name = match.group(1)
        arguments = match.group(2)
        results.append({"key": "Function", "value": f"{function_name}({arguments})"})
    return results

def match_web_port(log_text):
    compiled_re = _compile_regex(patterns['WebPort_p'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        web_port = match.group(0)
        results.append({"key": "Web Port", "value": web_port})
    return results

def match_slash_pattern(log_text):
    compiled_re = _compile_regex(patterns['slash_pattern'])
    matches = compiled_re.finditer(log_text)
    results = []
    for match in matches:
        key = match.group(1)
        value = match.group(2)
        results.append({"key": key, "value": value})
    return results

def match_user_agent(log_text):
    compiled_re = _compile_regex(patterns['user_agent_p'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        user_agent = match.group(0)
        results.append({"key": "User-Agent", "value": user_agent})
    return results

def match_HTTPS_code(log_text):
    compiled_re = _compile_regex(patterns['HTTPS_code_p'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        code = match.group(1)
        results.append({"key": "HTTP/S响应码", "value": code})
    return results

def match_web_attack(log_text):
    compiled_re = _compile_regex(patterns['web_attack_p'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        attack_type = match.group(1)
        attack_info = match.group(2)
        threat_level = match.group(3)
        results.append({"key": "WEB攻击类型", "value": attack_type})
        results.append({"key": "WEB攻击信息", "value": attack_info})
        results.append({"key": "威胁等级", "value": threat_level})
    return results

def match_sys_attack(log_text):
    compiled_re = _compile_regex(patterns['sys_attack_p'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        attack_type = match.group(1)
        attack_info = match.group(2)
        threat_level = match.group(3)
        rule_id = match.group(4)
        results.append({"key": "系统告警类型", "value": attack_type})
        results.append({"key": "系统告警信息", "value": attack_info})
        results.append({"key": "威胁等级", "value": threat_level})
        results.append({"key": "规则ID", "value": rule_id})
    return results

def match_json_string(log_text):
    compiled_re = _compile_regex(patterns['json_str_p'], re.VERBOSE)
    matches = compiled_re.finditer(log_text)
    results = []
    for match in matches:
        key = match.group(1)
        value = match.group(2)
        results.append({"key": key, "value": value})
    return results

def match_segment(log_text):
    compiled_re = _compile_regex(patterns['segment_p'], re.VERBOSE)
    matches = compiled_re.finditer(log_text)
    results = []
    for match in matches:
        key = match.group(1)
        value = match.group(2)
        results.append({"key": key, "value": value})
    return results

def match_fangkuohao(log_text):
    compiled_re = _compile_regex(patterns['fangkuohao_p'])
    matches = compiled_re.finditer(log_text)
    results = []
    for match in matches:
        value = match.group(1)
        results.append({"key": "方括号内容", "value": value})
    return results

def match_key_words(log_text):
    compiled_re = _compile_regex(patterns['key_words_p'])
    matches = compiled_re.finditer(log_text)
    results = []
    for match in matches:
        key_word = match.group(0)
        results.append({"key": key_word, "value": key_word})
    return results

def get_components(log_text):
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_pid(log_text))
    results.extend(match_ip_port(log_text))
    results.extend(match_session_id(log_text))
    results.extend(match_function_call(log_text))
    results.extend(match_web_port(log_text))
    results.extend(match_slash_pattern(log_text))
    results.extend(match_user_agent(log_text))
    results.extend(match_HTTPS_code(log_text))
    results.extend(match_web_attack(log_text))
    results.extend(match_sys_attack(log_text))
    results.extend(match_json_string(log_text))
    results.extend(match_segment(log_text))
    results.extend(match_fangkuohao(log_text))
    results.extend(match_key_words(log_text))
    results.extend(match_key_value_pairs(log_text))
    return results

if __name__ == '__main__':
    log_text = f"""<178>Oct 21 10:05:12 10-50-86-13 DBAppWAF: 发生时间/2024-10-21 10:05:08,威胁/低,事件/检测SQL注入攻击,请求方法/POST,URL地址/10.50.109.3/login.php,POST数据/user=admin&password=123456,服务器IP/10.50.109.3,主机名/10.50.109.3,服务器端口/80,客户端IP/10.50.86.36,客户端端口/46383,客户端环境/Mozilla/5.0 [en] (X11, U; DBAPPSecurity 21.4.3),标签/SQL注入,动作/阻断,HTTP/S响应码/403,攻击特征串/user=admin&password=123456,触发规则/10350001,访问唯一编号/7428040015955890766,国家/局域网,省/未知,市/未知,XFF_IP/"""
    res = get_components(log_text)
    json_data = json.dumps(res, ensure_ascii=False)
    print(json_data)