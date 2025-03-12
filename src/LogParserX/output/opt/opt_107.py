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
    "ip_port": r"(\d+\.\d+\.\d+\.\d+)\s+port\s+(\d+)",
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

def match_key_value(text):
    compiled_re = _compile_regex(patterns['key_value'], re.VERBOSE)
    matches = compiled_re.finditer(text)
    results = []
    for match in matches:
        key = match.group('key').strip()
        value = match.group('value').strip()
        results.append({"key": key, "value": value})
    return results

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
        hostname = match.group(1).strip()
        results.append({"key": "", "value": hostname})
    return results

def match_pid(text):
    compiled_re = _compile_regex(patterns['pid'])
    match = compiled_re.search(text)
    results = []
    if match:
        pid = match.group(0)
        results.append({"key": "", "value": pid})
    return results

def match_ip_port(text):
    compiled_re = _compile_regex(patterns['ip_port'])
    matches = compiled_re.finditer(text)
    results = []
    for match in matches:
        ip = match.group(1)
        port = match.group(2)
        results.append({"key": "IP", "value": ip})
        results.append({"key": "Port", "value": port})
    return results

def match_session(text):
    compiled_re = _compile_regex(patterns['session'])
    match = compiled_re.search(text)
    results = []
    if match:
        session = match.group(1)
        results.append({"key": "Session", "value": session})
    return results

def match_function(text):
    compiled_re = _compile_regex(patterns['function'])
    matches = compiled_re.finditer(text)
    results = []
    for match in matches:
        function = match.group(1)
        args = match.group(2)
        results.append({"key": "Function", "value": f"{function}({args})"})
    return results

def match_web_port(text):
    compiled_re = _compile_regex(patterns['web_port'])
    match = compiled_re.search(text)
    results = []
    if match:
        web_port = match.group(0)
        results.append({"key": "WebPort", "value": web_port})
    return results

def match_slash(text):
    compiled_re = _compile_regex(patterns['slash'])
    matches = compiled_re.finditer(text)
    results = []
    for match in matches:
        key = match.group(1)
        value = match.group(2)
        results.append({"key": key, "value": value})
    return results

def match_user_agent(text):
    compiled_re = _compile_regex(patterns['user_agent'])
    match = compiled_re.search(text)
    results = []
    if match:
        user_agent = match.group(0)
        results.append({"key": "User-Agent", "value": user_agent})
    return results

def match_http_response_code(text):
    compiled_re = _compile_regex(patterns['http_response_code'])
    match = compiled_re.search(text)
    results = []
    if match:
        http_response_code = match.group(1)
        results.append({"key": "HTTP/S响应码", "value": http_response_code})
    return results

def match_web_attack(text):
    compiled_re = _compile_regex(patterns['web_attack'])
    match = compiled_re.search(text)
    results = []
    if match:
        attack_type = match.group(1)
        attack_details = match.group(2)
        threat_level = match.group(3)
        results.append({"key": "WEB攻击类型", "value": attack_type})
        results.append({"key": "WEB攻击详情", "value": attack_details})
        results.append({"key": "威胁等级", "value": threat_level})
    return results

def match_sys_attack(text):
    compiled_re = _compile_regex(patterns['sys_attack'])
    match = compiled_re.search(text)
    results = []
    if match:
        attack_type = match.group(1)
        attack_details = match.group(2)
        threat_level = match.group(3)
        count = match.group(4)
        results.append({"key": "系统告警类型", "value": attack_type})
        results.append({"key": "系统告警详情", "value": attack_details})
        results.append({"key": "威胁等级", "value": threat_level})
        results.append({"key": "次数", "value": count})
    return results

def match_json_str(text):
    compiled_re = _compile_regex(patterns['json_str'], re.VERBOSE)
    matches = compiled_re.finditer(text)
    results = []
    for match in matches:
        key = match.group(1)
        value = match.group(2)
        results.append({"key": key, "value": value})
    return results

def match_target_keys(text):
    compiled_re = _compile_regex(patterns['target_keys'], re.VERBOSE)
    matches = compiled_re.finditer(text)
    results = []
    for match in matches:
        key = match.group(1)
        value = match.group(2)
        results.append({"key": key, "value": value})
    return results

def match_fangkuohao(text):
    compiled_re = _compile_regex(patterns['fangkuohao'])
    matches = compiled_re.finditer(text)
    results = []
    for match in matches:
        number = match.group(1)
        results.append({"key": "方括号内数字", "value": number})
    return results

def match_key_words(text):
    compiled_re = _compile_regex(patterns['key_words'])
    matches = compiled_re.finditer(text)
    results = []
    for match in matches:
        key_word = match.group(0)
        results.append({"key": "关键词", "value": key_word})
    return results

def get_components(log_text):
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
    results.extend(match_target_keys(log_text))
    results.extend(match_fangkuohao(log_text))
    results.extend(match_key_words(log_text))
    results.extend(match_key_value(log_text))
    return results

if __name__ == '__main__':
    log_text = "<178>Oct 21 09:50:26 10-50-86-12 DBAppWAF: 发生时间/2024-10-21 09:50:12,威胁/高,事件/检测SQL注入,请求方法/GET,URL地址/10.50.109.2/ez/showcategory.php?cid=-101+union+select+12345678987654321,12345678987654321,3,4,5--,POST数据/,服务器IP/10.50.109.2,主机名/10.50.109.2,服务器端口/80,客户端IP/10.50.86.35,客户端端口/56184,客户端环境/Mozilla/5.0 [en] (X11, U; DBAPPSecurity 21.4.3),标签/通用防护,动作/告警,HTTP/S响应码/301,攻击特征串/-101 union select 12345678987654321,12345678987654321,3,4,5--,触发规则/10120000,访问唯一编号/7428040333788713714,国家/局域网,省/未知,市/未知,XFF_IP/"
    res = get_components(log_text)
    json_data = json.dumps(res, ensure_ascii=False)
    print(json_data)