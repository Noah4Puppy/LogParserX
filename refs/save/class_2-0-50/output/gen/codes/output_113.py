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
    "ip_port": r"(\d+\.\d+\.\d+\.\d+)\s+port\s+(\d+)",
    "user_agent": r"Mozilla/5\.0\s*\([^)]+\)\s*(?:AppleWebKit/[\d\.]+\s*\([^)]+\)\s*Chrome/[\d\.]+\s*Safari/[\d\.]+|[\w\s]+/[\d\.]+)",
    "HTTP_response_code": r"HTTP/S响应码/(\d+)",
    "attack_info": r"WEB攻击~([^~]+)~([^~]*)~([中高低]+)",
    "target_keys": r"""
        ^\s*                    # 开头可能存在的空格
        ({})                    # 捕获目标键（类型|Host|解析域名）
        \s*:\s*                 # 冒号及两侧空格
        (.+?)                   # 非贪婪捕获值
        \s*$                    # 结尾可能存在的空格
    """.format('|'.join({'事件', '请求方法', 'URL地址', '服务器IP', '客户端环境', '标签', '动作'}))
}

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
        pid = match.group(0)
        results.append({"key": "", "value": pid})
    return results

def match_ip_port(log_text):
    compiled_re = _compile_regex(patterns['ip_port'])
    matches = compiled_re.finditer(log_text)
    results = []
    for match in matches:
        ip = match.group(1)
        port = match.group(2)
        results.append({"key": "IP", "value": ip})
        results.append({"key": "Port", "value": port})
    return results

def match_user_agent(log_text):
    compiled_re = _compile_regex(patterns['user_agent'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        user_agent = match.group(0)
        results.append({"key": "客户端环境", "value": user_agent})
    return results

def match_HTTP_response_code(log_text):
    compiled_re = _compile_regex(patterns['HTTP_response_code'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        code = match.group(1)
        results.append({"key": "HTTP/S响应码", "value": code})
    return results

def match_attack_info(log_text):
    compiled_re = _compile_regex(patterns['attack_info'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        attack_type = match.group(1)
        attack_details = match.group(2)
        threat_level = match.group(3)
        results.append({"key": "攻击类型", "value": attack_type})
        results.append({"key": "攻击详情", "value": attack_details})
        results.append({"key": "威胁等级", "value": threat_level})
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

def get_components(log_text):
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_pid(log_text))
    results.extend(match_ip_port(log_text))
    results.extend(match_user_agent(log_text))
    results.extend(match_HTTP_response_code(log_text))
    results.extend(match_attack_info(log_text))
    results.extend(match_target_keys(log_text))
    return results

if __name__ == '__main__':
    log_text = "<178>Oct 21 09:51:17 10-50-86-12 DBAppWAF: 发生时间/2024-10-21 09:51:09,威胁/高,事件/检测SQL注入,请求方法/GET,URL地址/10.50.109.2/news.php4?nid=-12'+union+select+1,2,0x53514c2d496e6a656374696f6e2d54657374,4,5,6,7,8,9,10,11/*,POST数据/,服务器IP/10.50.109.2,主机名/10.50.109.2,服务器端口/80,客户端IP/10.50.86.35,客户端端口/50435,客户端环境/Mozilla/5.0 [en] (X11, U; DBAPPSecurity 21.4.3),标签/通用防护,动作/告警,HTTP/S响应码/301,攻击特征串/-12' union select 1,2,0x53514c2d496e6a656374696f6e2d54657374,4,5,6,7,8,9,10,11/*,触发规则/10120000,访问唯一编号/7428040578590315358,国家/局域网,省/未知,市/未知,XFF_IP/"
    res = get_components(log_text)
    json_data = json.dumps(res, ensure_ascii=False)
    print(json_data)
```
```