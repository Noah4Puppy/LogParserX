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
    "ip_port": r"(\d+\.\d+\.\d+\.\d+):(\d+)",
    "client_ip_port": r"客户端IP/(\d+\.\d+\.\d+\.\d+),客户端端口/(\d+)"
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
        hostname = match.group(1)
        results.append({"key": "", "value": hostname})
    return results

def match_ip_port(log_text):
    compiled_re = _compile_regex(patterns['ip_port'])
    matches = compiled_re.findall(log_text)
    results = []
    for ip, port in matches:
        results.append({"key": "服务器IP", "value": ip})
        results.append({"key": "服务器端口", "value": port})
    return results

def match_client_ip_port(log_text):
    compiled_re = _compile_regex(patterns['client_ip_port'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        client_ip = match.group(1)
        client_port = match.group(2)
        results.append({"key": "客户端IP", "value": client_ip})
        results.append({"key": "客户端端口", "value": client_port})
    return results

def get_components(log_text):
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_key_value(log_text))
    results.extend(match_ip_port(log_text))
    results.extend(match_client_ip_port(log_text))
    return results

if __name__ == '__main__':
    log_text = f"""<178>Dec 20 10:25:30 10-50-86-12 DBAppWAF: 发生时间/2024-12-20 10:25:28,威胁/中,事件/检测SQL注入(语义分析),请求方法/GET,URL地址/10.50.109.90:31001/vBulletin/?routestring=ajax/render/widget_sql,GET数据/query=SELECT+*+FROM+users+WHERE+username=%27admin%27+--+AND+password=%27123456%27,服务器IP/10.50.109.90,主机名/10.50.109.90:31001,服务器端口/31001,客户端IP/10.50.24.198,客户端端口/45937,客户端环境/Python-requests/2.25.1,标签/通用防护,动作/阻断,HTTP/S响应码/403,攻击特征串/SELECT * FROM users WHERE username='admin' -- AND password='123456',触发规则/10130001,访问唯一编号/7438514908615983271,国家/局域网,省/未知,市/未知,XFF_IP/"""
    res = get_components(log_text)
    json_data = json.dumps(res, ensure_ascii=False)
    print(json_data)