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
    "http_response_code": r"HTTP/S响应码/(\d+)"
}

def match_date(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['date'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        date = match.group(0)
        results.append({"key": "", "value": date})
    return results

def match_hostname(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['hostname'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        hostname = match.group(1)
        results.append({"key": "", "value": hostname})
    return results

def match_key_value_pairs(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['key_value'], re.VERBOSE)
    matches = compiled_re.finditer(log_text)
    results = []
    for match in matches:
        key = match.group('key').strip()
        value = match.group('value').strip()
        if key and value:
            results.append({"key": key, "value": value})
    return results

def match_ip_port(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['ip_port'])
    matches = compiled_re.finditer(log_text)
    results = []
    for match in matches:
        ip = match.group(1)
        port = match.group(2)
        results.append({"key": "服务器IP", "value": ip})
        results.append({"key": "服务器端口", "value": port})
    return results

def match_http_response_code(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['http_response_code'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        http_response_code = match.group(1)
        results.append({"key": "HTTP/S响应码", "value": http_response_code})
    return results

def get_components(log_text: str) -> list:
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_key_value_pairs(log_text))
    results.extend(match_ip_port(log_text))
    results.extend(match_http_response_code(log_text))
    return results

if __name__ == '__main__':
    log_text = f"""<178>Nov 15 14:23:12 10-50-86-15 DBAppWAF: 发生时间/2024-11-15 14:23:01,威胁/高,事件/检测SQL注入攻击,请求方法/POST,URL地址/10.50.109.2/api/login.php,POST数据/user=admin' OR '1'='1,服务器IP/10.50.109.2,主机名/10.50.109.2,服务器端口/80,客户端IP/10.50.86.45,客户端端口/51234,客户端环境/Mozilla/5.0 [en] (X11, U; DBAPPSecurity 21.4.3),标签/通用防护,动作/阻断,HTTP/S响应码/403,攻击特征串/admin' OR '1'='1,触发规则/10350001,访问唯一编号/7428040947963794435,国家/局域网,省/未知,市/未知,XFF_IP/"""
    res = get_components(log_text)
    json_data = json.dumps(res, ensure_ascii=False)
    print(json_data)