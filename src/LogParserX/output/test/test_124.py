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
    "client_port": r"客户端端口/(\d+)",
    "action": r"动作/(\w+)",
    "unique_id": r"访问唯一编号/(\d+)",
    "country": r"国家/(\w+)"
}

# Define functions to match patterns
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
        hostname = match.group(1)
        results.append({"key": "", "value": hostname})
    return results

def match_client_port(text):
    compiled_re = _compile_regex(patterns['client_port'])
    match = compiled_re.search(text)
    results = []
    if match:
        client_port = match.group(1)
        results.append({"key": "客户端端口", "value": client_port})
    return results

def match_action(text):
    compiled_re = _compile_regex(patterns['action'])
    match = compiled_re.search(text)
    results = []
    if match:
        action = match.group(1)
        results.append({"key": "动作", "value": action})
    return results

def match_unique_id(text):
    compiled_re = _compile_regex(patterns['unique_id'])
    match = compiled_re.search(text)
    results = []
    if match:
        unique_id = match.group(1)
        results.append({"key": "访问唯一编号", "value": unique_id})
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
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_key_value(log_text))
    results.extend(match_client_port(log_text))
    results.extend(match_action(log_text))
    results.extend(match_unique_id(log_text))
    results.extend(match_country(log_text))
    return results

if __name__ == '__main__':
    log_text = f"""<178>Nov 15 14:32:45 10-50-86-12 DBAppWAF: 发生时间/2024-11-15 14:32:38,威胁/中,事件/检测SQL注入,请求方法/POST,URL地址/10.50.109.2/backend/plugin/Login/index.php?action=login&username=admin&password=123456,POST数据/username=admin&password=123456,服务器IP/10.50.109.2,主机名/10.50.109.2,服务器端口/80,客户端IP/10.50.86.35,客户端端口/50582,客户端环境/Mozilla/5.0 [en] (X11, U; DBAPPSecurity 21.4.3),标签/通用防护,动作/阻断,HTTP/S响应码/403,攻击特征串/123456,触发规则/10240001,访问唯一编号/7428041905744647457,国家/局域网,省/未知,市/未知,XFF_IP/"""
    res = get_components(log_text)
    json_data = json.dumps(res, ensure_ascii=False)
    print(json_data)