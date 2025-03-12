import re
import json
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

# Optimized patterns
patterns = {
    "date": r"\b[A-Za-z]{3}\s{1,2}\d{1,2}\s\d{4}\s\d{2}:\d{2}:\d{2}\b",
    "hostname": r"(?<=:\d{2}) ([a-zA-Z0-9._-]+)(?=\s)",
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
    """
}

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

def match_key_value(log_text: str) -> list:
    regex = _compile_regex(patterns['key_value'], re.VERBOSE)
    matches = regex.finditer(log_text)
    results = []
    for match in matches:
        key = match.group('key').strip()
        value = match.group('value').strip()
        results.append({"key": key, "value": value})
    return results

def get_components(log_text: str) -> list:
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_key_value(log_text))
    return results

if __name__ == '__main__':
    log_text = f"""<178>Oct 1 14:22:35 10-50-86-13 DBAppWAF: 发生时间/2024-10-01 14:22:22,威胁/中,事件/HTTP请求User-Agent头部包含恶意字符串,请求方法/GET,URL地址/10.50.109.151:8888/struts2-blank-2.3.28/example/Login.action,GET数据/?username=admin&password=123456"""
    res = get_components(log_text)
    json_data = json.dumps(res, ensure_ascii=False)
    print(json_data)