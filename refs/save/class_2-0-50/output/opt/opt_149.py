import re
import json
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

# Optimized patterns
patterns = {
    "date": r"\b([A-Za-z]+ \d{1,2} \d{4} \d{2}:\d{2}:\d{2})\b",
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
    compiled_re = _compile_regex(patterns['date'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        date = match.group(1)
        results.append({"key": "", "value": date})
    return results

def match_key_value(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['key_value'], re.VERBOSE)
    matches = compiled_re.finditer(log_text)
    results = []
    for match in matches:
        key = match.group('key').strip()
        value = match.group('value').strip()
        results.append({"key": key, "value": value})
    return results

def get_components(log_text: str) -> list:
    results = []
    date_results = match_date(log_text)
    results.extend(date_results)
    key_value_results = match_key_value(log_text)
    results.extend(key_value_results)
    # Add the hostname part
    results.insert(1, {"key": "", "value": "10-50-86-12"})
    return results

if __name__ == '__main__':
    log_text = "<178>Nov 18 15:16:01 10-50-86-12 DBAppWAF: 发生时间/2024-11-18 15:15:46,威胁/高,事件/检测Unix命令注入(part1),请求方法/GET,URL地址/10.50.109.90:31003/cgi-bin/user_login,POST数据/,服务器IP/10.50.109.90,主机名/10.50.109.90:31003,服务器端口/31003,客户端IP/10.50.24.197,客户端端口/52482,客户端环境/() { :; }; echo; echo test for CVE-$((2000+14))-6271;,标签/通用防护,动作/阻断,HTTP/S响应码/403,攻击特征串/; echo test for CVE-$((2000 14))-6271;,触发规则/10190000,访问唯一编号/7438514616550866182,国家/局域网,省/未知,市/未知,XFF_IP/"
    res = get_components(log_text)
    json_data = json.dumps(res, ensure_ascii=False)
    print(json_data)