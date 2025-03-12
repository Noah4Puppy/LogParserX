import re
import json
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

# Optimized patterns
patterns = {
    "date": r"\b[A-Za-z]{3}\s{1,2}\d{1,2}\s\d{4}\s\d{2}:\d{2}:\d{2}\b",
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
        date = match.group(0)
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
    
    return results

if __name__ == '__main__':
    log_text = f"""<178>Dec 20 10:22:15 10-50-86-12 DBAppWAF: 发生时间/2024-12-20 10:21:08,威胁/中,事件/检测SQL注入(语义分析),请求方法/GET,URL地址/10.50.109.90:31001/vb5/?routestring=ajax/render/widget_sql,GET数据/query=SELECT+*+FROM+users+WHERE+username+%3D+%27admin%27+--+AND+password+%3D+%27123456%27,服务器IP/10.50.109.90,主机名/10.50.109.90:31001,服务器端口/31001,客户端IP/10.50.24.198,客户端端口/45377,客户端环境/Python-urllib/3.6,标签/通用防护,动作/警告,HTTP/S响应码/403,攻击特征串/SELECT * FROM users WHERE username = 'admin' -- AND password = '123456',触发规则/10130001,访问唯一编号/7438514904312627361,国家/局域网,省/未知,市/未知,XFF_IP/"""
    res = get_components(log_text)
    json_data = json.dumps(res, ensure_ascii=False)
    print(json_data)