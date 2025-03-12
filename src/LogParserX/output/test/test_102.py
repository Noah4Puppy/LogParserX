import re
import json
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

# Optimized patterns
patterns = {
    "date": r"\b([A-Za-z]{3})\s{1,2}(\d{1,2})\s(\d{2}:\d{2}:\d{2})\b",
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
    """
}

def match_date(log_text: str) -> list:
    regex = _compile_regex(patterns['date'])
    match = regex.search(log_text)
    results = []
    if match:
        date = f"{match.group(1)} {int(match.group(2)):02d} {match.group(3)}"
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
        if key or value:
            results.append({'key': key, 'value': value})
    return results

def get_components(log_text: str) -> list:
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    key_value_pairs = match_key_value(log_text)
    filtered_results = [item for item in key_value_pairs if item['key'] in ['事件', '服务器IP', '服务器端口', '客户端IP', '标签', '动作', '访问唯一编号', '国家']]
    results.extend(filtered_results)
    return results

if __name__ == '__main__':
    log_text = f"""<178>Nov 15 14:22:15 10-50-86-13 DBAppWAF: 发生时间/2024-11-15 14:22:03,威胁/中,事件/SQL注入攻击,请求方法/POST,URL地址/10.50.109.2/admin/login.php,POST数据/username=admin&password=123456,服务器IP/10.50.109.2,主机名/10.50.109.2,服务器端口/80,客户端IP/10.50.86.36,客户端端口/56789,客户端环境/Mozilla/5.0 [en] (X11, U; DBAPPSecurity 21.4.3),标签/SQL注入,动作/阻断,HTTP/S响应码/403,攻击特征串/admin/login.php?username=admin&password=123456,触发规则/11010102,访问唯一编号/7428041192777978970,国家/局域网,省/未知,市/未知,XFF_IP/"""
    res = get_components(log_text)
    json_data = json.dumps(res, ensure_ascii=False)
    print(json_data)