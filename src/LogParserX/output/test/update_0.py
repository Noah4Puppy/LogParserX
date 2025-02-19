
import re
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

key_value_p = r"""
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

date_p_2 = r"([A-Za-z]{3})\s+ (\d{1,2})\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})([+-]\d{2}):(\d{2})"

hostname_p = r"(?<=:\d{2}) ([a-zA-Z0-9._-]+)*(?=\s)"

session_p = r"session (\d+)"

def match_key_value(pattern, text):
    results = []
    compiled_re = _compile_regex(pattern, re.VERBOSE | re.IGNORECASE)
    for match in compiled_re.finditer(text):
        key = match.group("key").strip()
        value = match.group("value").strip()
        if key and value:
            key = re.sub(r'\s+', ' ', key)
            results.append({'key': key, 'value': value})
    return results

def match_date_with_zone(pattern, text):
    compile_re = _compile_regex(pattern)
    match = compile_re.search(text)
    if match:
        month = match.group(1)
        day = match.group(2)
        year = match.group(3)
        hour = match.group(4)
        minute = match.group(5)
        second = match.group(6)
        timezone_offset = match.group(7) + match.group(8)
        date = f'{month} {day} {year} {hour}:{minute}:{second}{timezone_offset}'
        return [{"key": "", "value": date}]
    else:
        return []

def match_hostname(pattern, text):
    exclude_keywords = [
        "Removed", "session", "adjust", "Postponed", "for", "from", "port", "closed", "user", "of", "New",
    ]
    compiled_re = _compile_regex(pattern)
    matches = compiled_re.findall(text)
    results = []
    for match in matches:
        if match and match not in exclude_keywords:
            value = match if isinstance(match, str) else match
            if not value.isdigit():
                results.append({'key': '', 'value': value})
    return results

def match_session_id(pattern, text):
    compiled_re = _compile_regex(pattern, re.IGNORECASE)
    matches = compiled_re.findall(text)
    for match in matches:
        if match:
            id = [match.group(1) for match in re.finditer(pattern, text, re.IGNORECASE)]
            if id:
                return [{'key': '', 'value': id[0]}]
    else:
        return []

def get_components(keyword, log_text):
    component_map = {
        'key_value': (match_key_value, [key_value_p]),
        'date': (match_date_with_zone, [date_p_2]),
        'hostname': (match_hostname, [hostname_p]),
        'session': (match_session_id, [session_p]),
    }
    result = []
    for key in keyword:
        if key in component_map:
            func, args = component_map[key]
            call_args = args + [log_text] if args else [log_text]
            result.extend(func(*call_args))
    return result

if __name__ == '__main__':
    log_text = "<21>Aug 13 09:04:02 soc-32 systemd-logind: Removed session 3831379."
    keyword = ['key_value', 'date', 'hostname', 'session']
    result = get_components(keyword=keyword, log_text=log_text)
    print(result)