```python`
import re
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    """带缓存的正则编译函数（线程安全）"""
    return re.compile(pattern, flags)

key_value_p = r"""
    (?:                        # 起始分隔符检测
        (?<=[;:,=(\-])|       # 关键修正：添加冒号:和连字符-作为合法分隔符
        ^                      # 或行首
    )
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

function_p = r"(?!%%.*)([a-zA-Z0-9_-]+)\((.*?)\)"

def remove_prefix(text):
    """
    去除形如<...>前缀及其后的空格
    示例： 
    输入 "<21> XXXXX,XXXX" → 输出 "XXXXX,XXXX"
    输入 "<123>abc def" → 输出 "abc def"
    """
    return re.sub(r'^<.*?>\s*', '', text)

def match_key_value(pattern, text):
    results = []
    compiled_re = _compile_regex(pattern, re.VERBOSE | re.IGNORECASE)
    for match in compiled_re.finditer(text):
        key = match.group("key").strip()
        value = match.group("value").strip()
        if (value.startswith('"') and value.endswith('"')) or \
           (value.startswith("'") and value.endswith("'")):
            value = value[1:-1].replace('\\"', '"')
        if value.endswith('.') and not re.search(r'\d+\.\d+\.\d+', value):
            value = value[:-1]
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
        "Removed",
        "session",
        "adjust",
        "Postponed",
        "for",
        "from",
        "port",
        "closed",
        "user",
        "of",
        "New",
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

def match_function(pattern, text):
    compiled_re = _compile_regex(pattern)
    match = compiled_re.search(text)
    results = []
    if match:
        function_name = match.group(1)
        bracket_content = match.group(2)
        results.append({'key': '', 'value': function_name})
        results.append({'key': '', 'value': bracket_content})
    return results

def get_components(log_text):
    results = []
    log_text = remove_prefix(log_text)
    
    # Match date with timezone
    date_results = match_date_with_zone(date_p_2, log_text)
    results.extend(date_results)
    
    # Match hostname
    hostname_results = match_hostname(hostname_p, log_text)
    results.extend(hostname_results)
    
    # Match key-value pairs
    key_value_results = match_key_value(key_value_p, log_text)
    results.extend(key_value_results)
    
    # Match function
    function_results = match_function(function_p, log_text)
    results.extend(function_results)
    
    return results
```