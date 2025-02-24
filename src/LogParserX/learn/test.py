import re

def extract_functions(code_str: str) -> dict:
    """
    从Python代码字符串中提取特定格式函数，返回字典结构
    参数：
    code_str : 需要解析的Python代码字符串
    返回：
    {
        "_compile_regex": "@lru_cache(...)\ndef _compile_regex(...): ...",
        "extract_date": "@lru_cache(...)\ndef extract_date(...): ...",
        ...
    }
    """
    # 使用正则表达式匹配目标函数结构
    # 匹配装饰器部分（如果有），函数定义以及函数体
    pattern = re.compile(
        r'(@lru_cache\(.*?\)\s+)?'  # 匹配装饰器部分（如果有）
        r'def\s+(?!get_components\b)(\w+)'  # 排除get_components的其他函数
        r'\(.*?\):'  # 匹配函数头，包括参数部分
        r'([\s\S]+?)(?=\n\s*def\s+|\n@lru_cache\(.*?\)\s*|$)',  # 捕获函数体，直到下一个函数定义或装饰器
        flags=re.DOTALL
    )

    functions = {}

    # 查找所有匹配项
    for match in re.finditer(pattern, code_str):
        decorator, func_name, body = match.groups()
        # 构造函数定义
        if decorator:
            func_def = f"{decorator}def {func_name}{body}"
        else:
            func_def = f"def {func_name}{body}"

        functions[func_name] = func_def.strip()

    return functions


str_code = """
import re
@lru_cache(maxsize=100)
def _compile_regex(pattern, flags=0):           
    return re.compile(pattern, flags)

@lru_cache(maxsize=100)
def extract_date(text):
    compiled_re = _compile_regex(patterns['date_p'])
    match = compiled_re.search(text)
    if match:
        return {'key': '', 'value': match.group(0)}
    return {}

def get_components(log_text):
    results = []
    # Extract date and time
    compiled_date_p = _compile_regex(date_p_)
    match_date = compiled_date_p.search(log_text)
    if match_date:
        date_time = match_date.group(1)
        results.append({'key': '', 'value': date_time})
"""

# 测试函数提取
functions = extract_functions(str_code)
for name, func in functions.items():
    print(f"Function Name: {name}\n{func}\n")
