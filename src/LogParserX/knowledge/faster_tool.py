import re
from functools import lru_cache
@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

def match_type_1(pattern: str, log_text: str) -> list:
    regex = _compile_regex(pattern)
    # Your can use findall() or finditer(), search()
    matches = regex.findall(log_text)
    results = []
    # Your codes or None
    for match in matches:
        results.append({"key": "", "value": match})
    return results
    
def match_type_2(pattern: str, log_text: str) -> list:
    regex = _compile_regex(pattern)
    # Your can use findall() or finditer(), search()
    matches = regex.findall(log_text)
    results = []
    # Your codes or None
    for key, value in matches:
        results.append({"key": key, "value": value})
    return results

def get_components(log_text):
    results = []
    # your codes here
    # example:
    possible_res = match_type_1(r'hostname=(?P<hostname>[^ ]+)', log_text)
    results.extend(possible_res)
    
    return results
    
# 函数调用例子
if __name__ == '__main__':
    log_text = "<128>May 16 14:54:09 2024 dbapp APT~30~1~2024-05-16 14:54:09~10.50.134.18:47013~1.1.1.1:53~远程控制~漏洞利用攻击事件~类型:    C&C~高~2405161454090000256~~请求DNS服务器 [1.1.1.1] 解析域名: oast.pro~~~0~4~2~60:db:15:73:46:01~00:00:5e:00:01:0a~0~Host: oast.pro~~~~成功~12~1~630~212002"
    res = get_components(log_text)
    print(res)