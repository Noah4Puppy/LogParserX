import re
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

# Optimized patterns
patterns = {
    "date": r"\b[A-Za-z]{3}\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2}\b",
    "hostname": r"(?<=:\d{2}) ([a-zA-Z0-9._-]+)(?=\s)",
    "pid": r"([a-zA-Z0-9_-]+)\[(\d+)\]",
    "function_call": r"(?!%%.*)([a-zA-Z0-9_-]+)\((.*?)\)"
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

def match_pid(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['pid'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        process_name = match.group(1)
        process_id = match.group(2)
        results.append({"key": "", "value": process_name})
        results.append({"key": "", "value": process_id})
    return results

def match_function_call(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['function_call'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        function_name = match.group(1)
        function_args = match.group(2)
        results.append({"key": "", "value": function_name})
        results.append({"key": "", "value": function_args})
    return results

def get_components(log_text: str) -> list:
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_pid(log_text))
    results.extend(match_function_call(log_text))
    return results

if __name__ == '__main__':
    log_text = "Oct 29 00:00:01 soc-32 CROND[26434]: (root) CMD (/usr/lib64/sa/sa1 1 1)"
    res = get_components(log_text)
    print(res)