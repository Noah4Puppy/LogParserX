import re
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

# Optimized patterns
patterns = {
    "date": r"(\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\b)",
    "hostname": r"(\b[A-Za-z0-9._-]+\b)",
    "level": r"(\b[A-Z]+\b)",
    "process": r"(\b[a-zA-Z0-9_-]+\[\d+\]\b)"
}

def match_date(log_text):
    compiled_re = _compile_regex(patterns['date'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        date = match.group(1)
        results.append({"key": "", "value": date})
    return results

def match_hostname(log_text):
    compiled_re = _compile_regex(patterns['hostname'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        hostname = match.group(1)
        results.append({"key": "", "value": hostname})
    return results

def match_level(log_text):
    compiled_re = _compile_regex(patterns['level'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        level = match.group(1)
        results.append({"key": "", "value": level})
    return results

def match_process(log_text):
    compiled_re = _compile_regex(patterns['process'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        process = match.group(1)
        results.append({"key": "", "value": process})
    return results

def get_components(log_text):
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_level(log_text))
    results.extend(match_process(log_text))
    return results

if __name__ == '__main__':
    log_text = "2023-10-10 10:10:10 ABC ERROR: This is an error message"
    res = get_components(log_text)
    print(res)