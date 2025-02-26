import re
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

# Optimized patterns
patterns = {
    "date": r"\b\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b",
    "hostname": r"(?<=\d{2}:\d{2}:\d{2}\s)([a-zA-Z0-9._-]+)(?=\s)",
    "process_name": r"([a-zA-Z0-9_-]+):",
    "session_id": r"session (\d+)"
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

def match_process_name(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['process_name'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        process_name = match.group(1)
        results.append({"key": "", "value": process_name})
    return results

def match_session_id(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['session_id'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        session_id = match.group(1)
        results.append({"key": "", "value": session_id})
    return results

def get_components(log_text: str) -> list:
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_process_name(log_text))
    results.extend(match_session_id(log_text))
    return results

if __name__ == '__main__':
    log_text = f'<21>Oct 28 18:00:14 soc-32 systemd-logind: Removed session 4996702.'
    res = get_components(log_text)
    print(res)