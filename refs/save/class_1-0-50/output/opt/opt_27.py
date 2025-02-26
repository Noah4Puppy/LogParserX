import re
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

# Optimized patterns
patterns = {
    "date": r"\b[A-Za-z]{3}\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2}\b",
    "hostname": r"(?<=:\d{2}) ([a-zA-Z0-9._-]+)(?=\s)",
    "service": r"([a-zA-Z0-9_-]+):",
    "session_id": r"session (\d+)",
    "user": r"user ([a-zA-Z0-9]+)"
}

def match_date(log_text):
    compiled_re = _compile_regex(patterns['date'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        date = match.group(0)
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

def match_service(log_text):
    compiled_re = _compile_regex(patterns['service'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        service = match.group(1)
        results.append({"key": "", "value": service})
    return results

def match_session_id(log_text):
    compiled_re = _compile_regex(patterns['session_id'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        session_id = match.group(1)
        results.append({"key": "", "value": session_id})
    return results

def match_user(log_text):
    compiled_re = _compile_regex(patterns['user'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        user = match.group(1)
        results.append({"key": "", "value": user})
    return results

def get_components(log_text):
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_service(log_text))
    results.extend(match_session_id(log_text))
    results.extend(match_user(log_text))
    return results

if __name__ == '__main__':
    log_text = "<21>Oct 28 18:00:13 soc-32 systemd-logind: New session 4996702 of user root."
    res = get_components(log_text)
    print(res)