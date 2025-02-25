import re
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

# Optimized patterns
patterns = {
    "date": r"\b[A-Za-z]{3}\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2}\b",
    "hostname": r"(?<=:\d{2}) ([a-zA-Z0-9._-]+)(?=\s)",
    "service": r"(?<=\s)([a-zA-Z0-9_-]+)(?=:)",
    "session_id": r"session (\d+)"
}

# Define functions to match each pattern
def match_date(text):
    compiled_re = _compile_regex(patterns['date'])
    match = compiled_re.search(text)
    results = []
    if match:
        date = match.group(0)
        results.append({"key": "", "value": date})
    return results

def match_hostname(text):
    compiled_re = _compile_regex(patterns['hostname'])
    match = compiled_re.search(text)
    results = []
    if match:
        hostname = match.group(1)
        results.append({"key": "", "value": hostname})
    return results

def match_service(text):
    compiled_re = _compile_regex(patterns['service'])
    match = compiled_re.search(text)
    results = []
    if match:
        service = match.group(1)
        results.append({"key": "", "value": service})
    return results

def match_session_id(text):
    compiled_re = _compile_regex(patterns['session_id'])
    match = compiled_re.search(text)
    results = []
    if match:
        session_id = match.group(1)
        results.append({"key": "", "value": session_id})
    return results

# Main function to get all components
def get_components(log_text):
    res = []
    res.extend(match_date(log_text))
    res.extend(match_hostname(log_text))
    res.extend(match_service(log_text))
    res.extend(match_session_id(log_text))
    return res

if __name__ == '__main__':
    log_text = f'<21>Mar 15 14:22:33 soc-32 sshd[82915]: Postponed publickey for admin from 192.168.1.10 port 54321 ssh2 [preauth]'
    res = get_components(log_text)
    print(res)