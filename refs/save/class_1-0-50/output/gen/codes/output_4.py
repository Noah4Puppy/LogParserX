```python
import re
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

# Optimized patterns
patterns = {
    "date": r"([A-Za-z]{3}\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2})",
    "hostname": r"(?<=:\d{2})\s+([a-zA-Z0-9._-]+)",
    "pid": r"([a-zA-Z0-9_-]+)\[(\d+)\]"
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

def match_pid(log_text):
    compiled_re = _compile_regex(patterns['pid'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        process_name = match.group(1)
        process_id = match.group(2)
        results.append({"key": "", "value": process_name})
        results.append({"key": "", "value": process_id})
    return results

def get_components(log_text):
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_pid(log_text))
    return results

if __name__ == '__main__':
    log_text = "<21>Aug 12 08:11:56 soc-32 sshd[33101]: pam_unix(sshd:session): session closed for user root"
    res = get_components(log_text)
    print(res)
```
```