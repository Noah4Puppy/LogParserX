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
    "pid": r"([a-zA-Z0-9_-]+)\[(\d+)\]",
    "ip_port": r"from\s+(\d+\.\d+\.\d+\.\d+)\sport\s+(\d+)",
    "protocol": r"(\w+)",
    "preauth": r"\[preauth\]"
}

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

def match_pid(text):
    compiled_re = _compile_regex(patterns['pid'])
    match = compiled_re.search(text)
    results = []
    if match:
        process_name = match.group(1)
        pid = match.group(2)
        results.append({"key": "", "value": process_name})
        results.append({"key": "", "value": pid})
    return results

def match_ip_port(text):
    compiled_re = _compile_regex(patterns['ip_port'])
    match = compiled_re.search(text)
    results = []
    if match:
        ip = match.group(1)
        port = match.group(2)
        results.append({"key": "", "value": ip})
        results.append({"key": "", "value": port})
    return results

def match_protocol(text):
    compiled_re = _compile_regex(patterns['protocol'])
    match = compiled_re.search(text)
    results = []
    if match:
        protocol = match.group(0)
        results.append({"key": "", "value": protocol})
    return results

def match_preauth(text):
    compiled_re = _compile_regex(patterns['preauth'])
    match = compiled_re.search(text)
    results = []
    if match:
        preauth = match.group(0)
        results.append({"key": "", "value": preauth})
    return results

def get_components(log_text):
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_pid(log_text))
    results.extend(match_ip_port(log_text))
    results.extend(match_protocol(log_text))
    results.extend(match_preauth(log_text))
    return results

if __name__ == '__main__':
    log_text = "<21>Jul 29 07:02:20 soc-32 sshd[174980]: Postponed publickey for root from 3.66.0.23 port 40030 ssh2 [preauth]"
    res = get_components(log_text)
    print(res)
```