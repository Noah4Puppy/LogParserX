import re
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

# Optimized patterns
patterns = {
    "date": r"\b([A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2})\b",
    "hostname": r"(?<=:\d{2}) ([a-zA-Z0-9._-]+)(?=\s)",
    "pid": r"([a-zA-Z0-9_-]+)\[(\d+)\]",
    "ip_port": r"from (\d+\.\d+\.\d+\.\d+) port (\d+)",
    "protocol": r"(\w+)$",
    "status": r"\[(\w+)\]"
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

def match_ip_port(log_text):
    compiled_re = _compile_regex(patterns['ip_port'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        ip = match.group(1)
        port = match.group(2)
        results.append({"key": "", "value": ip})
        results.append({"key": "", "value": port})
    return results

def match_protocol(log_text):
    compiled_re = _compile_regex(patterns['protocol'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        protocol = match.group(1)
        results.append({"key": "", "value": protocol})
    return results

def match_status(log_text):
    compiled_re = _compile_regex(patterns['status'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        status = match.group(1)
        results.append({"key": "", "value": status})
    return results

def get_components(log_text):
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_pid(log_text))
    results.extend(match_ip_port(log_text))
    results.extend(match_protocol(log_text))
    results.extend(match_status(log_text))
    return results

if __name__ == '__main__':
    log_text = f'<21>Aug 12 08:08:52 soc-32 sshd[24720]: Postponed publickey for root from 3.66.0.23 port 44196 ssh2 [preauth]'
    res = get_components(log_text)
    print(res)