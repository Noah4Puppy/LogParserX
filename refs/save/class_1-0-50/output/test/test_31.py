import re
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

# Optimized patterns
patterns = {
    "date": r"([A-Za-z]{3}\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2})",
    "hostname": r"(\S+)",  # Simplified to match the first non-space sequence
    "pid": r"([a-zA-Z0-9_-]+)\[(\d+)\]",
    "ip_port": r"from\s+(\d+\.\d+\.\d+\.\d+)\sport\s+(\d+)",
    "ssh_protocol": r"ssh2"
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
        pid = match.group(2)
        results.append({"key": "", "value": process_name})
        results.append({"key": "", "value": pid})
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

def match_ssh_protocol(log_text):
    compiled_re = _compile_regex(patterns['ssh_protocol'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        protocol = match.group(0)
        results.append({"key": "", "value": protocol})
    return results

def get_components(log_text):
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_pid(log_text))
    results.extend(match_ip_port(log_text))
    results.extend(match_ssh_protocol(log_text))
    return results

if __name__ == '__main__':
    log_text = f'<21>Jul 29 07:10:08 soc-32 sshd[195746]: Accepted publickey for root from 3.66.0.252 port 52800 ssh2: RSA SHA256:M/HclYq1V9UXKEtEyF03gXBB7IyFJKcs8tU6lqWNuyM'
    res = get_components(log_text)
    print(res)