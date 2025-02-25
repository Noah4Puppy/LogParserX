import re
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

# Date patterns
patterns = {
    'date_p': r'\b[A-Za-z]{3}\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2}\b',
    'hostname_p': r'(?<=:\d{2}) ([a-zA-Z0-9._-]+)*(?=\s)',
    'pid_p': r'([a-zA-Z0-9_-]+)\[(\d+)\]',
    'ip_p': r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
}

# Function to extract date
@lru_cache(maxsize=100)
def extract_date(text):
    compiled_re = _compile_regex(patterns['date_p'])
    match = compiled_re.search(text)
    if match:
        return {'key': '', 'value': match.group(0)}
    return {}

# Function to extract hostname
@lru_cache(maxsize=100)
def extract_hostname(text):
    compiled_re = _compile_regex(patterns['hostname_p'])
    match = compiled_re.search(text)
    if match:
        return {'key': '', 'value': match.group(1)}
    return {}

# Function to extract process ID
@lru_cache(maxsize=100)
def extract_pid(text):
    compiled_re = _compile_regex(patterns['pid_p'])
    match = compiled_re.search(text)
    if match:
        return {'key': '', 'value': match.group(1)}, {'key': '', 'value': match.group(2)}
    return {}, {}

# Function to extract IP address
@lru_cache(maxsize=100)
def extract_ip(text):
    compiled_re = _compile_regex(patterns['ip_p'])
    match = compiled_re.search(text)
    if match:
        return {'key': '', 'value': match.group(1)}
    return {}

# Main function to extract all components
@lru_cache(maxsize=100)
def get_components(log_text):
    results = []
    results.append(extract_date(log_text))
    results.append(extract_hostname(log_text))
    pid_result, pid_num_result = extract_pid(log_text)
    results.append(pid_result)
    results.append(pid_num_result)
    results.append(extract_ip(log_text))
    return [result for result in results if result]

if __name__ == '__main__':
    log_text = f'<21>Aug 12 07:14:12 soc-32 sshd[71841]: Postponed publickey for root from 3.66.0.23 port 43604 ssh2 [preauth]'
    res = get_components(log_text)
    print(res)