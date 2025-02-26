```python
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
    "ip_port": r"(\d+\.\d+\.\d+\.\d+)\s+port\s+(\d+)",
    "key_value": r"""
        (?:                        # Start delimiter detection
        (?<=[;:,=(\-])|       # Lookbehind for valid delimiters
        ^)
        \s*                        # Allow leading spaces
        (?P<key>                   # Key name rule
            (?![\d\-])             # Cannot start with a digit or hyphen
            [\w\s.-]+              # Allow letters, digits, spaces, dots, and hyphens
        )
        \s*=\s*                    # Equal sign with optional spaces
        (?P<value>                 # Value part
            (?:                   
                (?!\s*[,;)=\-])    # Exclude trailing delimiters
                [^,;)=\-]+         # Basic match excluding delimiters
            )+
        )
        (?=                        # Lookahead for truncation
            \s*[,;)=\-]|           # Delimiters
            \s*$|                  # End of string
            (?=\S+\s*=)            # Followed by new key (including space key)
        )
    """,
    "function_call": r"(?!%%.*)([a-zA-Z0-9_-]+)\((.*?)\)"
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

def match_key_value(text):
    compiled_re = _compile_regex(patterns['key_value'], re.VERBOSE)
    matches = compiled_re.finditer(text)
    results = []
    for match in matches:
        key = match.group('key')
        value = match.group('value')
        results.append({"key": key, "value": value})
    return results

def match_function_call(text):
    compiled_re = _compile_regex(patterns['function_call'])
    match = compiled_re.search(text)
    results = []
    if match:
        function_name = match.group(1)
        parameters = match.group(2)
        results.append({"key": function_name, "value": parameters})
    return results

def get_components(log_text):
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_pid(log_text))
    results.extend(match_ip_port(log_text))
    results.extend(match_key_value(log_text))
    results.extend(match_function_call(log_text))
    return results

if __name__ == '__main__':
    log_text = "<21>Jul 29 07:31:56 soc-32 sshd[60636]: Postponed publickey for root from 3.66.0.23 port 48454 ssh2 [preauth]"
    res = get_components(log_text)
    print(res)
```
This code will extract the required fields from the log text and return them in the specified format. Each function is designed to match a specific pattern and append the results to the `results` list, which is then returned by the `get_components` function. The main block demonstrates how to call the `get_components` function and print the results.