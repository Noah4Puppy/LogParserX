import re
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

# Optimized patterns
patterns = {
    "date": r"\b([A-Za-z]{3}\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2})\b",
    "hostname": r"(?<=:\d{2}) ([a-zA-Z0-9._-]+)(?=\s)",
    "pid": r"([a-zA-Z0-9_-]+)\[(\d+)\]",
    "ip_port": r"(\d+\.\d+\.\d+\.\d+)\s+port\s+(\d+)",
    "key_value": r"""
        (?:                        # Start delimiter detection
        (?<=[;:,=(\-])|       # Key correction: add colon : and hyphen - as valid delimiters
        ^)
        \s*                        # Allow leading spaces
        (?P<key>                   # Key name rule
            (?![\d\-])             # Cannot start with a digit or hyphen
            [\w\s.-]+              # Allow letters/numbers/spaces/dots/hyphens
        )
        \s*=\s*                    # Equal sign with optional spaces on both sides
        (?P<value>                 # Value part
            (?:                   
                (?!\s*[,;)=\-])    # Exclude leading delimiters (added -)
                [^,;)=\-]+         # Basic match (added exclusion of -)
            )+
        )
        (?=                        # Lookahead to truncate
            \s*[,;)=\-]|           # Delimiters (added -)
            \s*$|                  # End of string
            (?=\S+\s*=)            # Followed by new key (including space key)
        )
    """
}

def match_date(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['date'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        date = match.group(1)
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

def match_pid(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['pid'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        process_name = match.group(1)
        process_id = match.group(2)
        results.append({"key": "", "value": process_name})
        results.append({"key": "", "value": process_id})
    return results

def match_ip_port(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['ip_port'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        ip = match.group(1)
        port = match.group(2)
        results.append({"key": "", "value": ip})
        results.append({"key": "", "value": port})
    return results

def match_key_value(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['key_value'], re.VERBOSE)
    matches = compiled_re.finditer(log_text)
    results = []
    for match in matches:
        key = match.group('key').strip()
        value = match.group('value').strip()
        if key == "Postponed publickey for":
            user = value.split()[1]
            results.append({"key": "", "value": user})
        elif key == "from":
            ip = value.split()[0]
            results.append({"key": "", "value": ip})
        elif key == "port":
            port = value.split()[0]
            results.append({"key": "", "value": port})
        elif key == "ssh2":
            protocol = value.split()[0]
            results.append({"key": "", "value": protocol})
        elif key == "[preauth]":
            status = value.split()[0]
            results.append({"key": "", "value": status})
    return results

def get_components(log_text: str) -> list:
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_pid(log_text))
    results.extend(match_ip_port(log_text))
    results.extend(match_key_value(log_text))
    return results

if __name__ == '__main__':
    log_text = "<21>Aug 12 08:06:01 soc-32 sshd[16209]: Postponed publickey for root from 3.66.0.23 port 38316 ssh2 [preauth]"
    res = get_components(log_text)
    print(res)