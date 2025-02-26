import re
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

# Optimized patterns
patterns = {
    "date": r"\b[A-Za-z]{3}\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2}\b",
    "hostname": r"(?<=:\d{2}) ([a-zA-Z0-9._-]+)(?=\s)",
    "process": r"(\S+)\s+\[(.*?)\]",
    "session": r"session (\d+)",
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
        (?=                        # Lookahead assertion
            \s*[,;)=\-]|           # Delimiters (added -)
            \s*$|                  # End of string
            (?=\S+\s*=)            # Followed by a new key (including space key names)
        )
    """
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

def match_process(text):
    compiled_re = _compile_regex(patterns['process'])
    match = compiled_re.search(text)
    results = []
    if match:
        process = match.group(1)
        pid = match.group(2)
        results.append({"key": "", "value": process})
    return results

def match_session(text):
    compiled_re = _compile_regex(patterns['session'])
    match = compiled_re.search(text)
    results = []
    if match:
        session = match.group(1)
        results.append({"key": "", "value": session})
    return results

def match_key_value(text):
    compiled_re = _compile_regex(patterns['key_value'], re.VERBOSE)
    matches = compiled_re.finditer(text)
    results = []
    for match in matches:
        key = match.group("key").strip()
        value = match.group("value").strip()
        results.append({"key": key, "value": value})
    return results

# Main function to extract all components
def get_components(log_text):
    res = []
    res.extend(match_date(log_text))
    res.extend(match_hostname(log_text))
    res.extend(match_process(log_text))
    res.extend(match_session(log_text))
    res.extend(match_key_value(log_text))
    return res

if __name__ == '__main__':
    log_text = f'<21>Mar 15 14:22:33 soc-32 sshd[82915]: Postponed publickey for admin from 192.168.1.10 port 54321 ssh2 [preauth]'
    res = get_components(log_text)
    print(res)