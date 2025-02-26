import re
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

# Optimized patterns
patterns = {
    "date": r"\b[A-Za-z]{3}\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2}\b",
    "hostname": r"(?<=:\d{2}) ([a-zA-Z0-9._-]+)(?=\s)",
    "process_name": r"([a-zA-Z0-9_-]+)",
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
            (?=\S+\s*=)            # Followed by a new key (including space key)
        )
    """
}

def match_date(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['date'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        date = match.group(0)
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

def match_process_name(log_text: str) -> list:
    hostname_match = _compile_regex(patterns['hostname']).search(log_text)
    if hostname_match:
        start_index = hostname_match.end()
        compiled_re = _compile_regex(patterns['process_name'])
        match = compiled_re.search(log_text[start_index:])
        results = []
        if match:
            process_name = match.group(1)
            results.append({"key": "", "value": process_name})
        return results
    return []

def match_key_value_pairs(log_text: str) -> list:
    compiled_re = _compile_regex(patterns['key_value'], re.VERBOSE)
    matches = compiled_re.finditer(log_text)
    results = []
    for match in matches:
        results.append({"key": match.group("key").strip(), "value": match.group("value").strip()})
    return results

def get_components(log_text: str) -> list:
    results = []
    results.extend(match_date(log_text))
    results.extend(match_hostname(log_text))
    results.extend(match_process_name(log_text))
    results.extend(match_key_value_pairs(log_text))
    return results

if __name__ == '__main__':
    log_text = "<21>Jul 29 16:57:28 soc-32 systemd: Started Client agent got collecting & sending logs & metrics.."
    res = get_components(log_text)
    print(res)