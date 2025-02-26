import re
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

patterns = {
    "date": r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\b",
    "hostname": r"\b([a-zA-Z0-9._-]+)\b",
    "level": r"\b([A-Z]+)\b",
    "message": r"(.+)"
}

def match_date(log_text):
    compiled_re = _compile_regex(patterns['date'])
    match = compiled_re.search(log_text)
    results = []
    if match:
        date = match.group(0)
        results.append({"key": "", "value": date})
    return results

def match_hostname(log_text, start_index):
    compiled_re = _compile_regex(patterns['hostname'])
    match = compiled_re.search(log_text[start_index:])
    results = []
    if match:
        hostname = match.group(1)
        results.append({"key": "", "value": hostname})
    return results

def match_level(log_text, start_index):
    compiled_re = _compile_regex(patterns['level'])
    match = compiled_re.search(log_text[start_index:])
    results = []
    if match:
        level = match.group(1)
        results.append({"key": "", "value": level})
    return results

def match_message(log_text, start_index):
    compiled_re = _compile_regex(patterns['message'])
    match = compiled_re.search(log_text[start_index:])
    results = []
    if match:
        message = match.group(1)
        results.append({"key": "", "value": message})
    return results

def get_components(log_text):
    results = []

    # Match date
    date_results = match_date(log_text)
    results.extend(date_results)

    if date_results:
        date_end_index = len(date_results[0]['value'])
        # Match hostname
        hostname_results = match_hostname(log_text, date_end_index)
        results.extend(hostname_results)

        if hostname_results:
            hostname_end_index = date_end_index + len(hostname_results[0]['value'])
            # Match level
            level_results = match_level(log_text, hostname_end_index)
            results.extend(level_results)

            if level_results:
                level_end_index = hostname_end_index + len(level_results[0]['value'])
                # Match message
                message_results = match_message(log_text, level_end_index)
                results.extend(message_results)

    return results

if __name__ == '__main__':
    log_text = "2023-10-10 10:10:10 ABC ERROR: This is an error message"
    res = get_components(log_text)
    print(res)