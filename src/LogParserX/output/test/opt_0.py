import re
from functools import lru_cache

@lru_cache(maxsize=100)
def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)

# Optimized patterns
# Date patterns
date_p = r'\b[A-Za-z]{3}\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2}\b'
date_p_ = r'\b([A-Za-z]+ \d{1,2} \d{2}:\d{2}:\d{2})\b'
date_p_2 = r'(\d{4}-\d{1,2}-\d{1,2} \d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2})?)'

# Hostname pattern
hostname_p = r'(?<=:\d{2}) ([a-zA-Z0-9._-]+)'

# Specific field patterns
vs_p = r'VS=([^;]+)'
vs_cid_p = r'VS-CID=([^;]+)'
oid_p = r'OID=([^;]+)'
domain_no_p = r'DomainNo.=([^,]+)'
domain_name_p = r'DomainName=([^)]+)'

# Function to extract components from log text
def get_components(log_text):
    results = []
    # Extract date and time
    compiled_date_p = _compile_regex(date_p_)
    match_date = compiled_date_p.search(log_text)
    if match_date:
        date_time = match_date.group(1)
        results.append({'key': '', 'value': date_time})

    # Extract hostname
    compiled_hostname_p = _compile_regex(hostname_p)
    match_hostname = compiled_hostname_p.search(log_text)
    if match_hostname:
        hostname = match_hostname.group(1)
        results.append({'key': '', 'value': hostname})

    # Extract service name
    service_name = 'systemd-logind'
    results.append({'key': '', 'value': service_name})

    # Extract session ID
    session_id_p = r'Removed session (\d+)'
    compiled_session_id_p = _compile_regex(session_id_p)
    match_session_id = compiled_session_id_p.search(log_text)
    if match_session_id:
        session_id = match_session_id.group(1)
        results.append({'key': '', 'value': session_id})

    return results

# Test the function with the provided log text
if __name__ == '__main__':
    log_text = f'<21>Aug 12 07:14:12 soc-32 sshd[71841]: Postponed publickey for root from 3.66.0.23 port 43604 ssh2 [preauth]'
    res = get_components(log_text)
    print(res)