# key-value 常见 {key}={value}, 
# 否则 直接 key = ""
# -*- coding: utf-8 -*-
# 正则函数库
import re
        
def get_concrete_words(text):
    keywords = [
        "root",
        "system-logind",
        "systemd",
        "APT",
        "run-parts",
    ]
    keyword_pattern = re.compile(
    r'\b(' + '|'.join(map(re.escape, keywords)) + r')\b', 
    flags=re.IGNORECASE
    )
    key_matches = keyword_pattern.findall(text)
    results = []
    for match in key_matches:
        if match:
            results.append({'key': '', 'value': match})
    if results:
        print("Concrete Words Results:", results)
        return results
    else:
        print("未找到匹配的具体词汇")
        return []

def remove_prefix(text):
    """
    去除形如<...>前缀及其后的空格
    示例： 
    输入 "<21> XXXXX,XXXX" → 输出 "XXXXX,XXXX"
    输入 "<123>abc def" → 输出 "abc def"
    """
    return re.sub(r'^<.*?>\s*', '', text)


def match_key_value(pattern, text):
    results = []
    for match in re.finditer(pattern, text, re.VERBOSE):
        key = match.group("key").strip()
        value = match.group("value").strip()
        # 处理引号包裹的值
        if (value.startswith('"') and value.endswith('"')) or \
           (value.startswith("'") and value.endswith("'")):
            value = value[1:-1].replace('\\"', '"')
        # 智能截断结尾点号（仅当点号后无其他内容）
        if value.endswith('.') and not re.search(r'\d+\.\d+\.\d+', value):
            value = value[:-1]
            
        if key and value:
            key = re.sub(r'\s+', ' ', key)
            results.append({'key': key, 'value': value})
    if results:
        print("Key-Value Results:", results)
        return results
    else:
        print("未找到匹配的键值对")
        return []

def match_date_year(pattern, text):
    matches = re.findall(pattern, text)
    results = []
    for match in matches:
        if match:
            results.append({'key': '', 'value': match})
    if results:
        print("Date Results:", results)
        return results
    else:
        print("未找到匹配的日期时间信息, 类似：Oct 28 17:58:09 OR Jun 24 2016 22:16:51")
        return []
    
def match_date_with_zone(pattern, text):
    match = re.search(pattern, text)
    if match:
        month = match.group(1)
        day = match.group(2)
        year = match.group(3)
        hour = match.group(4)
        minute = match.group(5)
        second = match.group(6)
        timezone_offset = match.group(7) + match.group(8)
        date = f'{month} {day} {year} {hour}:{minute}:{second}{timezone_offset}'
        # print(f"提取的日期时间信息: {month} {day} {year} {hour}:{minute}:{second}{timezone_offset}")
        print("With year:", {"key": "", "value": date})
        return [{"key": "", "value": date}]
    else:
        print("未找到匹配的时区信息, 类似：Nov 5 2021 11:34:18+08:00")
        return []
    
def match_date_ISO(pattern, text):
    match = re.search(pattern, text)
    results = []
    if match:
        date = match.group(0)
        results.append({'key': '', 'value': date}) 
        return results
    else:
        print("未找到匹配的ISO日期时间信息, 类似：2015-12-28 06:16:28+08:00")
        return []  


def match_hostname(pattern, text):
    exclude_keywords = [
    "Removed",
    "session",
    "adjust",
    "Postponed",
    "for",
    "from",
    "port",
    "closed",
    "user",
    "of",
    "New",
    "to",
    "alloc",
    "IP",
    "address",
    "like"]
    matches = re.findall(pattern, text)
    results = []
    for match in matches:
        if match and match not in exclude_keywords:
            # 这里可能需要根据实际分组调整match的处理
            # 如果正则中有分组，match会是元组，否则是字符串
            value = match if isinstance(match, str) else match
            if not value.isdigit():
                results.append({'key': '', 'value': value})
    print("Hostname Results:", results)
    return results

def match_pid(pattern, text):
    matches = re.findall(pattern, text)
    results = []
    for match in matches:
        process_name, pid = match
        results.append({'key': '', 'value': process_name})
        results.append({'key': '', 'value': pid})
    print("PID Results:", results)
    return results
    

def match_ip_number_1(pattern, text):
    match = re.search(pattern, text)
    results = []
    if match:
        ip = match.group(1)
        port = match.group(2)
        results.append({'key': '', 'value': ip})
        results.append({'key': '', 'value': port})
        print("IP Results:", results)
        return results
    else:
        print("未找到匹配的 IP 地址和端口号-1")
        return []
    
def match_ip_number_2(pattern, text):
    matches = re.findall(pattern, text)
    results = []
    for ip, port in matches:
        print(f"IP: {ip}, Port: {port}")
        if ip and port:
            results.append({'key': '', 'value': ip})
            results.append({'key': '', 'value': port})
    if results:
        print("IP-Port Number Results:", results)
        return results
    else:
        print("未找到匹配的 IP 地址和端口号-2")
        return []
    
def match_ip_number_3(pattern, text):
    matches = re.findall(pattern, text)
    results = []
    if matches:
        for item in matches:
            print(f"IP: {item[0]}, Port: {item[1]}")
            ip_port = f"{item[0]}:{item[1]}"
            results.append({'key': '', 'value': ip_port})
    if results:
        print("IP-Port Number Results:", results)
        return results
    else:
        print("未找到匹配的 IP 地址和端口号-3")
        return []
    
def match_session_id(pattern, text):
    matches = re.findall(pattern, text, re.IGNORECASE)
    for match in matches:
        if match:
            id = [match.group(1) for match in re.finditer(pattern, text, re.IGNORECASE)]
            if id:
                print("Session ID Results:", {'key': "", 'value': id[0]})
                return [{'key': '', 'value': id[0]}]
    else:
        print("未找到匹配的 Session ID")
        return []
    

def match_function(pattern, text):
    match = re.search(pattern, text)
    results = []
    if match:
        function_name = match.group(1)
        bracket_content = match.group(2)
        results.append({'key': '', 'value': function_name})
        results.append({'key': '', 'value': bracket_content})
        print("Function Results:", results)
        return results
    else:
        print("未找到匹配的函数名和括号内的内容")
        return []

def match_WebPort(pattern, text):
    match = re.search(pattern, text)
    results = []
    if match:
        WebPort = match.group(1)
        results.append({'key': '', 'value': WebPort})
        print("WebPort Results:", results)
        return results
    else:
        print("未找到匹配的 WebPort")
        return []

def match_slash(pattern, text):
    keywords = [
        "URL地址",
        "发生时间",
        "服务器IP",
        "服务器端口",
        "主机名",
        "攻击特征串",
        "触发规则",
        "访问唯一编号",
        "国家",
        "事件",
        "请求方法",
        "标签",
        "动作",
        "威胁",
        "POST数据",
        "省",
        "HTTP/S响应码",
    ]
    matches = re.findall(pattern, text)
    results = []
    for match in matches:
        print("Matched:", match)
        if match and match[0] in keywords:
            results.append({'key': match[0], 'value': match[1]})
    else:
        print("未找到匹配的斜杠")
    print("Slash Results:", results)
    return results
    
def match_user_agent(pattern, text):
    match =  re.findall(pattern, text)
    if match:
        if len(match) == 1:
            value = match[0]
            print("User-Agent Results:", {'key': "客户端环境", 'value': value})
            return {'key': '客户端环境', 'value': value}
    else:
        p = r"Mozilla/5\.0\s*\[.*?\]\s*\([^)]*\)"
        match = re.findall(p, text)
        if match:
            if len(match) == 1:
                value = match[0]
                print("User-Agent Results:", {'key': "客户端环境", 'value': value})
                return {'key': '客户端环境', 'value': value}
    print("未找到匹配的 User-Agent")
    return []


def match_HTTPS_code(pattern, text):
    match = re.search(pattern, text)
    if match:    
        value = match.group(1)
        print("HTTPS Code Results:", {'key': "HTTP/S响应码", 'value': value})    
        return {'key': 'HTTP/S响应码', 'value': value}
    else:
        print("未找到匹配的 HTTPS响应码")
        return []


def slash_filter(results, custom_env_p, https_p, log_text):
    custom_env_item = match_user_agent(custom_env_p, log_text)
    https_item = match_HTTPS_code(https_p, log_text)
    new_results = []
    for item in results:
        if custom_env_item and item['key'] == custom_env_item['key']:
            print("替换UserAgent")
            item = custom_env_item
        if https_item and item['key'] == 'HTTP':
            print("替换 HTTPS 响应码")
            item = https_item
        new_results.append(item)
    print("Slash Filter Results:", new_results)
    return new_results

def match_mail(text):
    fields = re.findall(r'"(?:\\"|[^"])*"|[^,]+', text)
    cleaned_fields = []
    for field in fields:
        cleaned = field.strip('"').replace('\\"', '"')
        cleaned_fields.append(cleaned)
    results = []
    email_pattern = re.compile(r'^[\w.-]+@[\w.-]+\.\w+$')  # 邮箱匹配规则
    # mail_keywords = re.compile(r'mail', re.IGNORECASE)     # 忽略大小写的mail匹配
    mail_keywords = re.compile(r'mail') # 只有小写

    for field in cleaned_fields:
        if mail_keywords.search(field) or email_pattern.fullmatch(field):
            results.append({"key": "", "value":field})
    print("Mail Results:", results)
    return results


def match_web_attack(pattern, text):
    matches = re.findall(pattern, text)
    results = []
    if matches:
        results.append({'key': '', 'value': 'WEB攻击'})
    for attack_type, extra_info, severity in matches:
        results.append({'key': '', 'value': attack_type})
        results.append({'key': '', 'value': severity})
    if results:
        print("Web Attack Results:", results)
        return results
    else:   
        print("未找到匹配的Web攻击信息")
        return [] 


def match_sys_attack(pattern, text):
    matches = re.findall(pattern, text)
    results = []
    if matches:
        results.append({'key': '', 'value': '系统告警'})
    for _, _, severity, num in matches:
        results.append({'key': '', 'value': severity})
        results.append({'key': '', 'value': num})
    if results:
        print("Sys Attack Results:", results)
        return results
    else:   
        print("未找到匹配的sys信息")
        return [] 

def match_json_str(pattern, text):
    import json
    try:
        json_str = re.search(r'\{.*\}', text)
    except:
        return []    
    if not json_str: return []
    matches = re.findall(pattern, json_str.group(), re.VERBOSE)
    results = []
    for key, value in matches:
        try:
            parsed_value = json.loads(value)
        except:
            parsed_value = value
        results.append({'key': key, 'value': parsed_value})
    if results:
        print("JSON String Results:", results)
        return results
    else:
        print("未找到匹配的JSON字符串")
        return [] 

def match_segment(pattern, text):
    result = []
    segments = text.split('~')
    for seg in segments:
        match = re.search(pattern, seg, re.VERBOSE)
        if match:
            key, value = match.groups()
            result.append({'key': key, 'value': value.strip()})
    if result:
        print("Segment Results:", result)
        return result
    else:
        print("未找到匹配的Segment ~")
        return []   
    
def match_fangkuohao(pattern, text):
    match = re.search(pattern, text)
    if match:
        v = match.group(1)
        print("找到匹配的方括号:", {'key': "", 'value': v})
        return [{'key': '', 'value': v}]
    else:
        print("未找到匹配的方括号")
        return []