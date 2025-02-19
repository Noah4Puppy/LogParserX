import json
from regex_pattern import *
from tool import *

# -*- coding: utf-8 -*-

def get_all_datetimes(log_text):
    res1 = match_date_year(date_p, log_text)
    res1_ = match_date_year(date_p_, log_text)
    res2 = match_date_with_zone(date_p_2, log_text)
    res3 = match_date_ISO(date_p_3, log_text)
    res = res1 + res1_+ res2 + res3
    print(res)
    return res

def get_all_ip_ports(log_text):
    res1 = match_ip_number_1(ip_port_p, log_text)
    res2 = match_ip_number_2(ip_port_p_2, log_text)     
    res3 = match_ip_number_3(ip_port_p_3, log_text)
    res = res1 + res2 + res3
    print(res)
    return res
def Test(log_text):
    key_value_l = match_key_value(key_value_p, log_text)
    hostname_l = match_hostname(hostname_p, log_text)
    date_t = get_all_datetimes(log_text)
    pid = match_pid(pid_p, log_text)
    if not pid:
        pid = match_pid(pid_p_2, log_text)
    pid_ = match_pid(pid_p_2, log_text)

    ip_port = get_all_ip_ports(log_text)
    session = match_session_id(session_p, log_text)
    res = match_slash(slash_pattern, log_text)
    res_ = slash_filter(res, user_agent_p, HTTPS_code_p, log_text)
    webport = match_WebPort(WebPort_p, log_text)
    web_attack = match_web_attack(web_attack_p, log_text)
    sys_attack = match_sys_attack(sys_attack_p, log_text)
    json_str = match_json_str(json_str_p, log_text)
    email = match_mail(log_text)
    function = match_function(function_p, log_text)
    segment = match_segment(segment_p, log_text)
    keywords = get_concrete_words(log_text)

    L = []
    L.extend(key_value_l)
    L.extend(hostname_l)
    L.extend(date_t)
    L.extend(pid)
    L.extend(pid_)
    L.extend(ip_port)
    L.extend(session)
    L.extend(res)
    L.extend(session)
    L.extend(res_)
    L.extend(webport)
    L.extend(web_attack)
    L.extend(sys_attack)
    L.extend(json_str)
    L.extend(email)
    L.extend(function)
    L.extend(segment)
    L.extend(keywords)
    return L


text = "<188>2015-07-20 13:51:15 USG5500_master %%01SEC/4/POLICYDENY(l): protocol=6, source-ip=175.149.48.121, source-port=50188, destination-ip=10.32.12.68, destination-port=7203, time=2015/07/20 13:51:15, interzone-untrust(public)-dzsw(public) inbound, policy=8."
R = Test(text)

print(R)

# import re

# key_value_p = re.compile(r"""
#     (?<![,;=(\-])       # 确保不是从分隔符中间开始
#     \s*                  
#     (?P<key>
#         (?!\d)          # 键名不能以数字开头
#         [\w\-\.\s]+?    # 支持带连字符、点号的键名
#     )
#     \s*=\s*             
#     (?P<value>
#         (?:             
#             (?!\s*[,;)=])  # 排除前置分隔符
#             [^=,;)]+?      # 非贪婪匹配值内容（允许内部点号）
#         )+                
#         (?<![.])        # 确保值不以点号结尾（关键修正）
#     )
#     (?:\.(?=\s*([,;)]|$)))?  # 捕获结尾点但不计入value
#     (?=\s*([,;)]|$))    # 断言后跟分隔符或行尾
# """, re.VERBOSE | re.IGNORECASE)

# text = "<188>2015-07-20 13:51:15 USG5500_master %%01SEC/4/POLICYDENY(l): protocol=6, source-ip=175.149.48.121, source-port=50188, destination-ip=10.32.12.68, destination-port=7203, time=2015/07/20 13:51:15, interzone-untrust(public)-dzsw(public) inbound, policy=8."

# # 执行解析
# results = [
#     {"key": m.group("key").strip(), "value": m.group("value").strip()}
#     for m in key_value_p.finditer(text)
# ]

# print("Key-Value Results:", results)

# # 测试案例
# test_text = (
#     "protocol=6, source-ip=175.149.48.121, policy=8., "
#     "error=192.168..1, version=2.5., time='13:45:00'"
# )
# match_key_value(test_text)