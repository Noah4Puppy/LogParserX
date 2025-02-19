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
    log_text = remove_prefix(log_text)
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
    # function = match_function(function_p, log_text)
    segment = match_segment(segment_p, log_text)
    keywords = get_concrete_words(log_text)
    fangkuohao = match_fangkuohao(fangkuohao_p, log_text)

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
    # L.extend(function)
    L.extend(fangkuohao)
    L.extend(segment)
    L.extend(keywords)

    return L


text = "<188>2019-10-21 15:19:57 USG5500 %%01SEC/4/POLICYDENY(l): protocol=6, source-ip=175.149.48.121, source-port=50188, destination-ip=10.32.12.68, destination-port=7203, time=2015/07/20 13:51:15, interzone-untrust(public)-dzsw(public) inbound, policy=8."
# text = "<164>Nov 5 2021 11:34:18+08:00 ME60-1 %%01BRASAM/4/hwAllocUserIPFailAlarm (t):VS=Admin-VS-CID=0x81d80420-OID=1.3.6.1.4.1.2011.6.8.2.2.0.3;Fail to alloc IP address from domain. (DomainNo.=72,DomainName=vlan3260)"
# text = "<178>Aug 14 15:08:12 192.168.19.39 DBAppWAF: 发生时间/2024-08-14 15:08:09,威胁/高,事件/漏洞防护,请求方法/GET,URL地址/59.202.175.8:9030/jinhua/api/classgrade/list?page=1&limit=10&unCancelSelect=4&infoState=&impState=&ctblevel=&cancelState=&source=&open=&appState=2&themeState=2&backflow=&provinState=2&access=&openPlatformType=&generationStatus=&highRailState=&editState=,POST数据/,服务器IP/59.202.175.8,主机名/59.202.175.8:9030,服务器端口/9030,客户端IP/10.44.58.133,客户端端口/52889,客户端环境/Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36,标签/漏洞防护,动作/告警,HTTP/S响应码/200,攻击特征串/LNmOu4hN58dg86cF3d6tiJ0tBC19IulEUR/NuVpV7SEnkO/6aSKWc7GLu101kSHvtUG3ovi/YssYBZvZdP9Y9DfrOalOHkQ4KwMuWmzYEMF5hB9THkfL/vseX/NJjmpALTTL439QF/FzM9w5Uz9uQSyxwav9YGJZjoCbBHxWV2IGxl21Czs2tm9Ivb6Hn/EQVIldDNLhQlu2w9dn56cDgxWKsRmP+3ETHn62KCmj7rBh1QtL3A9zK6KsuZ8aVSc6if+cu+etsBSnKEI40ilID2UwD54UgAU5aG6JGC3MTSPtP1cqqxXY7ZPJB0wjdsEfAyENjGprrsnjBIOIfh0wWIwFOyK07KhDh1a71j2gmDIL/r2/iHe2hgQAece2dpvMTVyOckgiy0c3bV79Rd3QO1LJVBA5i3YPY5ULeY8/xtaWZxErTaGT0eTmYMpMESOJeACzN68XLXkQjR2Z6kjJONwAJ1kvxAq5St9FezgCRvta5pb4b9x5PKzp9Iob0Lufon0Ft439k2QbAoGdJz2tZfNUY9b5HvS4nZlGBEJjFRQhmg==,触发规则/18010101,访问唯一编号/7402888116246734199,国家/LAN,省/,市/,XFF_IP/"
# text = "<188>Jun  4 2019 00:58:52 SD-RZ-ZYL-SR-1.MAN %%01RM/4/INST_RCH_MAX_RT_LMT(s)[222079]:The number of routes in VPN instance DCN-ITMS was 30000, which reached or exceeded the maximum value 30000. (InstanceId=6, AcceptOrRejectFlag=Reject)"
        
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