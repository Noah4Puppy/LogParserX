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

def get_components(keyword, log_text):
    # 定义关键字与对应函数及参数的映射关系
    component_map = {
        'key_value': (match_key_value, [key_value_p]),
        'hostname': (match_hostname, [hostname_p]),
        'date': (get_all_datetimes, []),
        'pid': [(match_pid, [pid_p]), (match_pid, [pid_p_2])],  # 多模式匹配
        'ip_port': (get_all_ip_ports, []),
        'session': (match_session_id, [session_p]),
        'slash': (match_slash, [slash_pattern]),
        'slash_filtered': (lambda txt: slash_filter(match_slash(slash_pattern, txt), user_agent_p, HTTPS_code_p, txt), []),
        'webport': (match_WebPort, [WebPort_p]),
        'web_attack': (match_web_attack, [web_attack_p]),
        'sys_attack': (match_sys_attack, [sys_attack_p]),
        'json_str': (match_json_str, [json_str_p]),
        'email': (match_mail, []),
        'function': (match_function, [function_p]),
        'segment': (match_segment, [segment_p]),
        # f'{new_key}': (f'match_{new_key}', [f'{new_pattern}'])
    }

    result = []
    for key in keyword:
        if key in component_map:
            # 处理多模式匹配的情况（如pid）
            handlers = component_map[key]
            if not isinstance(handlers, list):
                handlers = [handlers]
            
            for handler in handlers:
                func, args = handler
                # 动态构建参数：模式参数 + log_text
                call_args = args + [log_text] if args else [log_text]
                # 执行函数并收集结果
                result.extend(func(*call_args))
                
    return result


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
    return L

def calculate_coverage(original, testing):
    if original and testing:
        original_values = {item["value"] for item in original}
        testing_values = {item["value"] for item in testing}
        common = original_values & testing_values
        return len(common) / len(original_values) * 100
    else:
        return 0.0

if __name__ == '__main__':
    json_data = json.load(open('data/dataset.json', 'r', encoding='utf-8'))
    keywords_data = json.load(open('src/data_analysis/temp/default_keywords.json', 'r', encoding='utf-8'))
    target_log = []
    origin_logField = []
    for log in json_data:
        target_log.append(log['logText'])
        origin_logField.append(log['logField'])
    # print(target_log[:5])
    START = 300
    END = 399
    T = target_log[START:END]
    O = origin_logField[START:END]
    # print(O)
    R = []
    keywords = keywords_data['keywords']
    # 高级用法：自定义处理流程
    for i, l in zip(O, T):
        # item = {"Original_logField": i, "Test_logField": Test(l)}
        res = get_components(keywords, l)
        item = {"Original_logField": i, "Test_logField": res}
        R.append(item)
    # for r in R:
    #     print(f"original: {r['Original_logField']}\n")
    #     print(f"testing: {r['Test_logField']}\n")
    #     print(f"覆盖率: {calculate_coverage(r['Original_logField'], r['Test_logField']):.1f}%\n")
        
    overall_coverage = 0.0
    total_logs = len(R)
    # Open a file to write the output
    bad_pattern_list = []
    with open(f"src/data_analysis/log/{START}-{END}_log_output.txt", "w", encoding="utf-8") as file:
        for idx, r in enumerate(R):
            original = r.get("Original_logField", [])
            test = r.get("Test_logField", [])
            print(f"original: {original}\n")
            print(f"testing: {test}\n")
            
            coverage = calculate_coverage(original, test)
            file.write(f"Record {idx + 1}:\n")
            file.write(f"Original: {original}\n")
            file.write(f"Testing: {test}\n")
            file.write(f"Coverage: {coverage:.1f}%\n\n")

            if coverage <= 70:
                str = f"Record {idx + 1}:\n"
                str += f"Original: {original}\n"
                str += f"Testing: {test}\n"
                str += f"Coverage: {coverage:.1f}%\n\n"
                bad_pattern_list.append(str)

            overall_coverage += coverage

        # Calculate and write overall coverage
        overall_coverage = overall_coverage / total_logs
        file.write(f"Total Coverage: {overall_coverage:.1f}%\n")
        print(f"Total Coverage: {overall_coverage:.1f}%\n")
        print("The results have been saved to log_output.txt.")

    with open(f"src/data_analysis/log/{START}-{END}_bad_perf.txt", "w", encoding="utf-8") as file:
        file.write("Bad Performance Records:\n")
        for item in bad_pattern_list:
            file.write(item)
        file.write(f"Total Bad Records: {len(bad_pattern_list)}\n")
    print(f"Total Bad Records: {len(bad_pattern_list)}\n The bad performance records have been saved to bad_perf.txt.")













    # log_text = """<21>Oct 28 17:58:09 soc-32 systemd: lgent.service: main process exited, code=exited, status=2/INVALIDARGUMENT"""
    # log_text = """<21>Aug 12 08:06:01 soc-32 sshd[16209]: Postponed publickey for root from 3.66.0.23 port 38316 ssh2 [preauth]"""
    # log_text = "Oct 21 09:55:07 10-50-86-12 DBAppWAF: 发生时间/2024-10-21 09:54:52,威胁/中,事件/检测路径穿越攻击,请求方法/GET,URL地址/10.50.109.2/pulsecms/index.php??p=../../../../../../../../../winnt/win.ini%00,POST数据/,服务器IP/10.50.109.2,主机名/10.50.109.2,服务器端口/80,客户端IP/10.50.86.35,客户端端口/36381,客户端环境/Mozilla/5.0 [en] (X11, U; DBAPPSecurity 21.4.3),标签/通用防护,动作/告警,HTTP/S响应码/301,攻击特征串/../,触发规则/10350000,访问唯一编号/7428041536381654217,国家/局域网,省/未知,市/未知,XFF_IP/"
    # log_text = "<178>Aug 14 15:08:12 192.168.19.39 DBAppWAF: 发生时间/2024-08-14 15:08:09,威胁/高,事件/漏洞防护,请求方法/GET,URL地址/59.202.175.8:9030/jinhua/api/classgrade/list?page=1&limit=10&unCancelSelect=4&infoState=&impState=&ctblevel=&cancelState=&source=&open=&appState=2&themeState=2&backflow=&provinState=2&access=&openPlatformType=&generationStatus=&highRailState=&editState=,POST数据/,服务器IP/59.202.175.8,主机名/59.202.175.8:9030,服务器端口/9030,客户端IP/10.44.58.133,客户端端口/52889,客户端环境/Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36,标签/漏洞防护,动作/告警,HTTP/S响应码/200,攻击特征串/LNmOu4hN58dg86cF3d6tiJ0tBC19IulEUR/NuVpV7SEnkO/6aSKWc7GLu101kSHvtUG3ovi/YssYBZvZdP9Y9DfrOalOHkQ4KwMuWmzYEMF5hB9THkfL/vseX/NJjmpALTTL439QF/FzM9w5Uz9uQSyxwav9YGJZjoCbBHxWV2IGxl21Czs2tm9Ivb6Hn/EQVIldDNLhQlu2w9dn56cDgxWKsRmP+3ETHn62KCmj7rBh1QtL3A9zK6KsuZ8aVSc6if+cu+etsBSnKEI40ilID2UwD54UgAU5aG6JGC3MTSPtP1cqqxXY7ZPJB0wjdsEfAyENjGprrsnjBIOIfh0wWIwFOyK07KhDh1a71j2gmDIL/r2/iHe2hgQAece2dpvMTVyOckgiy0c3bV79Rd3QO1LJVBA5i3YPY5ULeY8/xtaWZxErTaGT0eTmYMpMESOJeACzN68XLXkQjR2Z6kjJONwAJ1kvxAq5St9FezgCRvta5pb4b9x5PKzp9Iob0Lufon0Ft439k2QbAoGdJz2tZfNUY9b5HvS4nZlGBEJjFRQhmg==,触发规则/18010101,访问唯一编号/7402888116246734199,国家/LAN,省/,市/,XFF_IP/"
    # log_text = "<164>Nov 5 2021 11:34:18+08:00 ME60-1 %%01BRASAM/4/hwAllocUserIPFailAlarm (t):VS=Admin-VS-CID=0x81d80420-OID=1.3.6.1.4.1.2011.6.8.2.2.0.3;Fail to alloc IP address from domain. (DomainNo.=72,DomainName=vlan3260)"
    # log_text = "<190>Oct 26 2023 10:00:05 fw001.cn-lvliang-2 %%01CONFIGURATION/6/hwCfgConfigChangeLog(t):CID=0x80cb000c-OID=1.3.6.1.4.1.2011.6.10.2.17;The configuration changed. (Internal change =True, User name =-, Session ID =65535, Command source address =0.0.0.0, Storage type =running, Terminal type =65535)"
    # log_text = "<190>Jun 24 2016 22:16:51 YC-SLPT-ASW %%01SHELL/6/CMDCONFIRM_NOPROMPT(l):Record command information. (Task=VT0, IP=192.23.140.97, User=admin, Command=\"sa\", UserInput=Y)"
    # log_text = "<188>2015-12-28 06:16:28 USG6300 %%01AUDIT/4/MAIL(l):2015-12-28 06:00:00,192.168.1.100,1022,8.8.8.123,80,userA,usergroupA,test@163.com,\"mail,content\",/log/mailcontent_01.txt,permit,3,{10240,/log/attach01.jpg},{6584,/log/attach02.txt},{7890,/log/attach03.jpg}"
    # log_text = remove_prefix(log_text)

    # key_value_l = match_key_value(key_value_p, log_text)
    # match_date_no_year(date_p, log_text)
    # date_y_l = match_date_with_year(date_p_2, log_text)
    # date_iso = match_date_ISO(date_p_3, log_text)
    # hostname_l = match_hostname(hostname_p, log_text)
    # log_text = "2015-12-28 06:16:28, Oct 28 17:58:09, Jun 24 2016 22:16:51, Nov 5 2021 11:34:18+08:00"
    # date_t = get_all_datetimes(log_text)
    # logField = key_value_l + date_y_l + hostname_l
    # print({"logField": logField})
    # if match_pid(pid_p, log_text):
    #     match_pid(pid_p_2, log_text)
    # match_ip(ip_port_p, log_text)
    # match_session_id(session_p, log_text)
    # res = match_slash(slash_pattern, log_text)
    # res_ = slash_filter(res, user_agent_p, HTTPS_code_p, log_text)
    # match_date(date_p, log_text)
    # match_WebPort(WebPort_p, log_text)
