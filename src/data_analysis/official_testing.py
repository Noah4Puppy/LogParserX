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

# def calculate_coverage(original, testing):
#     if original and testing:
#         original_values = {item["value"] for item in original}
#         testing_values = {item["value"] for item in testing}
#         common = original_values & testing_values
#         return len(common) / len(original_values) * 100
#     else:
#         return 0.0

def is_perfect_match(original, test):
    """完全匹配：所有字段的key和value都正确且数量一致"""
    if len(original) != len(test):
        return False  # 字段数量不一致直接判定不匹配
    
    original_dict = {f['key']: f['value'] for f in original}
    test_dict = {f['key']: f['value'] for f in test}
    return original_dict == test_dict  # 字典比对自动校验key-value对

def has_any_match(original, test):
    """至少有一个字段的key和value都正确"""
    original_set = {(f['key'], f['value']) for f in original}
    test_set = {(f['key'], f['value']) for f in test}
    return len(original_set & test_set) > 0  # 集合交集判断

def calculate_metrics(original, test):
    """核心指标计算函数"""
    if not original and not test:
        return True, True  # 双方均为空视为完全匹配
    
    # 完全匹配需满足字段数量、key、value全部一致
    perfect = is_perfect_match(original, test)
    # 匹配只需至少一个字段正确
    matched = has_any_match(original, test) or perfect
    
    return matched, perfect

if __name__ == '__main__':
    json_data = json.load(open('data/dataset.json', 'r', encoding='utf-8'))
    keywords_data = json.load(open('src/data_analysis/temp/default_keywords.json', 'r', encoding='utf-8'))
    target_log = []
    origin_logField = []
    for log in json_data:
        target_log.append(log['logText'])
        origin_logField.append(log['logField'])
    # print(target_log[:5])
    START = 120
    END = 125
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
        
    total_logs = len(R)
    match_count = 0
    perfect_count = 0
    bad_records = []
    
    with open(f"src/data_analysis/record/{START}-{END}_log_output.txt", "w", encoding="utf-8") as file:
        for idx, r in enumerate(R):
            original = r.get("Original_logField", [])
            test = r.get("Test_logField", [])
            
            # 计算匹配状态
            is_matched, is_perfect = calculate_metrics(original, test)
            
            # 更新统计
            if is_matched:
                match_count += 1
            if is_perfect:
                perfect_count += 1
                
            # 记录错误案例（匹配率低于70%或未完全匹配）
            if not is_matched or not is_perfect:
                bad_entry = [
                    f"Record {idx + 1}:",
                    f"Original: {original}",
                    f"Testing: {test}",
                    f"Matched: {is_matched}",
                    f"Perfect: {is_perfect}\n"
                ]
                bad_records.append("\n".join(bad_entry))
            
            # 写入详细日志
            file.write(f"Record {idx + 1}:\n")
            file.write(f"Original: {original}\n")
            file.write(f"Testing: {test}\n")
            file.write(f"Matched: {is_matched}\n")
            file.write(f"Perfect: {is_perfect}\n\n")
    
    # 计算最终指标
    match_rate = (match_count / total_logs) * 100
    perfect_rate = (perfect_count / total_logs) * 100
    final_metric = match_rate * 0.4 + perfect_rate * 0.6
    
    # 输出总指标
    print(f"""
    ========== 最终指标 ==========
    匹配率: {match_rate:.1f}%
    完全正确率: {perfect_rate:.1f}%
    综合得分: {final_metric:.1f}
    =============================
    """)

    with open(f"src/data_analysis/record/{START}-{END}_log_output.txt", "a+", encoding="utf-8") as file:
        file.write(f"总计{total_logs}条日志，匹配率{match_rate:.1f}%, 完全正确率{perfect_rate:.1f}%, 综合得分{final_metric:.1f}\n")
    # 保存错误记录（修改为存储未匹配/未完全匹配的记录）
    with open(f"src/data_analysis/record/{START}-{END}_bad_perf.txt", "w", encoding="utf-8") as file:
        file.write(f"问题记录（共{len(bad_records)}条）:\n")
        file.write("\n".join(bad_records))