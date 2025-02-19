
import yaml


def generate_mapping(mapping_file):
    with open(mapping_file, "r", encoding="utf-8") as f:
        patterns = yaml.load(f, Loader=yaml.FullLoader)
    


    # component_map = {
    #     'key_value': (match_key_value, [key_value_p]),
    #     'hostname': (match_hostname, [hostname_p]),
    #     'date': (get_all_datetimes, []),
    #     'pid': [(match_pid, [pid_p]), (match_pid, [pid_p_2])],  # 多模式匹配
    #     'ip_port': (get_all_ip_ports, []),
    #     'session': (match_session_id, [session_p]),
    #     'slash': (match_slash, [slash_pattern]),
    #     'slash_filtered': (lambda txt: slash_filter(match_slash(slash_pattern, txt), user_agent_p, HTTPS_code_p, txt), []),
    #     'webport': (match_WebPort, [WebPort_p]),
    #     'web_attack': (match_web_attack, [web_attack_p]),
    #     'sys_attack': (match_sys_attack, [sys_attack_p]),
    #     'json_str': (match_json_str, [json_str_p]),
    #     'email': (match_mail, []),
    #     'function': (match_function, [function_p]),
    #     'segment': (match_segment, [segment_p]),
    #     'keywords': (get_concrete_words, []),
    #     # f'{new_key}': (f'match_{new_key}', [f'{new_pattern}'])
    # }



def get_components(component_map, keyword, log_text):
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