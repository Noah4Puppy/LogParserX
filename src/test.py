# # import re

# # # 定义包含多个 User-Agent 字符串的文本
# # text = """
# # Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36, 
# # Mozilla/5.0 (X11; U; Linux x86_64; zh-CN; rv:1.9.2.10) Gecko/20100922 Ubuntu/10.10 (maverick) Firefox/3.6.10, 
# # Mozilla/5.0 (Linux; Android 10; Pixel 3 XL Build/QQ3A.200805.001) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36
# # Mozilla/5.0 (Windows NT 6.1; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0,
# # Mozilla/5.0 [en] (X11, U; DBAPPSecurity 21.4.3),
# # Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2, Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50,
# # Mozilla/5.0 (X11; U; Linux x86_64; zh-CN; rv:1.9.2.10) Gecko/20100922 Ubuntu/10.10 (maverick) Firefox/3.6.10
# # Mozilla/5.0 (iPhone; U; CPU iPhone OS 4_3_3 like Mac OS X; en-us) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8J2 Safari/6533.18.5
# # """

# # # 定义匹配 User-Agent 的正则表达式
# # pattern = r"Mozilla/5\.0\s*\([^)]+\)\s*(?:AppleWebKit/[\d\.]+\s*\([^)]+\)\s*Chrome/[\d\.]+\s*Safari/[\d\.]+|[\w\s]+/[\d\.]+)"

# # # 使用 re.findall 进行匹配
# # matches = re.findall(pattern, text)

# # # 输出结果
# # for match in matches:
# #     print(f"提取的 User-Agent 信息: {match}")

# # 定义包含多个 User-Agent 字符串的文本
# # text = """
# # Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36, 
# # Mozilla/5.0 (X11; U; Linux x86_64; zh-CN; rv:1.9.2.10) Gecko/20100922 Ubuntu/10.10 (maverick) Firefox/3.6.10, 
# # Mozilla/5.0 (Linux; Android 10; Pixel 3 XL Build/QQ3A.200805.001) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36,
# # Mozilla/5.0 [en] (X11, U; DBAPPSecurity 21.4.3),
# # """

# # # 定义匹配 User-Agent 的正则表达式
# # pattern = r"Mozilla/5\.0\s*\([^)]+\)\s*(?:AppleWebKit/[\d\.]+\s*\([^)]+\)\s*Chrome/[\d\.]+\s*Safari/[\d\.]+|[\w\s]+/[\d\.]+|\[.*?\]\s*\([^)]*\))"
# # p = r"Mozilla/5\.0\s*\[.*?\]\s*\([^)]*\)"
# # # 使用 re.findall 进行匹配
# # matches = re.findall(pattern, text)
# # m = re.findall(p, text)
# # print(m)
# # # 输出结果
# # for match in matches:
# #     print(f"提取的 User-Agent 信息: {match}")


# # import re

# # # 定义包含日期时间的文本
# # text = "<164>Nov 5 2021 11:34:18+08:00 ME60-1 %%01BRASAM/4/"

# # # 定义匹配日期时间的正则表达式
# # pattern = r"([A-Za-z]{3})\s+(\d{1,2})\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})([+-]\d{2}):(\d{2})"

# # # 使用 re.match 进行匹配
# # match = re.search(pattern, text)

# # if match:
# #     month = match.group(1)
# #     day = match.group(2)
# #     year = match.group(3)
# #     hour = match.group(4)
# #     minute = match.group(5)
# #     second = match.group(6)
# #     timezone_offset = match.group(7) + match.group(8)
# #     print(f"提取的日期时间信息: {month} {day} {year} {hour}:{minute}:{second}{timezone_offset}")
# # else:
# #     print("未找到匹配的日期时间信息")


# # import re

# # # Define the text containing key-value pairs
# # text = "VS=Admin-VS-CID=0x81d80420-OID=1.3.6.1.4.1.2011.6.8.2.2.0.3;Fail to alloc IP address from domain. (DomainNo.=72,DomainName=vlan3260)"
# # text = "VS=Admin,VS-CID=0x81d80420,OID=1.3.6.1.4.1.2011.6.8.2.2.0.3;Fail to alloc IP address from domain. (DomainNo.=72,DomainName=vlan3260)"
# # text = "<190>Oct 26 2023 10:00:05 fw001.cn-lvliang-2 %%01CONFIGURATION/6/hwCfgConfigChangeLog(t):CID=0x80cb000c-OID=1.3.6.1.4.1.2011.6.10.2.17;The configuration changed. (Internal change =True, User name =-, Session ID =65535, Command source address =0.0.0.0, Storage type =running, Terminal type =65535)"

# # # Define the regular expression to match key-value pairs with either a comma or hyphen separator
# # # pattern = r"(\w+)=([^,;=\)\s]+)"

# # # # Use re.findall to extract all key-value pairs
# # # matches = re.findall(pattern, text)

# # # # Print the extracted key-value pairs
# # # for key, value in matches:
# # #     print(f"{{ {key} }} = {{ {value} }}")

# # import re

# # def extract_kv_pairs(text):
# #     pattern = r"""
# #         (?P<key>[^\W-][\w.-]+)          # 键名：允许字母、数字、下划线、连字符、点号
# #         \s*=\s*                   # 等号两侧允许空格
# #         (?P<value>[^ ,;)\-]*)     # 值：直到遇到空格/逗号/分号/)/- 停止（修正字符范围）
# #         (?=                       # 正向预查截断点
# #             [ ,;)\-]|             # 分隔符（正确转义-）
# #             (?=\w+[\-.]?\w+=)     # 后面紧跟新键（如 -OID= 或 Domain.）
# #             |$                    # 或字符串结束
# #         )
# #     """
# #     return {
# #         match.group("key"): match.group("value")
# #         for match in re.finditer(pattern, text, re.VERBOSE)
# #     }

# # # 执行并打印结果
# # result = extract_kv_pairs(text)
# # print("解析结果：")
# # for k, v in result.items():
# #     print(f"{k} = {v}")

# # def extract_kv_pairs_(text):
# #     # 精准匹配复杂键值对的正则表达式
# #     pattern = r"""
# #         (?:                        # 起始分隔符检测
# #             (?<=[;,(=])|           # 前导分隔符：; , ( =
# #             ^                      # 或行首
# #         )
# #         \s*                        # 允许前置空格
# #         (?P<key>                   # 键名规则
# #             (?!\d)                 # 不能以数字开头
# #             [\w\s.-]+              # 允许字母/数字/空格/点/连字符
# #         )
# #         \s*=\s*                    # 等号两侧允许空格
# #         (?P<value>                 # 值部分
# #             (?:                   
# #                 (?!\s*[,;)=])      # 排除前置分隔符
# #                 [^,;)=]+           # 基础匹配（排除分隔符）
# #             )+
# #         )
# #         (?=\s*[,;)=]|\s*$)        # 截断预查
# #     """
    
# #     return {
# #         match.group("key").strip(): match.group("value").strip()
# #         for match in re.finditer(pattern, text, re.VERBOSE)
# #         if match.group("key").strip()
# #     }

# # # 执行解析
# # result = extract_kv_pairs_(text)

# # # 打印完整结果
# # print("完整解析结果：")
# # for k, v in result.items():
# #     print(f"{k!r}: {v!r}")


# # print("Update")

# # import re

# # def extract_kv_pairs(text):
# #     pattern = r"""
# #         (?:                        # 起始分隔符检测
# #             (?<=[;,:,=(\-])|       # 关键修正：添加冒号:和连字符-作为合法分隔符
# #             ^                      # 或行首
# #         )
# #         \s*                        # 允许前置空格
# #         (?P<key>                   # 键名规则
# #             (?![\d\-])             # 不能以数字或连字符开头
# #             [\w\s.-]+              # 允许字母/数字/空格/点/连字符
# #         )
# #         \s*=\s*                    # 等号两侧允许空格
# #         (?P<value>                 # 值部分
# #             (?:                   
# #                 (?!\s*[,;)=\-])    # 排除前置分隔符（新增-）
# #                 [^,;)=\-]+         # 基础匹配（新增排除-）
# #             )+
# #         )
# #         (?=                        # 截断预查
# #             \s*[,;)=\-]|           # 分隔符（新增-）
# #             \s*$|                  # 字符串结束
# #             (?=\S+\s*=)            # 后面紧跟新键（含空格键名）
# #         )
# #     """
    
# #     result = {}
# #     for match in re.finditer(pattern, text, re.VERBOSE):
# #         key = match.group("key").strip()
# #         value = match.group("value").strip()
        
# #         if key and value:
# #             key = re.sub(r'\s+', ' ', key)
# #             result[key] = value
    
# #     return result

# # # 测试日志文本

# # text = "VS=Admin-VS-CID=0x81d80420-OID=1.3.6.1.4.1.2011.6.8.2.2.0.3;Fail to alloc IP address from domain. (DomainNo.=72,DomainName=vlan3260)"
# # text = "VS=Admin,VS-CID=0x81d80420,OID=1.3.6.1.4.1.2011.6.8.2.2.0.3;Fail to alloc IP address from domain. (DomainNo.=72,DomainName=vlan3260)"
# # text = "<190>Oct 26 2023 10:00:05 fw001.cn-lvliang-2 %%01CONFIGURATION/6/hwCfgConfigChangeLog(t):CID=0x80cb000c-OID=1.3.6.1.4.1.2011.6.10.2.17;The configuration changed. (Internal change =True, User name =-, Session ID =65535, Command source address =0.0.0.0, Storage type =running, Terminal type =65535)"
# # text = "<190>Jun 24 2016 22:16:51 YC-SLPT-ASW %%01SHELL/6/CMDCONFIRM_NOPROMPT(l)[211]:Record command information. (Task=VT0, IP=192.23.140.97, User=admin, Command=\"sa\", UserInput=Y)"
# # result = extract_kv_pairs(text)
# # print("完整解析结果：")
# # for k, v in result.items():
# #     print(f"{k!r}: {v!r}")


# # KV_PATTERN = re.compile(r"""
# #     (?:(?<=[;,:,=(\-])|^)
# #     \s*
# #     (?P<key>(?![\d\-])[\w\s.-]+)
# #     \s*=\s* 
# #     (?P<value>(?!\s*[,;)=\-])[^,;)=\-]+)
# #     (?=\s*[,;)=\-]|\s*$|(?=\S+\s*=))
# # """, re.VERBOSE)

# # import re

# # def extract_kv_pairs(text):
# #     pattern = r"""
# #         (?:                        # 起始分隔符检测
# #             (?<=[;,:,=(\-])|       # 支持冒号、连字符等分隔符
# #             ^                      # 或行首
# #         )
# #         \s*                        # 允许前置空格
# #         (?P<key>                   # 键名规则
# #             (?![\d\-])             # 不能以数字或连字符开头
# #             [\w\s.-]+              # 允许字母/数字/空格/点/连字符
# #         )
# #         \s*=\s*                    # 等号两侧允许空格
# #         (?P<value>                 # 值部分
# #             (?:                   
# #                 "(?:\\"|[^"])*"    # 匹配被双引号包裹的值（含转义）
# #                 |                  # 或
# #                 [^,;)=\-]+         # 普通值（排除分隔符）
# #             )
# #         )
# #         (?=                        # 截断预查
# #             \s*[,;)=\-]|           # 分隔符
# #             \s*$|                  # 字符串结束
# #             (?=\S+\s*=)            # 后面紧跟新键
# #         )
# #     """
    
# #     result = {}
# #     for match in re.finditer(pattern, text, re.VERBOSE):
# #         key = match.group("key").strip().replace(' ', '_')  # 可选：将空格转为下划线
# #         value = match.group("value").strip()
        
# #         # 处理被双引号包裹的值
# #         if value.startswith('"') and value.endswith('"'):
# #             value = value[1:-1].replace('\\"', '"')  # 去除引号并处理转义
        
# #         if key and value:
# #             result[key] = value
    
# #     return result

# # # 测试日志
# # text = '<190>Jun 24 2016 22:16:51 YC-SLPT-ASW %%01SHELL/6/CMDCONFIRM_NOPROMPT(l):Record command information. (Task=VT0, IP=192.23.140.97, User=admin, Command=\"sa\", UserInput=Y)'

# # result = extract_kv_pairs(text)
# # print("解析结果：")
# # for k, v in result.items():
# #     print(f"{k!r}: {v!r}")


# # import re

# # def extract_mail_related(text):
# #     fields = re.findall(r'"(?:\\"|[^"])*"|[^,]+', text)
# #     cleaned_fields = []
# #     for field in fields:
# #         cleaned = field.strip('"').replace('\\"', '"')
# #         cleaned_fields.append(cleaned)
# #     results = []
# #     email_pattern = re.compile(r'^[\w.-]+@[\w.-]+\.\w+$')  # 邮箱匹配规则
# #     # mail_keywords = re.compile(r'mail', re.IGNORECASE)     # 忽略大小写的mail匹配
# #     mail_keywords = re.compile(r'mail') # 只有小写

# #     for field in cleaned_fields:
# #         if mail_keywords.search(field) or email_pattern.fullmatch(field):
# #             results.append({"key": "", "value":field})
    
# #     return results

# # # 测试日志
# # log_text = '<188>2015-12-28 06:16:28 USG6300 %%01AUDIT/4/MAIL(l):2015-12-28 06:00:00,192.168.1.100,1022,8.8.8.123,80,userA,usergroupA,test@163.com,\"mail,content\",/log/mailcontent_01.txt,permit,3,{10240,/log/attach01.jpg},{6584,/log/attach02.txt},{7890,/log/attach03.jpg}'

# # # 执行提取
# # output = extract_mail_related(log_text)
# # print("提取Email结果：", output)


# # def calculate_coverage(original, testing):
# #     original_values = {item["value"] for item in original}
# #     testing_values = {item["value"] for item in testing}
# #     common = original_values & testing_values
# #     return len(common) / len(original_values) * 100

# # # 测试数据
# # original = [
# #     {"key": "", "value": "Aug 13 09:04:02"},
# #     {"key": "", "value": "soc-32"},
# #     {"key": "", "value": "systemd-logind"},
# #     {"key": "", "value": "3831379"}
# # ]

# # testing = [
# #     {"key": "", "value": "soc-32"},
# #     {"key": "", "value": "Aug 13 09:04:02"},
# #     {"key": "", "value": "3831379"}
# # ]

# # print(f"覆盖率: {calculate_coverage(original, testing):.1f}%")

# # import re
# # text = "10.207.94.231(52445) 120.25.115.20"
# # pattern = r"(\d+\.\d+\.\d+\.\d+)\((\d+)\)"

# # match = re.match(pattern, text)
# # if match:
# #     ip = match.group(1)
# #     port = match.group(2)
# #     print(f"IP: {ip}, Port: {port}")
# # else:
# #     print("No match found.")

# # import re

# # text = "10.207.94.231(52445) 120.25.115.20"
# # pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"

# # ips = re.findall(pattern, text)
# # print("Extracted IPs:", ips)


# # import re

# # text = "10.207.94.231(52445) 120.25.115.20"

# # # Regular expression to capture both IPv4 addresses with and without ports
# # pattern = r"(\d+\.\d+\.\d+\.\d+)(?:\((\d+)\))?"

# # # Find all matches in the text
# # matches = re.findall(pattern, text)

# # # Process extracted IPs and ports
# # extracted_ips = []
# # extracted_ports = []
# # for ip, port in matches:
# #     extracted_ips.append(ip)
# #     if port:
# #         extracted_ports.append(port)

# # print("Extracted IPs:", extracted_ips)
# # print("Extracted Ports:", extracted_ports)


# # import re

# # # Sample text
# # text = "Aug 13 09:04:02 soc-32 systemd-logind: Removed session 3831379."

# # # Create the regex pattern with the updated session_p pattern
# # session_p = r"\bsession\s+(?P<session_id>\d+)"

# # # Find all matches
# # matches = re.findall(session_p, text, re.IGNORECASE)

# # # Extract session IDs
# # session_ids = [match.group(1) for match in re.finditer(session_p, text, re.IGNORECASE)]

# # print("Session IDs:", session_ids)


# import re

# text = "<128>April 25 19:52:48 2013 apt APT~2~1~2013-04-25 17:28:02~192.168.58.200:36720~192.168.58.102:80~WEB攻击~onmouseup跨站~NULL~中; WEB攻击~检测到命令执行漏洞攻击(exec)~~高,WEB攻击~createtextrange跨站~NULL~中; WEB攻击~通用目录遍历(..\\/)~~低;"
# text = "<128>April 25 19:52:48 2013 apt APT~2~1~2013-04-25 17:28:02~192.168.58.200:36720~192.168.58.102:80~WEB攻击~脚本文件上传~NULL~高~1304251728020000001~NULL~POST"
# # 正则表达式
# pattern = r"WEB攻击~([^~]+)~([^~]*)~([中高低]+)"

# # 提取匹配项
# matches = re.findall(pattern, text)

# # 结构化输出
# results = []
# for attack_type, extra_info, severity in matches:
#     results.append({
#         "攻击类型": attack_type.strip(),
#         # "附加信息": extra_info.strip(),
#         "风险等级": severity.strip()
#     })

# print(results)

# def match_web_attack(pattern, text):
#     matches = re.findall(pattern, text)
#     results = []
#     if matches:
#         results.append({'key': '', 'value': 'WEB攻击'})
#     for attack_type, extra_info, severity in matches:
#         results.append({'key': '', 'value': attack_type})
#         results.append({'key': '', 'value': severity})
#     if results:
#         print("Web Attack Results:", results)
#         return results
#     else:   
#         print("未找到匹配的Web攻击信息")
#         return []  

# match_web_attack(pattern, text)

# # import re
# # import json

# # log_text = "<14>Sep  3 16:32:54 edr-center {\"logType\":\"alert\",\"dnames\":[\"TargetFilename\"],\"techniqueArray\":[\"T1558\",\"T1558.003\"],\"collectorReceiptTime\":\"2024-09-03 16:32:45\",\"sendHostAddress\":\"10.50.86.44\",\"technique\":[\"T1558\"],\"lessUser\":\"user01\",\"subTechnique\":[\"T1558.003\"],\"deviceReceiptTime\":\"2024-09-03 16:32:45\",\"deviceName\":\"主机安全防护组件\",\"deviceAddress\":\"10.50.86.44\",\"riskType\":\"入侵威胁\",\"ruleType\":\"/Malware/Others\",\"destAddress\":\"10.50.109.179\",\"startTime\":\"2024-09-03 16:33:17\",\"attckWarningId\":\"20fdf501-8730-4636-9bf9-e9c7e7952971\",\"ruleId\":\"FY000327\",\"uKey\":\"ceff3bb9a1220708986d77b4f9fd1407\",\"timestamp\":1725352397000,\"eventNum\":60202,\"uploadtime\":1725352365284,\"severity\":\"5\",\"eventId\":\"664168eb-d6a1-4b44-91be-d329fa5499ee\",\"image\":\"C:\\\\hd\\\\peer\\\\assembly\\\\tools\\\\hdcommand.exe\",\"machineCode\":\"EDE8237F7CE130455307EA4199B837DD42752F71EBF2A9C40DBE039BD6CBB0BF97D53DE3\",\"eventStr\":[\"文件内容\"],\"level\":\"HIGH\",\"tacticIds\":[\"TA0006\"],\"author\":\"\",\"clientOperatingSystem\":\"windows\",\"threatTarget\":\"C:\\\\hd\\\\peer\\\\assembly\\\\tools\\\\hdcommand.exe\",\"deviceAssetSubType\":\"主机安全管理系统(EDR)\",\"deviceVersion\":\"3.0.9.114\",\"userName\":\"user01\",\"productVendorName\":\"安恒信息股份有限公司\",\"groupName\":\"系统默认组\",\"machineId\":\"3df7212cd7a3bfacbb5ee3bfcba775f091ae7ecb4c00078873a4a876842a9ee0\",\"newName\":\"WIN-RH45I247P86\",\"attckName\":\"创建使用Invoke-Kerberoast进行kerberosating攻击\",\"createTime\":1725352365122,\"deviceSendProductName\":\"主机安全防护组件\",\"name\":\"入侵检测\",\"deviceAssetSubTypeId\":\"56\",\"endTime\":\"2024-09-03 16:33:17\"}"

# # # Extract the JSON-like part
# # pattern = r"\{[^{}]+\}"
# # match = re.search(pattern, log_text)

# # if match:
# #     json_str = match.group()
# #     try:
# #         # Parse the JSON string
# #         json_data = json.loads(json_str)
# #         # Extract key-value pairs
# #         key_value_pairs = {k: v for k, v in json_data.items()}
# #         print("Extracted Key-Value Pairs:")
# #         for k, v in key_value_pairs.items():
# #             print(f"{k}: {v}")
# #     except json.JSONDecodeError:
# #         print("Invalid JSON format.")
# # else:
# #     print("No JSON-like part found.")


# import re
# import json

# log_text = '''<14>Sep  3 17:12:26 edr-center {\"logType\":\"alert\",\"dnames\":[\"TargetFilename\"],\"techniqueArray\":[\"T1134\",\"T1098\",\"T1547\",\"T1555\",\"T1003\",\"T1207\",\"T1649\",\"T1558\",\"T1552\",\"T1550\",\"T1134.005\",\"T1547.005\",\"T1555.003\",\"T1555.004\",\"T1558.001\",\"T1558.002\",\"T1552.004\",\"T1550.002\",\"T1550.003\"],\"collectorReceiptTime\":\"2024-09-03 17:12:20\",\"sendHostAddress\":\"10.50.86.44\",\"technique\":[\"T1134\",\"T1098\",\"T1547\",\"T1555\",\"T1003\",\"T1207\",\"T1649\",\"T1558\",\"T1552\",\"T1550\"],\"lessUser\":\"user01\",\"subTechnique\":[\"T1134.005\",\"T1547.005\",\"T1555.003\",\"T1555.004\",\"T1558.001\",\"T1558.002\",\"T1552.004\",\"T1550.002\",\"T1550.003\"],\"deviceReceiptTime\":\"2024-09-03 17:12:20\",\"deviceName\":\"主机安全防护组件\",\"deviceAddress\":\"10.50.86.44\",\"riskType\":\"入侵威胁\",\"ruleType\":\"/Malware/Others\",\"destAddress\":\"10.50.109.179\",\"startTime\":\"2024-09-03 17:12:53\",\"attckWarningId\":\"e9013056-ed25-4385-a21b-b6a5dd63520e\",\"ruleId\":\"FY000536\",\"uKey\":\"a8d518d9cdbf3a464b8a14ef2e9c1d29\",\"timestamp\":1725354773000,\"eventNum\":60202,\"uploadtime\":1725354740778,\"severity\":\"5\",\"eventId\":\"21d0b0ab-ed15-456c-b321-ae3d7e1f89b8\",\"image\":\"C:\\\\hd\\\\peer\\\\assembly\\\\tools\\\\hdcommand.exe\",\"machineCode\":\"EDE8237F7CE130455307EA4199B837DD42752F71EBF2A9C40DBE039BD6CBB0BF97D53DE3\",\"eventStr\":[\"文件内容\"],\"level\":\"HIGH\",\"tacticIds\":[\"TA0004\",\"TA0003\",\"TA0006\",\"TA0005\",\"TA0008\"],\"author\":\"\",\"clientOperatingSystem\":\"windows\",\"threatTarget\":\"C:\\\\hd\\\\peer\\\\assembly\\\\tools\\\\hdcommand.exe\",\"deviceAssetSubType\":\"主机安全管理系统(EDR)\",\"deviceVersion\":\"3.0.9.114\",\"userName\":\"user01\",\"productVendorName\":\"安恒信息股份有限公司\",\"groupName\":\"系统默认组\",\"machineId\":\"3df7212cd7a3bfacbb5ee3bfcba775f091ae7ecb4c00078873a4a876842a9ee0\",\"newName\":\"WIN-RH45I247P86\",\"attckName\":\"创建mimikatz恶意程序\",\"createTime\":1725354740627,\"deviceSendProductName\":\"主机安全防护组件\",\"name\":\"入侵检测\",\"deviceAssetSubTypeId\":\"56\",\"endTime\":\"2024-09-03 17:12:53\"}'''
        
# json_str = re.search(r'\{.*\}', log_text).group()
# # print(json_str)

# # 方法一：直接使用json解析（推荐）
# # try:
# #     data = json.loads(json_str)
# #     print("=== JSON解析结果 ===")
# #     for k, v in data.items():
# #         print(f"{k}: {v}")
# # except json.JSONDecodeError as e:
# #     print(f"JSON解析失败: {e}")

# # 方法二：正则表达式提取（兼容不标准格式）
# print("\n=== 正则表达式提取结果 ===")
# pattern = r'''
#     "([^"]+)"            # 键
#     \s*:\s*              # 分隔符
#     (                    # 值
#         "(?:\\"|[^"])*"  # 字符串（支持转义）
#         |$$.*?$$         # 数组
#         |-?\d+           # 整数
#         |-?\d+\.\d+      # 浮点数
#         |true|false|null # 布尔/空值
#     )
# '''
# matches = re.findall(pattern, json_str, re.VERBOSE)
# for key, value in matches:
#     # 尝试转换数据类型
#     try:
#         parsed_value = json.loads(value)
#     except:
#         parsed_value = value
#     # print(f"{key}: {parsed_value}")

# # match_json_str(pattern, log_text)


# # import re  # 将导入移到函数外部避免重复加载
# # import json
# # from json import JSONDecodeError

# # def match_json_str(pattern, text):
# #     try:
# #         # 优化点1：使用非贪婪模式并处理嵌套结构
# #         json_match = json_str = re.search(r'\{.*\}', log_text)
# #         if not json_match:
# #             print("未找到JSON对象结构")
# #             return []
# #         json_str = json_match.group()
# #     except AttributeError:  # 明确捕获group()调用失败的异常
# #         print("正则匹配失败：未找到{}包裹的JSON结构")
# #         return []
# #     except re.error as e:  # 处理非法正则表达式
# #         print(f"正则表达式错误：{str(e)}")
# #         return []

# #     try:
# #         # 优化点2：添加flags参数容错
# #         matches = re.findall(pattern, json_str, flags=re.VERBOSE)
# #     except re.error as e:
# #         print(f"模式语法错误：{str(e)}")
# #         return []

# #     results = []
# #     for key, value in matches:
# #         try:
# #             # 优化点3：限定捕获JSON解析错误
# #             parsed_value = json.loads(value)
# #         except JSONDecodeError:
# #             print(f"值解析失败（key={key}）：{value}")
# #             parsed_value = value
# #         except TypeError:  # 处理非字符串类型输入
# #             parsed_value = str(value)
# #         results.append({'key': key, 'value': parsed_value})

# #     return results if results else []
# # print(match_json_str(pattern=pattern, text=log_text))


# # SystemError
# text = "<128>April 26 13:30:32 2013 apt APT~0~1~2013-04-26 13:30:25~127.0.0.1:0~127.0.0.1:0~系统告警~~NULL~高~55~~许可证有问题: 你现在拥有的许可证无效!"
# pattern = r"系统告警~+([^~]*)~+([^~]*)~+([中高低]+)~+(\d+)"
# def match_sys_attack(pattern, text):
#     matches = re.findall(pattern, text)
#     print(matches)
#     results = []
#     if matches:
#         results.append({'key': '', 'value': '系统告警'})
#     for _, _, severity, num in matches:
#         # results.append({'key': '', 'value': attack_type})
#         results.append({'key': '', 'value': severity})
#         results.append({'key': '', 'value': num})
#     if results:
#         print("Sys Attack Results:", results)
#         return results
#     else:   
#         print("未找到匹配的sys信息")
#         return [] 
# match_sys_attack(pattern, text)

import re
# ip_port_p_2 = r"(\d+\.\d+\.\d+\.\d+)((\d+))"
ip_port_p_2 = r"(\d+\.\d+\.\d+\.\d+)(?:\((\d+)\))?"
text = "<128>April 26 13:30:32 2013 apt APT~0~1~2013-04-26 13:30:25~127.0.0.1:0~127.0.0.1:0~系统告警~~NULL~高~55~~探测器:{0},报表相关表{1}同步失败，相关功能可能会出现异常！"
text = "127.0.0.1(80),127.0.0.1(443),127.0.0.1(3306),127.0.0.1(27017),127.0.0.1(22),127.0.0.1(53),127.0.0.1(135),127.0.0.1(139),127.0.0.1(445),127.0.0.1(1433),127.0.0.1(1521),127.0.0.1(3389),127.0.0.1(8080),127.0.0.1(8000),127"
text = "127.0.0.1:0, 192.168.58.200:36720, 192.168.58.200:10000"
def match_ip_number(pattern, text):
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

def match_ip_number_(pattern, text):
    matches = re.findall(pattern, text)
    results = []
    if matches:
        for item in matches:
            ip_port = f"{item[0]}:{item[1]}"
            results.append({'key': '', 'value': ip_port})
    if results:
        print("IP-Port Number Results:", results)
        return results
    else:
        print("未找到匹配的 IP 地址和端口号-3")
        return []

# match_ip_number(ip_port_p_2, text)
ip_port_p_3 = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{*}$"
ip_port_p_3 = r'(\d+.\d+.\d+.\d+):(\d+)'
match_ip_number_(ip_port_p_3, text)


# import re  # 需要安装 regex 模块
# text = "<128>May 16 14:54:09 2024 dbapp APT~30~1~2024-05-16 14:54:09~10.50.134.18:47013~1.1.1.1:53~远程控制~漏洞利用攻击事件~类型:    C&C~高~2405161454090000256~~请求DNS服务器 [1.1.1.1] 解析域名: oast.pro~~~0~4~2~60:db:15:73:46:01~00:00:5e:00:01:0a~0~Host: oast.pro~~~~成功~12~1~630~212002"
# segments = text.split('~')
# # Step 2: 定义关键字段匹配规则
# target_keys = {'类型', 'Host', '解析域名'}
# pattern = r"""
#     ^\s*                    # 开头可能存在的空格
#     ({})                    # 捕获目标键（类型|Host|解析域名）
#     \s*:\s*                 # 冒号及两侧空格
#     (.+?)                   # 非贪婪捕获值
#     \s*$                    # 结尾可能存在的空格
# """.format('|'.join(target_keys))

# # Step 3: 遍历字段提取数据
# result = {}
# for seg in segments:
#     match = re.search(pattern, seg, re.VERBOSE)
#     if match:
#         key, value = match.groups()
#         result[key] = value.strip()
# print(result)
