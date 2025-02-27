# import json
# import re
# from json import JSONDecodeError

# def auto_escape_json(json_str):
#     def enhanced_escape(s):
#         """增强型转义函数（保留已有合法转义）"""
#         return re.sub(
#             r'(?<!\\)([\"\\\b\f\n\r\t])',
#             lambda m: f'\\{m.group(1)}',
#             s
#         )

#     def fix_hex_notation(match):
#         """转换十六进制表示格式：66.74.70... -> ASCII字符串"""
#         hex_str = match.group(1).replace('.', '')
#         try:
#             return bytes.fromhex(hex_str).decode('utf-8', 'ignore')
#         except ValueError:
#             return hex_str

#     try:
#         # 预处理阶段：修复关键结构问题
#         # 1. 转换十六进制格式（修复正则表达式）
#         json_str = re.sub(
#             r'$$([0-9a-fA-F.]+)\s*$$hex$$$$',  # 修正正则表达式
#             lambda m: f'"{fix_hex_notation(m)}"', 
#             json_str
#         )

#         # 2. 修复键名引号缺失问题
#         json_str = re.sub(
#             r'(?<![":])\b([a-zA-Z_]\w*)\b(?=\s*:)',
#             r'"\1"',
#             json_str
#         )

#         # 3. 转义特殊字符（保留已有转义）
#         json_str = re.sub(
#             r'(?<!\\)(")((?:\\"|[^"])*?)(?<!\\)(")', 
#             lambda m: f'"{enhanced_escape(m.group(2))}"',
#             json_str
#         )

#         # 4. 处理控制字符
#         json_str = re.sub(
#             r'[\x00-\x1F\x7F-\x9F]',
#             lambda c: f'\\u{ord(c.group()):04x}',
#             json_str
#         )

#         # 容错解析（添加循环重试机制）
#         for _ in range(3):
#             try:
#                 data = json.loads(json_str)
#                 break
#             except JSONDecodeError as e:
#                 # 自动修复常见结构问题
#                 if e.msg.startswith('Expecting'):
#                     json_str = re.sub(r'([{,]\s*)(\w+)(\s*:)', r'\1"\2"\3', json_str)
#                 if e.msg.startswith('Unterminated string'):
#                     json_str += '"'

#         # 递归清洗数据
#         def recursive_clean(obj):
#             if isinstance(obj, dict):
#                 return {k: recursive_clean(v) for k, v in obj.items()}
#             elif isinstance(obj, list):
#                 return [recursive_clean(elem) for elem in obj]
#             elif isinstance(obj, str):
#                 return enhanced_escape(obj)
#             return obj

#         cleaned_data = recursive_clean(data)
        
#         return json.dumps(
#             cleaned_data,
#             ensure_ascii=False,
#             indent=4,
#             separators=(',', ': ')
#         )
    
#     except Exception as e:
#         err_pos = getattr(e, 'pos', 0)
#         context = json_str[max(0, err_pos-50):err_pos+50]
#         raise ValueError(f"修复失败：{str(e)}\n错误上下文：{context}")

# # 测试用例保持原样
# test = """
# {
#     "logId": 266,
#     "logText": "<148>Jan 15 2017 14:22:33 11G-West %%01SNMP/4/SNMP_MIB_SET(s)[10835]:MIB node set. (UserName=%^%#:K9^G@JW`E!tM6/78|@LJw\'M8>Q~(=Bx@b%l4n@$1C(n7@crz/0z4\"I8I:RECUFeov>$=V\'!MVckT+%^%#, SourceIP=100.78.141.251, Version=v2c, RequestId=1635095918, hwFlhOperType.23=2, hwFlhOperProtocol.23=1, hwFlhOperServerUser.23=[61.64.6d.69.6e (hex)], hwFlhOperPassword.23=******, hwFlhOperSourceFile.23=[66.74.70.73.79.6e.63.2f.39.64.66.61.5f.73.66.74.70.73.79.6e.63.5f.31.33.2e.78.6d.6c (hex)], hwFlhOperDestinationFile.23=[66.6c.61.73.68.3a.2f.39.64.66.61.5f.73.66.74.70.73.79.6e.63.5f.31.33.2e.78.6d.6c (hex)], hwFlhOperRowStatus.23=5, hwFlhOperServerPort.23=31923, hwFlhOperServerAddress.23=100.78.141.251, VPN= )",
#     "logField": [
#         {
#             "key": "",
#             "value": "Jan 15 2017 14:22:33"
#         },
#         {
#             "key": "",
#             "value": "11G-West"
#         },
#         {
#             "key": "",
#             "value": "10835"
#         },
#         {
#             "key": "UserName",
#             "value": "%^%#:K9^G@JW`E!tM6/78|@LJw'M8>Q~(=Bx@b%l4n@$1C(n7@crz/0z4\"I8I:RECUFeov>$=V'!MVckT+%^%#"
#         },
#         {
#             "key": "SourceIP",
#             "value": "100.78.141.251"
#         },
#         {
#             "key": "Version",
#             "value": "v2c"
#         },
#         {
#             "key": "RequestId",
#             "value": "1635095918"
#         },
#         {
#             "key": "hwFlhOperType.23",
#             "value": "2"
#         },
#         {
#             "key": "hwFlhOperProtocol.23",
#             "value": "1"
#         },
#         {
#             "key": "hwFlhOperSourceFile.23",
#             "value": "[66.74.70.73.79.6e.63.2f.39.64.66.61.5f.73.66.74.70.73.79.6e.63.5f.31.33.2e.78.6d.6c (hex)]"
#         }
#     ]
# }"""

# print(auto_escape_json(test))
# import re


# text = """
# if __name__ == '__main__':
#     log_text = "<178>Nov 18 15:17:06 10-50-86-12 DBAppWAF: 发生时间/2024-11-18 15:16:53,威胁/高,事件/检测PHP代码注入(语义分析),请求方法/POST,URL地址/10.50.109.90:31001/vb5/?routestring=ajax/render/widget_php,POST数据/widgetConfig%5Bcode%5D=echo+md5%28%27VbGfhSQC%27%29%3B+exit%3B,服务器IP/10.50.109.90,主机名/10.50.109.90:31001,服务器端口/31001,客户端IP/10.50.24.197,客户端端口/45376,客户端环境/Python-urllib/2.7,标签/通用防护,动作/阻断,HTTP/S响应码/403,攻击特征串/echo md5('VbGfhSQC'); exit;,触发规则/10130000,访问唯一编号/7438514904312627360,国家/局域网,省/未知,市/未知,XFF_IP/"
#     res = get_components(log_text)
#     print(res)
# """
# new_text = "<178>Nov 18 15:17:06 10-50-86-12 DBAppWAF: \u53d1\u751f\u65f6\u95f4/2024-11-18 15:16:53,\u5a01\u80c1/\u9ad8,\u4e8b\u4ef6/\u68c0\u6d4bPHP\u4ee3\u7801\u6ce8\u5165(\u8bed\u4e49\u5206\u6790),\u8bf7\u6c42\u65b9\u6cd5/POST,URL\u5730\u5740/10.50.109.90:31001/vb5/?routestring=ajax/render/widget_php,POST\u6570\u636e/widgetConfig%5Bcode%5D=echo+md5%28%27VbGfhSQC%27%29%3B+exit%3B,\u670d\u52a1\u5668IP/10.50.109.90,\u4e3b\u673a\u540d/10.50.109.90:31001,\u670d\u52a1\u5668\u7aef\u53e3/31001,\u5ba2\u6237\u7aefIP/10.50.24.197,\u5ba2\u6237\u7aef\u7aef\u53e3/45376,\u5ba2\u6237\u7aef\u73af\u5883/Python-urllib/2.7,\u6807\u7b7e/\u901a\u7528\u9632\u62a4,\u52a8\u4f5c/\u963b\u65ad,HTTP/S\u54cd\u5e94\u7801/403,\u653b\u51fb\u7279\u5f81\u4e32/echo md5('VbGfhSQC'); exit;,\u89e6\u53d1\u89c4\u5219/10130000,\u8bbf\u95ee\u552f\u4e00\u7f16\u53f7/7438514904312627360,\u56fd\u5bb6/\u5c40\u57df\u7f51,\u7701/\u672a\u77e5,\u5e02/\u672a\u77e5,XFF_IP/"

# new_main_function = re.sub(r"log_text\s*=\s*[\"'].*?[\"']", f'log_text = f\"\"\"{new_text}\"\"\"', text)
# print(new_main_function)  


import json
import re


text = """
if __name__ == '__main__':
    log_text = "<178>Nov 18 15:17:06 10-50-86-12 DBAppWAF: 发生时间/2024-11-18 15:16:53,威胁/高,事件/检测PHP代码注入(语义分析),请求方法/POST,URL地址/10.50.109.90:31001/vb5/?routestring=ajax/render/widget_php,POST数据/widgetConfig%5Bcode%5D=echo+md5%28%27VbGfhSQC%27%29%3B+exit%3B,服务器IP/10.50.109.90,主机名/10.50.109.90:31001,服务器端口/31001,客户端IP/10.50.24.197,客户端端口/45376,客户端环境/Python-urllib/2.7,标签/通用防护,动作/阻断,HTTP/S响应码/403,攻击特征串/echo md5('VbGfhSQC'); exit;,触发规则/10130000,访问唯一编号/7438514904312627360,国家/局域网,省/未知,市/未知,XFF_IP/"
    res = get_components(log_text)
    print(res)
"""


# text = """
# if __name__ == '__main__':
#     log_text = "<178>Nov 18 15:17:06 10-50-86-12 DBAppWAF: "new" 发生时间/2024-11-18 15:16:53,威胁/高,事件/检测PHP代码注入(语义分析),请求方法/POST,URL地址/10.50.109.90:31001/vb5/?routestring=ajax/render/widget_php,POST数据/widgetConfig%5Bcode%5D=echo+md5%28%27VbGfhSQC%27%29%3B+exit%3B,服务器IP/10.50.109.90,主机名/10.50.109.90:31001,服务器端口/31001,客户端IP/10.50.24.197,客户端端口/45376,客户端环境/Python-urllib/2.7,标签/通用防护,动作/阻断,HTTP/S响应码/403,攻击特征串/echo md5('VbGfhSQC'); exit;,触发规则/10130000,访问唯一编号/7438514904312627360,国家/局域网,省/未知,市/未知,XFF_IP/"
#     res = get_components(log_text)
#     print(res)
# """
# match = re.search(r'log_text\s*=\s*(["\'])(.*?)\1', text, re.DOTALL)

# if match:
#     log_text = match.group(2)
#     print(f"提取的 log_text: {log_text}")
# else:
#     print("未找到匹配项")


# import re

# input_text = """[{"key": "", "value": "2024-12-20 10:21:08"}, {"key": "AND password", "value": ""123456""}, {"key": "hostname", "value": "10-50-86-12"}, {"key": "ip_port", "value": "10-50-86-12"}, {"key": "HTTP/S响应码", "value": "403"}]"""

# # 使用正则替换双引号对
# output_text = re.sub(r'"value":\s*""(.*?)""', r'"value": "\1"', input_text)

# print(output_text)

import re
import json

input_text = '''[{"key": "", "value": "10-50-86-15"}, {"key": "function", "value": "alert("XSS")"}, {"key": "攻击特征串", "value": "<script>alert("XSS")</script>"}, ...]'''

