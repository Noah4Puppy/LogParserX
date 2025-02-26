import json
import re
from json import JSONDecodeError

def auto_escape_json(json_str):
    def enhanced_escape(s):
        """增强型转义函数（保留已有合法转义）"""
        return re.sub(
            r'(?<!\\)([\"\\\b\f\n\r\t])',
            lambda m: f'\\{m.group(1)}',
            s
        )

    def fix_hex_notation(match):
        """转换十六进制表示格式：66.74.70... -> ASCII字符串"""
        hex_str = match.group(1).replace('.', '')
        try:
            return bytes.fromhex(hex_str).decode('utf-8', 'ignore')
        except ValueError:
            return hex_str

    try:
        # 预处理阶段：修复关键结构问题
        # 1. 转换十六进制格式（修复正则表达式）
        json_str = re.sub(
            r'$$([0-9a-fA-F.]+)\s*$$hex$$$$',  # 修正正则表达式
            lambda m: f'"{fix_hex_notation(m)}"', 
            json_str
        )

        # 2. 修复键名引号缺失问题
        json_str = re.sub(
            r'(?<![":])\b([a-zA-Z_]\w*)\b(?=\s*:)',
            r'"\1"',
            json_str
        )

        # 3. 转义特殊字符（保留已有转义）
        json_str = re.sub(
            r'(?<!\\)(")((?:\\"|[^"])*?)(?<!\\)(")', 
            lambda m: f'"{enhanced_escape(m.group(2))}"',
            json_str
        )

        # 4. 处理控制字符
        json_str = re.sub(
            r'[\x00-\x1F\x7F-\x9F]',
            lambda c: f'\\u{ord(c.group()):04x}',
            json_str
        )

        # 容错解析（添加循环重试机制）
        for _ in range(3):
            try:
                data = json.loads(json_str)
                break
            except JSONDecodeError as e:
                # 自动修复常见结构问题
                if e.msg.startswith('Expecting'):
                    json_str = re.sub(r'([{,]\s*)(\w+)(\s*:)', r'\1"\2"\3', json_str)
                if e.msg.startswith('Unterminated string'):
                    json_str += '"'

        # 递归清洗数据
        def recursive_clean(obj):
            if isinstance(obj, dict):
                return {k: recursive_clean(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [recursive_clean(elem) for elem in obj]
            elif isinstance(obj, str):
                return enhanced_escape(obj)
            return obj

        cleaned_data = recursive_clean(data)
        
        return json.dumps(
            cleaned_data,
            ensure_ascii=False,
            indent=4,
            separators=(',', ': ')
        )
    
    except Exception as e:
        err_pos = getattr(e, 'pos', 0)
        context = json_str[max(0, err_pos-50):err_pos+50]
        raise ValueError(f"修复失败：{str(e)}\n错误上下文：{context}")

# 测试用例保持原样
test = """
{
    "logId": 266,
    "logText": "<148>Jan 15 2017 14:22:33 11G-West %%01SNMP/4/SNMP_MIB_SET(s)[10835]:MIB node set. (UserName=%^%#:K9^G@JW`E!tM6/78|@LJw\'M8>Q~(=Bx@b%l4n@$1C(n7@crz/0z4\"I8I:RECUFeov>$=V\'!MVckT+%^%#, SourceIP=100.78.141.251, Version=v2c, RequestId=1635095918, hwFlhOperType.23=2, hwFlhOperProtocol.23=1, hwFlhOperServerUser.23=[61.64.6d.69.6e (hex)], hwFlhOperPassword.23=******, hwFlhOperSourceFile.23=[66.74.70.73.79.6e.63.2f.39.64.66.61.5f.73.66.74.70.73.79.6e.63.5f.31.33.2e.78.6d.6c (hex)], hwFlhOperDestinationFile.23=[66.6c.61.73.68.3a.2f.39.64.66.61.5f.73.66.74.70.73.79.6e.63.5f.31.33.2e.78.6d.6c (hex)], hwFlhOperRowStatus.23=5, hwFlhOperServerPort.23=31923, hwFlhOperServerAddress.23=100.78.141.251, VPN= )",
    "logField": [
        {
            "key": "",
            "value": "Jan 15 2017 14:22:33"
        },
        {
            "key": "",
            "value": "11G-West"
        },
        {
            "key": "",
            "value": "10835"
        },
        {
            "key": "UserName",
            "value": "%^%#:K9^G@JW`E!tM6/78|@LJw'M8>Q~(=Bx@b%l4n@$1C(n7@crz/0z4\"I8I:RECUFeov>$=V'!MVckT+%^%#"
        },
        {
            "key": "SourceIP",
            "value": "100.78.141.251"
        },
        {
            "key": "Version",
            "value": "v2c"
        },
        {
            "key": "RequestId",
            "value": "1635095918"
        },
        {
            "key": "hwFlhOperType.23",
            "value": "2"
        },
        {
            "key": "hwFlhOperProtocol.23",
            "value": "1"
        },
        {
            "key": "hwFlhOperSourceFile.23",
            "value": "[66.74.70.73.79.6e.63.2f.39.64.66.61.5f.73.66.74.70.73.79.6e.63.5f.31.33.2e.78.6d.6c (hex)]"
        }
    ]
}"""

print(auto_escape_json(test))