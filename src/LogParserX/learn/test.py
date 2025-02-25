import re
keywords = [
    "root",
    "system-logind",
    "systemd",
    "APT",
    "run-parts",
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

pattern = r"\b(" + "|".join(re.escape(keyword) for keyword in keywords) + r")\b"

print(pattern)