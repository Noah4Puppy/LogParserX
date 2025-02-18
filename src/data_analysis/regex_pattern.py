# 正则表达式
# key=value
# key_value_p = r"""\b(\w+)\s*=\s*([^=]+)(?=\s|$)"""
# key_value_p = r"(\w+)=([^,;=\)\s]+)"

keywords = [
    "root",
    "CMD",
    "system-logind",
    "systemd",
    "APT",
    "",
]

key_value_p = r"""
        (?:                        # 起始分隔符检测
            (?<=[;,:,=(\-])|       # 关键修正：添加冒号:和连字符-作为合法分隔符
            ^                      # 或行首
        )
        \s*                        # 允许前置空格
        (?P<key>                   # 键名规则
            (?![\d\-])             # 不能以数字或连字符开头
            [\w\s.-]+              # 允许字母/数字/空格/点/连字符
        )
        \s*=\s*                    # 等号两侧允许空格
        (?P<value>                 # 值部分
            (?:                   
                (?!\s*[,;)=\-])    # 排除前置分隔符（新增-）
                [^,;)=\-]+         # 基础匹配（新增排除-）
            )+
        )
        (?=                        # 截断预查
            \s*[,;)=\-]|           # 分隔符（新增-）
            \s*$|                  # 字符串结束
            (?=\S+\s*=)            # 后面紧跟新键（含空格键名）
        )
    """

# 时间：不带年份+带年份
date_p = r"""\b([A-Za-z]+ \d{2} \d{2}:\d{2}:\d{2})\b"""
date_p_ = r"""\b([A-Za-z]+ \d{2} \d{4} \d{2}:\d{2}:\d{2})\b"""
date_p_2 = r"([A-Za-z]{3})\s+(\d{1,2})\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})([+-]\d{2}):(\d{2})"
date_p_3 = r"""\b(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(\.\d{1,6})?\b"""
# 主机名字
hostname_p = r"(?<=\s)([a-zA-Z0-9-]+)(?=\s)"
# 进程ID
pid_p = r"([a-zA-Z0-9_-]+)\[(\d+)\]"
pid_p_2 = r"(\S+)\s+\[(.*?)\]"
# 端口号
# from {ip} port {port}
ip_port_p = r"(\d+\.\d+\.\d+\.\d+)\s+port\s+(\d+)"
# ip(port)
ip_port_p_2 = r"(\d+\.\d+\.\d+\.\d+)(?:\((\d+)\))?"
# ip:port
ip_port_p_3 = r'(\d+.\d+.\d+.\d+):(\d+)'
# cmd
cmd_p = r"""\b\w+\b(?=\s*CMD)"""
# 会话ID
session_p = r"session (\d+)"
# session_p = r"(?i)\bsession\s+\d+"
# 函数调用
function_p = r"([a-zA-Z0-9_-]+)\((.*?)\)"
# 90-09-10-20
WebPort_p = r"(\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3})"

# 粗提取 +替换
# XXX/YYYY 
slash_pattern = r"([^,/]+)\/([^,]+)"
# user-agent
user_agent_p = r"Mozilla/5\.0\s*\([^)]+\)\s*(?:AppleWebKit/[\d\.]+\s*\([^)]+\)\s*Chrome/[\d\.]+\s*Safari/[\d\.]+|[\w\s]+/[\d\.]+)"
# HTTP响应码
HTTPS_code_p = r"HTTP/S响应码/(\d+)"
# mail关键词
# email_p = r"(^|\s)([\w\u0080-\uFFFF.-]+@([\w\u0080-\uFFFF-]+\.)+[\w\u0080-\uFFFF]{2,18})(?=\s|$)"

# attack info
web_attack_p = r"WEB攻击~([^~]+)~([^~]*)~([中高低]+)"
sys_attack_p = r"系统告警~+([^~]*)~+([^~]*)~+([中高低]+)~+(\d+)"

# json_str
json_str_p = r'''
    "([^"]+)"            # 键
    \s*:\s*              # 分隔符
    (                    # 值
        "(?:\\"|[^"])*"  # 字符串（支持转义）
        |$$.*?$$         # 数组
        |-?\d+           # 整数
        |-?\d+\.\d+      # 浮点数
        |true|false|null # 布尔/空值
    )'''

target_keys = {'类型', 'Host'}
segment_p = r"""
    ^\s*                    # 开头可能存在的空格
    ({})                    # 捕获目标键（类型|Host|解析域名）
    \s*:\s*                 # 冒号及两侧空格
    (.+?)                   # 非贪婪捕获值
    \s*$                    # 结尾可能存在的空格
""".format('|'.join(target_keys))