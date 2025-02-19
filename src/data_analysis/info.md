# 类别分类说明

## 关键信息提取分类
### 1. 时间
1.1 无年份时间：Jul 29 16:57:28

1.2 有时间年份：Nov 5 2021 11:34:18+08:00

1.3 有年份无月份：2017-06-22 15:10:21

### 2. 设备信息

2.1 主机名字：sco-12

keywords and excluded keywords
排除项 和 提取项

2.2 User-Agent: 多种
- Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36
- Mozilla/5.0 (X11; U; Linux x86_64; zh-CN; rv:1.9.2.10) Gecko/20100922 Ubuntu/10.10 (maverick) Firefox/3.6.10
- Mozilla/5.0 (Linux; Android 10; Pixel 3 XL Build/QQ3A.200805.001) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36
- Mozilla/5.0 [en] (X11, U; DBAPPSecurity 21.4.3)
...
2.3 IP地址和端口号：
3 种
- for root from 3.66.0.23 port 44196
- 10.207.94.231(52445)
- 10.207.94.231

2.4 会话ID：
session 12222

2.5 SSH 信息 OR 其他 形如: XXX[YYY]

SSH守护进程 sshd[1234]；

SSH2 协议版本 ssh2 [preauth]；

时间同步的进程 ntpdate[41916]；

1. key-value 类型的信息

形如 key=value

3.1 CID

3.2 OID

3.3 Session ID

3.4 Storage type:

3.5 Domain: DomainNo.=72, DomainName=vlan3260

3.6 Slot: Slot=0

4. Email：
test@mail.com
mail.contents
./log/mail.log
./log/mail.err
....

5. Attack
形如:
WEB攻击~php $_get代码注入~NULL~中;
WEB攻击~createtextrange跨站~NULL~中;
WEB攻击~通用目录遍历(..\\/)~~低;


6. Warning
形如:
系统告警~~NULL~高~55

7. Function 

需要增加排除项
形如 func(param) 需要提取 func, param

8. Slash 斜杠过滤器

形如：