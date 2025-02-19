# First Version Answers
1-5 log parsing:
只记录未覆盖的 并不会记录错的 
1. system-logind 未提取 
2. ip地址未提取 因为只有第一种提取方式 
3. systemd 未提取
4. root 未提取 
5. 完全覆盖

目前未覆盖的原因：
- 关键词未提取
- 在类别里面但是没有匹配上提取格式

覆盖率：
3/4，75%
4/5，80%
4/5，80%
8/9, 88.9%
4/4, 100%

源数据：（人工检查）
```txt
original: [{'key': '', 'value': 'Aug 13 09:04:02'}, {'key': '', 'value': 'soc-32'}, {'key': '', 'value': 'systemd-logind'}, {'key': '', 'value': '3831379'}]

testing: [{'key': '', 'value': 'soc-32'}, {'key': '', 'value': 'Aug 13 09:04:02'}, {'key': '', 'value': '3831379'}]   

original: [{'key': '', 'value': 'Oct 28 18:00:09'}, {'key': '', 'value': 'soc-32'}, {'key': '', 'value': 'ntpdate'}, {'key': '', 'value': '172578'}, {'key': '', 'value': '120.25.115.20'}]

testing: [{'key': '', 'value': 'soc-32'}, {'key': '', 'value': 'Oct 28 18:00:09'}, {'key': '', 'value': 'ntpdate'}, {'key': '', 'value': '172578'}]

original: [{'key': '', 'value': 'Oct 28 17:58:09'}, {'key': '', 'value': 'soc-32'}, {'key': '', 'value': 'systemd'}, {'key': 'code', 'value': 'exited'}, {'key': 'status', 'value': '2/INVALIDARGUMENT'}]

testing: [{'key': 'code', 'value': 'exited'}, {'key': 'status', 'value': '2/INVALIDARGUMENT'}, {'key': '', 'value': 'soc-32'}, {'key': '', 'value': 'Oct 28 17:58:09'}, {'key': ' status=2', 'value': 'INVALIDARGUMENT'}]

original: [{'key': '', 'value': 'Aug 12 08:06:01'}, {'key': '', 'value': 'soc-32'}, {'key': '', 'value': 'sshd'}, {'key': '', 'value': '16209'}, {'key': '', 'value': 'root'}, {'key': '', 'value': '3.66.0.23'}, {'key': '', 'value': '38316'}, {'key': '', 'value': 'ssh2'}, {'key': '', 'value': 'preauth'}]

testing: [{'key': '', 'value': 'soc-32'}, {'key': '', 'value': 'ssh2'}, {'key': '', 'value': 'Aug 12 08:06:01'}, {'key': '', 'value': 'sshd'}, {'key': '', 'value': '16209'}, {'key': '', 'value': 'ssh2'}, {'key': '', 'value': 'preauth'}, {'key': '', 'value': '3.66.0.23'}, {'key': '', 'value': '38316'}]

original: [{'key': '', 'value': 'Aug 12 08:11:56'}, {'key': '', 'value': 'soc-32'}, {'key': '', 'value': 'sshd'}, {'key': '', 'value': '33101'}]

testing: [{'key': '', 'value': 'soc-32'}, {'key': '', 'value': 'Aug 12 08:11:56'}, {'key': '', 'value': 'sshd'}, {'key': '', 'value': '33101'}]
```

# Second Version Answers
未添加关键字提取修改和分类
0-100日志 命中率 84.6% ，命中率在70%下的有15条 损失15%

370-399日志 命中率 68.3%， 命中率在70%以下有9条 损失30%
300-399日志 命中率 70.8%， 命中率在70%以下有39条 损失39%
可见对于后面日志来说这些规则的筛选率不高

目前的分类如下：
"keywords": ["key_value", "hostname", "date", "pid", "ip_port", "session", 
//"slash", //"slash_filtered", "webport", "web_attack", "sys_attack", "json_str", "email", "function"]
其中 slash相关可以先去掉

分析后面日志的命中情况：
```txt
Record 73:
Original: [{'key': '', 'value': 'May 16 14:54:09 2024'}, {'key': '', 'value': 'APT'}, {'key': '', 'value': '2024-05-16 14:54:09'}, {'key': '', 'value': '10.50.134.18:47013'}, {'key': '', 'value': '1.1.1.1:53'}, {'key': '', 'value': '远程控制'}, {'key': '', 'value': '漏洞利用攻击事件'}, {'key': '类型', 'value': 'C&C'}, {'key': 'Host', 'value': 'oast.pro'}]

Testing: [{'key': '', 'value': 'dbapp'}, {'key': '', 'value': 'May 16 14:54:09'}, {'key': '', 'value': '2024-05-16 14:54:09'}, {'key': '', 'value': 'C&C~高~2405161454090000256~~请求DNS服务器'}, {'key': '', 'value': '1.1.1.1'}, {'key': '', 'value': '2024-05-16 14:54'}, {'key': '', 'value': '10.50.134.18:47013'}, {'key': '', 'value': '1.1.1.1:53'}, {'key': '', 'value': '73:46:01~00:00'}]
Coverage: 33.3%

# 这里 {'key': '类型', 'value': 'C&C'}, {'key': 'Host', 'value': 'oast.pro'}


Record 81:
Original: [{'key': '', 'value': 'October 24 20:11:31 2013'}, {'key': '', 'value': 'APT'}, {'key': '', 'value': '2013-10-24 20:11:19'}, {'key': '', 'value': '192.168.29.124:0'}, {'key': '', 'value': '122.224.213.5:0'}, {'key': '', 'value': '恶意行为'}, {'key': '', 'value': 'WEB自动扫描'}, {'key': '', 'value': '高'}]
Testing: [{'key': '', 'value': 'dbapp'}, {'key': '', 'value': 'October 24 20:11:31'}, {'key': '', 'value': '2013-10-24 20:11:19'}, {'key': '', 'value': '2013-10-24 20:11'}, {'key': '', 'value': '192.168.29.124:0'}, {'key': '', 'value': '122.224.213.5:0'}, {'key': '<128>October 24 20:11:31 2013 dbapp APT~2~1~2013-10-24 20:11:19~192.168.29.124:0~122.224.213.5:0~恶意行为~WEB自动扫描~NULL~高~1310242011199910111~NULL~POST ', 'value': 'new/jeecms/ajax/cms/search/trsSearch.do'}, {'key': '<128>October 24 20:11:31 2013 dbapp APT~2~1~2013-10-24 20:11:19~192.168.29.124:0~122.224.213.5:0~恶意行为~WEB自动扫描~NULL~高~1310242011199910111~NULL~POST ', 'value': 'new/jeecms/ajax/cms/search/trsSearch.do'}]
Coverage: 37.5%
```

## Thrid Version Answers

| Index | Coverage(Mine) | Matched(Official)|  Perfect_Macthed(Official) |  70%< Coverage Count(Mine)|
|--|--|--|--|--|
| 0 - 5 | 91.0% | 100.0% | 0.0% |  0 |
| 0 - 10 | 91.0% | 100.0% | 0.0%|  0 |
| 0 - 100 | 84.6% | 100.0% | 1.0%  |  15 |
| 0 - 400 | 79.6% |  98.2%| 0.2% |  106 |
| 100 - 200 | 81.1% | 99.0% | 0.0% |  27 |
| 120 - 125 | 92.0% | 100.0% | 0.0% |  0 |
| 200 - 300 | 66.9% | 95.0% | 0.0%|  46 |
| 300 - 400 | 71.0% |  99.0% | 0.0% |  39 |