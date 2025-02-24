# README
## 分类
把原始数据集分成0-100, 100-200, 200-300, 300-400的四个集合
分别应对不同的pattern组合，设置训练-测试-验证比例=8：1：1
## class_1
第一个数据集的结构比较简单基本为：时间 主机号 提示信息（session id / system-info / ip - port / 形如XXX[YYY] XXX-YYY / 某些关键字 CMD, root...）
例子：
1. id = 84, 时间+主机号+XXX[YYY]+ip-port+ root+XXX[YYY]
```json
{
        "logId": 84,
        "logText": "<21>Aug 12 07:08:35 soc-32 sshd[56542]: Postponed publickey for root from 3.66.0.23 port 60188 ssh2 [preauth]",
        "logField": [
            {
                "key": "",
                "value": "Aug 12 07:08:35"
            },
            {
                "key": "",
                "value": "soc-32"
            },
            {
                "key": "",
                "value": "sshd"
            },
            {
                "key": "",
                "value": "56542"
            },
            {
                "key": "",
                "value": "root"
            },
            {
                "key": "",
                "value": "3.66.0.23"
            },
            {
                "key": "",
                "value": "60188"
            },
            {
                "key": "",
                "value": "ssh2"
            },
            {
                "key": "",
                "value": "preauth"
            }
        ]
    }
```
2. id = 80, 时间+主机名+系统服务+session id

```json
{
        "logId": 80,
        "logText": "<21>Oct 28 17:57:09 soc-32 systemd-logind: Removed session 4996668.",
        "logField": [
            {
                "key": "",
                "value": "Oct 28 17:57:09"
            },
            {
                "key": "",
                "value": "soc-32"
            },
            {
                "key": "",
                "value": "systemd-logind"
            },
            {
                "key": "",
                "value": "4996668"
            }
        ]
    }
```
3. id = 25, 时间+主机名+系统服务+session id+关键词root
```json
{
        "logId": 25,
        "logText": "<21>Jul 29 17:01:24 soc-32 systemd: Started Session 3604702 of user root.",
        "logField": [
            {
                "key": "",
                "value": "Jul 29 17:01:24"
            },
            {
                "key": "",
                "value": "soc-32"
            },
            {
                "key": "",
                "value": "systemd"
            },
            {
                "key": "",
                "value": "3604702"
            },
            {
                "key": "",
                "value": "root"
            }
        ]
    }
```
## class_2
第二个数据集的结构比较复杂，主要是包含了一些特殊的带斜杠信息需要提取
基本格式：时间+主机名+App名字:+App输出
App输出(X/Y)：时间+URL信息+编程语言+请求方法+请求参数+响应状态码+响应内容+IP-PORT+关键字（中文，服务器，...）+失败原因...

例子
1.id=129
```json
{
        "logId": 129,
        "logText": "<178>Nov 18 15:17:05 10-50-86-12 DBAppWAF: \u53d1\u751f\u65f6\u95f4/2024-11-18 15:16:54,\u5a01\u80c1/\u9ad8,\u4e8b\u4ef6/\u68c0\u6d4bPHP\u4ee3\u7801\u6ce8\u5165(\u8bed\u4e49\u5206\u6790),\u8bf7\u6c42\u65b9\u6cd5/POST,URL\u5730\u5740/10.50.109.90:31001/vBulletin/?routestring=ajax/render/widget_php,POST\u6570\u636e/widgetConfig%5Bcode%5D=echo+md5%28%27vi8fxaLe%27%29%3B+exit%3B,\u670d\u52a1\u5668IP/10.50.109.90,\u4e3b\u673a\u540d/10.50.109.90:31001,\u670d\u52a1\u5668\u7aef\u53e3/31001,\u5ba2\u6237\u7aefIP/10.50.24.197,\u5ba2\u6237\u7aef\u7aef\u53e3/45936,\u5ba2\u6237\u7aef\u73af\u5883/Python-urllib/2.7,\u6807\u7b7e/\u901a\u7528\u9632\u62a4,\u52a8\u4f5c/\u963b\u65ad,HTTP/S\u54cd\u5e94\u7801/403,\u653b\u51fb\u7279\u5f81\u4e32/echo md5('vi8fxaLe'); exit;,\u89e6\u53d1\u89c4\u5219/10130000,\u8bbf\u95ee\u552f\u4e00\u7f16\u53f7/7438514908615983270,\u56fd\u5bb6/\u5c40\u57df\u7f51,\u7701/\u672a\u77e5,\u5e02/\u672a\u77e5,XFF_IP/",
        "logField": [
            {
                "key": "",
                "value": "Nov 18 15:17:05"
            },
            {
                "key": "",
                "value": "10-50-86-12"
            },
            {
                "key": "\u53d1\u751f\u65f6\u95f4",
                "value": "2024-11-18 15:16:54"
            },
            {
                "key": "\u4e8b\u4ef6",
                "value": "\u68c0\u6d4bPHP\u4ee3\u7801\u6ce8\u5165(\u8bed\u4e49\u5206\u6790)"
            },
            {
                "key": "\u8bf7\u6c42\u65b9\u6cd5",
                "value": "POST"
            },
            {
                "key": "URL\u5730\u5740",
                "value": "10.50.109.90:31001/vBulletin/?routestring=ajax/render/widget_php"
            },
            {
                "key": "POST\u6570\u636e",
                "value": "widgetConfig%5Bcode%5D=echo+md5%28%27vi8fxaLe%27%29%3B+exit%3B"
            },
            {
                "key": "\u670d\u52a1\u5668IP",
                "value": "10.50.109.90"
            },
            {
                "key": "\u670d\u52a1\u5668\u7aef\u53e3",
                "value": "31001"
            },
            {
                "key": "\u5ba2\u6237\u7aef\u7aef\u53e3",
                "value": "45936"
            }
        ]
    }
```