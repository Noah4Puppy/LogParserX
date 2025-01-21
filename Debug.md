# Bugs in LogParserX Recording

## Bug1: 代理无法使用
设置你的代理如下，https使用的配置和http一致。
```python
import os
os.environ['HTTP_PROXY'] = 'http://127.0.0.1:8800'
os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:8800'
```
## Bug2: OpenAI 接口调用失败
修改`base_link`和`APIKEY`的值

