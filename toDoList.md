# toDoList
✅: 已完成的任务
🚧: 正在进行的任务
❌: 未完成的任务

### 2025.1.21-23

🚧1.分析官方数据分布 data_analysis/json_parser.py   11/400

✅2.调研如何使用Qwen-2.5-72B - 完成

🚧3.智能体框架设计 - 对比试验

### 2025.2.12-13
数据说明：
测试集合: 包含logField部分（标签），主要用于规则学习，从若干个类似的数据里面学习到共性的规则 
```shell
"logField": [
            {
                "key": "", # 可以是空或者其他
                "value": "???" # 必须有值
            }, ..., {}]
```

验证集合： 去掉logField部分，用于规则验证； logField部分要人工提取作为答案

规则和损失设定：
提取的规则设计为正则表达式集合，相当于探索一系列的数据特征，用正则表达式来最大化覆盖
规则将会不断迭代，最后生成一个损失最小的规则，这里设定损失为相对损失，即当前更新的规则相对于每一个数据logField结果的差异
最后采用累加计算方式： loss = sum(rate_i * related_loss_i) 每个相对损失*数据所占据的比例 
允许key为空，但是value必须要有值； 就是说可以放宽LLM对于value总结的要求，因为正则表达式主要筛选的是value的值，key是后天填入

设计框架： 应对于每次输入一条测试日志+若干条验证日志这样的结构
1. RuleExtraction 规则提取

API_Implement: Qwen-72b-structure模型API 交互部分
- 正则表达式prompt：
你是一个正则表达式和提取信息的专家，在给定logText作为应用正则表达式的明文, 应用正则表达式后的logField是提取结果，生成能够提取到logField的正则表达式和对应的key;
key如果在logField有出现直接使用它的值，若是""则考虑从以下key中选取，若不满足以下key则保持""
重点关注的key:
    - startTime: 开始时间。通常指某个特定操作或事件的起始时间或发生时间。
    - endTime: 结束时间。通常指某个特定操作或事件的结束时间。
    - opType: 操作类型。指在日志或系统中记录的各种不同的操作或类型。
    - srcAddress: 来源IP。指发起请求或连接的设备的IP地址。
    - destAddress: 的IP。指数据包、请求或连接的目标设备的IP地址。
    - srcPort: 来源端口。指发起网络请求或连接的设备使用的端口号。
    - destPort: 目的端口。指数据包、请求或连接的目标设备的IP地址。
    - srcMacAddress: 来源MAC地址。指发起网络请求或通信的设备的物理地址。
    - destMacAddress: 目的MAC地址。指网络通信中目标设备的物理地址。
    - srcUserName: 来源用户名。是指在网络流量、系统日志、访问记录等数据中，标识来源用户身份的用户名。
    - UserId: 来源用户ID。通常指在一个系统或平台中，用来唯一标识某个来源用户的独特识别码。
    - srcHostName: 来源主机名。在计算机网络和信息技术中通常指发起某个网络请求或连接的计算机或设备的名称。
    - taskName: 任务名称,指为某一特定任务或项目所设定的标识性名称。
    - sessionId: 会话ID。指用于唯一标识一次会话或通信过程的标识符。
    - requestUrl: 请求URL。
    - loginType: 登录方法。是指用户访问和进入某个系统、应用程序或在线服务的步骤和手段。
    - fileMd5: 文件MD5。
    - dnsType: DNS类型。此日志属于DNS查询还是属于DNS响应。
    - srcProcessCmd: 来源进程命令行。通常指在计算机系统中用于启动来源进程的命令行。
    - appName: 应用名称。即软件或应用程序的名字，是用户识别和记住该应用的主要标识。

给出的logText是{logText}, 提取结果logField是{logField}，你给出的答案应该是这个格式：
{
    "key": "",
    "logText": "{logText}",
    "regex": "",
}
- 生成验证日志prompt:
你是一个生成验证日志的智能体，给定你一个测试日志结构作为原生参考，需要你根据它的格式派生出跟它同源的日志一条，需要保持结构相同但是内容不同。
你可以加入攻击内容，这是提供的可能篡改的key内容：
    - startTime: 开始时间。通常指某个特定操作或事件的起始时间或发生时间。
    - endTime: 结束时间。通常指某个特定操作或事件的结束时间。
    - opType: 操作类型。指在日志或系统中记录的各种不同的操作或类型。
    - srcAddress: 来源IP。指发起请求或连接的设备的IP地址。
    - destAddress: 的IP。指数据包、请求或连接的目标设备的IP地址。
    - srcPort: 来源端口。指发起网络请求或连接的设备使用的端口号。
    - destPort: 目的端口。指数据包、请求或连接的目标设备的IP地址。
    - srcMacAddress: 来源MAC地址。指发起网络请求或通信的设备的物理地址。
    - destMacAddress: 目的MAC地址。指网络通信中目标设备的物理地址。
    - srcUserName: 来源用户名。是指在网络流量、系统日志、访问记录等数据中，标识来源用户身份的用户名。
    - UserId: 来源用户ID。通常指在一个系统或平台中，用来唯一标识某个来源用户的独特识别码。
    - srcHostName: 来源主机名。在计算机网络和信息技术中通常指发起某个网络请求或连接的计算机或设备的名称。
    - taskName: 任务名称,指为某一特定任务或项目所设定的标识性名称。
    - sessionId: 会话ID。指用于唯一标识一次会话或通信过程的标识符。
    - requestUrl: 请求URL。
    - loginType: 登录方法。是指用户访问和进入某个系统、应用程序或在线服务的步骤和手段。
    - fileMd5: 文件MD5。
    - dnsType: DNS类型。此日志属于DNS查询还是属于DNS响应。
    - srcProcessCmd: 来源进程命令行。通常指在计算机系统中用于启动来源进程的命令行。
    - appName: 应用名称。即软件或应用程序的名字，是用户识别和记住该应用的主要标识。
其中logField是根据logText提取的关键信息，请根据你生成的logText来设定，key如果未在列表中出现可以保持""。
Id设置为{id}.
你返回的格式应该类似：
{
    "logId": "{logId}_{id}",
    "logText": "",
    "logField": [
        {
            "key": "",
            "value": ""
        },
        {
            "key": "",
            "value": ""
        },
        ...,]
}

- 保存LLM交互的轨迹: 
step: 调用次数
    {
        'step': i,
        'logId': log_id,
        'input': input,
        'output': output
    }

Loss_Calculator: 计算正则表达式相对与原来的标签的差异值
- 计算差值并返回

Optimization: 优化正则表达式
API_implement: 输入当前的正则表达式 和 局部正则表达式， 要求其写出满足两个正则表达式的合并版本


main_structure: 主要框架

A：
(1) 测试日志 -> API_implement -> 正则表达式（value） + 键(key) 
(2) 测试日志 -> API_implement -> 生成类似的随机logText 含logField 若干条 这里设置X条验证日志 10-20条左右
(3) 使用正则表达式应用验证日志 -> 得到 logField 集合
(4) 对于这个正则表达式，计算相对误差累加和： loss

B：
重复生成正则表达式M次，对应于一批验证日志的验证，记录每次的loss，最后选loss最小的正则表达式
判断loss的变化做实验来设置M,X的数值

2. RuleApplication 规则应用
判断当前验证日志是否含有标签部分logField, 有则跳过，没有则作为验证日志
应用1生成的表达式来提取logField

3. ValidDataGeneration 验证集合生成
使用生成验证日志的prompt生成4000条作为验证集合
1:10的测试/验证比例投入 测试400条


官方给出的框架主要分为 extract.py 和 generate.py:
```text
评测阶段我们执行以下命令运行生成阶段的代码:
python generate.py --labeled_data_file_path "LABELED_DATA_FILE_PATH" --rules_save_file_path "RULES_SAVE_FILE_PATH" \
    --api_key "API_KEY" --base_url "BASE_URL" --use_llm_model "USE_LLM_MODEL"

执行以下命令运行提取阶段的代码:
python extract.py --unlabeled_data_file_path "UNLABELED_DATA_FILE_PATH" --rules_save_file_path "RULES_SAVE_FILE_PATH" \
    --result_file_path "RESULT_FILE_PATH"
请将对应的代码实现在 generate.py 和 extract.py 中, 并且确保能够处理上述命令行参数。
```
~~解析代码省略~~

A. generate.py

```python
def generate(labeled_data_file_path: str, rules_save_file_path: str) -> None:
    """
    使用有标签日志数据生成解析规则。

    这个函数从文件中读入有标签数据, 生成一系列规则, 并以任意形式将规则保存到一个文件中。
    可以无限次数的使用大语言模型, 充分利用有标签数据实现智能体的自我优化。

    参数:
        labeled_data_file_path (str): 有标签数据集的文件路径, 格式如[数据集介绍]中所述。
        rules_save_file_path (str): 保存规则的文件路径。
    
    返回:
        None, 这个函数不需要有返回值
    """
    ...
```
这里是 RuleExtraction(只有这个写到里面)+ValidDataGeneration(用来测试)


B. extract.py
```python
def extract(unlabeled_data_file_path: str, rules_save_file_path: str, result_file_path: str) -> None:
    """
    使用解析规则对无标签数据进行解析。

    这个函数从文件中读入无标签数据和保存的规则, 使用规则解析无标签数据, 并将解析结果保存到结果文件中。
    读入的无标签数据的 logField 字段为空, 只需要将解析的结果放回 logField 字段再保存到结果文件中即可。

    参数:
        unlabeled_data_file_path (str): 无标签数据集的文件路径, 格式如[数据集介绍]中所述。
        rules_save_file_path (str): 保存规则的文件路径。
        result_file_path: 保存解析结果的文件路径。
    
    返回:
        None, 这个函数不需要有返回值
    """
    ...
# 保存结果
with open(result_file_path, 'w', encoding='utf-8') as f:
    json.dump(result_list, f, ensure_ascii=False, indent=4)
```

具体代理使用CrewAI框架来设置 初步定义