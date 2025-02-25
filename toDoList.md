# toDoList
✅: 已完成的任务
🚧: 正在进行的任务
❌: 未完成的任务

### 2025.1.21-23

✅1.分析官方数据分布 data_analysis/json_parser.py   11/400

✅2.调研如何使用Qwen-2.5-72B - 完成

🚧3.智能体框架设计 - 对比试验

# 2025.2.20-2.21
## 任务分析
一看这要求，要求你使用智能体框架，并且更新高精度规则，那么很自然地就想到分成几个不同部分的智能体并分配工作。

分别代号为1，2，3，4，5
### Keywords Extraction Agent 关键字提取代理 
负责在`logText`里分析所有需要提取的关键字列表，生成这些键的列表，只需要提取提供的键，不需要提取额外的值。这里是生成一系列分类的键，用于对应所要对一个`logText`提取的时候所使用的正则提取式拼接组合。
比如，一条日志明文里面包含ip, port, session_id; 那么这些类别应该被生成。

若这些类别已经出现在知识库，则直接使用并计算筛选结果，若不满足命中100%进入正则优化代理进行优化，否则进入正则提取代理生成正则+匹配函数。
输入：logText, logField
输出1：logText, logField*, generated_logField, type_list
输出2：type_list: {...}, logText: "..."

### Regex Generation Agent 正则提取代理
根据输入的`logText`和`logField`内容，生成相应的正则表达式+匹配函数，并验证合理性。
如果计算结果不合理（匹配率过低<70%）则传递给差异提取代理，生成差异内容。
如果计算结果合理（匹配率合理>=80%），则证明这个正则合理加入知识库，传给维护代理。
输入：logText, logField, type_list
输出1：generated_logField, logField, logText
输出2：regex, func, type_list 

### Optimization Agent 正则优化代理
负责把当前所使用知识库的正则做优化，使用当前正则+匹配函数，比较筛选出来的结果和标准值的差异。
优化正则表达式和匹配函数。

输入：generated_logField, logField*, logText, type_list, reasons
输出：regex, func, type_list

### Difference Extraction Agent 差异提取代理
根据输入的Generated内容和标准答案，对比没有被提取出来的字段和明文部分，和错误原因，将其组合输入给正则提取代理。
输入：generated_logField, logField, logText
输出：logText*, logField, reasons

### Update Agent 维护代理
负责更新知识库内容，默认使用用户提供的知识库正则，出现由正则提取代理传过来的正则，则先进行二次验证：
若传过来的正则未在知识库类别里，则生成新的组件，并验证合理性。
若存在，则计算新旧组件对于当前明文的的匹配率，选最高匹配率的一个保留。

## 实验对比
官方标准：
  - 字段抽取正确: 解析结果中字段的 key 和 value 与人工打标的对应字段相等, 则认为字段抽取正确。
   - 匹配日志: 对于每条日志, 人工打标的结果中至少有一个字段抽取正确, 认为该条日志能被规则匹配。
   - 完全匹配日志: 对于每条日志,人工打标的结果中所有字段均抽取正确, 认为该条日志能被规则完全匹配。

基于字段抽取和日志匹配情况, 可以计算匹配率与完全正确率进行最终打分:
   - 匹配率 = (匹配日志数 / 总日志数) * 100%
   - 完全正确率 = (完全匹配日志数 / 总日志数) * 100%

`metric = 匹配率 * 0.4 + 完全正确率 * 0.6`

按照道理来说完全匹配率越高越好，但实际上的情况是不可能完全匹配，则是尽可能输出多的key-value对用于计算覆盖率，就是尽量覆盖参考值的内容，尽管有些不属于参考值。就是Soundness的概念，尽可能输出多的解决方案，尽管有错，但是包含Truth的值。
### 人工生成正则筛选器
通过人工分类得到默认的正则表达式列表，用于几种不同类型的日志进行提取分析。这里我分别选取几种不同范围的日志来检测我人工手动建立的知识库的覆盖率：
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


# 2025.2.22-2.24
这里修改了相关逻辑，把原来很复杂的代理优化成三个，并且要求知识库合并这个难题去掉。

原因见如下：

目前存在的瓶颈是如何把多个日志所应对的py规则程序整合在一起，但是如果针对开发集的每一条日志，都有对应的验证集的一条类似结构的同源数据（只是内容不同，结构极其类似）

比如 时间-主机名-信息 这种结构！

它只是内容不同 那么使用的pattern正则程序应该是可以通用的！那么并不需要对所有对应的程序整合，因为这样会增加运算量（两两融合就要N方复杂度），根据理想状态他们是一一对应的顺序分布，每一个生成的py程序都用于同源结构的日志验证那么是直接可以允许运行该程序验证的！所以这里就不用再考虑多个py程序整合的难题了。（考虑了也没法完美解决）

所以就只到生成程序并运行的这一步了，之后规则存储的就是每个生成的代码的相对地址，对应每一个验证集的数据。

# LogParserX框架
```mermaid
graph LR
    A[Keyword Detection] --> B[Knowledge Query]
    B -->|existing_rules| F[Knowledge Maintainer]
    B -->|missing_types| C[Regex Generation]
    C -->|optimized regex| D[Code Generation]
    D -->|codes with optimized regex| E[Codes Optimizer]
    E -->|analysis report| F
    F -->|update rules| G[Knowledge Base]
```
提取report里面的代码并验证它的提取率。
输入输出IO文件流：
```mermaid
graph LR
   A[Start Point]
   B[Regex Pattern Checker]
   C[Code Generation]
   D[Code Validation]
   E[Code Extrator]
   F[Testing Unit]
   A --> |manual patterns| B
   A --> |logText, logField| B
   B --> |optimized regex patterns| C
   B --> |logText, logField| C
   B --> |py codes template| C
   C --> |output py codes| D
   D --> |optimized report| E
   E --> |new codes| F
   E --> |logText, logField| F
   F --> G[testing info]
```
其中B-D是agents交互llm生成, E-F用于验证。
生成中间量是trace：大模型交互日志，py codes：优化后的规则代码，report：提取结果。
## Agents & Tasks 
agents 均两两之间上下文开启，并允许代码编译。
输入的logText, logField为训练集的日志。
### Pattern Checker & pattern check task
输入manual_patterns, logText, logField, 用于验证pattern的正确性并优化输出patterns.md
### Code Generation & code generation task
输入patterns.md(默认)，py codes template, logText, logField, 输出优化后的output.py.
### Code Validation & code validation task
输入output.py, logText, logField, 输出优化后的报告report.md，包含codes, 覆盖率分析等。
## Testing Part
输入的logText, logField为测试集的日志。
这里主要是验证优化后的opt.py是否能正确提取测试集的logText, logField。
### Code Extrator & code extrator task
输入report.md , 输出提取结果opt.py。
### Testing Unit & testing unit task
输入opt.py, 测试集的logText, logField, 输出测试结果result.txt。

# 2025.2.25-2.26
## 测试结果
### 0-9:10条AI生成代码 1->1日志 能力评估  `TestUnit`
```txt
My Scores (1 for full): [0.75, 0.8, 0.8, 0.67, 1.0, 0.6, 0.67, 0.67, 0.67, 0.67]
My Average Score: 0.73
Match Rate:  1.0
Perfect Match Rate: 0.1
Official Score (1 for full): 0.46
```
### 0-9:10条AI生成代码 1->10日志 能力评估  `MultiTestUnit`
```txt
Index: 0 ======================================================================
My Scores (1 for full): [0.75, 0.4, 0.8, 0.33, 0.5, 0.6, 0.33, 0.33, 0.33, 0.33]
My Average Score: 0.47
Match Rate:  1.0
Perfect Match Rate: 0.0
Official Score (1 for full): 0.4
Index: 1 ======================================================================
My Scores (1 for full): [0.5, 0.8, 0.8, 0.44, 1.0, 0.4, 0.44, 0.44, 0.44, 0.44]
My Average Score: 0.57
Match Rate:  1.0
Perfect Match Rate: 0.1
Official Score (1 for full): 0.46
Index: 2 ======================================================================
My Scores (1 for full): [0.5, 0.4, 0.8, 0.22, 0.5, 0.4, 0.22, 0.22, 0.22, 0.22]
My Average Score: 0.37
Match Rate:  1.0
Perfect Match Rate: 0.0
Official Score (1 for full): 0.4
Index: 3 ======================================================================
My Scores (1 for full): [0.5, 0.8, 0.8, 0.67, 1.0, 0.4, 0.67, 0.67, 0.67, 0.67]
My Average Score: 0.69
Match Rate:  1.0
Perfect Match Rate: 0.1
Official Score (1 for full): 0.46
Index: 4 ======================================================================
My Scores (1 for full): [0.5, 0.8, 0.4, 0.44, 1.0, 0.4, 0.44, 0.44, 0.44, 0.44]
My Average Score: 0.53
Match Rate:  1.0
Perfect Match Rate: 0.1
Official Score (1 for full): 0.46
Index: 5 ======================================================================
My Scores (1 for full): [1.0, 0.4, 0.4, 0.22, 0.5, 0.6, 0.22, 0.22, 0.22, 0.22]
My Average Score: 0.4
Match Rate:  1.0
Perfect Match Rate: 0.1
Official Score (1 for full): 0.46
Index: 6 ======================================================================
My Scores (1 for full): [0.5, 0.8, 0.8, 0.67, 1.0, 0.4, 0.67, 0.67, 0.67, 0.67]
My Average Score: 0.69
Match Rate:  1.0
Perfect Match Rate: 0.1
Official Score (1 for full): 0.46
Index: 7 ======================================================================
My Scores (1 for full): [0.5, 0.8, 0.8, 0.67, 1.0, 0.4, 0.67, 0.67, 0.67, 0.67]
My Average Score: 0.69
Match Rate:  1.0
Perfect Match Rate: 0.1
Official Score (1 for full): 0.46
Index: 8 ======================================================================
My Scores (1 for full): [0.5, 0.8, 0.8, 0.67, 1.0, 0.4, 0.67, 0.67, 0.67, 0.67]
My Average Score: 0.69
Match Rate:  1.0
Perfect Match Rate: 0.0
Official Score (1 for full): 0.4
Index: 9 ======================================================================
My Scores (1 for full): [0.5, 0.8, 0.8, 0.67, 1.0, 0.4, 0.67, 0.67, 0.67, 0.67]
My Average Score: 0.69
Match Rate:  1.0
Perfect Match Rate: 0.1
Official Score (1 for full): 0.46
```