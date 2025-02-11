# Survey

前言: 这部分任务主要聚焦于调研和技术讨论, 主要来源于GPT建议和个人观点总结, 并不具有最合理的参考价值

## 主要任务

给出一个生成阶段的智能体模型(LLM交互部分作为你的一个功能产出) + 提取解析阶段的代码  ->结果评测

1.给定一些少量的带标签的数据集，输入你的**生成模型**里进行提取规则生成

2.把提取出来的规则和大量的无标签的数据集输入到**提取解析模型**

规则是一段可执行代码: (我们需要从模型里产生的字段)

```bash
Sep 9 16:15:01: Started Session 1001 of user root
```

有意义的字段是: `timestamp (Sep 9 16:15:01)`, `id (1001)`, `username (root)`

即你所需要的大模型的主要任务是从有标签的数据里提取得到上面格式的规则代码部分,然后下游的工作负责使用它产生的规则对无标签的数据进行字段解析

即给定 有标签数据->模型->输出规则代码+无标签数据->解析字段

## LLM 智能体
### 参考
- AI智能体框架
https://github.com/BinNong/meet-libai

https://github.com/fufankeji/BiliAgent

https://github.com/cjyyx/AI_Gen_Novel

https://github.com/business24ai/crewai-obsidian

- 正则表达式生成：
https://github.com/ua-parser/uap-core

https://github.com/sagar-arora/LogAgent

https://github.com/sercanarga/fuckregex

https://github.com/lucasrpatten/RegexGenerator

https://github.com/riteshtambe/RegexAI

智能体框架CrewAI: https://crewai.theforage.cn/core-concepts/Crews/#crew_3