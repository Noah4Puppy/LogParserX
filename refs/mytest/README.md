# MY NOTES
请注意，使用转发链接的看这里: 针对不是官方API的接口，黄牛/中转接口!

官方文档（最好全部看英文）：https://docs.crewai.com

# 环境设置 env
注意如果兼容openai接口就默认这样：在`.env`里设置：
```# your env
OPENAI_API_BASE="https://XXXX/api/gpt/v1"
OPENAI_API_KEY="sk-XXXXXX"
MODEL_NAME="openai/XXXXXX"
```
# 使用工具 tools
需要安装工具才能使用，在虚拟环境里安装：
```shell
pip install crewai[tools]
```
注意官方教程使用的`SerperDevTool`需要注册和购买api，所以弃用，改成可以自定义`llm`的工具接口
比如：https://docs.crewai.com/tools/githubsearchtool
```python
tool = GithubSearchTool(
config=dict(
        llm=dict(
            provider="openai",
            config=dict(
                base_url="https://xxxxxxx/v1",
                api_key="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                model="openai/gpt-4o"
            ),
        ),
        embedder=dict(
            provider="openai",
            config=dict(
                api_base="https://xxxxxxx/v1",
                api_key="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                model="openai/text-embedding-3-small"
            ),
        ),
    )
)
```
自定义版本PDF_SearchTool示例：
```python
pdf_tool = PDFSearchTool(
    config=dict(
        llm=dict(
            provider="openai",
            config=dict(
                base_url="https://xxxxxxx/v1",
                api_key="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                model="gpt-4o"
            ),
        ),
        embedder=dict(
            provider="openai",
            config=dict(
                api_base="https://xxxxxxx/v1",
                api_key="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                model="text-embedding-3-small"
            ),
        ),
    )
)
```