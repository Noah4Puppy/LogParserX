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

## Usage
这是官方使用配置文件的用法：
### agents.yaml 配置
这里设定所有你要使用的agents, 如果你不想通过这个使用就直接把agents.yaml文件删除。
例如：
```yaml
researcher:
  role: >
    {topic} Senior Data Researcher
  goal: >
    Uncover cutting-edge developments in {topic}
  backstory: >
    You're a seasoned researcher with a knack for uncovering the latest
    developments in {topic}. Known for your ability to find the most relevant
    information and present it in a clear and concise manner.

reporting_analyst:
  role: >
    {topic} Reporting Analyst
  goal: >
    Create detailed reports based on {topic} data analysis and research findings
  backstory: >
    You're a meticulous analyst with a keen eye for detail. You're known for
    your ability to turn complex data into clear and concise reports, making
    it easy for others to understand and act on the information you provide.
```
### tasks.yaml 配置
```yaml
# src/latest_ai_development/config/tasks.yaml
research_task:
  description: >
    Conduct a thorough research about {topic}
    Make sure you find any interesting and relevant information given
    the current year is 2025.
  expected_output: >
    A list with 10 bullet points of the most relevant information about {topic}
  agent: researcher

reporting_task:
  description: >
    Review the context you got and expand each topic into a full section for a report.
    Make sure the report is detailed and contains any and all relevant information.
  expected_output: >
    A fully fledge reports with the mains topics, each with a full section of information.
    Formatted as markdown without '```'
  agent: reporting_analyst
```

### crew.py 使用
注意这里的命名之后调用的时候名字要保持一致：
```python
	def researcher(self) -> Agent:
		return Agent(
			config=self.agents_config['researcher'],
			llm=self._init_llm(),
			verbose=True,
		)
	
	@task
	def research_task(self) -> Task:
		return Task(
		config=self.tasks_config['research_task'],
		)
	
	@agent
	def reporting_analyst(self) -> Agent:
		return Agent(
		config=self.agents_config['reporting_analyst'],
		llm=self._init_llm(),
		verbose=True,
		)
	
	@task
	def reporting_task(self) -> Task:
		return Task(
			config=self.tasks_config['reporting_task'],
			output_file='refs/mytest/output/report.md' # This is the file that will be contain the final report.
		)
```

直接使用代码硬写：

我更喜欢这个，定制自由，不过管理项目或者迁移的时候建议用前一个配置
```python
your_agent = Agent(
    role="your role",
    
    goal="Final target",

    backstory="""your role background""",

    llm=your_model,
)

your_task = Task(
    description= """your task
    """,
    agent=your_agent,
    expected_output=
    """
    ???
    """
)
single_crew = Crew(
            agents=[your_agent],
            tasks=[your_task],
            process=Process.sequential,
            verbose=True,
        )
# log 要在task.description中定义{log}使用
inputs = {
    "log": f"{item}",
}
# result 是 CrewOutput对象 写入文件要转str(result)
result = single_crew.kickoff(inputs=inputs)
```
注意在Windows里的路径要加r"",Ubuntu里面就是/.