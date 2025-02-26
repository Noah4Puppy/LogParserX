# src/latest_ai_development/crew.py
from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
# from crewai_tools import GithubSearchTool
from langchain_openai import ChatOpenAI  
from dotenv import load_dotenv
import os
load_dotenv(override=True)

# search_tool = GithubSearchTool(
#  config=dict(
#         llm=dict(
#             provider="openai",
#             config=dict(
#                 base_url=os.getenv("OPENAI_API_BASE"),  
#                 api_key=os.getenv("OPENAI_API_KEY"),
#                 model=os.getenv("MODEL_NAME"),  
#             ),
#         ),
#         embedder=dict(
#             provider="openai",
#             config=dict(
#                 api_base=os.getenv("OPENAI_API_BASE"),  
#                 api_key=os.getenv("OPENAI_API_KEY"),
#                 model=os.getenv("EMBED_MODEL_NAME"), 
#             ),
#         ),
#     ),
# 	gh_token=os.getenv("GITHUB_TOKEN"),
# 	# github_repo="",
# 	content_types=['code', 'issue']
# )

@CrewBase
class MyTest():
	def __init__(self):
        # 配置模型参数
		self.llm_config = {
			"model_name": os.getenv("MODEL_NAME"),
			"api_base": os.getenv("OPENAI_API_BASE"),  # 实际API端点
			"api_key": os.getenv("OPENAI_API_KEY"),        # 平台提供的密钥
			"temperature": 0.3,
			"max_tokens": 4096
		}
	def _init_llm(self):
		"""初始化大模型实例"""
		return ChatOpenAI(
			model=self.llm_config["model_name"],
			openai_api_base=self.llm_config["api_base"],
			openai_api_key=self.llm_config["api_key"],
			temperature=self.llm_config["temperature"],
			max_tokens=self.llm_config["max_tokens"],
			streaming=False  # 关闭流式避免中断
		)

	@agent
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
			output_file='D:/Competition_Xihu/Resources/LogParserX/refs/mytest/output/report.md' # This is the file that will be contain the final report.
		)

	@crew
	def crew(self) -> Crew:
		"""Creates the LatestAiDevelopment crew"""
		return Crew(
			agents=self.agents, # Automatically created by the @agent decorator
			tasks=self.tasks, # Automatically created by the @task decorator
			process=Process.sequential,
			verbose=True,
		)