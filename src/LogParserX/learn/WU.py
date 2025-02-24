from crewai import Agent, Task, Crew, Process
import json
import os

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
load_dotenv(override=True)

call_logs = []
log_id_counter = 0

QWEN_MODEL_NAME = os.getenv("MODEL_NAME")
QWEN_API_BASE = os.getenv("OPENAI_API_BASE")
QWEN_API_KEY = os.getenv("OPENAI_API_KEY")
# EMBED_MODEL_NAME = os.getenv("EMBED_MODEL_NAME")
Temperature = os.getenv("Temperature")
max_tokens = os.getenv("max_tokens")
# print(f"QWEN_MODEL_NAME: {QWEN_MODEL_NAME}, QWEN_API_BASE: {QWEN_API_BASE}, QWEN_API_KEY: {QWEN_API_KEY}, Temperature: {Temperature}, max_tokens: {max_tokens}")
qwen = ChatOpenAI(
			model=QWEN_MODEL_NAME,
			openai_api_base=QWEN_API_BASE,
			openai_api_key=QWEN_API_KEY,
			temperature=Temperature,
			max_tokens=max_tokens,
			streaming=False,
            timeout=60
		)
pattern_checker = Agent(
    role="正则模式审核专家",
    goal="验证正则模式准确性",
    backstory="""我是拥有十年日志分析经验的正则表达式专家，擅长从复杂日志中提取结构化数据，
    曾为多家网络安全公司设计日志解析方案。""",  # 必须添加的字段
    allow_code_execution=False,
    verbose=True,
    memory=True,
    llm=qwen
)

code_generator = Agent(
    role="Python代码工程师",
    goal="生成高可靠性的解析代码",
    backstory="""我是专注于日志处理系统的全栈开发工程师，精通Python正则表达式优化，
    开发过多个高性能日志解析框架。""",  # 必须添加的字段
    verbose=True,
    allow_code_execution=True,
    llm=qwen
)
# 旧版本任务定义
pattern_check_task = Task(
    description="""验证正则模式：
    日志：{log_text}
    目标字段：{fields}
    现有模式：{existing_patterns}""",
    agent=pattern_checker,
    expected_output="""JSON格式验证报告：
    {{
        "valid_patterns": ["date_p"],
        "improved": {{"host_p": "新正则"}}
    }}""",
    output_file="reports/pattern_{log_id}.json",
)

code_gen_task = Task(
    description="""生成解析代码：
    原始模式：{existing_patterns}
    现有模式：上一步的结果
    日志样本：{log_text}""",
    agent=code_generator,
    context=[pattern_check_task],  # 上一步输出将会作为输入
    output_file="output/code_{log_id}.py",
    expected_output="格式规范的Python脚本文件，包含日志解析逻辑和结构化输出功能"
)
# 执行引擎
class LogProcessor:
    def __init__(self):
        self.crew = Crew(
            agents=[pattern_checker, code_generator],
            tasks=[pattern_check_task, code_gen_task],
            process=Process.sequential,
            verbose=True
        )
    
    def process(self, log_data, pattern_lib):
        inputs = {
            "log_text": log_data["logText"],
            "fields": json.dumps(log_data["logField"]),
            "existing_patterns": pattern_lib,
            "log_id": log_data["logId"]
        }
        
        try:
            result = self.crew.kickoff(inputs=inputs)
            print(f"生成文件：{result['output_files']}")
            return True
        except Exception as e:
            print(f"失败原因：{str(e)}")
            return False

# 使用示例
if __name__ == "__main__":
    # 加载模式库
    with open(r"src\LogParserX\knowledge\pattern.py", "r", encoding="utf-8")  as f:
        patterns = f.read()
    
    # 测试数据
    test_log = {
        "logId": "20240520_001",
        "logText": "<12>May 20 10:15:32 router1 system: Interface eth0 down",
        "logField": [
            {"key": "", "value": "May 20 10:15:32"},
            {"key": "", "value": "router1"},
            {"key": "", "value": "Interface down"}
        ]
    }
    
    processor = LogProcessor()
    success = processor.process(test_log, patterns)
    print(f"处理结果：{'成功' if success else '失败'}")