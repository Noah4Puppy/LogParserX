from crewai import Agent, Task, Crew, Process
import json
import os
pattern_checker = Agent(
    role="正则模式审核专家",
    goal="验证正则模式准确性",
    backstory="""我是拥有十年日志分析经验的正则表达式专家，擅长从复杂日志中提取结构化数据，
    曾为多家网络安全公司设计日志解析方案。""",  # 必须添加的字段
    allow_code_execution=False,
    verbose=True,
    memory=True
)

code_generator = Agent(
    role="Python代码工程师",
    goal="生成高可靠性的解析代码",
    backstory="""我是专注于日志处理系统的全栈开发工程师，精通Python正则表达式优化，
    开发过多个高性能日志解析框架。""",  # 必须添加的字段
    verbose=True,
    allow_code_execution=True
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
    output_key="validation_report"  # 关键输出标识
)

code_gen_task = Task(
    description="""生成解析代码：
    验证结果：{validation_report}  # 使用前置任务的output_key
    原始模式：{existing_patterns}
    日志样本：{log_text}""",
    agent=code_generator,
    context=[pattern_check_task],  # 声明依赖关系
    output_file="output/code_{log_id}.py"
)

# 执行引擎
class LogProcessor:
    def __init__(self):
        self.crew = Crew(
            agents=[pattern_checker, code_generator],
            tasks=[pattern_check_task, code_gen_task],
            process=Process.sequential,
            verbose=2
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
    with open(r"src\LogParserX\knowledge\pattern.py") as f:
        patterns = f.read()
    
    # 测试数据
    test_log = {
        "logId": "20240520_001",
        "logText": "<12>May 20 10:15:32 router1 system: Interface eth0 down",
        "logField": [
            {"key": "timestamp", "value": "May 20 10:15:32"},
            {"key": "device", "value": "router1"},
            {"key": "event", "value": "Interface down"}
        ]
    }
    
    processor = LogProcessor()
    success = processor.process(test_log, patterns)
    print(f"处理结果：{'成功' if success else '失败'}")