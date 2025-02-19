import datetime
import json
import os
from langchain_openai import ChatOpenAI  
from dotenv import load_dotenv
from crewai import Agent, Task, Process, Crew
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
    
    role="Regex Pattern Checker",
    
    goal="Check if the regular expression pattern is correct and precise for given logText and logField data",

    backstory="""You are a regular expression pattern checker with experience in regular expressions.
    You can check if the regular expression pattern is correct and precise for given logText and logField data.
    Correct and precise regular expression patterns should be applied to logText and get the same results as logField.""",
    allow_code_execution=False,
    llm=qwen,
    memory=True,
)

pattern_check_task = Task(
    description= """Check if the regular expression pattern is correct and precise for given logText and logField data.
    Your logText: {logText}, Your logField: {logField}, Your pattern: {pattern}, your pattern should be correct and precise to match to the logText and get results as logField.
    Here is an example of a regular expression pattern.
    You can reason step by step instead of completing only one regular expression for all conditions.
    Your logText: "<164>Nov  5 2021 11:34:18+08:00 ME60-1 %%01BRASAM/4/hwAllocUserIPFailAlarm (t):VS=Admin-VS-CID=0x81d80420-OID=1.3.6.1.4.1.2011.6.8.2.2.0.3;Fail to alloc IP address from domain. (DomainNo.=72,DomainName=vlan3260)"
    Your logField: 
    [
        {{
            "key": "",
            "value": "Nov  5 2021 11:34:18+08:00"
        }},
        {{
            "key": "",
            "value": "ME60-1"
        }},
        {{
            "key": "VS",
            "value": "Admin"
        }},
        {{
            "key": "VS-CID",
            "value": "0x81d80420"
        }},
        {{
            "key": "OID",
            "value": "1.3.6.1.4.1.2011.6.8.2.2.0.3"
        }},
        {{
            "key": "DomainNo.",
            "value": "72"
        }},
        {{
            "key": "DomainName",
            "value": "vlan3260"
        }}
    ]
    """,
    agent=pattern_checker,
    expected_output=
    """
    {
        "valid_patterns": [
            {"name": "date_p_2", "pattern": "..."},
            {"name": "hostname_p", "pattern": "..."}
        ],
        "improved_patterns": [
            {
                "original": "function_p", 
                "optimized": "r'(?!%%.*)([a-zA-Z0-9_-]+)$$(.*?)$$'"
            }
        ]
    }
    """, 
    output_file="{output_file_p}",
    output_key="pattern_report"
)

code_generator = Agent(
    role="Regex Python Code Generator",
    
    goal="Generate precise regular expressions codes with Python",

    backstory="""You are a Python code generator with experience in regular expressions.
    You can generate corresponding python codes for regular expressions from labeled data.
    With given labeled data and standard answers, your generated codes can be semantical and precise.
    You are allowed to use any Python libraries and modules and check the correctness of your generated codes through execution them.""",
    allow_code_execution=False,
    llm=qwen,
)

code_generation_task = Task(
    description="""Generate code based on verification results:
    Verified pattern: {pattern_report}
    Original pattern library: {pattern}
    Log sample: {logText}
    Target field: {logField}""", # Explicitly reference upstream output
    agent=code_generator,
    context=[pattern_check_task], # Establish dependency chain
    expected_output=""" Python function containing the following elements:
    - Use the verified pattern_report pattern
    - Compatible with the original pattern library
    - Complete exception handling""",
    output_file="{output_file}",
)


def get_str(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        res = f.read()
    return res


def record_log(file_path, st):
    with open(file_path, "a", encoding="utf-8") as f:
        for i in st:
            f.write(str(i))
            f.write("\n")
    print(f"{file_path} recorded!")


def add_log(step, id, inputs, outputs):
    item = {
        "step": step,
        "logId": id,
        "inputs": inputs,
        "outputs": outputs
    }
    return item

def run(test_data, pattern, python_code, output_file, output_file_p):
    record_list = []
    step = 0
    for item in test_data:
        single_crew = Crew(
            agents=[pattern_checker, code_generator],
            tasks=[pattern_check_task, code_generation_task],
            process=Process.sequential,
            verbose=True
        )
        log_id = item["logId"]
        log_text = item["logText"]
        log_field = item["logField"]
        inputs = {
            "logText": f"{log_text}",
            "logField": f"{log_field}",
            "pattern": f"{pattern}",
            "python_code": f"{python_code}",
            "output_file": output_file.format(log_id),
            "output_file_p": output_file_p.format(log_id)
        }
        result = single_crew.kickoff(inputs=inputs)
        print("####################")
        print(result)
        pattern_report = pattern_check_task.output.export() 
        generated_code = code_generation_task.output.export()
        
        with open(inputs["output_file_p"], 'w') as f:
            json.dump(pattern_report, f, indent=2)
        with open(inputs["output_file"], 'w') as f:
            f.write(generated_code)

    # record_log(r"D:\Competition_Xihu\Resources\LogParserX\src\LogParserX\trace\trace_{}.txt".
    #            format(datetime.datetime.now().strftime("%Y%m%d%H%M%S")), record_list)
    # print(record_list)

def launcher(S,E):
    python_tool = r"D:/Competition_Xihu/Resources/LogParserX/src/LogParserX/knowledge/faster_tool.py"
    python_pattern = r"D:/Competition_Xihu/Resources/LogParserX/src/LogParserX/knowledge/pattern.py"
    output_file = r"D:/Competition_Xihu/Resources/LogParserX/src/LogParserX/output/gen/output_{}.py"
    output_file_p = r"D:/Competition_Xihu/Resources/LogParserX/src/LogParserX/output/gen/pattern_{}.py"
    json_path = r"D:/Competition_Xihu/Resources/LogParserX/data/dataset.json"
    with open(python_tool, "r", encoding="utf-8")as f:
        python_code = f.read()
    with open(python_pattern, "r", encoding="utf-8")as f:
        pattern = f.read()
    data = json.load(open(json_path, "r", encoding="utf-8"))
    test_data= data[S:E]
    run(test_data, pattern, python_code, output_file, output_file_p)
    print("Done!")

if __name__ == '__main__':
    launcher(S=1,E=2)
