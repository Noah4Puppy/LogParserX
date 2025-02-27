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
    Correct and precise regular expression patterns should be applied to logText and get the same results as logField. 
    Try to make your regular expression pattern as precise as possible to cover all possible conditions as enough as possible.
    You can use any Python libraries and modules and check the correctness of your regular expression patterns through execution them.""",
    allow_code_execution=True,
    llm=qwen,
    memory=True,
)

pattern_check_task = Task(
    description= """Check if the regular expression pattern is correct and precise for given logText and logField data.
    Your logText: {logText}, Your logField: {logField}, Your pattern: {pattern}, your pattern should be correct and precise to match to the logText and get results as logField.
    Pay attention to the key-value pairs, the key and value should all come from the logText, allow key to be empty, but value should not be empty.
    Your pattern should be correct and precise to match to the logText and get results as logField (cover more items as possible).
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
    Optimized Pattern:
    date_p = r"\b[A-Za-z]{{3}}\s{1,2}\d{1,2}\s\d{4}\s\d{2}:\d{2}:\d{2}\b"
    date_p_ = r"\b([A-Za-z]+ \d{1,2} \d{4} \d{2}:\d{2}:\d{2})\b"
    date_p_2 = r"([A-Za-z]{3})\s+ (\d{1,2})\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})([+-]\d{2}):(\d{2})"
    date_p_3 = r"(\d{4}-\d{1,2}-\d{1,2} \d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2})?)"
    Optimized Reasons:
    - This regex can face some false positives, such as "Nov 5 2021 11:34:18+08:00"
    - Fix some unmatched conditions, such as "Nov  5 2021 11:34:18+08:00", and why use optimized pattern can solve this problem.
    - This regex can face some false positives, such as "Nov 5 2021 11:34:18+08:00", ...
    ...
    Optimized Rate:
    Compared to the original pattern, the optimized pattern can cover X%, except for some conditions: XXX.
    """, 
    output_file="{output_file_p}",
)

code_generator = Agent(
    role="Regex Python Code Generator",
    
    goal="Generate precise regular expressions codes with Python",

    backstory="""You are a Python code generator with experience in regular expressions.
    You can generate corresponding python codes for regular expressions from labeled data.
    With given labeled data and standard answers, your generated codes can be semantical and precise.
    You are allowed to use any Python libraries and modules and check the correctness of your generated codes through execution them.""",
    llm=qwen,
    allow_code_execution=True,
    memory = True,
)

code_generation_task = Task(
    description="""Generate code based on verification results:
    Log sample: {logText}
    Target field: {logField},
    Python Code Template: {python_code},
    Read Report from Pattern Checker, and use the optimized pattern to generate Python codes.
    If the optimized pattern is not correct, you can modify it and re-run the code generation task.
    Execute the generated codes and check if the results match the logField.
    You should generate codes in Python that can match the logText to the logField with the verified pattern.
    You had better return clear codes instead of markdown format with starting and ending quotes.
    For example: ```python```""", # Explicitly reference upstream output
    agent=code_generator,
    context=[pattern_check_task], # Establish dependency chain
    expected_output =
    """Python function containing the following elements:
    - Use the optimized patterns
    - Complete all functions and variables with proper values
    - The codes can be executed and return the expected results
    - Use python format instead of markdown format for better readability
    - Only python codes are allowed, no markdown format is allowed

    For example(clean codes), your codes should be **strict** like this, main function only change log_text contents:
    import re
    import json
    from functools import lru_cache
    @lru_cache(maxsize=100)
    def _compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
        return re.compile(pattern, flags)
    # use optimized pattern
    patterns = {
        "pattern_name": "",
        "date": r"\b[A-Za-z]{{3}}\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2}\b",
        "hostname": r"(?<=:\d{2}) ([a-zA-Z0-9._-]+)",
        "pid": r"([a-zA-Z0-9_-]+)\[(\d+)\]",
        ...
    }
    # define functions like match_{pattern_name}
    def match_date(text):
        compiled_re = _compile_regex(patterns['date'])
        match = compiled_re.search(text)
        results = []
        if match:
            date = match.group(0)
            results.append({"key": "", "value": date})
            print("ISO Date Results:", results)
            return results
        return [] 
    # other functions
    ...
    def get_components(log_text):
        res = match_date(log_text)
        ...
        return res

    if __name__ == '__main__':
        log_text = {{logText}}
        res = get_components(log_text)
        json_data = json.dumps(res, ensure_ascii=False)
        print(json_data)
    """,
    output_file="{output_file}",
)


code_validater = Agent(
    role="Regex Python Code Validator",
    goal="""Validate the generated Python codes by executing them and checking the results, try to find ismatched context and give analysis for codes.
    Try to increase the macth rate of original codes by modifying the codes and re-run the validation task.""",
    backstory="""You are a Python code validator with experience in regular expressions. 
    You can validate the generated Python codes by executing them and checking the results.
    You can find ismatched context and give analysis for codes.
    You can modify the codes and re-run the validation task to increase the macth rate of original codes.""",
    llm=qwen,
    allow_code_execution=True,
    memory = True,
)

code_validation_task = Task(
    description="""Validate the generated Python codes by executing them and checking the results.
    You should execute the generated codes and check if the results match the logField.
    Pay attention to the key-value pairs, the key and value should all come from the logText, allow key to be empty, but value should not be empty.
    Do not try to assign type for key when key does not occur in logText!
    For example:
    logText = "2023-10-10 10:10:10 ABC ERROR: This is an error message"
    logField = [{{"key": "", "value": "2023-10-10 10:10:10"}}, {{"key": "", "value": "ABC"}}, {{"key": "", "value": "ERROR"}}]
    In this logField, three key is empty because they are not in logText. Date, hostname and level these types are pattern types.
    Your pattern should be correct and precise to match to the logText and get results as logField (cover more items as possible). 
    If the results do not match, you should modify the codes and re-run the validation task.
    If the results match, you can submit the codes to the code review team for review.
    """,
    agent=code_validater,
    context=[code_generation_task],
    expected_output="""A markdown report containing the following elements:
    - The generated codes are executed and return the expected results
    - The results match the logField 
    - The matche rate and comparison with the original codes are provided (must completely match, include key and value)
    Like this format:
    # Optimized Codes Analysis
    ## Optimized Codes
    ```python
    ...
    ```
    ## Output
    ```txt
    {"key": "", "value": ""}
    ```
    ## Comparison
    Optimized codes Matched Rate: X%
    Original codes Matched Rate: Y%
    In Optimized codes, [{"key": "", "value": ""},...] are matched, while ... are unmatched.
    In Original codes, [{"key": "", "value": ""},...] are matched, while ... are unmatched.
    """,
    output_file="{output_file_md}",
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

def generate_log_fileName():
    """
    根据当前时间生成日志文件路径
    Returns:
        str: 完整的日志文件路径
    """
    # 日志目录，根据自己项目修改
    log_dir = "src/LogParserX/log"  
    os.makedirs(log_dir, exist_ok=True)
    # 生成精确到秒的时间戳
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    # 返回完整日志文件路径
    return os.path.join(log_dir, f'crewai_{timestamp}.log')

def run(test_data, pattern, python_code, output_file, output_file_p, output_file_md):
    record_list = []
    step = 0
    for item in test_data:
        single_crew = Crew(
            agents=[pattern_checker, code_generator, code_validater],
            tasks=[pattern_check_task, code_generation_task, code_validation_task],
            process=Process.sequential,
            verbose=True,
            output_log_file=generate_log_fileName()
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
            "output_file_p": output_file_p.format(log_id),
            "output_file_md": output_file_md.format(log_id),
        }
        result = single_crew.kickoff(inputs=inputs)

        print(40*"#")
        print(result)
        print(40*"#")
        
        item = add_log(step, log_id, inputs, str(result))
        step += 1
        record_list.append(item)

    record_log("src/LogParserX/trace/trace_{}.txt".
               format(datetime.datetime.now().strftime("%Y%m%d%H%M%S")), record_list)
    # print(record_list)




def launcher(S, E, class_path):
    python_tool = r"src/LogParserX/knowledge/faster_tool.py"
    python_pattern = r"src/LogParserX/knowledge/pattern.py"
    output_file = r"src/LogParserX/output/gen/codes/output_{}.py"
    output_file_p = r"src/LogParserX/output/gen/patterns/pattern_{}.md"
    output_file_md = r"src/LogParserX/output/gen/reports/report_{}.md"
    with open(python_tool, "r", encoding="utf-8")as f:
        python_code = f.read()
    with open(python_pattern, "r", encoding="utf-8")as f:
        pattern = f.read()
    data = json.load(open(class_path, "r", encoding="utf-8"))
    test_data= data[S:E]
    run(test_data, pattern, python_code, output_file, output_file_p, output_file_md)
    print("Done!")

if __name__ == '__main__':
    class_path = r"data/classified_data/class_2.json"
    launcher(S=0,E=3, class_path=class_path)
