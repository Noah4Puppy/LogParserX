import datetime
import json
import os
from langchain_openai import ChatOpenAI  
from dotenv import load_dotenv
from crewai import Agent, Task, Process, Crew
load_dotenv(override=True)

# model config  
QWEN_MODEL_NAME = os.getenv("MODEL_NAME")
QWEN_API_BASE = os.getenv("OPENAI_API_BASE")
QWEN_API_KEY = os.getenv("OPENAI_API_KEY")
# EMBED_MODEL_NAME = os.getenv("EMBED_MODEL_NAME")
Temperature = os.getenv("Temperature")
max_tokens = os.getenv("max_tokens")

qwen = ChatOpenAI(
			model=QWEN_MODEL_NAME,
			openai_api_base=QWEN_API_BASE,
			openai_api_key=QWEN_API_KEY,
			temperature=Temperature,
			max_tokens=max_tokens,
			streaming=False,
            timeout=60
		)

log_generator = Agent(
    role="Log Info Generator",
    
    goal="Generate the same format of given log, make them belong to the same source.",

    backstory="""You are an experienced expert for log extraction and log generation, through scan log and extract keywords from given records, 
    can get enough features of log and generate target log info. You can return clean log info with the same structure and different contexts 
    and make the given logs and generated log from the same source.""",
    llm=qwen,
)

data_generation_task = Task(
    description= """You are given a log: {log}, you should generate a log with the same format and different context and belong to the same source.
    For example, your given example is:
    {{
        "logId": 4,
        "logText": "<21>Aug 12 08:11:56 soc-32 sshd[33101]: pam_unix(sshd:session): session closed for user root",
        "logField": [
            {{
                "key": "",
                "value": "Aug 12 08:11:56"
            }},
            {{
                "key": "",
                "value": "soc-32"
            }},
            {{
                "key": "",
                "value": "sshd"
            }},
            {{
                "key": "",
                "value": "33101"
            }}
        ]
    }},
    Your generated example is as follows:
    {{
        "logId": 4,
        "logText": "<21>Feb 12 23:11:44 cxx-Legion sshd[123456]: pam_unix(sshd:session): session closed for user cxx",
        "logField": [
            {{
                "key": "",
                "value": "Feb 12 23:11:44"
            }},
            {{
                "key": "",
                "value": "cxx-Legion"
            }},
            {{
                "key": "",
                "value": "sshd"
            }},
            {{
                "key": "",
                "value": "123456"
            }}
        ]
    }},
    Your generated result should only include the whole log  without any explanation or other texts.
    """,
    agent=log_generator,
    expected_output=
    """
    {
        "logId": ??,
        "logText": "????",
        "logField": [
            {
                "key": "",
                "value": "???"
            },
            {
                "key": "",
                "value": "???"
            },
            {
                "key": "",
                "value": "???"
            },
            {
                "key": "",
                "value": "???"
            },
            {
                "key": "",
                "value": "???"
            },
        ]
    }
    """
)

def get_generated_log(text):
    # text = """{"name": "Kimi", "age": 3, "is_active": true, "last_seen": null}"""
    valid_json = text.replace("'", "\"")
    valid_json = text.replace("True", "true")
    data = json.loads(valid_json)
    return data

def generate_log_fileName():
    """
    根据当前时间生成日志文件路径
    Returns:
        str: 完整的日志文件路径
    """
    # 日志目录，根据自己项目修改
    log_dir = r"src\LogParserX\log"  
    os.makedirs(log_dir, exist_ok=True)
    # 生成精确到秒的时间戳
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    # 返回完整日志文件路径
    return os.path.join(log_dir, f'crewai_{timestamp}.log')

def run(test_data, output_file):
    generated_list = []
    for item in test_data:
        single_crew = Crew(
            agents=[log_generator],
            tasks=[data_generation_task],
            process=Process.sequential,
            verbose=True,
            output_log_file=generate_log_fileName()
        )
        inputs = {
            "log": f"{item}",
        }
        result = single_crew.kickoff(inputs=inputs)
        print("C")
        # print(40* "#")
        # print(result)
        # print(40* "#")
        res = get_generated_log(str(result))
        generated_list.append(res)
    print(generated_list)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(generated_list, f, indent=4, ensure_ascii=False) 
    print(f"Generated data saved to {output_file}!")
    # with open(output_file, 'w', encoding='utf-8') as f:
    #     f.write('\n'.join(generated_list))
    # print(f"Generated data saved to {output_file}!")

def launcher(s, e, log_path):
    json_data = json.load(open(log_path, "r", encoding="utf-8"))
    test_data = json_data[s: e]
    print(len(test_data))
    run(test_data=test_data, output_file="data/generated_data/class_1.json")

if __name__ == '__main__':
    launcher(0, 100, "data/classified_data/class_1.json")
