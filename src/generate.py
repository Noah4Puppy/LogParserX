import os
import openai


def generate(labeled_data_file_path: str, rules_save_file_path: str) -> None:
    """
    使用有标签日志数据生成解析规则。

    这个函数从文件中读入有标签数据, 生成一系列规则, 并以任意形式将规则保存到一个文件中。
    可以无限次数的使用大语言模型, 充分利用有标签数据实现智能体的自我优化。

    参数:
        labeled_data_file_path (str): 有标签数据集的文件路径, 格式如[数据集介绍]中所述。
        rules_save_file_path (str): 保存规则的文件路径。
    
    返回:
        None, 这个函数不需要有返回值
    """
    pass


api_key = os.getenv('QWEN_API_KEY')
base_url = os.getenv('QWEN_API_URL')
use_llm_model = os.getenv('QWEN_USE_LLM_MODEL')

def get_chat_completions(messages, api_key, base_url, use_llm_model):
    client = openai.OpenAI(api_key=api_key, base_url=base_url)
    response = client.chat.completions.create(model=use_llm_model, temperature=0.3,
                                              messages=messages)   # 限制响应长度messages=messages)
    return response.choices[0].message.content

def get_python_codes(python_path):
    with open(python_path, 'r', encoding='utf-8') as f:
        code = f.read()
    return code

def prompt(python_code, role, context):
    messages = {
        "role": role,
        "context": context,
        "code": python_code
    }