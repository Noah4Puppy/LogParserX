# my demo scripts
import openai
# Qwen-2.5-72b-instruct
def get_chat_completions(messages, api_key, base_url, use_llm_model):
    """
    使用 openai 接口调用大模型。
    """
    client = openai.OpenAI(api_key=api_key, base_url=base_url)

    response = client.chat.completions.create(model=use_llm_model, messages=messages)

    return response

def check_money():
  import requests
  url = "https://wcode.net/api/account/billing/grants"
  payload = {}
  headers = {
    'Authorization': 'Bearer sk-63.h3A5gkOyaHkT8W9wPKtu28gqEzhkpR5X53NKFyzX9eq5dIEH'  # <-------- TODO: 替换这里的 API_KEY
  }
  response = requests.request("GET", url, headers=headers, data=payload)
  print(response.text)
  return response.text

# print(openai.proxy)
# usage example
messages = [
    {
      "role": "system",
      "content": "You are a helpful assistant."
    },
    {
      "role": "user",
      "content": "你好"
    }
  ]

api_key = "sk-63.h3A5gkOyaHkT8W9wPKtu28gqEzhkpR5X53NKFyzX9eq5dIEH"
base_url = "https://wcode.net/api/gpt/v1"
use_llm_model = "qwen2.5-72b-instruct"

# run something
# import os
# os.environ['HTTP_PROXY'] = 'http://127.0.0.1:8800'
# os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:8800'

# response = get_chat_completions(messages, api_key, base_url, use_llm_model)
# reply_content = response.choices[0].message.content
# print(reply_content)
# check_money()

# response = ChatCompletion(id='chatcmpl-e3086a05-a198-96d3-9dab-8543c566134e', 
#                choices=[Choice(finish_reason='stop', index=0, logprobs=None, 
#             message=ChatCompletionMessage(content='你好！有什么可以帮助你的吗？', role='assistant', function_call=None, tool_calls=None))], created=1737474028, model='qwen2.5-72b-instruct', object='chat.completion', 
#             system_fingerprint=None, 
#                usage=CompletionUsage(completion_tokens=7, prompt_tokens=20, total_tokens=27))

