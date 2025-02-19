#!/usr/bin/env python
import sys
import os

import litellm
# 动态获取项目根目录（关键修正）
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)  # 确保优先加载项目路径

import warnings
from datetime import datetime
from mytest.crew import MyTest

warnings.filterwarnings("ignore", category=SyntaxWarning, module="pysbd")
# litellm._turn_on_debug()

def run():
    """
    Run the crew.
    """
    inputs = {
        'topic': 'AI LLMs',
        'current_year': str(datetime.now().year)
    }
    
    try:
        MyTest().crew().kickoff(inputs=inputs)
    except Exception as e:
        raise Exception(f"An error occurred while running the crew: {e}")
    
run()