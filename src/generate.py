import json
import os
import openai

from LogParserX.learn.MergeRegexController import launcher


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
    with open(labeled_data_file_path, "r", encoding="utf-8") as f:
        labeled_data = json.load(f)
    S = 0
    E = 400
    launcher(S,E, labeled_data)
