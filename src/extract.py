def extract(unlabeled_data_file_path: str, rules_save_file_path: str, result_file_path: str) -> None:
    """
    使用解析规则对无标签数据进行解析。

    这个函数从文件中读入无标签数据和保存的规则, 使用规则解析无标签数据, 并将解析结果保存到结果文件中。
    读入的无标签数据的 logField 字段为空, 只需要将解析的结果放回 logField 字段再保存到结果文件中即可。

    参数:
        unlabeled_data_file_path (str): 无标签数据集的文件路径, 格式如[数据集介绍]中所述。
        rules_save_file_path (str): 保存规则的文件路径。
        result_file_path: 保存解析结果的文件路径。
    
    返回:
        None, 这个函数不需要有返回值
    """
    pass
# 保存结果
# with open(result_file_path, 'w', encoding='utf-8') as f:
#     json.dump(result_list, f, ensure_ascii=False, indent=4)

