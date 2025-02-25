# 产生我需要的数据集
# 测试集划分 0-100 100-200 200-300 300-400

import json

def get_classified_data(json_file_path):
    # 读取 JSON 文件
    with open(json_file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
    
    # 检查数据长度是否为 400
    if len(data) != 400:
        raise ValueError("JSON 文件中数据项数目不是 400 项。")
    
    # 划分数据集
    dataset_1 = data[0:100]  # 索引 0 到 99
    dataset_2 = data[100:200]  # 索引 100 到 199
    dataset_3 = data[200:300]  # 索引 200 到 299
    dataset_4 = data[300:400]  # 索引 300 到 399
    
    # 返回划分后的数据集
    return {
        "dataset_1": dataset_1,
        "dataset_2": dataset_2,
        "dataset_3": dataset_3,
        "dataset_4": dataset_4
    }

# 示例使用
json_file_path = "data/dataset.json"  # 这里替换为实际的文件路径
classified_data = get_classified_data(json_file_path)

json_class_path = "data/classified_data/class_{}.json" 

for i in range(1, 5):
    with open(json_class_path.format(i), 'w', encoding='utf-8') as file:
        json.dump(classified_data["dataset_{}".format(i)], file, indent=4)
        print("数据集划分完成。")

