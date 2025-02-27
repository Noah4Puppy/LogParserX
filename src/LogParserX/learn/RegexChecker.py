import ast
import json
import os
import sys
from Executor import execute_python_code
import re
from pathlib import Path

def extract_python_code_from_md(md_content: str) -> list:
    """使用正则表达式提取所有Python代码块"""
    pattern = r'```python\n(.*?)```'
    matches = re.findall(pattern, md_content, re.DOTALL)
    return [match.strip() for match in matches]

def get_all_reports(dir_path: str) -> list:
    """获取指定目录下的所有报告
    按文件名中的数字序号排序（report_0.md, report_1.md...）
    Args:
        dir_path: 要扫描的目录路径

    Returns:
        list: 按数字排序的完整文件路径列表
        
    Example:
        >>> get_all_reports("./reports")
        [
            '/path/report_0.md',
            '/path/report_1.md',
            '/path/report_2.md'
        ]
    """
    file_list = []
    pattern = re.compile(r'^report_(\d+)\.md$')  # 精确匹配文件名格式
    try:
        for filename in os.listdir(dir_path):
            # 组合完整路径并验证文件类型
            full_path = os.path.join(dir_path, filename)
            if not os.path.isfile(full_path):
                continue
            
            # 匹配文件名格式
            match = pattern.match(filename)
            if match:
                # 提取数字并存储元组（数字转为int类型用于排序）
                file_list.append((
                    int(match.group(1)),  # 数字部分
                    full_path            # 完整路径
                ))
        file_list.sort(key=lambda x: x[0])
        rename_lst = [item[1].replace("report_", "opt_") for item in file_list]
        rename_lst = [item.replace(".md", ".py") for item in rename_lst]
        rename_lst = [item.replace("gen/reports", "opt") for item in rename_lst]

        return [item[1] for item in file_list], rename_lst
    
    except FileNotFoundError:
        print(f"错误：目录不存在 {dir_path}")
        return [], []
    except PermissionError:
        print(f"错误：无权限访问目录 {dir_path}")
        return [], []
    except Exception as e:
        print(f"未知错误：{str(e)}")
        return [], []

class ExtractedCodes:
    def __init__(self):
        self.main_function = []
        self.libs = []
        self.func_fields = []
        self.param_fields = []
        self.testing_main_function = []
    
    def get_libs(self, code: str) -> list:
        """提取所有库导入代码"""
        pattern = r"import\s+([\w\.]+)"
        matches = re.findall(pattern, code)
        return matches

    def get_main_function(self, code: str) -> str:
        """提取main函数代码"""
        pattern = r"if __name__\s*==\s*['\"]__main__['\"]\s*:\s*\n((?:^\s+.*\n?)*)"
        match = re.search(pattern, code, flags=re.MULTILINE | re.IGNORECASE)
        if match:
            main_block = match.group(0)
            return main_block.strip()
        else:
            return ""
            
    def get_param_field(self, code: str) -> dict:
        # 找到 patterns = { ... } 中的内容，处理嵌套情况
        # pattern = r"patterns\s*=\s*\{(.*?)\}"
        depth = 0
        start_index = code.find("{")
        end_index = start_index
        for i in range(start_index + 1, len(code)):
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                if depth == 0:
                    end_index = i
                    break
                depth -= 1

        patterns_str = code[start_index + 1:end_index]
        results = {}
        if patterns_str:
            key_value_pattern = r"'([^']+)'\s*:\s*r'([^']+)'"
            key_value_matches = re.findall(key_value_pattern, patterns_str)    
            for key, value in key_value_matches:
                results[key] = value
        return results

    def extract_functions(self, code_str: str) -> dict:
        """
        从Python代码字符串中提取特定格式函数，返回字典结构
        参数：
        code_str : 需要解析的Python代码字符串
        返回：
        {
            "_compile_regex": "@lru_cache(...)\ndef _compile_regex(...): ...",
            "extract_date": "@lru_cache(...)\ndef extract_date(...): ...",
            ...
        }
        """
        code_str = re.sub(r'\"\"\".*?\"\"\"', '', code_str, flags=re.DOTALL)  # 去除文档字符串
        code_str = re.sub(r'#.*', '', code_str)  # 去除单行注释
        # 使用正则表达式匹配目标函数结构
        # 匹配装饰器部分（如果有），函数定义以及函数体
        pattern = re.compile(
            r'(@lru_cache\(.*?\)\s+)?'  # 匹配装饰器部分（如果有）
            r'def\s+(?!get_components\b)(\w+)'  # 排除get_components的其他函数
            r'\(.*?\):'  # 匹配函数头，包括参数部分
            r'([\s\S]+?)(?=\n\s*def\s+|\n@lru_cache\(.*?\)\s*|$)',  # 捕获函数体，直到下一个函数定义或装饰器
            flags=re.DOTALL
        )
        functions = {}
        # 查找所有匹配项
        for match in re.finditer(pattern, code_str):
            decorator, func_name, body = match.groups()
            # 构造函数定义
            if decorator:
                func_def = f"{decorator}def {func_name}{body}"
            else:
                func_def = f"def {func_name}{body}"
            functions[func_name] = func_def.strip()
        return functions

    def rewrite_codes(self, log_text: str, code_str: str) -> str:
        self.main_function = self.get_main_function(code_str)
        # print(f"log_text: {log_text}")
        if self.main_function:
            # print("Check")
            # new_main_function = re.sub(r"log_text\s*=\s*[\"'].*?[\"']", f'log_text = f\"\"\"{log_text}\"\"\"', self.main_function)
            new_main_function = re.sub(r'log_text\s*=\s*(["\'])(.*?)\1', f'log_text = f\"\"\"{log_text}\"\"\"', self.main_function, flags=re.DOTALL)
            # print(new_main_function)
            new_code = code_str.replace(self.main_function, new_main_function)
            return new_code
        else:
            return code_str

def is_perfect_match(original, test):
    """完全匹配：所有字段的key和value都正确且数量一致"""
    if len(original) != len(test):
        return False  # 字段数量不一致直接判定不匹配
    
    original_dict = {f['key']: f['value'] for f in original}
    test_dict = {f['key']: f['value'] for f in test}
    return original_dict == test_dict  # 字典比对自动校验key-value对

def has_any_match(original, test):
    """至少有一个字段的key和value都正确"""

    original_set = {(f['key'], f['value']) for f in original}
    test_set = {(f['key'], f['value']) for f in test}
    return len(original_set & test_set) > 0  # 集合交集判断

def calculate_coverage(original, testing):
    if original and testing:
        original_values = {item["value"] for item in original}
        testing_values = {item["value"] for item in testing}
        common = original_values & testing_values
        c = len(common) / len(original_values)
        return round(c, 2)
    else:
        return 0.0
    
def get_testing_result(opt_path, log_text, opt_code, obj):
    # log_text = "<21>Aug 13 09:08:09 soc-32 ntpdate[187386]: adjust time server 120.25.115.20 offset 0.002019 sec" 
    new_code = obj.rewrite_codes(log_text, opt_code)
    # print(new_code)
    new_code_path = opt_path.replace("opt", "test")
    with open(new_code_path, "w", encoding="utf-8") as f:
        f.write(new_code)
    result = execute_python_code(new_code_path)
    return result
                     

def get_json_dict(text):
    # 如果是json格式的标准字符串即可，直接打印出现单引号不好处理

    # 这里全是单引号需要修复的bug...
    # 将文本中的单引号替换为双引号 但是如果是字符串中的单引号则不替换
    # print(f"init data: {text}\n")
    # valid_json = text.replace("'", "\"")
    # # 去掉连续""
    # valid_json = re.sub(r'"value":\s*""(.*?)""', r'"value": "\1"', valid_json)
    # print(f"valid data: {valid_json}\n")
    # # 非法字符 None True
    # valid_json = valid_json.replace("None", "null").replace("True", "true")
    # data = json.loads(valid_json)
    # # 返回转换后的JSON字典
    # print(type(data))
    data = json.loads(text)
    return data

class TeeStream:
    # 初始化函数，传入文件路径和标准输出流
    def __init__(self, file_path, stdout):
        # 打开文件，以写入模式，编码为utf-8
        self.file = open(file_path, 'w', encoding='utf-8')
        # 保存标准输出流
        self.stdout = stdout

    # 写入函数，传入要写入的文本
    def write(self, text):
        # 将文本写入标准输出流
        self.stdout.write(text)
        # 将文本写入文件
        self.file.write(text)

    # 刷新函数，刷新标准输出流和文件
    def flush(self):
        # 刷新标准输出流
        self.stdout.flush()
        # 刷新文件
        self.file.flush()

    # 关闭函数，关闭文件
    def close(self):
        self.file.close()



def TestUnit(class_dataset_path, output_dir):
    tee = TeeStream("src/LogParserX/output/result_ori.txt", sys.stdout)
    original_stdout = sys.stdout
    sys.stdout = tee

    with open(class_dataset_path, "r", encoding="utf-8") as f:
        data_set = json.load(f)
    testing_data = data_set[:50]
    scores = []
    match_rate = 0.0
    perfect_match_rate = 0.0
    # report -> /gen/report_0.md, rename -> /gen/opt_0.py, new_code -> /test/opt_0.py
    report_list, rename_list = get_all_reports(output_dir)
    for i, j in zip(report_list, rename_list):
        code_path = Path(i).read_text()
        codes = extract_python_code_from_md(code_path)
        with open(j, "w", encoding="utf-8") as f:
            f.write(codes[0])
        idx = i.split("\\")[-1].split("_")[1].replace(".md", "")
        idx = int(idx) % 100
        print(idx)
        score = 0.0
        testing_id = testing_data[idx]["logId"]
        testing_logText = testing_data[idx]["logText"]
        testing_logField = testing_data[idx]["logField"]
        obj = ExtractedCodes()
        gen_result = get_testing_result(j, testing_logText, codes[0], obj)
        gen_result = gen_result["output"]
        print(f"gen_result = {gen_result}\n")
        gen_result = get_json_dict(gen_result)
        print(gen_result)
        # 验证结果
        print(f"Testing ID: {testing_id}:")
        print(f"Testing LogText: {testing_logText}")
        print(f"Testing LogField: {testing_logField}")
        print(f"Generated LogField: {gen_result}")
        if is_perfect_match(testing_logField, gen_result):
            print(f"完全匹配！")
            score = 1.0
            perfect_match_rate += 1.0
            match_rate += 1.0
        elif has_any_match(testing_logField, gen_result):
            coverage = calculate_coverage(testing_logField, gen_result)
            score = coverage
            match_rate += 1.0
            print(f"至少有一个匹配！full_coverage: {coverage*100:.2f}%")
        else:
            print(f"完全不匹配！")

        scores.append(score)
    bad_len = len([i for i in scores if i < 0.7])
    official_score = 0.4 * match_rate / len(rename_list) + 0.6 * perfect_match_rate / len(rename_list)
    print(f"{70*'='}")
    print(f"My Scores (1 for full): {scores}")
    print(f"My Average Score: {round(sum(scores) / len(scores), 2)}")
    print(f"Match Rate:  {match_rate / len(rename_list)}")
    print(f"Perfect Match Rate: {perfect_match_rate / len(rename_list)}")
    print(f"Official Score (1 for full): {official_score}")
    print(f"Bad Case: {bad_len}")

    sys.stdout = original_stdout


def MultiTestUnit(class_dataset_path: str, output_dir: str):
    tee = TeeStream("src/LogParserX/output/result_multi.txt", sys.stdout)
    original_stdout = sys.stdout
    sys.stdout = tee

    with open(class_dataset_path, "r", encoding="utf-8") as f:
            data_set = json.load(f)
    testing_data = data_set[:50]
    # scores = []
    # match_rate = 0.0
    # perfect_match_rate = 0.0
    # report -> /gen/report_0.md, rename -> /gen/opt_0.py, new_code -> /test/opt_0.py
    report_list, rename_list = get_all_reports(output_dir)
    k = 0
    for i, j in zip(report_list, rename_list):
        code_path = Path(i).read_text()
        codes = extract_python_code_from_md(code_path)
        with open(j, "w", encoding="utf-8") as f:
            f.write(codes[0])
        scores = []
        match_rate = 0.0
        perfect_match_rate = 0.0
        for idx in range(0, len(rename_list)):
            score = 0.0
            testing_id = testing_data[idx]["logId"]
            testing_logText = testing_data[idx]["logText"]
            testing_logField = testing_data[idx]["logField"]
            obj = ExtractedCodes()
            gen_result = get_testing_result(j, testing_logText, codes[0], obj)
            gen_result = gen_result["output"]
            gen_result = get_json_dict(gen_result)
            # 验证结果
            # print(f"Testing ID: {testing_id}:")
            # print(f"Testing LogText: {testing_logText}")
            # print(f"Testing LogField: {testing_logField}")
            # print(f"Generated LogField: {gen_result}")
            if is_perfect_match(testing_logField, gen_result):
                # print(f"完全匹配！")
                score = 1.0
                perfect_match_rate += 1.0
                match_rate += 1.0
            elif has_any_match(testing_logField, gen_result):
                coverage = calculate_coverage(testing_logField, gen_result)
                score = coverage
                match_rate += 1.0
                # print(f"至少有一个匹配！full_coverage: {coverage:.2f}%")
            else:
                # print(f"完全不匹配！")
                pass
            scores.append(score)
        print(f"Index: {k} {70*'='}")
        official_score = 0.4 * match_rate / len(rename_list) + 0.6 * perfect_match_rate / len(rename_list)
        print(f"My Scores (1 for full): {scores}")
        print(f"My Average Score: {round(sum(scores) / len(scores), 2)}")
        print(f"Match Rate:  {match_rate / len(rename_list)}")
        print(f"Perfect Match Rate: {perfect_match_rate / len(rename_list)}")
        print(f"Official Score (1 for full): {official_score}")
        k+=1

    sys.stdout = original_stdout

if __name__ == "__main__":
    # TestUnit
    class_dataset_path = "data/generated_data/class_2.json"
    # class_dataset_path = "data/classified_data/class_2.json"
    output_dir = "src/LogParserX/output/gen/reports"
    # TestUnit: for one code, testing corresponding log to see if it can match 1->1
    TestUnit(class_dataset_path=class_dataset_path, output_dir=output_dir)
    # MultiTestUnit: for one code, testing num sample log to testing its coverage 1->N
    # MultiTestUnit(class_dataset_path=class_dataset_path, output_dir=output_dir)

