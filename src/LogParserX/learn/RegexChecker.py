import os
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
        if self.main_function:
            # print("Check")
            new_main_function = re.sub(r"log_text = '(.*?)'", f'log_text = f\'{log_text}\'', self.main_function)
            # print(new_main_function)
            new_code = code_str.replace(self.main_function, new_main_function)
            return new_code
        else:
            return code_str

            

if __name__ == "__main__":
    reports, rename_lst = get_all_reports(r"src\LogParserX\output\gen")
    print(reports)
    print(rename_lst)
    results = []
    ex_codes = ExtractedCodes()
    for i, j in zip(reports, rename_lst):
        code_path = Path(i).read_text()
        codes = extract_python_code_from_md(code_path)
        # ex_codes.main_function = ex_codes.get_main_function(codes[0])
        # ex_codes.param_fields = ex_codes.get_param_field(codes[0])
        # ex_codes.func_fields = ex_codes.extract_functions(codes[0])
        # print(f"main_function: {ex_codes.main_function}")
        # print(f"param_fields: {ex_codes.param_fields}")
        # print(f"func_fields: {ex_codes.func_fields}")
        with open(f"{j}", "w", encoding="utf-8") as f:
            f.write(codes[0])
        # result = execute_python_code(j)
        # print(f"original_codes: {codes[0]}, result: {result}")
        log_text = "Replaced Contents" 
        new_code = ex_codes.rewrite_codes(log_text, codes[0])
        print(f"new_code: {new_code}")
        # print(f"main_function: {new_code}")
        # if result["return_code"] == 0:
        #     gen_logField = result["output"]
        #     item = {
        #         "report_path": i,
        #         "output_path": j,
        #         "gen_logField": gen_logField
        #     }
        #     results.append(item)
        
    print(results)


    # report_path = Path(r"src\LogParserX\output\gen\report_0.md")
    # report_path = Path(r"src\LogParserX\output\gen\report_1.md")
    # output_path = Path(r"src\LogParserX\output\opt\output_1.py")
    # x = extract_python_code_from_md(report_path.read_text())
    # with output_path.open("w", encoding="utf-8") as f:
    #     f.write(x[0])
    # result = execute_python_code(output_path)
    # print(result)

