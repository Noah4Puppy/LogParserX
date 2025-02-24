import io
import re
import sys
import time

def get_clear_python_code(file_path, output_path):
    """
    从Markdown格式的文件中提取Python代码并保存为.py文件。
    
    参数:
        file_path (str): 输入的Markdown文件路径。
    """
    # 打开并读取Markdown文件
    with open(file_path, 'r', encoding='utf-8') as f:
        code = f.readlines()
    
    code = code[1:-1]

    # 保存为.py文件
    out = output_path 
    with open(out, 'w', encoding='utf-8') as f:
        f.write(''.join(code))  # 用空行分隔代码块

    print(f"Python代码已提取并保存为 {out}")

def add_main(logtext, path):
    main_code = f"""if __name__ == '__main__':
    log_text = "{logtext}"
    result = get_components(log_text)
    print(result)
    """
    with open(path, 'a', encoding='utf-8') as f:
        f.write(main_code)
    print(f"添加main函数成功，并保存为 {path}")

# def execute_python_code(file_path):
#     """
#     执行Python代码，并捕获打印内容。
    
#     参数:
#         file_path (str): 输入的Python文件路径。
    
#     返回:
#         dict: 包含执行结果（success）和打印内容（data）。
#     """
#     try:
#         # 使用io.StringIO捕获打印输出
#         stdout_capture = io.StringIO()
#         with open(file_path, 'r', encoding='utf-8') as f:
#             code = f.read()
#         # 重定向标准输出到捕获对象
#         sys.stdout = stdout_capture
#         # 执行代码
#         exec(code)
#         # 恢复标准输出
#         sys.stdout = sys.__stdout__
#         # 获取打印内容
#         print_output = stdout_capture.getvalue().strip()
#         return {'success': True, 'data': print_output}
#     except Exception as e:
#         # 捕获执行过程中的异常
#         return {'success': False, 'data': str(e)}
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional

def execute_python_code(file_path: str, timeout: int = 5) -> Dict[str, Optional[str]]:
    """
    执行Python代码并捕获输出及执行时间
    
    :param file_path: Python文件路径
    :param timeout: 超时时间（秒）
    :return: 包含执行结果和时间的字典 {
        "output": 标准输出,
        "error": 错误信息,
        "return_code": 返回码,
        "execution_time": 执行时间(秒)
    }
    """
    result = {
        "output": None,
        "error": None,
        "return_code": None,
        "execution_time": None
    }
    
    try:
        # 验证文件
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"文件不存在: {file_path}")
        if path.suffix.lower() != '.py':
            raise ValueError("仅支持.py文件")

        # 记录开始时间
        start_time = time.perf_counter()

        # 执行代码
        process = subprocess.run(
            [sys.executable, str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            encoding='utf-8',
            errors='ignore'
        )

        # 计算耗时
        end_time = time.perf_counter()
        elapsed = round(end_time - start_time, 3)  # 保留3位小数

        result.update({
            "output": process.stdout.strip(),
            "error": process.stderr.strip(),
            "return_code": process.returncode,
            "execution_time": elapsed
        })

    except subprocess.TimeoutExpired as e:
        # 计算实际超时耗时
        elapsed = round(time.perf_counter() - start_time, 3)
        result.update({
            "error": f"执行超时（设置{timeout}秒，实际耗时{elapsed}秒）",
            "execution_time": elapsed
        })
    except Exception as e:
        # 计算异常发生时的耗时
        elapsed = round(time.perf_counter() - start_time, 3) if 'start_time' in locals() else 0.0
        result.update({
            "error": f"执行失败: {str(e)}",
            "execution_time": elapsed
        })
    
    return result

def get_all_files(dir_path: str, suffix: str = None) -> list:
    """
    获取目录下所有文件路径
    
    :param dir_path: 目录路径
    :param suffix: 文件后缀
    :return: 文件路径列表
    """
    path = Path(dir_path)
    if not path.exists():
        raise FileNotFoundError(f"目录不存在: {dir_path}")
    if not path.is_dir():
        raise NotADirectoryError(f"不是目录: {dir_path}")

    files = []
    for p in path.iterdir():
        if p.is_file():
            if suffix is None or p.suffix.lower() == suffix.lower():
                files.append(str(p))
        elif p.is_dir():
            files.extend(get_all_files(str(p), suffix))
    # return files
    f = []
    for i in files:
        i = i.replace("\\", "/")
        # i = i.replace("output", "update")
        f.append(i)
    return f

# files_list = get_all_files(r"D:\Competition_Xihu\Resources\LogParserX\src\LogParserX\learn")

path = r"D:\Competition_Xihu\Resources\LogParserX\src\LogParserX\learn\gen\output_0.py"
out = r"D:\Competition_Xihu\Resources\LogParserX\src\LogParserX\learn\test\update_0.py"

def single(input_file, output_file, logtext):
    get_clear_python_code(input_file, output_file)
    add_main(logtext, output_file)
    r = execute_python_code(output_file)
    if r:
        gen_logField = r["output"]
        return gen_logField
    else:
        return []
# logtext=
# single(path, out, )

def multi(input_files, output_file, logtexts):
    output_list = [item.replace("output", "update") for item in input_files]
    Gen = []
    for i in range(len(input_files)):
        input_file = input_files[i]
        output_file = output_list[i]
        logtext = logtexts[i]
        gen_logField = single(input_file, output_file, logtext)
        Gen.append(
            {"logText": logtext, "genLogField": gen_logField})
    return Gen
