str_code = """
import re
i=0
if __name__ == '__main__':
    log_text = "<21>Aug 13 09:04:02 soc-32 systemd-logind: Removed session 3831379."
    keyword = ['key_value', 'date', 'hostname', 'session']
    result = get_components(keyword=keyword, log_text=log_text)
    print(result)"""
import re
logText = "RRRR"
str_code_ = re.sub(r'log_text = "(.*?)"', f'log_text = f"{logText}"', str_code)
print(str_code_)