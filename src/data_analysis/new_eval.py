def is_perfect_match(original, test):
    """检查测试数据是否完全覆盖原始数据（允许测试数据有额外字段）"""
    original_dict = {f['key']: f['value'] for f in original}
    test_dict = {f['key']: f['value'] for f in test}
    # 空数据特殊处理：双方均为空时视为匹配
    if not original_dict and not test_dict:
        return True
    # 检查原始数据的所有键值对都存在于测试数据
    for key, value in original_dict.items():
        if test_dict.get(key) != value:
            return False
    return True

def has_any_match(original, test):
    """至少有一个字段的key和value都正确"""
    original_set = {(f['key'], f['value']) for f in original}
    test_set = {(f['key'], f['value']) for f in test}
    return bool(original_set & test_set)  # 使用bool转换更直观

def calculate_metrics(original, test):
    """新版指标计算"""
    perfect = is_perfect_match(original, test)
    matched = has_any_match(original, test) or perfect
    return matched, perfect