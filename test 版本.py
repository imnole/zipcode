import pyzipper
import os
import itertools
import time
from tqdm import tqdm

def generate_all_case_combinations(password):
    """生成给定密码的所有大小写组合"""
    char_options = []
    for char in password:
        if char.isalpha():
            char_options.append([char.lower(), char.upper()])
        else:
            char_options.append([char])
    
    return [''.join(combo) for combo in itertools.product(*char_options)]

def test_extraction(zip_file, password, extract_dir):
    """尝试使用密码解压文件"""
    try:
        with pyzipper.AESZipFile(zip_file) as zip_ref:
            zip_ref.pwd = password.encode()
            # 尝试解压第一个文件来测试密码
            file_list = zip_ref.namelist()
            if file_list:
                zip_ref.extract(file_list[0], path=extract_dir)
            return True
    except Exception:
        return False

def try_all_passwords(zip_file, base_password, extract_dir="extracted_found"):
    """尝试所有可能的密码组合"""
    # 生成所有可能的大小写组合
    print(f"生成 '{base_password}' 的所有大小写组合...")
    combinations = generate_all_case_combinations(base_password)
    print(f"共生成 {len(combinations)} 种组合")
    
    # 创建临时解压目录
    temp_dir = "temp_extract"
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    
    # 创建最终解压目录
    if not os.path.exists(extract_dir):
        os.makedirs(extract_dir)
    
    correct_passwords = []
    
    # 测试所有组合
    print("\n开始测试所有密码组合...")
    with tqdm(total=len(combinations), desc="测试进度", unit="组合") as pbar:
        for i, password in enumerate(combinations):
            # 每10个密码显示一次当前测试的密码
            if (i + 1) % 10 == 0:
                print(f"\n当前测试: {password}")
                print(f"进度: {i + 1}/{len(combinations)}")
            
            # 测试密码
            if test_extraction(zip_file, password, temp_dir):
                print(f"\n找到有效密码: {password}")
                correct_passwords.append(password)
                
                # 使用找到的密码尝试解压所有文件
                try:
                    with pyzipper.AESZipFile(zip_file) as zip_ref:
                        zip_ref.pwd = password.encode()
                        print(f"尝试使用密码 '{password}' 解压所有文件...")
                        zip_ref.extractall(path=extract_dir)
                        print(f"解压成功！文件已保存到 {extract_dir} 目录")
                except Exception as e:
                    print(f"解压所有文件失败: {e}")
            
            pbar.update(1)
    
    # 清理临时目录
    if os.path.exists(temp_dir):
        import shutil
        shutil.rmtree(temp_dir)
    
    return correct_passwords

if __name__ == "__main__":
    # 放入你的字母组合和和顺序
    base_password = "pldgnsys89"
    # 根目录放入你的压缩包，19.zip 换成你的压缩包名字
    correct_passwords = try_all_passwords("19.zip", base_password)
    
    if correct_passwords:
        print(f"\n找到 {len(correct_passwords)} 个有效密码:")
        for pwd in correct_passwords:
            print(f" - {pwd}")
    else:
        print("\n未找到有效密码") 