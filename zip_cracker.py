#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
高级ZIP密码破解工具
- 支持10位字母大小写加数字的所有组合
- 使用pyzipper模块支持高级ZIP加密格式
- 通过进度条显示破解进度
- 支持断点续传和日志记录

作者: 鹿鸣小白
邮箱: noleit@icoud.com
版本: 1.0.0
日期: 2025-04-24
"""

import pyzipper
import os
import itertools
import time
import string
import argparse
import logging
import random
import sys
from datetime import datetime
from tqdm import tqdm
from multiprocessing import Pool, cpu_count

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='zip_cracker.log',
    filemode='a'
)
logger = logging.getLogger('zip_cracker')

# ANSI 颜色代码
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_banner():
    """打印漂亮的程序启动横幅"""
    banner = f"""
{Colors.CYAN}
    ██╗     ██╗   ██╗ ███╗   ███╗ ██╗ ███╗   ██╗  ██████╗
    ██║     ██║   ██║ ████╗ ████║ ██║ ████╗  ██║ ██╔════╝
    ██║     ██║   ██║ ██╔████╔██║ ██║ ██╔██╗ ██║ ██║  ███╗
    ██║     ██║   ██║ ██║╚██╔╝██║ ██║ ██║╚██╗██║ ██║   ██║
    ███████╗╚██████╔╝ ██║ ╚═╝ ██║ ██║ ██║ ╚████║ ╚██████╔╝
    ╚══════╝ ╚═════╝  ╚═╝     ╚═╝ ╚═╝ ╚═╝  ╚═══╝  ╚═════╝
    
    ██╗  ██╗ ██╗   ██╗  █████╗  ███╗   ██╗  ██████╗  ██╗   ██╗ ███████╗
    ██║ ██╔╝ ██║   ██║ ██╔══██╗ ████╗  ██║ ██╔════╝  ╚██╗ ██╔╝ ██╔════╝
    █████╔╝  ██║   ██║ ███████║ ██╔██╗ ██║ ██║  ███╗  ╚████╔╝  █████╗
    ██╔═██╗  ██║   ██║ ██╔══██║ ██║╚██╗██║ ██║   ██║   ╚██╔╝   ██╔══╝
    ██║  ██╗ ╚██████╔╝ ██║  ██║ ██║ ╚████║ ╚██████╔╝    ██║    ███████╗
    ╚═╝  ╚═╝  ╚═════╝  ╚═╝  ╚═╝ ╚═╝  ╚═══╝  ╚═════╝     ╚═╝    ╚══════╝
{Colors.ENDC}
{Colors.GREEN}高级ZIP密码破解工具 v1.0.0{Colors.ENDC}
{Colors.BOLD}鹿鸣矿业信息安全部 | 作者: 鹿鸣小白 | 邮箱: noleit@icoud.com{Colors.ENDC}
"""
    print(banner)
    
    # 随机显示一些黑客风格的提示
    tips = [
        f"{Colors.WARNING}提示: 使用模式破解（-b选项）比暴力破解快数百倍{Colors.ENDC}",
        f"{Colors.WARNING}提示: 多进程模式可以显著提高破解速度{Colors.ENDC}",
        f"{Colors.WARNING}提示: 断点续传功能让您可以随时中断并继续破解{Colors.ENDC}",
        f"{Colors.WARNING}提示: 测试模式(-t)下可以快速验证密码而不解压文件{Colors.ENDC}",
        f"{Colors.WARNING}提示: 使用自定义字符集可以减少破解时间{Colors.ENDC}",
        f"{Colors.WARNING}提示: 强制重启(-f)选项可以忽略之前的进度，从头开始{Colors.ENDC}",
        f"{Colors.WARNING}提示: 遇到问题请联系鹿鸣矿业信息安全部{Colors.ENDC}"
    ]
    print(random.choice(tips))
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.ENDC}\n")

def setup_argparse():
    """设置命令行参数"""
    parser = argparse.ArgumentParser(description='高级ZIP密码破解工具')
    parser.add_argument('zip_file', help='要破解的ZIP文件路径')
    parser.add_argument('--extract-dir', '-d', default='extracted', help='解压目录')
    parser.add_argument('--min-length', '-min', type=int, default=8, help='密码最小长度')
    parser.add_argument('--max-length', '-max', type=int, default=10, help='密码最大长度')
    parser.add_argument('--charset', '-c', choices=['full', 'alpha', 'alphanum', 'num', 'custom'], default='alphanum', 
                        help='字符集: full=所有字符, alpha=字母, alphanum=字母+数字, num=数字, custom=自定义')
    parser.add_argument('--custom-charset', help='自定义字符集，与--charset=custom一起使用')
    parser.add_argument('--resume', '-r', help='从指定字符串开始继续破解')
    parser.add_argument('--processes', '-p', type=int, default=1, help='使用的进程数')
    parser.add_argument('--chunk-size', '-cs', type=int, default=10000, help='每个进程处理的密码数量')
    parser.add_argument('--save-every', '-s', type=int, default=10000, help='每多少次尝试保存一次进度')
    parser.add_argument('--test-only', '-t', action='store_true', help='仅测试不解压')
    parser.add_argument('--base-pattern', '-b', help='基本模式，例如"PldGNsys89"，将测试所有大小写组合')
    parser.add_argument('--force-restart', '-f', action='store_true', help='强制从头开始，忽略之前的进度')
    
    return parser.parse_args()

def get_charset(args):
    """根据参数获取字符集"""
    if args.charset == 'full':
        return string.printable
    elif args.charset == 'alpha':
        return string.ascii_letters
    elif args.charset == 'alphanum':
        return string.ascii_letters + string.digits
    elif args.charset == 'num':
        return string.digits
    elif args.charset == 'custom':
        if not args.custom_charset:
            raise ValueError("使用custom字符集时必须指定--custom-charset")
        return args.custom_charset
    else:
        return string.ascii_letters + string.digits

def generate_pattern_combinations(pattern):
    """生成模式的所有大小写组合"""
    char_options = []
    for char in pattern:
        if char.isalpha():
            char_options.append([char.lower(), char.upper()])
        else:
            char_options.append([char])
    
    return [''.join(combo) for combo in itertools.product(*char_options)]

def test_password(zip_file, password, extract_dir=None, test_only=True):
    """测试密码是否正确"""
    try:
        with pyzipper.AESZipFile(zip_file) as zip_ref:
            zip_ref.pwd = password.encode()
            
            # 只检查是否能列出文件
            file_list = zip_ref.namelist()
            
            # 如果不是只测试模式且提供了解压目录，则解压文件
            if not test_only and extract_dir and file_list:
                if not os.path.exists(extract_dir):
                    os.makedirs(extract_dir)
                zip_ref.extractall(path=extract_dir)
            
            return True
    except Exception:
        return False

def worker(args):
    """工作进程函数"""
    zip_file, password, extract_dir, test_only = args
    return password if test_password(zip_file, password, extract_dir, test_only) else None

def crack_pattern(zip_file, pattern, extract_dir, test_only=False):
    """破解特定模式的所有大小写组合"""
    logger.info(f"为模式 '{pattern}' 生成所有大小写组合")
    combinations = generate_pattern_combinations(pattern)
    logger.info(f"共生成 {len(combinations)} 种组合")
    
    start_time = time.time()
    
    with tqdm(total=len(combinations), desc=f"破解 '{pattern}' 的所有组合", unit="组合") as pbar:
        for i, password in enumerate(combinations):
            # 每10个密码显示一次当前尝试的密码
            if (i + 1) % 10 == 0:
                tqdm.write(f"正在测试: {password}")
                tqdm.write(f"进度: {i+1}/{len(combinations)}")
            
            if test_password(zip_file, password, extract_dir, test_only):
                tqdm.write(f"\n{Colors.GREEN}成功! 找到密码: {password}{Colors.ENDC}")
                logger.info(f"找到密码: {password}")
                
                if not test_only:
                    try:
                        logger.info(f"尝试解压文件到 {extract_dir}")
                        with pyzipper.AESZipFile(zip_file) as zip_ref:
                            zip_ref.pwd = password.encode()
                            if not os.path.exists(extract_dir):
                                os.makedirs(extract_dir)
                            zip_ref.extractall(path=extract_dir)
                        logger.info("解压成功!")
                        tqdm.write(f"{Colors.GREEN}文件已解压到 {extract_dir} 目录{Colors.ENDC}")
                    except Exception as e:
                        logger.error(f"解压失败: {e}")
                        tqdm.write(f"{Colors.FAIL}解压失败: {e}{Colors.ENDC}")
                
                end_time = time.time()
                duration = end_time - start_time
                tqdm.write(f"总耗时: {duration:.2f} 秒")
                logger.info(f"破解耗时: {duration:.2f} 秒")
                return password
            
            pbar.update(1)
    
    end_time = time.time()
    logger.info(f"未找到密码，总耗时: {end_time - start_time:.2f} 秒")
    return None

def crack_zip(zip_file, extract_dir, charset, min_length, max_length, 
              resume=None, processes=1, chunk_size=10000, save_every=10000, test_only=True, force_restart=False):
    """破解ZIP密码"""
    if not os.path.exists(zip_file):
        logger.error(f"文件不存在: {zip_file}")
        print(f"{Colors.FAIL}错误: 文件不存在: {zip_file}{Colors.ENDC}")
        return None
    
    # 创建状态文件来记录进度
    status_file = "zip_cracker_status.txt"
    
    # 设置起始点
    start_point = 0
    current_length = min_length
    current_prefix = ""
    
    # 如果强制重启，删除状态文件
    if force_restart and os.path.exists(status_file):
        os.remove(status_file)
        print(f"{Colors.WARNING}已删除之前的进度，将从头开始破解{Colors.ENDC}")
    
    # 如果提供了断点续传位置
    if resume:
        logger.info(f"从 '{resume}' 继续破解")
        current_prefix = resume
        current_length = len(resume)
    # 如果存在状态文件，读取上次的状态
    elif os.path.exists(status_file):
        with open(status_file, "r") as f:
            last_status = f.read().strip()
            if last_status:
                logger.info(f"从状态文件恢复: {last_status}")
                parts = last_status.split("|")
                if len(parts) >= 3:
                    current_length = int(parts[0])
                    current_prefix = parts[1]
                    start_point = int(parts[2])
    
    # 确认字符集
    logger.info(f"使用字符集: {charset}")
    logger.info(f"密码长度范围: {min_length}-{max_length}")
    
    start_time = time.time()
    result = None
    attempts = 0
    
    # 遍历所有可能的密码长度
    for length in range(current_length, max_length + 1):
        if length != current_length:
            current_prefix = ""
            start_point = 0
        
        logger.info(f"尝试 {length} 位密码")
        total_combinations = len(charset) ** length
        
        # 使用迭代器生成密码，减少内存使用
        def password_generator():
            # 根据当前前缀生成所有可能的组合
            if current_prefix:
                prefix_len = len(current_prefix)
                if prefix_len == length:
                    # 如果前缀长度等于总长度，只测试这一个密码
                    yield current_prefix
                else:
                    # 生成所有以当前前缀开头的密码
                    for combo in itertools.product(charset, repeat=length - prefix_len):
                        yield current_prefix + ''.join(combo)
            else:
                # 从头开始生成所有密码
                for combo in itertools.product(charset, repeat=length):
                    yield ''.join(combo)
        
        print(f"\n{Colors.CYAN}开始测试 {length} 位密码:{Colors.ENDC}")
        print(f"理论可能组合: {total_combinations:,} (实际会根据断点位置减少)")
        
        # 批量处理密码
        password_count = 0
        with tqdm(total=total_combinations, desc=f"{length}位密码", unit="组合") as pbar:
            # 跳过已测试的组合
            if start_point > 0:
                print(f"{Colors.CYAN}跳过前 {start_point} 个已测试的组合{Colors.ENDC}")
            
            for _ in range(start_point):
                next(password_generator(), None)
                pbar.update(1)
                password_count += 1
            
            # 创建进程池
            if processes > 1:
                with Pool(processes=min(processes, cpu_count())) as pool:
                    # 批处理密码
                    passwords = []
                    for password in password_generator():
                        passwords.append((zip_file, password, extract_dir, test_only))
                        password_count += 1
                        
                        if len(passwords) >= chunk_size:
                            # 批量检查密码
                            for res in pool.map(worker, passwords):
                                if res:
                                    result = res
                                    break
                            
                            if result:
                                break
                            
                            # 更新进度条
                            pbar.update(len(passwords))
                            passwords = []
                            
                            # 保存当前状态
                            if password_count % save_every == 0:
                                with open(status_file, "w") as f:
                                    f.write(f"{length}|{current_prefix}|{password_count}")
                                logger.info(f"保存进度: {length}位 已尝试 {password_count:,} 种组合")
                    
                    # 处理剩余的密码
                    if passwords and not result:
                        for res in pool.map(worker, passwords):
                            if res:
                                result = res
                                break
                        pbar.update(len(passwords))
            else:
                # 单进程模式
                for password in password_generator():
                    attempts += 1
                    password_count += 1
                    
                    # 每1000次更新一次进度显示
                    if password_count % 1000 == 0:
                        tqdm.write(f"当前测试: {password}")
                    
                    if test_password(zip_file, password, extract_dir, test_only):
                        tqdm.write(f"\n{Colors.GREEN}成功! 找到密码: {password}{Colors.ENDC}")
                        logger.info(f"找到密码: {password}")
                        result = password
                        
                        if not test_only:
                            try:
                                with pyzipper.AESZipFile(zip_file) as zip_ref:
                                    zip_ref.pwd = password.encode()
                                    if not os.path.exists(extract_dir):
                                        os.makedirs(extract_dir)
                                    zip_ref.extractall(path=extract_dir)
                                logger.info("解压成功!")
                                tqdm.write(f"{Colors.GREEN}文件已解压到 {extract_dir} 目录{Colors.ENDC}")
                            except Exception as e:
                                logger.error(f"解压失败: {e}")
                                tqdm.write(f"{Colors.FAIL}解压失败: {e}{Colors.ENDC}")
                        
                        break
                    
                    pbar.update(1)
                    
                    # 保存当前状态
                    if password_count % save_every == 0:
                        with open(status_file, "w") as f:
                            f.write(f"{length}|{current_prefix}|{password_count}")
                        logger.info(f"保存进度: {length}位 已尝试 {password_count:,} 种组合")
            
            if result:
                break
    
    end_time = time.time()
    duration = end_time - start_time
    
    if result:
        print(f"\n{Colors.GREEN}{Colors.BOLD}密码破解成功! 密码是: {result}{Colors.ENDC}")
        print(f"总尝试次数: {attempts:,}")
        print(f"总耗时: {duration:.2f} 秒")
        logger.info(f"密码破解成功: {result}")
        logger.info(f"总尝试次数: {attempts:,}")
        logger.info(f"总耗时: {duration:.2f} 秒")
        
        # 删除状态文件
        if os.path.exists(status_file):
            os.remove(status_file)
        
        return result
    else:
        print(f"\n{Colors.WARNING}未找到密码{Colors.ENDC}")
        print(f"总尝试次数: {attempts:,}")
        print(f"总耗时: {duration:.2f} 秒")
        logger.info("未找到密码")
        logger.info(f"总尝试次数: {attempts:,}")
        logger.info(f"总耗时: {duration:.2f} 秒")
        return None

def main():
    """主函数"""
    print_banner()
    args = setup_argparse()
    
    print(f"{Colors.BOLD}ZIP密码破解工具 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")
    print(f"目标文件: {args.zip_file}")
    
    if args.processes > 1:
        print(f"{Colors.CYAN}使用 {args.processes} 个进程加速破解{Colors.ENDC}")
    
    start_time = time.time()
    result = None
    
    # 如果指定了模式，使用模式破解
    if args.base_pattern:
        print(f"{Colors.CYAN}使用模式破解: {args.base_pattern}{Colors.ENDC}")
        result = crack_pattern(args.zip_file, args.base_pattern, args.extract_dir, args.test_only)
    else:
        # 否则使用全面破解
        charset = get_charset(args)
        print(f"{Colors.CYAN}使用字符集: {args.charset}{Colors.ENDC}")
        print(f"{Colors.CYAN}密码长度范围: {args.min_length}-{args.max_length}{Colors.ENDC}")
        
        result = crack_zip(
            args.zip_file, args.extract_dir, charset, 
            args.min_length, args.max_length, args.resume,
            args.processes, args.chunk_size, args.save_every, 
            args.test_only, args.force_restart
        )
    
    end_time = time.time()
    
    if result:
        print(f"\n{Colors.GREEN}{Colors.BOLD}任务完成!{Colors.ENDC}")
        print(f"{Colors.GREEN}找到密码: {result}{Colors.ENDC}")
        print(f"总耗时: {end_time - start_time:.2f} 秒")
    else:
        print(f"\n{Colors.WARNING}任务完成，未找到密码{Colors.ENDC}")
        print(f"总耗时: {end_time - start_time:.2f} 秒")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}程序被用户中断{Colors.ENDC}")
        logger.warning("程序被用户中断")
    except Exception as e:
        print(f"{Colors.FAIL}错误: {e}{Colors.ENDC}")
        logger.exception("程序异常") 