# ZIP密码破解工具

这是一个功能强大的ZIP文件密码破解工具，使用Python和pyzipper模块实现，支持高级ZIP格式（包括AES加密）。

## 单位信息

- **单位:** 鹿鸣矿业信息安全部
- **作者:** 鹿鸣小白
- **邮箱:** noleit@icoud.com
- **版本:** 1.0.0

## 功能特点

- 支持所有字母大小写和数字组合的暴力破解
- 使用进度条直观显示破解进度
- 支持断点续传，意外中断后可恢复
- 支持多进程加速破解过程
- 可以按指定模式测试所有大小写组合
- 支持日志记录，保存破解历史
- 完全支持PK 5.1格式的ZIP文件
- 漂亮的彩色终端输出和启动横幅
- 强制重启功能，忽略之前的进度

## 安装依赖

```bash
# 创建虚拟环境（可选）
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或 venv\Scripts\activate  # Windows

# 安装依赖
pip install pyzipper tqdm
```

## 使用方法

### 基本用法

```bash
# 最简单的用法
python zip_cracker.py 你的文件.zip

# 指定解压目录
python zip_cracker.py 你的文件.zip -d 解压目录

# 指定密码长度范围
python zip_cracker.py 你的文件.zip --min-length 8 --max-length 10
```

### 高级用法-

```bash
# 使用多进程加速破解
python zip_cracker.py 你的文件.zip -p 4

# 从断点继续破解
python zip_cracker.py 你的文件.zip -r "已经测试到的密码前缀"

# 使用特定模式测试大小写组合（最快）
python zip_cracker.py 你的文件.zip -b "PldGNsys89"

# 自定义字符集
python zip_cracker.py 你的文件.zip -c custom --custom-charset "abc123ABC"

# 强制从头开始，忽略之前的进度
python zip_cracker.py 你的文件.zip -f
```

### 针对之前测试的ZIP文件

如果我们知道密码包含"pldgnsys89"这些字符：

```bash
# 测试"pldgnsys89"所有大小写组合
python zip_cracker.py 19.zip -b "pldgnsys89"
```

## 命令行参数

- `zip_file`：要破解的ZIP文件路径
- `-d, --extract-dir`：解压目录，默认为"extracted"
- `-min, --min-length`：密码最小长度，默认为8
- `-max, --max-length`：密码最大长度，默认为10
- `-c, --charset`：字符集选择：
  - `full`：所有可打印字符
  - `alpha`：仅字母
  - `alphanum`：字母+数字（默认）
  - `num`：仅数字
  - `custom`：自定义字符集
- `--custom-charset`：自定义字符集，与`-c custom`一起使用
- `-r, --resume`：从指定字符串开始继续破解
- `-p, --processes`：使用的进程数，默认为1
- `-t, --test-only`：仅测试密码不解压文件
- `-b, --base-pattern`：基本模式，测试其所有大小写组合
- `-f, --force-restart`：强制从头开始，忽略之前的进度

## 使用提示

1. 如果知道密码的大致模式，使用`-b`选项可以大大减少破解时间
2. 多进程模式可以充分利用CPU资源加速破解
3. 破解过程可能很长，可以随时中断，然后使用`-r`选项继续
4. 如果你设置了最小和最大密码长度，但工具仍从8位开始，可能是由于之前中断的进度被保存。使用`-f`选项可以强制从头开始
5. 对于高级ZIP格式（如PK 5.1），只能使用pyzipper模块解压，标准的Python zipfile模块不支持
6. 任何问题和建议请联系鹿鸣矿业信息安全部

## 版权声明

此工具仅供鹿鸣矿业内部安全测试使用，未经授权禁止分发和使用。 