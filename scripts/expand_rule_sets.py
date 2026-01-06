#!/usr/bin/env python3
"""
功能：读取 custom 目录下的 .list 文件，下载 RULE-SET 规则中的远程文件内容，
      并将所有规则展开拼接成新的 list 文件保存到 output 目录
"""

import os
import re
import sys
import subprocess
import requests
import logging
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime
from collections import defaultdict


def setup_logging(log_dir):
    """
    配置日志系统
    
    Args:
        log_dir: 日志目录路径
        
    Returns:
        str: 日志文件路径
    """
    # 创建日志目录
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # 生成带时间戳的日志文件名
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = log_dir / f"expand_rules_{timestamp}.log"
    
    # 配置日志格式
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'
    
    # 配置根日志记录器
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        datefmt=date_format,
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    return str(log_file)


def log_and_print(message, level='info'):
    """
    同时打印到控制台和记录到日志
    
    Args:
        message: 消息内容
        level: 日志级别 (info, warning, error)
    """
    if level == 'info':
        logging.info(message)
    elif level == 'warning':
        logging.warning(message)
    elif level == 'error':
        logging.error(message)
    else:
        logging.info(message)


def get_rule_statistics(rules):
    """
    统计各种规则类型的数量
    
    Args:
        rules: 规则列表
        
    Returns:
        dict: 各种规则类型的统计
    """
    stats = defaultdict(int)
    
    for rule in rules:
        # 提取规则类型（第一个逗号之前的部分）
        if ',' in rule:
            rule_type = rule.split(',')[0].strip()
            stats[rule_type] += 1
        elif rule.strip():
            # 处理没有逗号的特殊规则
            stats['OTHER'] += 1
    
    return stats


def format_header_comment(filename, stats, total, rule_set_info=None):
    """
    格式化文件头部注释
    
    Args:
        filename: 文件名
        stats: 规则统计字典
        total: 总规则数
        rule_set_info: RULE-SET 来源信息列表
        
    Returns:
        str: 格式化的头部注释
    """
    # 获取当前时间（东八区）
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # 构建注释
    lines = []
    lines.append(f"# Name: {filename}")
    lines.append(f"# Updated: {now}")
    
    # 如果有 RULE-SET 来源信息，添加到头部
    if rule_set_info:
        lines.append("#")
        lines.append("# Source RULE-SETs:")
        for idx, info in enumerate(rule_set_info, 1):
            url = info['url']
            count = info['count']
            original_total = info['original_total']
            if original_total > 0:
                lines.append(f"#   {idx}. {url}")
                lines.append(f"#      Downloaded: {count} rules (Source Total: {original_total})")
            else:
                lines.append(f"#   {idx}. {url}")
                lines.append(f"#      Downloaded: {count} rules")
        lines.append("#")
    
    # 按照特定顺序输出统计信息
    order = [
        'DOMAIN',
        'DOMAIN-KEYWORD', 
        'DOMAIN-SUFFIX',
        'IP-CIDR',
        'IP-CIDR6',
        'PROCESS-NAME',
        'USER-AGENT',
        'GEOIP',
        'DOMAIN-SET',
        'URL-REGEX',
        'AND',
        'OR',
        'NOT'
    ]
    
    # 先输出预定义顺序的规则类型
    for rule_type in order:
        if rule_type in stats:
            lines.append(f"# {rule_type}: {stats[rule_type]}")
    
    # 再输出其他未在预定义列表中的规则类型（按字母顺序）
    other_types = sorted([k for k in stats.keys() if k not in order])
    for rule_type in other_types:
        lines.append(f"# {rule_type}: {stats[rule_type]}")
    
    lines.append(f"# Total: {total}")
    
    return '\n'.join(lines)




def add_no_resolve(rule):
    """
    为需要的规则类型添加 no-resolve 参数
    
    Args:
        rule: 规则字符串
        
    Returns:
        str: 处理后的规则
    """
    if not rule or not ',' in rule:
        return rule
    
    parts = rule.split(',')
    rule_type = parts[0].strip()
    
    # 需要添加 no-resolve 的规则类型
    no_resolve_types = ['IP-CIDR', 'IP-CIDR6', 'GEOIP', 'IP-ASN']
    
    if rule_type in no_resolve_types:
        # 检查是否已经有 no-resolve 参数
        if 'no-resolve' not in rule.lower():
            return f"{rule},no-resolve"
    
    return rule


def convert_to_domain_rule(line, rule_type="DOMAIN-SET"):
    """
    将 DOMAIN-SET 等域名集合文件中的规则转换为标准的 DOMAIN 类相关规则
    
    Args:
        line: 原始规则行
        rule_type: 规则集类型 (DOMAIN-SET, RULE-SET 等)
        
    Returns:
        str: 转换后的规则，如果不是域名则返回原规则
    """
    line = line.strip()
    
    # 如果是 DOMAIN-SET，需要将纯域名转换为 DOMAIN-SUFFIX 规则
    if rule_type == "DOMAIN-SET":
        # 跳过空行和注释
        if not line or line.startswith('#'):
            return None
        
        # 如果已经是完整的规则格式（包含逗号），直接返回
        if ',' in line:
            return line
        
        # 否则，这是一个纯域名，转换为 DOMAIN-SUFFIX 格式
        # DOMAIN-SET 文件通常只包含域名列表
        return f"DOMAIN-SUFFIX,{line}"
    
    # 其他类型的规则集，保持原样
    return line


def download_remote_rules(url, rule_type="RULE-SET"):
    """
    下载远程规则文件（RULE-SET 或 DOMAIN-SET），并提取统计信息
    
    Args:
        url: 远程规则文件的 URL
        rule_type: 规则类型 (RULE-SET 或 DOMAIN-SET)
        
    Returns:
        tuple: (规则列表, 原始文件的 total 数量)
    """
    try:
        log_and_print(f"  正在下载 {rule_type}: {url}")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        rules = []
        original_total = 0
        
        for line in response.text.splitlines():
            line = line.strip()
            # 提取注释中的 Total 字段
            if line.startswith('#') and 'Total:' in line or line.startswith('#') and 'TOTAL:' in line:
                try:
                    # 支持 "# Total: 123" 或 "# TOTAL: 123" 格式
                    parts = line.split(':')
                    if len(parts) >= 2:
                        original_total = int(parts[-1].strip())
                except:
                    pass
            # 跳过空行和注释
            if not line or line.startswith('#'):
                continue
            
            # 如果是 DOMAIN-SET 类型，进行特殊处理
            if rule_type == "DOMAIN-SET":
                converted_line = convert_to_domain_rule(line, rule_type)
                if converted_line:
                    rules.append(converted_line)
            else:
                # 为 IP 相关规则添加 no-resolve 参数
                line = add_no_resolve(line)
                rules.append(line)
        
        log_and_print(f"  ✓ 成功下载 {len(rules)} 条规则" + (f" (原始标注: {original_total})" if original_total > 0 else ""))
        return rules, original_total
    
    except Exception as e:
        log_and_print(f"  ✗ 下载失败: {e}", level='error')
        return [], 0


def process_list_file(input_file, output_file):
    """
    处理单个 .list 文件
    
    Args:
        input_file: 输入文件路径
        output_file: 输出文件路径
    """
    log_and_print(f"\n处理文件: {input_file.name}")
    log_and_print("=" * 60)
    
    all_rules = []
    rule_set_count = 0
    domain_set_count = 0
    rule_set_info = []  # 存储 RULE-SET 的详细信息
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                original_line = line.strip()
                
                # 跳过空行和注释
                if not original_line or original_line.startswith('#'):
                    continue
                
                # 检查是否是 RULE-SET 或 DOMAIN-SET 等规则
                if original_line.startswith('RULE-SET,'):
                    # 解析 RULE-SET 规则
                    # 格式: RULE-SET,<URL>,<策略>[,<额外参数>]
                    parts = original_line.split(',')
                    if len(parts) >= 2:
                        url = parts[1]
                        log_and_print(f"\n第 {line_num} 行: 找到 RULE-SET")
                        
                        # 下载并展开规则
                        downloaded_rules, original_total = download_remote_rules(url, "RULE-SET")
                        if downloaded_rules:
                            all_rules.extend(downloaded_rules)
                            rule_set_count += 1
                            # 记录 RULE-SET 信息
                            rule_set_info.append({
                                'url': url,
                                'count': len(downloaded_rules),
                                'original_total': original_total
                            })
                elif original_line.startswith('DOMAIN-SET,'):
                    # 解析 DOMAIN-SET 规则
                    # 格式: DOMAIN-SET,<URL>[,<策略>]
                    parts = original_line.split(',')
                    if len(parts) >= 2:
                        url = parts[1]
                        log_and_print(f"\n第 {line_num} 行: 找到 DOMAIN-SET")
                        
                        # 下载并展开规则
                        downloaded_rules, original_total = download_remote_rules(url, "DOMAIN-SET")
                        if downloaded_rules:
                            all_rules.extend(downloaded_rules)
                            domain_set_count += 1
                            # 记录 DOMAIN-SET 信息
                            rule_set_info.append({
                                'url': url,
                                'count': len(downloaded_rules),
                                'original_total': original_total
                            })
                else:
                    # 非 RULE-SET 规则，直接添加（但去掉策略参数）
                    # 处理各种规则类型，保留规则本身但去掉策略
                    if ',' in original_line:
                        parts = original_line.split(',')
                        rule_type = parts[0]
                        
                        # 根据规则类型决定保留多少部分
                        if rule_type in ['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD']:
                            # 这些规则格式: TYPE,domain,策略
                            if len(parts) >= 2:
                                processed_rule = f"{parts[0]},{parts[1]}"
                        elif rule_type == 'DOMAIN-SET':
                            # DOMAIN-SET 格式: DOMAIN-SET,URL,策略
                            if len(parts) >= 2:
                                processed_rule = f"{parts[0]},{parts[1]}"
                        elif rule_type in ['IP-CIDR', 'IP-CIDR6', 'GEOIP']:
                            # 可能有 no-resolve 参数
                            # 格式: TYPE,value,策略[,no-resolve]
                            processed_rule = original_line
                        else:
                            # 其他规则类型，保持原样
                            processed_rule = original_line
                        
                        # 为 IP 相关规则添加 no-resolve
                        processed_rule = add_no_resolve(processed_rule)
                        all_rules.append(processed_rule)
                        log_and_print(f"第 {line_num} 行: 添加 {rule_type} 规则")
    
    except Exception as e:
        log_and_print(f"错误: 读取文件时出错: {e}", level='error')
        return False
    
    # 写入输出文件
    try:
        # 确保输出目录存在
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        # 统计规则类型
        stats = get_rule_statistics(all_rules)
        total = len(all_rules)
        
        # 生成头部注释（包含 RULE-SET 来源信息）
        header = format_header_comment(output_file.stem, stats, total, rule_set_info if rule_set_info else None)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            # 写入格式化的头部注释
            f.write(header + '\n\n')
            
            # 写入所有规则
            for rule in all_rules:
                f.write(rule + '\n')
        
        log_and_print(f"\n✓ 成功生成: {output_file}")
        log_and_print(f"  - 展开了 {rule_set_count} 个 RULE-SET")
        log_and_print(f"  - 展开了 {domain_set_count} 个 DOMAIN-SET")
        log_and_print(f"  - 总共 {total} 条规则")
        
        # 打印规则类型统计
        log_and_print(f"  - 规则类型统计:")
        for rule_type, count in sorted(stats.items()):
            log_and_print(f"    * {rule_type}: {count}")
        
        return True
    
    except Exception as e:
        log_and_print(f"错误: 写入输出文件时出错: {e}", level='error')
        return False


def main():
    # 获取脚本所在目录的父目录（项目根目录）
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    
    # 定义输入输出目录
    custom_dir = project_root / "custom"
    output_dir = project_root / "output"
    
    # 设置日志
    log_file = setup_logging(project_root / "logs")
    
    log_and_print("=" * 60)
    log_and_print("RULE-SET 展开脚本")
    log_and_print("=" * 60)
    log_and_print(f"项目目录: {project_root}")
    log_and_print(f"输入目录: {custom_dir}")
    log_and_print(f"输出目录: {output_dir}")
    log_and_print(f"日志文件: {log_file}")
    log_and_print("=" * 60)
    
    # 清空 output 目录
    if output_dir.exists():
        import shutil
        log_and_print("\n正在清空 output 目录...")
        shutil.rmtree(output_dir)
        log_and_print("✓ output 目录已清空")
    
    # 重新创建 output 目录
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 检查输入目录是否存在
    if not custom_dir.exists():
        log_and_print(f"错误: 输入目录 {custom_dir} 不存在", level='error')
        return
    
    # 查找所有 .list 文件
    list_files = sorted(custom_dir.glob("*.list"))
    
    if not list_files:
        log_and_print(f"警告: 在 {custom_dir} 目录下没有找到 .list 文件", level='warning')
        return
    
    log_and_print(f"\n找到 {len(list_files)} 个 .list 文件\n")
    
    # 处理每个文件
    success_count = 0
    for list_file in list_files:
        output_file = output_dir / list_file.name
        if process_list_file(list_file, output_file):
            success_count += 1
    
    log_and_print("\n" + "=" * 60)
    log_and_print(f"完成! 成功处理 {success_count}/{len(list_files)} 个文件")
    log_and_print("=" * 60)
    log_and_print(f"\n日志已保存到: {log_file}")
    
    # 自动执行 git_auto_push.sh 脚本
    git_push_script = script_dir / "git_auto_push.sh"
    if git_push_script.exists():
        log_and_print("\n" + "=" * 60)
        log_and_print("正在执行 Git 自动推送脚本...")
        log_and_print("=" * 60)
        try:
            # 执行 shell 脚本
            result = subprocess.run(
                [str(git_push_script)],
                cwd=str(project_root),
                capture_output=True,
                text=True,
                timeout=300  # 5分钟超时
            )
            
            # 输出脚本执行结果
            if result.stdout:
                log_and_print("\n脚本输出:")
                log_and_print(result.stdout)
            
            if result.stderr:
                log_and_print("\n脚本错误输出:")
                log_and_print(result.stderr, level='warning')
            
            if result.returncode == 0:
                log_and_print("\n✓ Git 自动推送脚本执行成功")
            else:
                log_and_print(f"\n✗ Git 自动推送脚本执行失败 (返回码: {result.returncode})", level='error')
        
        except subprocess.TimeoutExpired:
            log_and_print("\n✗ Git 自动推送脚本执行超时", level='error')
        except Exception as e:
            log_and_print(f"\n✗ 执行 Git 自动推送脚本时出错: {e}", level='error')
    else:
        log_and_print(f"\n警告: Git 自动推送脚本未找到: {git_push_script}", level='warning')


if __name__ == "__main__":
    main()
