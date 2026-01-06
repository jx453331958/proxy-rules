#!/usr/bin/env python3
"""
功能：读取 custom 目录下的 .list 文件，下载 RULE-SET 规则中的远程文件内容，
      并将所有规则展开拼接成新的 list 文件保存到 output 目录
"""

import os
import re
import requests
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime
from collections import defaultdict


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


def format_header_comment(filename, stats, total):
    """
    格式化文件头部注释
    
    Args:
        filename: 文件名
        stats: 规则统计字典
        total: 总规则数
        
    Returns:
        str: 格式化的头部注释
    """
    # 获取当前时间（东八区）
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # 构建注释
    lines = []
    lines.append(f"# Name: {filename}")
    lines.append(f"# Updated: {now}")
    
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


def download_rule_set(url):
    """
    下载 RULE-SET URL 指向的规则文件
    
    Args:
        url: RULE-SET 的 URL
        
    Returns:
        list: 规则列表
    """
    try:
        print(f"  正在下载: {url}")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        rules = []
        for line in response.text.splitlines():
            line = line.strip()
            # 跳过空行和注释
            if not line or line.startswith('#'):
                continue
            rules.append(line)
        
        print(f"  ✓ 成功下载 {len(rules)} 条规则")
        return rules
    
    except Exception as e:
        print(f"  ✗ 下载失败: {e}")
        return []


def process_list_file(input_file, output_file):
    """
    处理单个 .list 文件
    
    Args:
        input_file: 输入文件路径
        output_file: 输出文件路径
    """
    print(f"\n处理文件: {input_file.name}")
    print("=" * 60)
    
    all_rules = []
    rule_set_count = 0
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                original_line = line.strip()
                
                # 跳过空行和注释
                if not original_line or original_line.startswith('#'):
                    continue
                
                # 检查是否是 RULE-SET 规则
                if original_line.startswith('RULE-SET,'):
                    # 解析 RULE-SET 规则
                    # 格式: RULE-SET,<URL>,<策略>[,<额外参数>]
                    parts = original_line.split(',')
                    if len(parts) >= 2:
                        url = parts[1]
                        print(f"\n第 {line_num} 行: 找到 RULE-SET")
                        
                        # 下载并展开规则
                        downloaded_rules = download_rule_set(url)
                        if downloaded_rules:
                            all_rules.extend(downloaded_rules)
                            rule_set_count += 1
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
                        
                        all_rules.append(processed_rule)
                        print(f"第 {line_num} 行: 添加 {rule_type} 规则")
    
    except Exception as e:
        print(f"错误: 读取文件时出错: {e}")
        return False
    
    # 写入输出文件
    try:
        # 确保输出目录存在
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        # 统计规则类型
        stats = get_rule_statistics(all_rules)
        total = len(all_rules)
        
        # 生成头部注释
        header = format_header_comment(output_file.stem, stats, total)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            # 写入格式化的头部注释
            f.write(header + '\n\n')
            
            # 写入所有规则
            for rule in all_rules:
                f.write(rule + '\n')
        
        print(f"\n✓ 成功生成: {output_file}")
        print(f"  - 展开了 {rule_set_count} 个 RULE-SET")
        print(f"  - 总共 {total} 条规则")
        
        # 打印规则类型统计
        print(f"  - 规则类型统计:")
        for rule_type, count in sorted(stats.items()):
            print(f"    * {rule_type}: {count}")
        
        return True
    
    except Exception as e:
        print(f"错误: 写入输出文件时出错: {e}")
        return False


def main():
    # 获取脚本所在目录的父目录（项目根目录）
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    
    # 定义输入输出目录
    custom_dir = project_root / "custom"
    output_dir = project_root / "output"
    
    print("=" * 60)
    print("RULE-SET 展开脚本")
    print("=" * 60)
    print(f"输入目录: {custom_dir}")
    print(f"输出目录: {output_dir}")
    print("=" * 60)
    
    # 检查输入目录是否存在
    if not custom_dir.exists():
        print(f"错误: 输入目录 {custom_dir} 不存在")
        return
    
    # 查找所有 .list 文件
    list_files = sorted(custom_dir.glob("*.list"))
    
    if not list_files:
        print(f"警告: 在 {custom_dir} 目录下没有找到 .list 文件")
        return
    
    print(f"\n找到 {len(list_files)} 个 .list 文件\n")
    
    # 处理每个文件
    success_count = 0
    for list_file in list_files:
        output_file = output_dir / list_file.name
        if process_list_file(list_file, output_file):
            success_count += 1
    
    print("\n" + "=" * 60)
    print(f"完成! 成功处理 {success_count}/{len(list_files)} 个文件")
    print("=" * 60)


if __name__ == "__main__":
    main()
