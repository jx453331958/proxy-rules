#!/bin/bash

# 自动 git add、commit（带时间戳）和 push 脚本

# 获取脚本所在目录的父目录（项目根目录）
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# 切换到项目根目录
cd "$PROJECT_ROOT" || exit 1

echo "========================================"
echo "Git 自动提交推送脚本"
echo "========================================"
echo "项目目录: $PROJECT_ROOT"
echo ""

# 检查是否有变更
if [[ -z $(git status -s) ]]; then
    echo "✓ 没有需要提交的变更"
    exit 0
fi

# 显示当前状态
echo "当前变更："
git status -s
echo ""

# git add 所有文件
echo "正在添加所有变更..."
git add .

# 生成时间戳
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
COMMIT_MESSAGE="Auto update: $TIMESTAMP"

# git commit
echo "正在提交..."
git commit -m "$COMMIT_MESSAGE"

if [ $? -eq 0 ]; then
    echo "✓ 提交成功: $COMMIT_MESSAGE"
    echo ""
    
    # git push
    echo "正在推送到远程仓库..."
    git push
    
    if [ $? -eq 0 ]; then
        echo "✓ 推送成功"
        echo ""
        echo "========================================"
        echo "全部完成！"
        echo "========================================"
    else
        echo "✗ 推送失败"
        exit 1
    fi
else
    echo "✗ 提交失败"
    exit 1
fi
