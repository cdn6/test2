#!/bin/bash

# 批量替换所有网站根目录下的dd.js文件（不备份）
# 新文件路径
NEW_FILE="/www/wwwroot/default/dd.js"

# 检查新文件是否存在
if [ ! -f "$NEW_FILE" ]; then
    echo "错误：新文件 $NEW_FILE 不存在！"
    exit 1
fi

# 宝塔网站根目录
WEB_ROOT="/www/wwwroot"

echo "开始批量替换dd.js文件..."

# 遍历所有网站目录
find "$WEB_ROOT" -maxdepth 1 -type d | while read -r SITE_DIR; do
    # 跳过根目录本身和default目录
    if [ "$SITE_DIR" == "$WEB_ROOT" ] || [ "$SITE_DIR" == "/wwwroot/default" ]; then
        continue
    fi
    
    TARGET_PATH="$SITE_DIR/dd.js"
    
    # 如果目标文件存在则直接替换
    if [ -f "$TARGET_PATH" ]; then
        cp -f "$NEW_FILE" "$TARGET_PATH"
        echo "已替换: $TARGET_PATH"
    else
        echo "跳过: $SITE_DIR (未找到dd.js)"
    fi
done

echo "操作完成！"