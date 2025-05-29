#!/bin/bash

# 批量创建软链接，仅针对已存在dd.js的网站目录
# 源文件路径（统一管理的文件）
SOURCE_FILE="/www/wwwroot/default/dd.js"

# 检查源文件是否存在
if [ ! -f "$SOURCE_FILE" ]; then
    echo "错误：源文件 $SOURCE_FILE 不存在！"
    exit 1
fi

# 宝塔网站根目录
WEB_ROOT="/www/wwwroot"

echo "开始批量替换已存在的dd.js为软链接..."

# 遍历所有网站目录
find "$WEB_ROOT" -maxdepth 1 -type d | while read -r SITE_DIR; do
    # 跳过根目录本身和default目录
    if [ "$SITE_DIR" == "$WEB_ROOT" ] || [ "$SITE_DIR" == "/www/wwwroot/default" ]; then
        continue
    fi
    
    TARGET_PATH="$SITE_DIR/dd.js"
    
    # 只有当目标文件存在时才操作
    if [ -f "$TARGET_PATH" ] || [ -L "$TARGET_PATH" ]; then
        # 删除旧文件/软链接
        rm -f "$TARGET_PATH"
        echo "已删除旧文件: $TARGET_PATH"
        
        # 创建新软链接
        ln -s "$SOURCE_FILE" "$TARGET_PATH"
        echo "已创建软链接: $TARGET_PATH -> $SOURCE_FILE"
    else
        echo "跳过: $SITE_DIR (未找到dd.js)"
    fi
done

echo "操作完成！仅对已存在dd.js的网站进行了替换。"