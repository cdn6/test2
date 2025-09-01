#!/bin/bash

# 批量创建软链接，仅针对已存在dd.js或gdw.js的网站目录
# 源文件路径（统一管理的文件）
SOURCE_DD="/www/wwwroot/default/dd.js"
SOURCE_GDW="/www/wwwroot/default/gdw.js"

# 检查源文件是否存在
if [ ! -f "$SOURCE_DD" ]; then
    echo "警告：源文件 $SOURCE_DD 不存在！"
fi

if [ ! -f "$SOURCE_GDW" ]; then
    echo "警告：源文件 $SOURCE_GDW 不存在！"
fi

# 宝塔网站根目录
WEB_ROOT="/www/wwwroot"

echo "开始批量替换已存在的dd.js和gdw.js为软链接..."

# 遍历所有网站目录
find "$WEB_ROOT" -maxdepth 1 -type d | while read -r SITE_DIR; do
    # 跳过根目录本身和default目录
    if [ "$SITE_DIR" == "$WEB_ROOT" ] || [ "$SITE_DIR" == "/www/wwwroot/default" ]; then
        continue
    fi
    
    # 处理 dd.js
    TARGET_DD="$SITE_DIR/dd.js"
    if [ -f "$TARGET_DD" ] || [ -L "$TARGET_DD" ]; then
        # 删除旧文件/软链接
        rm -f "$TARGET_DD"
        echo "已删除旧文件: $TARGET_DD"
        
        # 创建新软链接（如果源文件存在）
        if [ -f "$SOURCE_DD" ]; then
            ln -s "$SOURCE_DD" "$TARGET_DD"
            echo "已创建软链接: $TARGET_DD -> $SOURCE_DD"
        else
            echo "警告：无法创建 $TARGET_DD，源文件不存在"
        fi
    fi
    
    # 处理 gdw.js
    TARGET_GDW="$SITE_DIR/gdw.js"
    if [ -f "$TARGET_GDW" ] || [ -L "$TARGET_GDW" ]; then
        # 删除旧文件/软链接
        rm -f "$TARGET_GDW"
        echo "已删除旧文件: $TARGET_GDW"
        
        # 创建新软链接（如果源文件存在）
        if [ -f "$SOURCE_GDW" ]; then
            ln -s "$SOURCE_GDW" "$TARGET_GDW"
            echo "已创建软链接: $TARGET_GDW -> $SOURCE_GDW"
        else
            echo "警告：无法创建 $TARGET_GDW，源文件不存在"
        fi
    fi
done

echo "操作完成！仅对已存在dd.js或gdw.js的网站进行了替换。"
