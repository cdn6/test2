#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#远程更新顶底固js广告脚本

# ================= 极简配置区域 (只需改这里) =================
# 1. 远程基础网址 (末尾不要加斜杠 /)
BASE_URL="https://域名"

# 2. 本地存放目录 (末尾不要加斜杠 /)
LOCAL_DIR="/www/wwwroot/default"

# 3. 需要检测的 JS 文件列表 (多个文件用空格隔开)
JS_FILES=("dd.js" "gdw.js")
# ============================================================


# ================= 核心检测逻辑 (无需修改) =================
check_and_update_js() {
    local FILE_NAME="$1"
    local REMOTE_URL="${BASE_URL}/${FILE_NAME}"
    local LOCAL_FILE="${LOCAL_DIR}/${FILE_NAME}"

    echo "----------------------------------------"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 开始检测: $FILE_NAME"

    # 1. 读取远程内容到内存
    local CONTENT=$(curl -sSLf --connect-timeout 10 -m 30 "$REMOTE_URL")

    if [ $? -ne 0 ] || [ -z "$CONTENT" ]; then
        echo "❌ [$FILE_NAME] 访问失败或内容为空，保留原文件不变。"
        return 1
    fi

    # 2. 检测内容是否仅为 "//待定" (忽略空格和换行)
    local CLEAN_CONTENT=$(printf "%s" "$CONTENT" | tr -d '[:space:]')
    if [ "$CLEAN_CONTENT" = "//待定" ]; then
        echo "⏸️ [$FILE_NAME] 检测到内容仅为 '//待定'，跳过不保存。"
        return 0
    fi

    # 3. 提取远程内容最后一行的日期 (YYYY-MM-DD)
    local REMOTE_LAST_LINE=$(printf "%s\n" "$CONTENT" | tail -n 1)
    local REMOTE_DATE=$(echo "$REMOTE_LAST_LINE" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | tail -n 1)

    if [ -z "$REMOTE_DATE" ]; then
        echo "❌ [$FILE_NAME] 最后一行未找到有效日期，判定为非目标内容，保留原文件。"
        return 1
    fi

    echo "[$FILE_NAME] 远程日期：$REMOTE_DATE"

    # 4. 提取本地文件日期并对比
    if [ -f "$LOCAL_FILE" ]; then
        local LOCAL_LAST_LINE=$(tail -n 1 "$LOCAL_FILE")
        local LOCAL_DATE=$(echo "$LOCAL_LAST_LINE" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | tail -n 1)
        echo "[$FILE_NAME] 本地日期：${LOCAL_DATE:-无日期}"

        if [ -n "$LOCAL_DATE" ]; then
            local REMOTE_NUM=${REMOTE_DATE//-/}
            local LOCAL_NUM=${LOCAL_DATE//-/}

            if [ "$LOCAL_NUM" -ge "$REMOTE_NUM" ]; then
                echo "⏭️ [$FILE_NAME] 无需更新 (本地: $LOCAL_DATE >= 远程: $REMOTE_DATE)，跳过。"
                return 0
            fi
        fi
    else
        echo "⚠️ [$FILE_NAME] 本地文件不存在，准备首次创建..."
        mkdir -p "$LOCAL_DIR"
    fi

    # 5. 所有条件满足，写入本地文件并修正权限
    printf "%s\n" "$CONTENT" > "$LOCAL_FILE"
    chown www:www "$LOCAL_FILE"
    chmod 644 "$LOCAL_FILE"
    echo "✅ [$FILE_NAME] 检测通过，已成功替换最新文件！"
}

# 循环遍历所有配置的 JS 文件
for file in "${JS_FILES[@]}"; do
    check_and_update_js "$file"
done
