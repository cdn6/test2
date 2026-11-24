#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#dd.js远程更新替换脚本

# ================= 配置区域 =================
REMOTE_URL="远程dd.js链接"
LOCAL_FILE="/www/wwwroot/default/dd.js"
# ===========================================

echo "----------------------------------------"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] 开始检测 JS 更新..."

# 1. 直接将远程内容读取到内存变量中 (-f 确保404/500等错误直接失败)
CONTENT=$(curl -sSLf --connect-timeout 10 -m 30 "$REMOTE_URL")

# 判断 curl 是否成功，且内容不为空
if [ $? -ne 0 ] || [ -z "$CONTENT" ]; then
    echo "❌ 访问失败或返回内容为空，保留原文件不变。"
    exit 1
fi

# 2. 提取远程内容最后一行的日期 (格式: YYYY-MM-DD)
REMOTE_LAST_LINE=$(printf "%s\n" "$CONTENT" | tail -n 1)
REMOTE_DATE=$(echo "$REMOTE_LAST_LINE" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | tail -n 1)

# 只要没检测到规范日期（比如返回了网页报错代码、被防火墙拦截等），直接放弃
if [ -z "$REMOTE_DATE" ]; then
    echo "❌ 未检测到有效日期，判定为非目标 JS 内容，保留原文件不变。"
    exit 1
fi

echo "远程文件日期：$REMOTE_DATE"

# 3. 提取本地文件日期并对比
if [ -f "$LOCAL_FILE" ]; then
    LOCAL_LAST_LINE=$(tail -n 1 "$LOCAL_FILE")
    LOCAL_DATE=$(echo "$LOCAL_LAST_LINE" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | tail -n 1)
    echo "本地文件日期：${LOCAL_DATE:-无日期}"

    # 如果本地有日期，则进行数字大小对比
    if [ -n "$LOCAL_DATE" ]; then
        REMOTE_NUM=${REMOTE_DATE//-/}
        LOCAL_NUM=${LOCAL_DATE//-/}

        if [ "$LOCAL_NUM" -ge "$REMOTE_NUM" ]; then
            echo "⏭️ 无需更新 (本地: $LOCAL_DATE >= 远程: $REMOTE_DATE)，跳过不保存。"
            exit 0
        fi
    fi
else
    echo "⚠️ 本地文件不存在，准备首次创建..."
    mkdir -p "$(dirname "$LOCAL_FILE")"
fi

# 4. 所有条件均满足，将内存中的内容写入本地文件
printf "%s\n" "$CONTENT" > "$LOCAL_FILE"
chown www:www "$LOCAL_FILE"
chmod 644 "$LOCAL_FILE"
echo "✅ 检测通过，已成功保存并替换最新 JS！"
