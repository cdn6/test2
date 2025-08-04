#!/bin/bash

# 检查宝塔面板中以www开头的域名网站运行目录是否在指定路径
# 统计在目标目录和不在目标目录的www域名数量

# 宝塔网站配置文件路径
CONFIG_DIR="/www/server/panel/vhost/nginx"

# 要检查的目标目录
TARGET_DIR="/www/wwwroot/demo.com"

# 统计变量
total_www=0
in_target=0
not_in_target=0
no_root=0

# 日志输出函数
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log "开始检查www域名网站运行目录..."

# 检查配置文件目录是否存在
if [ ! -d "$CONFIG_DIR" ]; then
    log "错误：宝塔网站配置目录不存在 - $CONFIG_DIR"
    exit 1
fi

# 遍历所有网站配置文件
for config_file in "$CONFIG_DIR"/*.conf; do
    # 从配置文件中提取网站域名
    domain=$(grep -oP 'server_name \K[^;]+' "$config_file" | head -1 | tr -d ' ')
    
    # 只处理以www开头的域名
    if [[ "$domain" == www.* ]]; then
        ((total_www++))
        site_root=$(grep -oP 'root \K[^;]+' "$config_file" | head -1 | tr -d ' ')

        # 检查是否找到运行目录
        if [ -z "$site_root" ]; then
            log "警告：www域名网站 $domain 的配置文件中没有找到运行目录设置"
            ((no_root++))
            continue
        fi

        # 检查运行目录是否在目标目录下
        if [[ "$site_root" != "$TARGET_DIR"* ]]; then
            log "警告：www域名网站 $domain 的运行目录 $site_root 不在 $TARGET_DIR 目录下"
            ((not_in_target++))
        else
            log "正常：www域名网站 $domain 的运行目录 $site_root 符合要求"
            ((in_target++))
        fi
    fi
done

# 输出统计结果
echo "======================================"
log "检查完成，统计结果："
log "总www域名数量: $total_www"
log "运行目录在 $TARGET_DIR 中的数量: $in_target"
log "运行目录不在 $TARGET_DIR 中的数量: $not_in_target"
log "未设置运行目录的数量: $no_root"

echo "======================================"
