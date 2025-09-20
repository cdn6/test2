#!/bin/bash
#检查伪静态是否设置及批量设置伪静态

# 伪静态规则文件存储路径
BT_SITE_REWRITE_DIR="/www/server/panel/vhost/rewrite"

# 0maccms10 伪静态规则文件
0maccms10_REWRITE_FILE="/www/server/panel/rewrite/nginx/0maccms10.conf"

# 需要排除的系统配置文件(支持通配符)
EXCLUDE_FILES=(
    "0.*"
    "btwaf*"
    "phpfpm_status*"
    "waf2monitor_data*"
)

# 统计变量
has_rewrite=0
no_rewrite=0
total_sites=0
no_rewrite_sites=()

echo "开始批量设置宝塔面板网站的伪静态规则..."
echo "----------------------------------------"

# 生成排除参数
exclude_args=()
for pattern in "${EXCLUDE_FILES[@]}"; do
    exclude_args+=(! -name "${pattern}.conf")
done

# 遍历所有网站的伪静态规则配置文件
while IFS= read -r -d '' rewrite_config_file; do
    site_name=$(basename "${rewrite_config_file}" .conf)
    ((total_sites++))
    
    # 检查文件大小是否为0B
    if [ ! -s "$rewrite_config_file" ]; then
        # 如果是0B，写入 0maccms10 伪静态规则
        echo "为站点 ${site_name} 添加 0maccms10 伪静态规则..."
        
        # 将 0maccms10 伪静态规则写入该文件
        cp "$0maccms10_REWRITE_FILE" "$rewrite_config_file"
        echo "站点 ${site_name} 伪静态规则已成功添加！"
        
        # 重载 Nginx 配置
        nginx -s reload
        
        # 记录未设置伪静态的站点
        no_rewrite_sites+=("${site_name}")
        ((no_rewrite++))
    else
        # 如果文件不是空的，跳过
        ((has_rewrite++))
        echo "站点 ${site_name} 已设置伪静态规则，跳过。"
    fi
done < <(find "${BT_SITE_REWRITE_DIR}" -maxdepth 1 -type f -name "*.conf" "${exclude_args[@]}" -print0)

# 输出未设置伪静态的网站列表
if [ ${#no_rewrite_sites[@]} -gt 0 ]; then
    echo "以下网站已成功添加伪静态规则："
    for site in "${no_rewrite_sites[@]}"; do
        echo "  ✔ ${site}"
    done
else
    echo "所有网站均已设置伪静态规则"
fi

echo "----------------------------------------"
echo "批量设置完成！统计结果："
echo "总网站数量: ${total_sites}"
echo "已设置伪静态规则的网站: ${has_rewrite}"
echo "成功添加伪静态规则的网站: ${no_rewrite}"
