#!/bin/bash

# 宝塔网站配置文件路径
BT_SITE_CONFIG_DIR="/www/server/panel/vhost/nginx"

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

echo "开始检测宝塔面板网站的伪静态规则设置情况..."
echo "----------------------------------------"

# 生成排除参数
exclude_args=()
for pattern in "${EXCLUDE_FILES[@]}"; do
    exclude_args+=(! -name "${pattern}.conf")
done

# 遍历所有网站的Nginx配置文件(排除系统文件)
while IFS= read -r -d '' config_file; do
    site_name=$(basename "${config_file}" .conf)
    ((total_sites++))
    
    # 检查是否包含rewrite规则
    if grep -q "rewrite" "${config_file}"; then
        ((has_rewrite++))
    else
        no_rewrite_sites+=("${site_name}")
        ((no_rewrite++))
    fi
done < <(find "${BT_SITE_CONFIG_DIR}" -maxdepth 1 -type f -name "*.conf" "${exclude_args[@]}" -print0)

# 输出未设置伪静态的网站列表
if [ ${#no_rewrite_sites[@]} -gt 0 ]; then
    echo "以下网站未设置伪静态规则："
    for site in "${no_rewrite_sites[@]}"; do
        echo "  × ${site}"
    done
else
    echo "所有网站均已设置伪静态规则"
fi

echo "----------------------------------------"
echo "检测完成！统计结果："
echo "总网站数量: ${total_sites}"
echo "已设置伪静态规则的网站: ${has_rewrite}"
echo "未设置伪静态规则的网站: ${no_rewrite}"
