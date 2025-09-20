#!/bin/bash
#检查伪静态是否设置及批量设置伪静态
#使用方法：新建添加程序的伪静态规则（nginx规则）并保存，如maccms-v10程序，maccms10.conf（字母前面不能加数字等特殊字符会报错导致不成功），一切就绪后复制本脚本添加到计划任务Shell脚本以root执行使用

# 伪静态规则文件存储路径
BT_SITE_REWRITE_DIR="/www/server/panel/vhost/rewrite"

# maccms10 伪静态规则文件
maccms10_REWRITE_FILE="/www/server/panel/rewrite/nginx/maccms10.conf"

# 统计变量
has_rewrite=0
no_rewrite=0
total_sites=0
no_rewrite_sites=()

echo "开始批量设置宝塔面板网站的伪静态规则..."
echo "----------------------------------------"

# 遍历所有网站的伪静态规则配置文件
while IFS= read -r -d '' rewrite_config_file; do
    site_name=$(basename "${rewrite_config_file}" .conf)
    ((total_sites++))
    
    # 检查文件大小是否为0B
    if [ ! -s "$rewrite_config_file" ]; then
        # 如果是0B，写入 maccms10 伪静态规则
        echo "为站点 ${site_name} 添加 maccms10 伪静态规则..."
        
        # 将 maccms10 伪静态规则写入该文件
        cp "$maccms10_REWRITE_FILE" "$rewrite_config_file"
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
done < <(find "${BT_SITE_REWRITE_DIR}" -maxdepth 1 -type f -name "*.conf" -print0)

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
