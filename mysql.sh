# 获取MySQL服务状态，并检查服务是否处于“active”状态
status=$(systemctl is-active mysqld)

# 检查服务状态
if [ "$status" != "active" ];
then
    echo -e "\n$(date '+%Y-%m-%d %H:%M:%S') MySQL 服务异常，尝试重启"
    # 宝塔面板的MySQL服务名称可能为mysqld、mysql或bt-mysql，此处使用mysqld，如果失败请根据实际情况调整
    systemctl restart mysqld
    echo "$(date '+%Y-%m-%d %H:%M:%S') 重启完成"
else
    echo $(date '+%F %T') "MySQL正在运行..."
    exit 0;
fi
