#MySQL运行监测脚本，计划任务开启Shell脚本每1分钟执行，服务器重启等异常会停止运行MySQL，用这个脚本监测运行状态及自动开启MySQL
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
