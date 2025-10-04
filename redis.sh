#redis运行监测脚本，计划任务开启Shell脚本每1分钟执行，服务器重启等异常会停止运行redis，用这个脚本监测运行状态及自动开启redis
ps=`ps -efl|grep redis|grep -v $0|grep -v grep|wc -l`
if [ $ps -eq 0 ];
then
    echo -e "\n$(date '+%Y-%m-%d %H:%M:%S') start "
    /etc/init.d/redis start
    echo "$(date '+%Y-%m-%d %H:%M:%S') done"
else
    echo $(date +%F%n%T) "redis正在运行..."
    exit 0;
fi
