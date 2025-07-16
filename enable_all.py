#宝塔nginx防火墙专业版插件一键开启禁止国外访问或cdn脚本
#使用方法：将本脚本上传到宝塔面板目录 /www/server/btwaf/enable_all.py，然后使用以下命令
#ssh连接服务器，赋予执行权限   chmod +x /www/server/btwaf/enable_all.py，然后测试执行或计划任务添加Shell脚本任务执行   python3 /www/server/btwaf/enable_all.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os

site_json_path = '/www/server/btwaf/site.json'

if not os.path.exists(site_json_path):
    print("site.json 文件不存在！")
    exit(1)

with open(site_json_path, 'r', encoding='utf-8') as f:
    data = json.load(f)

changed = False
for site, conf in data.items():
    if conf.get('cdn') != True:
        conf['cdn'] = True
        changed = True
    if conf.get('drop_abroad') != True:
        conf['drop_abroad'] = True
        changed = True

if changed:
    with open(site_json_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    # 重载防火墙服务（可选，视你的环境而定）
    os.system('btwaf')
    print('所有站点已批量开启禁止国外访问和CDN，并已重载防火墙。')
else:
    print('所有站点已是开启状态，无需更改。')