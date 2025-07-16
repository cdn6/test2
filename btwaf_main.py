# coding: utf-8
# +-------------------------------------------------------------------
# | 宝塔Linux面板
# +-------------------------------------------------------------------
# | Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
# +-------------------------------------------------------------------
# | Author: 黄文良 <287962566@qq.com>
# | Author: 梁凯强 <1249648969@qq.com>
# +-------------------------------------------------------------------
# +--------------------------------------------------------------------
# |   宝塔网站防火墙
# +--------------------------------------------------------------------
import totle_db
import totle_db2
import totle_db3
import sys, base64, binascii

sys.path.append('/www/server/panel/class')
import json, os, time, public, string, re, hashlib

os.chdir('/www/server/panel')
if __name__ != '__main__':
    from panelAuth import panelAuth
import ipaddress
# import db2
import time, datetime


class mobj:
    siteName = ''


class LuaMaker(set):
    """
    lua 处理器
    """

    @staticmethod
    def makeLuaTable(table):
        """
        table 转换为 lua table 字符串
        """
        _tableMask = {}
        _keyMask = {}

        def analysisTable(_table, _indent, _parent):
            if isinstance(_table, tuple):
                _table = list(_table)
            if isinstance(_table, list):
                _table = dict(zip(range(1, len(_table) + 1), _table))
            if isinstance(_table, dict):
                _tableMask[id(_table)] = _parent
                cell = []
                thisIndent = _indent + "    "
                for k in _table:
                    if sys.version_info[0] == 2:
                        if type(k) not in [int, float, bool, list, dict, tuple]:
                            k = k.encode()

                    if not (isinstance(k, str) or isinstance(k, int) or isinstance(k, float)):
                        return
                    key = isinstance(k, int) and "[" + str(k) + "]" or "[\"" + str(k) + "\"]"
                    if _parent + key in _keyMask.keys():
                        return
                    _keyMask[_parent + key] = True
                    var = None
                    v = _table[k]
                    if sys.version_info[0] == 2:
                        if type(v) not in [int, float, bool, list, dict, tuple]:
                            v = v.encode()
                    if isinstance(v, str):
                        var = "\"" + v + "\""
                    elif isinstance(v, bool):
                        var = v and "true" or "false"
                    elif isinstance(v, int) or isinstance(v, float):
                        var = str(v)
                    else:
                        var = analysisTable(v, thisIndent, _parent + key)
                    cell.append(thisIndent + key + " = " + str(var))
                lineJoin = ",\n"
                return "{\n" + lineJoin.join(cell) + "\n" + _indent + "}"
            else:
                pass

        return analysisTable(table, "", "root")


class btwaf_main:
    __to_lua_table = LuaMaker()
    __path = '/www/server/btwaf/'
    __state = {True: '开启', False: '关闭', 0: '停用', 1: '启用'}
    __config = None
    __webshell = '/www/server/btwaf/webshell.json'
    __wubao = '/www/server/panel/plugin/btwaf/wubao.json'
    __rule_path = ["args.json", "cookie.json", "post.json", "url_white.json", "url.json", "user_agent.json"]
    __isFirewalld = False
    __isUfw = False
    __Obj = None
    __webshell_data = []
    __session_name = None
    __PATH = '/www/server/panel/plugin/btwaf/'
    Recycle_bin = __PATH + 'Recycle/'

    __cms_list = {"EcShop": ["/ecshop/api/cron.php", "/appserver/public/js/main.js",
                             "/ecshop/js/index.js", "/ecshop/data/config.php"],
                  "weiqin": ["/framework/table/users.table.php", "/payment/alipay/return.php",
                             "/web/common/bootstrap.sys.inc.php"],
                  "haiyang": ["/data/admin/ping.php", "/js/history.js", "/templets/default/html/topicindex.html"],
                  "canzhi": ["/system/module/action/js/history.js", "/system/framework/base/control.class.php",
                             "/www/data/css/default_clean_en.css"],
                  "pingguo": ["/static/js/jquery.pngFix.js", "/static/css/admin_style.css",
                              "/template/default_pc/js/jquery-autocomplete.js"],
                  "PHPCMS": ["/phpsso_server/statics/css/system.css", "/phpcms/languages/en/cnzz.lang.php",
                             "/api/reg_send_sms.php"],
                  "wordpress": ["/wp-content/languages/admin-network-zh_CN.mo", "/wp-includes/js/admin-bar.js",
                                "/wp-admin/css/colors/ocean/colors.css"],
                  "zhimeng": ["/include/calendar/calendar-win2k-1.css", "/include/js/jquery/ui.tabs.js",
                              "/inc/inc_stat.php", "/images/js/ui.core.js"],
                  "Discuz": ["/static/js/admincp.js", "/api/javascript/javascript.php", "/api/trade/notify_invite.php"],
                  "metlnfo": ["/admin/content/article/save.php", "/app/system/column", "/config/metinfo.inc.php"]}

    def __init__(self):

        # 判断/www/server/btwaf/totla_db/totla_db.db 的权限是否是root
        if os.path.exists('/www/server/btwaf/totla_db/totla_db.db'):
            # 获取文件的用户权限
            user = os.stat('/www/server/btwaf/totla_db/totla_db.db').st_uid
            if user == "0" or user == 0:
                public.ExecShell("chown www:www /www/server/btwaf/totla_db/totla_db.db")
        if not os.path.exists(self.Recycle_bin):
            os.makedirs(self.Recycle_bin)
        if not os.path.exists('/www/wwwlogs/btwaf'):
            os.system("mkdir /www/wwwlogs/btwaf -p && chmod 777 /www/wwwlogs/btwaf")
        if os.path.exists('/usr/sbin/firewalld'): self.__isFirewalld = True
        if os.path.exists('/usr/sbin/ufw'): self.__isUfw = True
        if not self.__session_name:
            self.__session_name = self.__get_md5('btwa1f_sesssion_time' + time.strftime('%Y-%m-%d'))
        if not os.path.exists(self.__webshell):
            os.system("echo '[]'>/www/server/btwaf/webshell.json && chown www:www /www/server/btwaf/webshell.json")
        if not public.M('sqlite_master').where('type=? AND name=?', ('table', 'send_settings')).count():
            public.M('').execute('''CREATE TABLE "send_settings" (
                    "id" INTEGER PRIMARY KEY AUTOINCREMENT,"name" TEXT,"type" TEXT,"path" TEXT,"send_type" TEXT,"last_time" TEXT ,"time_frame" TEXT,"inser_time" TEXT DEFAULT'');''')
        if not public.M('sqlite_master').where('type=? AND name=?', ('table', 'send_msg')).count():
            public.M('').execute(
                '''CREATE TABLE "send_msg" ("id" INTEGER PRIMARY KEY AUTOINCREMENT,"name" TEXT,"send_type" TEXT,"msg" TEXT,"is_send" TEXT,"type" TEXT,"inser_time" TEXT DEFAULT '');''')

    def to_str(self, bytes_or_str):
        try:
            if isinstance(bytes_or_str, bytes):
                value = bytes_or_str.decode('utf-8')
            else:
                value = bytes_or_str
            return value
        except:
            return str(bytes_or_str)

    def index(self, args):
        if 'export' in args:
            return self.export_info(args)
        if self.is_check_version():
            from BTPanel import render_template_string, g
            str_templste = public.ReadFile('{}/templates/index.html'.format(self.__PATH))
            try:
                g.btwaf_version = json.loads(public.ReadFile('{}/info.json'.format(self.__PATH)))['versions']
            except:
                g.btwaf_version = '8.8.5'
            return render_template_string(str_templste, data={})
        else:
            from BTPanel import render_template_string, g
            str_templste = public.ReadFile('{}/templates/error4.html'.format(self.__PATH))
            try:
                g.btwaf_version = json.loads(public.ReadFile('{}/info.json'.format(self.__PATH)))['versions']
            except:
                g.btwaf_version = '8.8.5'
            return render_template_string(str_templste, data={})

    def index2(self, args):
        if self.is_check_version():
            from BTPanel import render_template_string, g
            str_templste = public.ReadFile('{}/templates/index.html'.format(self.__PATH))
            try:
                g.btwaf_version = json.loads(public.ReadFile('{}/info.json'.format(self.__PATH)))['versions']
            except:
                g.btwaf_version = '8.8.5'
            return render_template_string(str_templste, data={})
        else:
            from BTPanel import render_template_string, g
            str_templste = public.ReadFile('{}/templates/error4.html'.format(self.__PATH))
            try:
                g.btwaf_version = json.loads(public.ReadFile('{}/info.json'.format(self.__PATH)))['versions']
            except:
                g.btwaf_version = '8.8.5'
            return render_template_string(str_templste, data={})

    def M3(self, table):
        with totle_db.Sql() as sql:
            return sql.table(table)

    def M2(self, table):
        with totle_db2.Sql() as sql:
            return sql.table(table)

    # def M3(self,table):
    #     with db2.Sql() as sql:
    #         return sql.table(table)

    def is_check_time(self, tie, count_time, is_time, type_chekc):
        if type_chekc == '>':
            if 'is_status' in tie:
                if tie['is_status'] == False:
                    return False
            if int(tie['time'] + count_time) > int(is_time):
                return True
            else:
                return False
        if type_chekc == '<':
            if 'is_status' in tie:
                if tie['is_status'] == False: return False
            if int(tie['time'] + count_time) < int(is_time):
                return True
            else:
                return False
        else:
            return False

    def get_blocking_ip_logs(self, get):
        return self.M2('blocking_ip').field(
            'time,time_localtime,server_name,ip,blocking_time,is_status').where(
            "time>=?", int(time.time()) - 86400).order('id desc').select()

    def test222(self, get):
        self.M2('blocking_ip').field(
            'time,time_localtime,server_name,ip,blocking_time,is_status').order('id desc').select()

    def get_total_all_overview(self, get):
        result = {}
        # 封锁IP24小时内封锁   正在封锁的数量
        result['day24_lan'] = {}
        ### 拦截状态
        result['day24_lan']['is_count_ip'] = 0
        result['day24_lan']['info'] = []
        result['day24_lan']['day_count'] = 0

        result['map'] = {}
        result['map']['info'] = {}
        result['map']['24_day_count'] = 0
        result['map']['1_day_count'] = 0
        result['map']['top10_ip'] = {}
        result['map']['24_day_count'] = 0

        if not 'start_time' in get:
            start_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
        else:
            start_time = get.start_time.strip()
        if not 'end_time' in get:
            # end_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
            end_time = start_time
        else:
            end_time = get.end_time.strip()
        start_time = start_time + ' 00:00:00'
        end_time2 = end_time + ' 23:59:59'
        start_timeStamp = int(time.mktime(time.strptime(start_time, '%Y-%m-%d %H:%M:%S')))
        end_timeStamp = int(time.mktime(time.strptime(end_time2, '%Y-%m-%d %H:%M:%S')))

        if os.path.exists("/www/server/btwaf/totla_db/totla_db.db"):
            day_24_data = self.M2('blocking_ip').field(
                'time,time_localtime,server_name,ip,ip_country,ip_country,ip_city,ip_subdivisions,blocking_time,is_status').where(
                "time>=? and time<=?", (start_timeStamp, end_timeStamp)).order('id desc').limit("1000").select()

            is_time = time.time()
            if type(day_24_data) == str:
                if day_24_data == "error: file is encrypted or is not a database" or day_24_data == "error: database disk image is malformed":
                    try:
                        os.remove("/www/server/btwaf/totla_db/totla_db.db")
                    except:
                        pass
                return result
            result['day24_lan']['day_count'] = len(day_24_data)
            if len(day_24_data) == 0:
                day_24_data = self.M2('blocking_ip').field(
                    'time,time_localtime,server_name,ip,ip_country,ip_country,ip_city,ip_subdivisions,blocking_time,is_status').limit(
                    "30").order('id desc').select()
                for i in day_24_data:
                    if not i['is_status']: continue
                    check = self.is_check_time(i, i['blocking_time'], is_time, '>')
                    i['is_status'] = check
                    if check: result['day24_lan']['is_count_ip'] += 1
            else:
                for i in day_24_data:
                    if not i['is_status']: continue
                    check = self.is_check_time(i, i['blocking_time'], is_time, '>')
                    i['is_status'] = check
                    if check: result['day24_lan']['is_count_ip'] += 1
            if len(day_24_data) > 100:
                day_24_data = day_24_data[0:100]
            result['day24_lan']['info'] = day_24_data
        #
        ##攻击地图+ top10 攻击IP
        result['map'] = {}
        result['map']['info'] = {}
        result['map']['24_day_count'] = 0
        result['map']['1_day_count'] = 0
        result['map']['top10_ip'] = {}
        result['map']['24_day_count'] = 0
        result['map']['count'] = 0
        if os.path.exists("/www/server/btwaf/totla_db/totla_db.db"):

            count = self.M2('totla_log').count()
            if type(count) == "str":
                count = 0
            else:
                count = count
            result['map']['count'] = count

            map_24_data = self.M2('totla_log').field('time,ip,ip_country,ip_city,ip_subdivisions').where(
                "time>=? and time<=?", (start_timeStamp, end_timeStamp)).order(
                'id desc').limit("10000").select()
            if type(map_24_data) == str:
                map_24_data = []
            result['map']['24_day_count'] = len(map_24_data)
            is_time = time.time()

            ip_map = {}
            for i in map_24_data:
                check = self.is_check_time(i, 3600, is_time, '>')
                if check: result['map']['1_day_count'] += 1
                if not ip_map.get(i['ip'] + "country"):
                    ip_map[i['ip'] + "country"] = i['ip_country']
                if not ip_map.get(i['ip'] + "city"):
                    ip_map[i['ip'] + "city"] = i['ip_city']
                if not ip_map.get(i['ip'] + "subdivisions"):
                    ip_map[i['ip'] + "subdivisions"] = i['ip_subdivisions']
                if i['ip'] in result['map']['top10_ip']:
                    result['map']['top10_ip'][i['ip']] = result['map']['top10_ip'][i['ip']] + 1
                else:
                    result['map']['top10_ip'][i['ip']] = 1
                if i['ip_country'] == None: continue
                if i['ip_country'] in result['map']['info']:
                    result['map']['info'][i['ip_country']] = result['map']['info'][i['ip_country']] + 1
                else:
                    result['map']['info'][i['ip_country']] = 1
            if len(result['map']['info']):
                try:
                    result['map']['info'] = (sorted(result['map']['info'].items(), key=lambda kv: (kv[1], kv[0])))[::-1]
                except:
                    pass
            top10_ip = (sorted(result['map']['top10_ip'].items(), key=lambda kv: (kv[1], kv[0])))
            #
            if len(top10_ip) > 30:
                result['map']['top10_ip'] = top10_ip[::-1][:30]
            else:
                result['map']['top10_ip'] = top10_ip[::-1]
            result_top_10 = []
            for i in result['map']['top10_ip']:
                i2 = list(i)
                if ip_map.get(i[0] + "country"):
                    ret = ip_map[i[0] + "country"]
                    i2.append(ret)
                if ip_map.get(i[0] + "subdivisions"):
                    ret = ip_map[i[0] + "subdivisions"]
                    i2.append(ret)
                if ip_map.get(i[0] + "city"):
                    ret = ip_map[i[0] + "city"]
                    i2.append(ret)
                result_top_10.append(i2)
            result['map']['top10_ip'] = result_top_10
            # result
        return result

    def gongji_check(self, tongji):
        for i in range(len(tongji['gongji'])):
            if i == len(tongji['gongji']) - 1:
                del tongji['gongji'][i]
                continue
            tongji['gongji'][i][1] = tongji['gongji'][i + 1][1]
        return tongji

    # 验证Ip是否被封锁
    def is_feng(self, data):
        drop_iplist = self.get_waf_drop_ip(None)
        if 'data' in data:
            for i in data['data']:
                if not i['is_status']:
                    i['is_feng'] = False
                else:
                    if int(i['time'] + i['blocking_time']) > int(time.time()):
                        check = self.is_check_time(i, i['blocking_time'], time.time(), '>')
                        i['is_feng'] = True if i['ip'] in drop_iplist or check else False
                    else:
                        i['is_feng'] = False

    def get_safe_logs_sql(self, get):
        result = {}
        result['page'] = "<div><span class='Pcurrent'>1</span><span class='Pcount'>共0条</span></div>"
        result['data'] = []
        result['count'] = 0
        if 'keyword' in get:
            keyword = get.keyword.strip() + "%"
        else:
            keyword = ""
        flag = False
        if not 'start_time' in get:
            start_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
        else:
            # 判断时间格式
            if not re.match(r'^\d{4}-\d{2}-\d{2}$', get.start_time):
                return public.returnMsg(False, '时间格式错误')
            flag = True
            start_time = get.start_time.strip()
        if not 'end_time' in get:
            end_time = start_time
        else:
            end_time = get.end_time.strip()

        s_time = start_time + ' 00:00:00'
        e_time = end_time + ' 23:59:59'
        start_timeStamp = int(time.mktime(time.strptime(s_time, '%Y-%m-%d %H:%M:%S')))
        end_timeStamp = int(time.mktime(time.strptime(e_time, '%Y-%m-%d %H:%M:%S')))
        if 'limit' in get:
            limit = int(get.limit.strip())
        else:
            limit = 12
        if os.path.exists("/www/server/btwaf/totla_db/totla_db.db"):
            try:
                if self.M2('blocking_ip').order('id desc').count() == 0: return public.returnMsg(True, result)
            except:
                return public.returnMsg(True, result)
            import page
            page = page.Page()
            if keyword:
                if flag:
                    count = self.M2('blocking_ip').where(
                        "time>? and time<? and server_name like ? or ip like ? or ip_city like ? or ip_subdivisions like ? or ip_country like ? or type like ? or uri like ? or user_agent like ? or filter_rule like ?",
                        (start_timeStamp, end_timeStamp, keyword, keyword, keyword, keyword, keyword, keyword, keyword,
                         keyword, keyword)).order('id desc').count()
                else:
                    count = self.M2('blocking_ip').where(
                        "server_name like ? or ip like ? or ip_city like ? or ip_subdivisions like ? or ip_country like ? or type like ? or uri like ? or user_agent like ? or filter_rule like ?",
                        (keyword, keyword, keyword, keyword, keyword, keyword, keyword, keyword, keyword)).order(
                        'id desc').count()
            else:
                if flag:
                    count = self.M2('blocking_ip').where("time>? and time<?", (start_timeStamp, end_timeStamp)).order(
                        'id desc').count()
                else:
                    count = self.M2('blocking_ip').order('id desc').count()
            info = {}
            info['count'] = count
            info['row'] = limit
            info['p'] = 1
            if hasattr(get, 'p'):
                info['p'] = int(get['p'])
            info['uri'] = get
            info['return_js'] = ''
            if hasattr(get, 'tojs'):
                info['return_js'] = get.tojs
            data = {}
            # 获取分页数据
            data['page'] = page.GetPage(info, '1,2,3,4,5,8')
            if keyword:
                if flag:
                    data222 = self.M3('blocking_ip').field(
                        'time,time_localtime,server_name,ip,ip_city,ip_country,ip_subdivisions,ip_longitude,ip_latitude,type,uri,user_agent,filter_rule,incoming_value,value_risk,http_log,http_log_path,blockade,blocking_time,is_status').order(
                        'id desc').where(
                        "time>? and time<? and server_name like ? or ip like ? or ip_city like ? or ip_subdivisions like ? or ip_country like ? or type like ? or uri like ? or user_agent like ? or filter_rule like ?",
                        (start_timeStamp, end_timeStamp, keyword, keyword, keyword, keyword, keyword, keyword, keyword,
                         keyword, keyword)).limit(
                        str(page.SHIFT) + ',' + str(page.ROW)).select()

                else:
                    data222 = self.M3('blocking_ip').field(
                        'time,time_localtime,server_name,ip,ip_city,ip_country,ip_subdivisions,ip_longitude,ip_latitude,type,uri,user_agent,filter_rule,incoming_value,value_risk,http_log,http_log_path,blockade,blocking_time,is_status').order(
                        'id desc').where(
                        "server_name like ? or ip like ? or ip_city like ? or ip_subdivisions like ? or ip_country like ? or type like ? or uri like ? or user_agent like ? or filter_rule like ?",
                        (keyword, keyword, keyword, keyword, keyword, keyword, keyword, keyword, keyword)).limit(
                        str(page.SHIFT) + ',' + str(page.ROW)).select()
            else:
                if flag:
                    data222 = self.M3('blocking_ip').field(
                        'time,time_localtime,server_name,ip,ip_city,ip_country,ip_subdivisions,ip_longitude,ip_latitude,type,uri,user_agent,filter_rule,incoming_value,value_risk,http_log,http_log_path,blockade,blocking_time,is_status').order(
                        'id desc').where("time>? and time<?", (start_timeStamp, end_timeStamp)).limit(
                        str(page.SHIFT) + ',' + str(page.ROW)).select()

                else:
                    data222 = self.M3('blocking_ip').field(
                        'time,time_localtime,server_name,ip,ip_city,ip_country,ip_subdivisions,ip_longitude,ip_latitude,type,uri,user_agent,filter_rule,incoming_value,value_risk,http_log,http_log_path,blockade,blocking_time,is_status').order(
                        'id desc').limit(str(page.SHIFT) + ',' + str(page.ROW)).select()

            data['data'] = self.bytpes_to_string(data222)
            data['count'] = count
            self.is_feng(data)
            return public.returnMsg(True, data)
        return public.returnMsg(True, result)

    def get_all_tu(self, get):

        result = {}
        time_xianzai = int(time.time())
        # 攻击趋势图
        result['gongji'] = []
        result['server_name_top5'] = {}
        result['dongtai'] = {}
        if not 'start_time' in get:
            start_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
        else:
            start_time = get.start_time.strip()
        if not 'end_time' in get:
            # end_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
            end_time = start_time
        else:
            end_time = get.end_time.strip()
        start_time = start_time + ' 00:00:00'
        end_time2 = end_time + ' 23:59:59'
        start_timeStamp = int(time.mktime(time.strptime(start_time, '%Y-%m-%d %H:%M:%S')))
        end_timeStamp = int(time.mktime(time.strptime(end_time2, '%Y-%m-%d %H:%M:%S')))

        if os.path.exists("/www/server/btwaf/totla_db/totla_db.db"):
            for i in range(0, 8):
                day = end_timeStamp - (i * 86400)
                day2 = end_timeStamp - ((i - 1) * 86400)
                jintian = self.M2('totla_log').field('time').where("time>? and time<?", (day, day2)).order(
                    'id desc').limit("10000").count()
                result['gongji'].append([self.dtchg(day), jintian])
            self.gongji_check(result)
            map_24_data = self.M2('totla_log').field('time,server_name').order(
                'id desc').where(
                "time>=? and time<=?", (start_timeStamp, end_timeStamp)).limit("10000").select()
            if type(map_24_data) == str: return result

            if len(map_24_data) >= 1:
                for i in map_24_data:
                    if i['server_name'] in result['server_name_top5']:
                        result['server_name_top5'][i['server_name']] = result['server_name_top5'][i['server_name']] + 1
                    else:
                        result['server_name_top5'][i['server_name']] = 1

            if len(result['server_name_top5']) >= 1:
                server_top5 = (sorted(result['server_name_top5'].items(), key=lambda kv: (kv[1], kv[0])))[::-1]
                if len(server_top5) > 5:
                    result['server_name_top5'] = server_top5[:5]
                else:
                    result['server_name_top5'] = server_top5
            dongtai = self.M2('totla_log').field(
                'id,time,time_localtime,server_name,ip,ip_country,ip_subdivisions,ip_longitude,ip_latitude,type,filter_rule').where(
                "time>=?", int(time.time()) - 86400).order('id desc').limit("20").select()
            if len(dongtai) == 0:
                dongtai = self.M2('totla_log').field(
                    'id,time,time_localtime,server_name,ip,ip_country,ip_subdivisions,ip_longitude,ip_latitude,type,filter_rule').order(
                    'id desc').limit("20").select()
            if dongtai:
                result['dongtai'] = dongtai
        return result

    def btwaf_overview(self, get):
        result = {}

        start_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
        end_time = start_time
        start_time = start_time + ' 00:00:00'
        end_time2 = end_time + ' 23:59:59'
        start_timestamp = int(time.mktime(time.strptime(start_time, '%Y-%m-%d %H:%M:%S')))
        end_timestamp = int(time.mktime(time.strptime(end_time2, '%Y-%m-%d %H:%M:%S')))

        # 获取总览数据
        result["total"] = self.get_total(get)
        result["total"]['webshell'] = self.get_webshell_size()

        # 动态
        result['gongji'] = []
        result['server_name_top5'] = {}
        result['dongtai'] = {}

        # 封锁IP24小时内封锁   正在封锁的数量
        result['day24_lan'] = {}
        ### 拦截状态
        result['day24_lan']['is_count_ip'] = 0
        result['day24_lan']['info'] = []
        result['day24_lan']['day_count'] = 0

        result['map'] = {}
        result['map']['info'] = {}
        result['map']['24_day_count'] = 0
        result['map']['1_day_count'] = 0
        result['map']['top10_ip'] = {}
        result['map']['24_day_count'] = 0

        if os.path.exists("/www/server/btwaf/totla_db/totla_db.db"):
            # 动态内容获取
            dongtai = self.M2('totla_log').field(
                'id,time,time_localtime,server_name,ip,ip_country,ip_subdivisions,filter_rule').order('id desc').limit(
                "20").select()
            if dongtai:
                result['dongtai'] = dongtai

            # 攻击趋势图
            for i in range(0, 8):
                day = start_timestamp - (i * 86400)
                day2 = (start_timestamp - ((i - 1) * 86400)) - 1
                jintian = self.M2('totla_log').field('time').where("time>? and time<?", (day, day2)).order(
                    'id desc').limit("10000").count()
                day_info = time.strftime("%Y-%m-%d", time.localtime(day))
                result["gongji"].append([day_info, jintian])

            # map_24_data 24小时内网站倍攻击的数据
            map_24_data = self.M2('totla_log').field('time,server_name,ip,ip_country,ip_city,ip_subdivisions').order(
                'id desc').where("time>=? and time<=?", (start_timestamp, end_timestamp)).limit("10000").select()
            if type(map_24_data) == str:
                if map_24_data == "error: file is encrypted or is not a database" or map_24_data == "error: database disk image is malformed":
                    try:
                        os.remove("/www/server/btwaf/totla_db/totla_db.db")
                    except:
                        pass
                return result
            if len(map_24_data) >= 1:
                for i in map_24_data:
                    if i['server_name'] in result['server_name_top5']:
                        result['server_name_top5'][i['server_name']] = result['server_name_top5'][i['server_name']] + 1
                    else:
                        result['server_name_top5'][i['server_name']] = 1

            if len(result['server_name_top5']) >= 1:
                server_top5 = (sorted(result['server_name_top5'].items(), key=lambda kv: (kv[1], kv[0])))[::-1]
                if len(server_top5) > 5:
                    result['server_name_top5'] = server_top5[:5]
                else:
                    result['server_name_top5'] = server_top5

            if type(map_24_data) == str:
                map_24_data = []
            result['map']['24_day_count'] = len(map_24_data)
            is_time = time.time()

            ip_map = {}
            for i in map_24_data:
                check = self.is_check_time(i, 3600, is_time, '>')
                if check: result['map']['1_day_count'] += 1
                if not ip_map.get(i['ip'] + "country"):
                    ip_map[i['ip'] + "country"] = i['ip_country']
                if not ip_map.get(i['ip'] + "city"):
                    ip_map[i['ip'] + "city"] = i['ip_city']
                if not ip_map.get(i['ip'] + "subdivisions"):
                    ip_map[i['ip'] + "subdivisions"] = i['ip_subdivisions']
                if i['ip'] in result['map']['top10_ip']:
                    result['map']['top10_ip'][i['ip']] = result['map']['top10_ip'][i['ip']] + 1
                else:
                    result['map']['top10_ip'][i['ip']] = 1
                if i['ip_country'] == None: continue
                if i['ip_country'] in result['map']['info']:
                    result['map']['info'][i['ip_country']] = result['map']['info'][i['ip_country']] + 1
                else:
                    result['map']['info'][i['ip_country']] = 1
            if len(result['map']['info']):
                try:
                    result['map']['info'] = (sorted(result['map']['info'].items(), key=lambda kv: (kv[1], kv[0])))[::-1]
                except:
                    pass
            top10_ip = (sorted(result['map']['top10_ip'].items(), key=lambda kv: (kv[1], kv[0])))
            #
            if len(top10_ip) > 30:
                result['map']['top10_ip'] = top10_ip[::-1][:30]
            else:
                result['map']['top10_ip'] = top10_ip[::-1]
            result_top_10 = []
            for i in result['map']['top10_ip']:
                i2 = list(i)
                if ip_map.get(i[0] + "country"):
                    ret = ip_map[i[0] + "country"]
                    i2.append(ret)
                if ip_map.get(i[0] + "subdivisions"):
                    ret = ip_map[i[0] + "subdivisions"]
                    i2.append(ret)
                if ip_map.get(i[0] + "city"):
                    ret = ip_map[i[0] + "city"]
                    i2.append(ret)
                result_top_10.append(i2)
            result['map']['top10_ip'] = result_top_10

            day_24_data = self.M2('blocking_ip').field(
                'time,time_localtime,server_name,ip,ip_country,ip_country,ip_city,ip_subdivisions,blocking_time,is_status').where(
                "time>=? and time<=?", (start_timestamp, end_timestamp)).order('id desc').limit("1000").select()
            is_time = time.time()
            if type(day_24_data) == str:
                if day_24_data == "error: file is encrypted or is not a database" or day_24_data == "error: database disk image is malformed":
                    try:
                        os.remove("/www/server/btwaf/totla_db/totla_db.db")
                        pass
                    except:
                        pass
                return result
            result['day24_lan']['day_count'] = len(day_24_data)
            if len(day_24_data) == 0:
                day_24_data = self.M2('blocking_ip').field(
                    'time,time_localtime,server_name,ip,ip_country,ip_country,ip_city,ip_subdivisions,blocking_time,is_status').limit(
                    "30").order('id desc').select()
                for i in day_24_data:
                    if not i['is_status']: continue
                    check = self.is_check_time(i, i['blocking_time'], is_time, '>')
                    i['is_status'] = check
                    if check: result['day24_lan']['is_count_ip'] += 1
            else:
                for i in day_24_data:
                    if not i['is_status']: continue
                    check = self.is_check_time(i, i['blocking_time'], is_time, '>')
                    i['is_status'] = check
                    if check: result['day24_lan']['is_count_ip'] += 1
            if len(day_24_data) > 100:
                day_24_data = day_24_data[0:100]
            result['day24_lan']['info'] = day_24_data
        return result

    def remove_waf_drop_ip_data(self, get):
        pass

    '''设置表插入数据'''

    def insert_settings(self, name, type, path, send_type, time_frame=180):
        inser_time = self.dtchg(int(time.time()))
        last_time = int(time.time())
        if public.M('send_settings').where('name=?', (name,)).count(): return False
        data = {"name": name, "type": type, "path": path, "send_type": send_type, "time_frame": time_frame,
                "inser_time": inser_time, "last_time": last_time}
        return public.M('send_settings').insert(data)

    def dtchg(self, x):
        try:
            time_local = time.localtime(float(x))
            dt = time.strftime("%Y-%m-%d %H:%M:%S", time_local)
            return dt
        except:
            return False

    # 返回站点
    def return_site(self, get):
        data = public.M('sites').field('name,path').select()
        ret = {}
        for i in data:
            ret[i['name']] = i['path']
        return public.returnMsg(True, ret)

    # 获取规则
    def shell_get_rule(self, get):
        ret = []
        if os.path.exists(self.__PATH + 'rule.json'):
            try:
                data = json.loads(public.ReadFile(self.__PATH + 'rule.json'))
                return data
            except:
                return False
        else:
            return False

    # 查询站点跟目录
    def getdir(self, dir, pc='', lis=[]):
        try:
            list = os.listdir(dir)
            for l in list:
                if os.path.isdir(dir + '/' + l):
                    lis = self.getdir(dir + '/' + l, pc, lis)
                elif str(l.lower())[-4:] == '.php' and str(dir + '/' + l).find(pc) == -1:
                    print(dir + '/' + l)
                    lis.append(dir + '/' + l)
            return lis
        except:
            return lis

    # 目录
    def getdir_list(self, get):
        path = get.path
        if os.path.exists(path):
            pc = 'hackcnm'
            rs = self.getdir(path, pc)
            return rs
        else:
            return False

    # 扫描
    def scan(self, path, filelist, rule):
        import time
        time_data = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        ret = []
        path_list = self.path_json(path)
        for file in filelist:
            try:
                data = open(file).read()
                for r in rule:
                    if re.compile(r).findall(data):
                        if file in path_list: continue
                        result = {}
                        result[file] = r
                        if result not in ret:
                            ret.append(result)
                        # ret.append(result)
                        data = ("%s [!] %s %s  \n" % (time_data, file, r))
                        self.insert_log(data)
            except:
                pass
        return ret

    def insert_log(self, data):
        public.writeFile(self.__PATH + 'webshell.log', data, 'a+')

    # Log 取100行操作
    def get_log(self, get):
        path = self.__PATH + 'webshell.log'
        if not os.path.exists(path): return False
        return public.GetNumLines(path, 3000)

    # 不是木马的过滤掉
    def path_json(self, path):
        path_file = str(path).replace('/', '')
        if os.path.exists(path):
            if os.path.exists(self.__PATH + path_file + '.json'):
                try:
                    path_data = json.loads(public.ReadFile(self.__PATH + path_file + '.json'))
                    return path_data
                except:
                    ret = []
                    public.WriteFile(self.__PATH + path_file + '.json', json.dumps(ret))
                    return []
            else:
                ret = []
                public.WriteFile(self.__PATH + path_file + '.json', json.dumps(ret))
                return []
        else:
            return []

    def san_dir(self, get):
        result2222 = []
        file = self.getdir_list(get)
        if not file: return public.returnMsg(False, "当前目录中没有php文件")
        rule = self.shell_get_rule(get)
        if not rule: return public.returnMsg(False, "规则为空或者规则文件错误")
        ret = self.scan(get.path, file, rule)
        return ret

    #  xss 防御
    def xssencode(self, text):
        import html
        list = ['`', '~', '&', '<', '>']
        ret = []
        for i in text:
            if i in list:
                i = ''
            ret.append(i)
        str_convert = ''.join(ret)
        text2 = html.escape(str_convert, quote=True)
        return text2

    # 添加规则
    def shell_add_rule(self, get):
        rule = self.xssencode(get.rule)
        ret = []
        if os.path.exists(self.__PATH + 'rule.json'):
            try:
                data = json.loads(public.ReadFile(self.__PATH + 'rule.json'))
                if rule in data:
                    return public.returnMsg(False, '已经存在此规则')
                else:
                    data.append(rule)
                    public.WriteFile(self.__PATH + 'rule.json', json.dumps(data))
                    return public.returnMsg(True, '添加成功')
            except:
                return public.returnMsg(False, '规则库解析错误')
        else:
            return public.returnMsg(False, '规则库文件不存在')

    # 删除规则库
    def shell_del_rule(self, get):
        rule = get.rule
        if os.path.exists(self.__PATH + 'rule.json'):
            try:
                data = json.loads(public.ReadFile(self.__PATH + 'rule.json'))
                if rule in data:
                    data.remove(rule)
                    public.WriteFile(self.__PATH + 'rule.json', json.dumps(data))
                    return public.returnMsg(True, '删除成功')
                else:
                    return public.returnMsg(False, '规则库不存在此规则')
            except:
                return public.returnMsg(False, '规则库解析错误')
        else:
            return public.returnMsg(False, '规则库文件不存在')

    # 标记不是木马
    def lock_not_webshell(self, get):
        path = get.path
        not_path = get.not_path
        if not os.path.exists(not_path): return public.returnMsg(False, '文件不存在')
        path_file = str(path).replace('/', '')
        if not os.path.exists(self.__PATH + path_file + '.json'):
            ret = []
            ret.append(not_path)
            public.WriteFile(self.__PATH + path_file + '.json', json.dumps(ret))
        else:
            try:
                path_data = json.loads(public.ReadFile(self.__PATH + path_file + '.json'))
                if not not_path in path_data:
                    path_data.append(not_path)
                    public.WriteFile(self.__PATH + path_file + '.json', json.dumps(path_data))
                    return public.returnMsg(True, '添加成功')
                else:
                    return public.returnMsg(False, '已经存在')
            except:
                ret = []
                ret.append(not_path)
                public.WriteFile(self.__PATH + path_file + '.json', json.dumps(ret))
                return public.returnMsg(True, '11111111')

    '''
    @name 上传到云端判断是否是webshell
    @param filename 文件路径
    @param url 云端URL
    @return bool 
    '''

    def webshellchop(self, filename, url):
        try:
            import requests
            upload_url = url
            size = os.path.getsize(filename)
            if size > 1024000: return public.returnMsg(True, '未查出风险,需等待一段时间后查询')
            try:
                self.__user = json.loads(public.ReadFile('/www/server/panel/data/userInfo.json'))
            except:
                self.__user = []
                pass
            if len(self.__user) == 0: return public.returnMsg(True, '未查出风险,需等待一段时间后查询')
            upload_data = {'inputfile': public.ReadFile(filename), "md5": self.read_file_md5(filename),
                           "path": filename, "access_key": self.__user['access_key'], "uid": self.__user['uid'],
                           "username": self.__user["username"]}
            upload_res = requests.post(upload_url, upload_data, timeout=20).json()
            if upload_res['msg'] == 'ok':
                if (upload_res['data']['data']['level'] == 5):
                    shell_insert = {'filename': filename, "hash": upload_res['data']['data']['hash']}
                    self.send_baota2(filename)
                    return public.returnMsg(True, '此文件为webshell')
                elif upload_res['data']['level'] >= 3:
                    self.send_baota2(filename)
                    return public.returnMsg(True, '未查出风险,需等待一段时间后查询')
                return public.returnMsg(True, '未查出风险,需等待一段时间后查询')
        except:
            return public.returnMsg(True, '未查出风险,需等待一段时间后查询')

    def upload_file_url(self, get):
        return self.webshellchop(get.filename, "http://w-check.bt.cn/check.php")

    # webshell 流量查杀
    def get_webshell(self, get):
        try:
            data = json.loads(public.ReadFile(self.__webshell))
            return public.returnMsg(True, data)
        except:
            os.system("echo '[]'>/www/server/btwaf/webshell.json && chown www:www /www/server/btwaf/webshell.json")
            return public.returnMsg(True, [])

    # 打开二进制文件并计算md5
    def read_file_md5(self, filename):
        if os.path.exists(filename):
            with open(filename, 'rb') as fp:
                data = fp.read()
            file_md5 = hashlib.md5(data).hexdigest()
            return file_md5
        else:
            return False

    def send_baota2(self, filename):
        cloudUrl = 'http://www.bt.cn/api/panel/btwaf_submit'
        pdata = {'codetxt': public.ReadFile(filename), 'md5': self.read_file_md5(filename), 'type': '0',
                 'host_ip': public.GetLocalIp(), 'size': os.path.getsize(filename)}
        ret = public.httpPost(cloudUrl, pdata)
        return True

    # get_url
    def get_check_url(self, filename):
        try:
            import requests
            ret = requests.get('http://www.bt.cn/checkWebShell.php').json()
            if ret['status']:
                upload_url = ret['url']
                size = os.path.getsize(filename)
                if size > 1024000: return False
                upload_data = {'inputfile': public.ReadFile(filename)}
                upload_res = requests.post(upload_url, upload_data, timeout=20).json()
                if upload_res['msg'] == 'ok':
                    if (upload_res['data']['data']['level'] == 5):
                        self.send_baota2(filename)
                        return public.returnMsg(False, '当前文件为webshell')
                    elif upload_res['data']['level'] >= 3:
                        self.send_baota2(filename)
                        return public.returnMsg(False, '可疑文件,建议手工检查')
                    return public.returnMsg(True, '无风险')
            return public.returnMsg(True, '无风险')
        except:
            return public.returnMsg(True, '无风险')

    # 上传云端
    def send_baota(self, get):
        '''
        filename  文件
        '''
        try:
            if os.path.exists(get.filename):
                return self.get_check_url(get.filename)
            else:
                return public.returnMsg(True, '无风险')
        except:
            return public.returnMsg(True, '无风险')

    # 检测是否是木马
    def check_webshell(self, get):
        if 'filename' not in get: return public.returnMsg(False, '请选择你需要上传的文件')
        if not os.path.exists(get.filename): return public.returnMsg(False, '文件不存在')
        cloudUrl = 'http://www.bt.cn/api/panel/btwaf_check_file'
        pdata = {'md5': self.read_file_md5(get.filename), 'size': os.path.getsize(get.filename)}
        ret = public.httpPost(cloudUrl, pdata)
        if ret == '0':
            return public.returnMsg(True, '未查出风险,需等待一段时间后查询')
        elif ret == '1':
            return public.returnMsg(True, '该文件经过系统检测为webshell！！！！')
        elif ret == '-1':
            return public.returnMsg(True, '未查询到该文件,请上传检测')
        else:
            return public.returnMsg(False, '系统错误')

    # 删除列表中的一条数据
    def del_webshell_list(self, get):
        if 'path' not in get: return public.returnMsg(False, '请填写你需要删除的路径')
        if not os.path.exists(self.__wubao):

            public.WriteFile(self.__wubao, json.dumps([get.path.strip()]))
            list_data = json.loads(public.ReadFile(self.__webshell))
            if get.path in list_data:
                list_data.remove(get.path)
                public.writeFile(self.__webshell, json.dumps(list_data))
                return public.returnMsg(True, '添加成功')
            else:
                return public.returnMsg(False, '添加失败')
        else:
            try:
                result = json.loads(public.ReadFile(self.__wubao))
                if not get.path.strip() in result:
                    result.append(get.path.strip())
                    public.WriteFile(self.__wubao, json.dumps(result))
                list_data = json.loads(public.ReadFile(self.__webshell))
                if get.path in list_data:
                    list_data.remove(get.path)
                    public.writeFile(self.__webshell, json.dumps(list_data))
                    return public.returnMsg(True, '添加成功')
                else:
                    return public.returnMsg(False, '添加失败')
            except:
                public.WriteFile(self.__wubao, json.dumps([get.path.strip()]))
                list_data = json.loads(public.ReadFile(self.__webshell))
                if get.path in list_data:
                    list_data.remove(get.path)
                    public.writeFile(self.__webshell, json.dumps(list_data))
                    return public.returnMsg(True, '添加成功')
                else:
                    return public.returnMsg(False, '添加失败')

    def __get_md5(self, s):
        m = hashlib.md5()
        m.update(s.encode('utf-8'))
        return m.hexdigest()

    # 查看UA白名单 ua_white
    def get_ua_white(self, get):
        config = self.get_config(None)
        url_find_list = config['ua_white']
        return public.returnMsg(True, url_find_list)

    # 添加UA 白名单 ua_white
    def add_ua_white(self, get):
        url_find = get.ua_white
        config = self.get_config(None)
        url_find_list = config['ua_white']
        if url_find in url_find_list:
            return public.returnMsg(False, '已经存在')
        else:
            url_find_list.append(url_find)
            self.__write_config(config)
            return public.returnMsg(True, '添加成功')

    # 导入UA白名单
    def add_ua_list(self, get):
        if 'json' not in get:
            get.json = True
        else:
            get.json = False
        if get.json:
            pdata = json.loads(get.pdata)
        else:
            pdata = get.pdata.strip().split('\n')
        if not pdata: return public.returnMsg(False, '不能为空')
        for i in pdata:
            get.ua_white = i
            self.add_ua_white(get)
        return public.returnMsg(True, '导入成功')

    # 删除UA 白名单 ua_white
    def del_ua_white(self, get):
        url_find = get.ua_white
        config = self.get_config(None)
        url_find_list = config['ua_white']
        if url_find in url_find_list:
            url_find_list.remove(url_find)
            self.__write_config(config)
            return public.returnMsg(True, '删除成功')
        else:
            return public.returnMsg(False, '不存在')

    # 查看ua 黑名单ua_black
    def get_ua_black(self, get):
        config = self.get_config(None)
        url_find_list = config['ua_black']
        return public.returnMsg(True, url_find_list)

    # 导入UA黑名单
    def add_black_list(self, get):
        if 'json' not in get:
            get.json = True
        else:
            get.json = False
        if get.json:
            pdata = json.loads(get.pdata)
        else:
            pdata = get.pdata.strip().split('\n')
        if not pdata: return public.returnMsg(False, '不能为空')
        for i in pdata:
            get.ua_black = i
            self.add_ua_black(get)
        return public.returnMsg(True, '导入成功')

    # 添加UA 黑名单ua_black
    def add_ua_black(self, get):
        url_find = get.ua_black
        config = self.get_config(None)
        url_find_list = config['ua_black']
        if url_find in url_find_list:
            return public.returnMsg(False, '已经存在')
        else:
            url_find_list.append(url_find)
            self.__write_config(config)
            return public.returnMsg(True, '添加成功')

    # 删除UA 黑名单 ua_black
    def del_ua_black(self, get):
        url_find = get.ua_black
        config = self.get_config(None)
        url_find_list = config['ua_black']
        if url_find in url_find_list:
            url_find_list.remove(url_find)
            self.__write_config(config)
            return public.returnMsg(True, '删除成功')
        else:
            return public.returnMsg(False, '不存在')

    # 查看URL_FIND
    def get_url_find(self, get):
        config = self.get_config(None)
        url_find_list = config['uri_find']
        return public.returnMsg(True, url_find_list)

    # 导入URL拦截
    def add_url_list(self, get):
        if 'json' not in get:
            get.json = True
        else:
            get.json = False
        if get.json:
            pdata = json.loads(get.pdata)
        else:
            pdata = get.pdata.strip().split()
        if not pdata: return public.returnMsg(False, '不能为空')
        for i in pdata:
            get.url_find = i
            self.add_url_find(get)
        return public.returnMsg(True, '导入成功')

    # 添加URL FIND
    def add_url_find(self, get):
        url_find = get.url_find
        config = self.get_config(None)
        url_find_list = config['uri_find']
        if url_find in url_find_list:
            return public.returnMsg(False, '已经存在')
        else:
            url_find_list.append(url_find)
            self.__write_config(config)
            return public.returnMsg(True, '添加成功')

    # 添加URL FIND
    def del_url_find(self, get):
        url_find = get.url_find
        config = self.get_config(None)
        url_find_list = config['uri_find']
        if url_find in url_find_list:
            url_find_list.remove(url_find)
            self.__write_config(config)
            return public.returnMsg(True, '删除成功')
        else:
            return public.returnMsg(False, '不存在')

    def check_herader2(self, data, method_type):
        for i in data:
            if method_type == i[0]:
                return True
        return False

    # 删除请求类型
    def add_method_type(self, get):
        config = self.get_config(None)
        check = get.check.strip()
        if not check in ['0', '1']: return public.returnMsg(False, '类型错误')
        if int(check) == 0:
            check = False
        else:
            check = True
        url_find_list = config['method_type']
        if not self.check_herader2(url_find_list, get.method_type.strip()):
            return public.returnMsg(False, '不存在')
        else:
            for i in url_find_list:
                if get.method_type.strip() == i[0]:
                    i[1] = check
            self.__write_config(config)
            return public.returnMsg(True, '修改成功')

    # 删除请求类型
    def del_header_len(self, get):
        header_type = get.header_type.strip()
        header_len = get.header_type_len.strip()
        config = self.get_config(None)
        url_find_list = config['header_len']
        if not self.check_herader(url_find_list, header_type):
            return public.returnMsg(False, '不存在')
        else:
            url_find_list.remove([header_type, header_len])
            self.__write_config(config)
            return public.returnMsg(True, '删除成功')

    # 修改
    def edit_header_len(self, get):
        header_type = get.header_type.strip()
        header_len = get.header_type_len.strip()
        config = self.get_config(None)
        url_find_list = config['header_len']
        if self.check_herader(url_find_list, header_type):
            for i in url_find_list:
                if header_type == i[0]:
                    i[1] = header_len
            self.__write_config(config)
            return public.returnMsg(True, '修改成功')
        else:
            return public.returnMsg(False, '不存在')

    def check_herader(self, data, header):
        for i in data:
            if header == i[0]:
                return True
        return False

    # 添加
    def add_header_len(self, get):
        header_type = get.header_type.strip()
        header_len = get.header_type_len.strip()
        config = self.get_config(None)
        url_find_list = config['header_len']
        if self.check_herader(url_find_list, header_type):
            return public.returnMsg(False, '已经存在')
        else:
            url_find_list.append([header_type, header_len])
            self.__write_config(config)
            return public.returnMsg(True, '添加成功')

    # 查看URL_FIND
    def get_url_white_chekc(self, get):
        config = self.get_config(None)
        url_find_list = config['url_white_chekc']
        return public.returnMsg(True, url_find_list)

    # 添加URL FIND
    def add_url_white_chekc(self, get):
        url_find = get.url_find
        config = self.get_config(None)
        url_find_list = config['url_white_chekc']
        if url_find in url_find_list:
            return public.returnMsg(False, '已经存在')
        else:
            url_find_list.append(url_find)
            self.__write_config(config)
            return public.returnMsg(True, '添加成功')

    # 添加URL FIND
    def del_url_white_chekc(self, get):
        url_find = get.url_find
        config = self.get_config(None)
        url_find_list = config['url_white_chekc']
        if url_find in url_find_list:
            url_find_list.remove(url_find)
            self.__write_config(config)
            return public.returnMsg(True, '删除成功')
        else:
            return public.returnMsg(False, '不存在')

    def get_cc_status(self, get):
        config = self.get_config(None)
        if config['cc_automatic']:
            return public.returnMsg(True, '')
        else:
            return public.returnMsg(False, '')

    def stop_cc_status(self, get):
        # config = self.get_config(None)
        # config['cc_automatic'] = False
        # self.__write_config(config)
        # site_conf = self.get_site_config(None)
        # for i in site_conf:
        #     site_conf[i]['cc_automatic'] = False
        # self.__write_site_config(site_conf)
        # time.sleep(0.2)
        return public.returnMsg(True, '关闭成功')

    def start_cc_status(self, get):
        # config = self.get_config(None)
        # config['cc_automatic'] = True
        # site_conf=self.get_site_config(None)
        # for i in site_conf:
        #     site_conf[i]['cc_automatic'] = True
        # self.__write_site_config(site_conf)
        # self.__write_config(config)
        # time.sleep(0.2)
        return public.returnMsg(True, '开启成功')

    def isDigit(self, x):
        try:
            x = int(x)
            return isinstance(x, int)
        except ValueError:
            return False

    def set_cc_automatic(self, get):
        cc_time = get.cc_time
        cc_retry_cycle = get.cc_retry_cycle
        config = self.get_config(None)
        if not self.isDigit(cc_time) and not self.isDigit(cc_retry_cycle): return public.returnMsg(False,
                                                                                                   '需要设置数字!')
        config['cc_time'] = int(cc_time)
        config['cc_retry_cycle'] = int(cc_retry_cycle)
        site_conf = self.get_site_config(None)
        for i in site_conf:
            site_conf[i]['cc_time'] = int(cc_time)
            site_conf[i]['cc_retry_cycle'] = int(cc_retry_cycle)
        self.__write_site_config(site_conf)
        self.__write_config(config)
        return public.returnMsg(True, '设置成功!')

    # 设置全局uri 增强白名单
    def golbls_cc_zeng(self, get):
        if os.path.exists(self.__path + 'rule/cc_uri_white.json'):
            data = public.ReadFile(self.__path + 'rule/cc_uri_white.json')
            text = self.xssencode((get.text.strip()))
            # return text
            try:
                data = json.loads(data)
                if text in data:
                    return public.returnMsg(False, '已经存在!')
                else:
                    data.append(text)
                    public.WriteFile(self.__path + 'rule/cc_uri_white.json', json.dumps(data))
                    # public.WriteFile(self.__path + 'rule/cc_uri_white.lua', self.__to_lua_table.makeLuaTable(data))
                    return public.returnMsg(True, '设置成功!')
            except:
                ret = []
                ret.append(self.xssencode((get.text.strip())))
                public.WriteFile(self.__path + 'rule/cc_uri_white.json', json.dumps(ret))
                # public.WriteFile(self.__path + 'rule/cc_uri_white.lua', self.__to_lua_table.makeLuaTable(ret))
                return public.returnMsg(True, '设置成功!')
        else:
            ret = []
            ret.append(self.xssencode((get.text.strip())))
            public.WriteFile(self.__path + 'rule/cc_uri_white.json', json.dumps(ret))
            # public.WriteFile(self.__path + 'rule/cc_uri_white.lua', self.__to_lua_table.makeLuaTable(ret))
            return public.returnMsg(True, '设置成功!')

    # 查看
    def get_golbls_cc(self, get):
        if os.path.exists(self.__path + 'rule/cc_uri_white.json'):
            data2 = public.ReadFile(self.__path + 'rule/cc_uri_white.json')
            try:
                data = json.loads(data2)
                return public.returnMsg(True, data)
            except:
                ret = []
                public.WriteFile(self.__path + 'rule/cc_uri_white.json', json.dumps(ret))
                return public.returnMsg(True, '设置成功!')
        else:
            ret = []
            public.WriteFile(self.__path + 'rule/cc_uri_white.json', json.dumps(ret))
            return public.returnMsg(True, ret)

    def del_golbls_cc(self, get):
        if os.path.exists(self.__path + 'rule/cc_uri_white.json'):
            data = public.ReadFile(self.__path + 'rule/cc_uri_white.json')
            text = self.xssencode((get.text.strip()))
            try:
                data = json.loads(data)
                if text in data:
                    data.remove(text)
                    public.WriteFile(self.__path + 'rule/cc_uri_white.json', json.dumps(data))
                    return public.returnMsg(True, '删除成功!')
                else:
                    return public.returnMsg(False, '不存在!')
            except:
                ret = []
                public.WriteFile(self.__path + 'rule/cc_uri_white.json', json.dumps(ret))
                return public.returnMsg(True, '文件解析错误恢复出厂设置!')
        else:
            ret = []
            public.WriteFile(self.__path + 'rule/cc_uri_white.json', json.dumps(ret))
            return public.returnMsg(True, '文件不存在恢复出厂设置!')

    def site_golbls_cc(self, get):
        text = self.xssencode((get.text.strip()))
        data = self.get_site_config(get)
        for i in data:
            if get.siteName == i['siteName']:
                if 'cc_uri_white' not in i:
                    i['cc_uri_white'] = []
                    i['cc_uri_white'].append(text)

                else:
                    if text not in i['cc_uri_white']:
                        i['cc_uri_white'].append(text)
                        self.__write_site_config(data)
                        return public.returnMsg(True, '添加成功')
                    else:
                        return public.returnMsg(False, '已经存在!')
        return public.returnMsg(False, '未知错误!')

    def del_site_golbls_cc(self, get):
        text = self.xssencode((get.text.strip()))
        data = self.get_site_config(get)
        for i in data:
            if get.siteName == i['siteName']:
                if 'cc_uri_white' not in i:
                    i['cc_uri_white'] = []
                else:
                    if text not in i['cc_uri_white']:
                        return public.returnMsg(False, '不存在!')
                    else:
                        if text in i['cc_uri_white']:
                            i['cc_uri_white'].remove(text)
                            self.__write_site_config(data)
                            return public.returnMsg(True, '删除成功')
                        else:
                            return public.returnMsg(False, '不存在!')
        return public.returnMsg(False, '未知错误!')

    # 设置CC全局生效
    def set_cc_golbls(self, get):
        data = self.get_site_config(get)
        ret = []
        for i in data:
            ret.append(i['siteName'])
        if not ret: return False
        site_config = self.get_site_config(None)
        for i in ret:
            get.siteName = i
            site_config = self.set_cc_golbls_siteconfig(get, site_config)
        self.__write_site_config(site_config)
        public.WriteFile('/www/server/btwaf/site.json', json.dumps(site_config, ensure_ascii=False))
        return True

    def set_cc_golbls_siteconfig(self, get, site_config):
        if not 'cc_increase_type' in get: return site_config
        if not get.cc_increase_type in ['js', 'code', 'renji', 'huadong', 'browser']: return site_config
        if not 'cc_mode' in get: get.cc_mode = 1
        if not 'cc_time' in get: get.cc_time = False
        if not 'cc_retry_cycle' in get: get.cc_retry_cycle = False
        if not 'is_cc_url' in get: get.is_cc_url = False
        if not 'cc_ip_max' in get: return site_config
        if type(get.cc_ip_max) != dict: return site_config

        if 'open' not in get.cc_ip_max:
            return site_config
        if 'ip_max' not in get.cc_ip_max:
            return site_config
        if 'static' not in get.cc_ip_max:
            return site_config
        cc_ip_max = get.cc_ip_max

        if 'country' in get:
            try:
                countrysss = get.country.split(",")
                country = {}
                for i in countrysss:
                    i = i.strip()
                    if i:
                        country[i] = i
            except:
                country = {}
        else:
            country = {}
        if get.cc_mode and get.cc_retry_cycle:
            if not self.isDigit(get.cc_mode) and not self.isDigit(get.cc_retry_cycle): return site_config
            site_config[get.siteName]['cc_time'] = int(get.cc_time)
            site_config[get.siteName]['cc_mode'] = int(get.cc_mode)
            site_config[get.siteName]['cc']['cc_mode'] = int(get.cc_mode)
            site_config[get.siteName]['cc_retry_cycle'] = int(get.cc_retry_cycle)
            site_config[get.siteName]['cc_automatic'] = True
            site_config[get.siteName]['cc']['countrys'] = country
            site_config[get.siteName]['cc']['is_cc_url'] = (get.is_cc_url == '1') | False
        else:
            site_config[get.siteName]['cc']['is_cc_url'] = (get.is_cc_url == '1') | False
            site_config[get.siteName]['cc']['countrys'] = country
            site_config[get.siteName]['cc_automatic'] = False
            site_config[get.siteName]['cc_mode'] = int(get.cc_mode)
            site_config[get.siteName]['cc']['cc_mode'] = int(get.cc_mode)
            site_config[get.siteName]['cc']['cycle'] = int(get.cycle)
            site_config[get.siteName]['cc']['limit'] = int(get.limit)
            site_config[get.siteName]['cc']['endtime'] = int(get.endtime)
            site_config[get.siteName]['cc']['cc_increase_type'] = get.cc_increase_type
            site_config[get.siteName]['cc']['increase'] = (get.increase == '1') | False
            site_config[get.siteName]['increase_wu_heng'] = (get.increase_wu_heng == '1') | False
        site_config[get.siteName]['cc_type_status'] = int(get.cc_type_status)

        site_config[get.siteName]['cc']['cc_ip_max'] = cc_ip_max

        return site_config

    # 设置CC 增强全局生效
    def set_cc_retry_golbls(self, get):
        data = self.get_site_config(get)
        ret = []
        for i in data:
            ret.append(i['siteName'])
        if not ret: return False
        for i in ret:
            get.siteName = i
            self.set_site_retry(get)
        return True

    # 四层计划任务
    def site_time_uptate(self):
        id = public.M('crontab').where('name=?', (u'Nginx防火墙四层拦截IP',)).getField('id')
        import crontab
        if id: crontab.crontab().DelCrontab({'id': id})
        data = {}
        data['name'] = 'Nginx防火墙四层拦截IP'
        data['type'] = 'hour-n'
        data['where1'] = '1'
        data['sBody'] = 'python /www/server/panel/plugin/btwaf/firewalls_list.py start'
        data['backupTo'] = 'localhost'
        data['sType'] = 'toShell'
        data['hour'] = ''
        data['minute'] = '0'
        data['week'] = ''
        data['sName'] = ''
        data['urladdress'] = ''
        data['save'] = ''
        crontab.crontab().AddCrontab(data)
        return True

    # 设置四层屏蔽模式
    def set_stop_ip(self, get):
        self.site_time_uptate()
        return public.returnMsg(True, '设置成功!')

    # 关闭
    def set_stop_ip_stop(self, get):
        id = public.M('crontab').where('name=?', (u'Nginx防火墙四层拦截IP',)).getField('id')
        import crontab
        if id: crontab.crontab().DelCrontab({'id': id})
        return public.returnMsg(True, '关闭成功!')

    def get_stop_ip(self, get):
        id = public.M('crontab').where('name=?', (u'Nginx防火墙四层拦截IP',)).getField('id')
        if id:
            return public.returnMsg(True, '11')
        else:
            return public.returnMsg(False, '111')

    def get_site_config2(self):
        site_config = public.readFile(self.__path + 'site.json')
        try:
            data = json.loads(site_config)
        except:
            return False
        return data

    def add_body_site_rule(self, get):
        if not get.text.strip(): return public.returnMsg(False, '需要替换的数据不能为空')
        config = self.get_site_config2()
        if not config: public.returnMsg(False, '未知错误')
        config2 = config[get.siteName]
        if not 'body_character_string' in config2:
            config2['body_character_string'] = []
        if not get.text2.strip():
            ret = {get.text: ''}
        else:
            ret = {get.text: get.text2}
        body = config2['body_character_string']
        if len(body) == 0:
            config2['body_character_string'].append(ret)
            self.__write_site_config(config)
            return public.returnMsg(True, '添加成功重启Nginx生效')
        else:
            if body in config2['body_character_string']:
                return public.returnMsg(False, '已经存在')
            else:
                config2['body_character_string'].append(ret)
                self.__write_site_config(config)
                return public.returnMsg(True, '添加成功重启Nginx生效')

    def add_body_body_intercept(self, get):
        if not get.text.strip(): return public.returnMsg(False, '需要拦截数据不能为空')
        config = self.get_site_config2()
        if not config: public.returnMsg(False, '未知错误')
        config2 = config[get.siteName]
        if not 'body_intercept' in config2:
            config2['body_intercept'] = []
        if get.text.strip() in config2['body_intercept']:
            return public.returnMsg(False, '已经存在')
        else:
            config2['body_intercept'].append(get.text.strip())
            self.__write_site_config(config)
            return public.returnMsg(True, '添加成功')

    def del_body_body_intercept(self, get):
        if not get.text.strip(): return public.returnMsg(False, '需要拦截数据不能为空')
        config = self.get_site_config2()
        if not config: public.returnMsg(False, '未知错误')
        config2 = config[get.siteName]
        if not 'body_intercept' in config2:
            config2['body_intercept'] = []
        if get.text.strip() in config2['body_intercept']:
            config2['body_intercept'].pop(get.text.strip())
            self.__write_site_config(config)
            return public.returnMsg(True, '删除成功')
        else:
            return public.returnMsg(False, '不存在')

    def del_body_site_rule(self, get):
        body = json.loads(get.body)
        config = self.get_site_config2()
        if not config: public.returnMsg(False, '未知错误')
        config2 = config[get.siteName]
        if not 'body_character_string' in config2:
            config2['body_character_string'] = []
            self.__write_site_config(config)
            return public.returnMsg(False, '替换文件为空,请添加数据')
        else:
            data = config2['body_character_string']

            if body in data:
                ret = data.index(body)
                data.pop(ret)
                self.__write_site_config(config)
                return public.returnMsg(True, '删除成功,重启nginx生效')
            else:
                return public.returnMsg(False, '删除失败/不存在')

    #  xss 防御
    def xssencode(self, text):
        import html
        list = ['`', '~', '&', '#', '*', '$', '@', '<', '>', '\"', '\'', ';', '%', ',', '\\u']
        ret = []
        for i in text:
            if i in list:
                i = ''
            ret.append(i)
        str_convert = ''.join(ret)
        text2 = html.escape(str_convert, quote=True)
        return text2

    def del_body_rule(self, get):

        body = json.loads(get.body)

        config = self.get_config(get)
        if not 'body_character_string' in config:
            config['body_character_string'] = []
            self.__write_config(config)
            return public.returnMsg(False, '替换文件为空,请添加数据')
        else:
            data = config['body_character_string']
            if body in data:
                ret = data.index(body)
                data.pop(ret)
                self.__write_config(config)
                return public.returnMsg(True, '删除成功,重启nginx生效')
            else:
                return public.returnMsg(False, '删除失败/不存在')

    def add_body_rule(self, get):
        if not get.text.strip(): return public.returnMsg(False, '需要替换的数据不能为空')
        config = self.get_config(get)

        if not 'uri_find' in config:
            config['uri_find'] = []

        if not 'body_character_string' in config:
            config['body_character_string'] = []
        if not get.text2.strip():
            ret = {self.xssencode(get.text): ''}
        else:
            ret = {self.xssencode(get.text): self.xssencode(get.text2)}
        body = config['body_character_string']
        if len(body) == 0:
            config['body_character_string'].append(ret)
            self.__write_config(config)
            return public.returnMsg(True, '添加成功重启Nginx生效')
        else:
            if body in config['body_character_string']:
                return public.returnMsg(False, '已经存在')
            else:
                config['body_character_string'].append(ret)
                self.__write_config(config)
                return public.returnMsg(True, '添加成功重启Nginx生效')

    # 导入违禁词
    def import_body_intercept(self, get):
        if not get.text.strip(): return public.returnMsg(False, '需要拦截数据不能为空')
        data = get.text.strip().split()
        if len(data) == 0: return public.returnMsg(False, '需要拦截数据不能为空')
        config = self.get_config(get)
        if not 'body_intercept' in config:
            config['body_intercept'] = []
        if len(config['body_intercept']) == 0:
            config['body_intercept'] = data
            self.__write_config(config)
            return public.returnMsg(True, '导入成功')
        else:
            config['body_intercept'] = list(set(data) | set(config['body_intercept']))
            self.__write_config(config)
            return public.returnMsg(True, '导入成功')

    # 导出违禁词
    def export_body_intercept(self, get):
        config = self.get_config(get)
        if not 'body_intercept' in config:
            config['body_intercept'] = []
            return ''
        else:
            return '\n'.join(config['body_intercept'])

    # 清空
    def empty_body_intercept(self, get):
        config = self.get_config(get)
        config['body_intercept'] = []
        self.__write_config(config)
        return public.returnMsg(True, '清空成功')

    def add_body_intercept(self, get):
        if not get.text.strip(): return public.returnMsg(False, '你需要的拦截内容不能为空')
        config = self.get_config(get)
        if not 'body_intercept' in config:
            config['body_intercept'] = []
        if not 'body_intercept' in config:
            config['body_intercept'] = []
        if get.text.strip() in config['body_intercept']:
            return public.returnMsg(False, '拦截的内容已经存在')
        else:
            config['body_intercept'].append(get.text.strip())
            self.__write_config(config)
            return public.returnMsg(True, '添加成功')

    def del_body_intercept(self, get):
        if not get.text.strip(): return public.returnMsg(False, '你需要的拦截内容不能为空')
        config = self.get_config(get)
        if not 'body_intercept' in config:
            config['body_intercept'] = []
        if not 'body_intercept' in config:
            config['body_intercept'] = []
        if get.text.strip() in config['body_intercept']:
            config['body_intercept'].remove(get.text.strip())
            self.__write_config(config)
            return public.returnMsg(True, '删除成功')
        else:
            return public.returnMsg(False, '拦截的内容不存在')

    def ipv6_check(self, addr):
        ip6_regex = (
            r'(^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$)|'
            r'(\A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,6}\Z)|'
            r'(\A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}\Z)|'
            r'(\A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}\Z)|'
            r'(\A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}\Z)|'
            r'(\A([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}\Z)|'
            r'(\A([0-9a-f]{1,4}:){1,6}(:[0-9a-f]{1,4}){1,1}\Z)|'
            r'(\A(([0-9a-f]{1,4}:){1,7}|:):\Z)|(\A:(:[0-9a-f]{1,4}){1,7}\Z)|'
            r'(\A((([0-9a-f]{1,4}:){6})(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})\Z)|'
            r'(\A(([0-9a-f]{1,4}:){5}[0-9a-f]{1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})\Z)|'
            r'(\A([0-9a-f]{1,4}:){5}:[0-9a-f]{1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|'
            r'(\A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|'
            r'(\A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,3}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|'
            r'(\A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,2}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|'
            r'(\A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,1}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|'
            r'(\A(([0-9a-f]{1,4}:){1,5}|:):(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|'
            r'(\A:(:[0-9a-f]{1,4}){1,5}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)')
        return bool(re.match(ip6_regex, addr, flags=re.IGNORECASE))

    # IPV6 黑名单
    def set_ipv6_back(self, get):
        addr = str(get.addr).split()
        addr = addr[0]
        ret = self.get_ipv6(get)
        if ret['status']:
            return public.returnMsg(False, '请开启IPV6访问!')
        else:
            if self.ipv6_check(addr):
                if not os.path.exists(self.__path + 'ipv6_back.json'):
                    list = []
                    list.append(addr)
                    public.WriteFile(self.__path + 'ipv6_back.json', json.dumps(list))
                    self.add_ipv6(addr)
                    return public.returnMsg(True, '添加成功!')
                else:
                    list_addr = public.ReadFile(self.__path + 'ipv6_back.json')
                    if list_addr:
                        list_addr = json.loads(list_addr)
                        if str(addr) in list_addr:
                            return public.returnMsg(False, '已经存在!')
                        else:
                            list_addr.append(addr)
                            self.add_ipv6(addr)
                            public.WriteFile(self.__path + 'ipv6_back.json', json.dumps(list_addr))
                            return public.returnMsg(True, '添加成功!')
                    else:
                        list = []
                        list.append(addr)
                        public.WriteFile(self.__path + 'ipv6_back.json', json.dumps(list))
                        self.add_ipv6(addr)
                        return public.returnMsg(True, '添加成功!')
            else:
                return public.returnMsg(False, '请输入正确的IPV6地址')

    def del_ipv6_back(self, get):
        addr = str(get.addr).split()
        addr = addr[0]
        list_addr = public.ReadFile(self.__path + 'ipv6_back.json')
        if list_addr:
            list_addr = json.loads(list_addr)
            if addr in list_addr:
                self.del_ipv6(addr)
                list_addr.remove(addr)
                public.WriteFile(self.__path + 'ipv6_back.json', json.dumps(list_addr))
                return public.returnMsg(True, '删除成功!')
            else:
                return public.returnMsg(False, '地址不存在!')
        else:
            list = []
            public.WriteFile(self.__path + 'ipv6_back.json', json.dumps(list))
            return public.returnMsg(True, '列表为空!')

    def add_ipv6(self, addr):
        if self.__isFirewalld:
            public.ExecShell(
                '''firewall-cmd --permanent --add-rich-rule="rule family="ipv6" source address="%s"  port protocol="tcp" port="80"  reject" ''' % addr)
            self.FirewallReload()
        if self.__isUfw:
            return public.returnMsg(False, '不支持乌班图哦!')
        else:
            return public.returnMsg(False, '暂时只支持Centos7')

    def del_ipv6(self, addr):
        if self.__isFirewalld:
            public.ExecShell(
                '''firewall-cmd --permanent --remove-rich-rule="rule family="ipv6" source address="%s"  port protocol="tcp" port="80"  reject" ''' % addr)
            self.FirewallReload()
        if self.__isUfw:
            return public.returnMsg(False, '不支持乌班图哦!')
        else:
            return public.returnMsg(False, '暂时只支持Centos7')

    def get_ipv6_address(self, get):
        if os.path.exists(self.__path + 'ipv6_back.json'):
            list_addr = public.ReadFile(self.__path + 'ipv6_back.json')
            list_addr = json.loads(list_addr)
            return public.returnMsg(True, list_addr)
        else:
            return public.returnMsg(False, [])

    # 重载防火墙配置
    def FirewallReload(self):
        if self.__isUfw:
            public.ExecShell('/usr/sbin/ufw reload')
            return;
        if self.__isFirewalld:
            public.ExecShell('firewall-cmd --reload')
        else:
            public.ExecShell('/etc/init.d/ip6tables save')
            public.ExecShell('service ip6tables restart')

    # 关闭IPV6地址访问
    def stop_ipv6(self, get):
        if self.__isFirewalld:
            public.ExecShell(
                '''firewall-cmd --permanent --add-rich-rule="rule family="ipv6"  port protocol="tcp" port="443" reject"''')
            public.ExecShell(
                '''firewall-cmd --permanent --add-rich-rule="rule family="ipv6"  port protocol="tcp" port="80" reject" ''')
            self.FirewallReload()
            return public.returnMsg(True, '设置成功!')
        if self.__isUfw:
            return public.returnMsg(False, '不支持乌班图开启和关闭!')
        else:
            public.ExecShell('ip6tables -F && ip6tables -X && ip6tables -Z')
            public.ExecShell('''ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport 80 -j DROP''')
            public.ExecShell('''ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport 443 -j DROP''')
            return public.returnMsg(True, '设置成功!')

    def start_ipv6(self, get):
        if self.__isFirewalld:
            public.ExecShell(
                '''firewall-cmd --permanent --remove-rich-rule="rule family="ipv6"  port protocol="tcp" port="443" reject"''')
            public.ExecShell(
                '''firewall-cmd --permanent --remove-rich-rule="rule family="ipv6"  port protocol="tcp" port="80" reject" ''')
            self.FirewallReload()
            return public.returnMsg(True, '设置成功!')
        if self.__isUfw:
            return public.returnMsg(False, '不支持乌班图开启和关闭!')
        else:
            public.ExecShell(''' ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport 80 -j DROP ''')
            public.ExecShell(''' ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport 443 -j DROP''')
            return public.returnMsg(True, '设置成功!')

    def get_ipv6(self, get):
        if self.__isFirewalld:
            import re
            ret = '''family="ipv6" port port="443" protocol="tcp" reject'''
            ret2 = '''family="ipv6" port port="80" protocol="tcp" reject'''
            lit = public.ExecShell('firewall-cmd --list-all')
            if re.search(ret, lit[0]) and re.search(ret2, lit[0]):
                return public.returnMsg(True, '')
            else:
                return public.returnMsg(False, '!')
        if self.__isUfw:
            return public.returnMsg(False, '')
        else:
            import re
            list = public.ReadFile('/etc/sysconfig/ip6tables')
            ret = 'INPUT -p tcp -m state --state NEW -m tcp --dport 80 -j DROP'
            ret2 = 'INPUT -p tcp -m state --state NEW -m tcp --dport 443 -j DROP'
            if re.search(ret, list) and re.search(ret2, list):
                return public.returnMsg(True, '')
            else:
                return public.returnMsg(False, '')

    # 获取蜘蛛池类型
    def get_zhizu_list(self):
        if os.path.exists(self.__path + 'zhi.json'):
            try:
                ret = json.loads(public.ReadFile(self.__path + 'zhi.json'))
                return ret
            except:
                os.remove(self.__path + 'zhi.json')
                return False
        else:
            rcnlist = public.httpGet('http://www.bt.cn/api/panel/get_spider_type')
            if not rcnlist: return False
            public.WriteFile(self.__path + 'zhi.json', rcnlist)
            try:
                rcnlist = json.loads(rcnlist)
                return rcnlist
            except:
                os.remove(self.__path + 'zhi.json')
                return False

    # 获取蜘蛛池地址
    def get_zhizu_ip_list(self):
        # from BTPanel import session
        # type = self.get_zhizu_list()
        # if not type: return False
        # if 'types' in type:
        #     if len(type['types']) >= 1:
        #         for i in type['types']:
        #             ret = public.httpGet('http://www.bt.cn/api/panel/get_spider?spider=%s' % str(i['id']))
        #             if not ret:
        #                 if not os.path.exists(self.__path + str(i['id']) + '.json'):
        #                     ret = []
        #                     public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
        #                 continue
        #             if os.path.exists(self.__path + str(i['id']) + '.json'):
        #                 local = public.ReadFile(self.__path + str(i['id']) + '.json')
        #                 if local:
        #                     try:
        #                         ret = json.loads(ret)
        #                         local = json.loads(local)
        #                         localhost_json = list(set(json.loads(local)).union(ret))
        #                         public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(localhost_json))
        #                         yum_list_json = list(set(local).difference(set(ret)))
        #                         public.httpGet(
        #                             'https://www.bt.cn/api/panel/add_spiders?address=%s' % json.dumps(yum_list_json))
        #                     except:
        #                         pass
        #                 else:
        #                     try:
        #                         ret = json.loads(ret)
        #                         public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
        #                     except:
        #                         ret = []
        #                         public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
        #             else:
        #                 try:
        #                     ret = json.loads(ret)
        #                     public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
        #                 except:
        #                     ret = []
        #                     public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
        # public.ExecShell('chown www:www /www/server/btwaf/*.json')
        # if not 'zhizu' in session: session['zhizu'] = 1
        return public.returnMsg(True, '更新蜘蛛成功!')

    # 获取蜘蛛池地址
    def get_zhizu_list22(self, get):
        # type = self.get_zhizu_list()
        # if not type: return public.returnMsg(False, '云端连接错误!')
        # if 'types' in type:
        #     if len(type['types']) >= 1:
        #         for i in type['types']:
        #             ret = public.httpGet('http://www.bt.cn/api/panel/get_spider?spider=%s' % str(i['id']))
        #             if not ret:
        #                 if not os.path.exists(self.__path + str(i['id']) + '.json'):
        #                     ret = []
        #                     public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
        #                 continue
        #
        #             if os.path.exists(self.__path + str(i['id']) + '.json'):
        #                 local = public.ReadFile(self.__path + str(i['id']) + '.json')
        #                 if local:
        #                     try:
        #                         ret = json.loads(ret)
        #                         local = json.loads(local)
        #                         localhost_json = list(set(json.loads(local)).union(ret))
        #                         public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(localhost_json))
        #                         yum_list_json = list(set(local).difference(set(ret)))
        #                         public.httpGet(
        #                             'https://www.bt.cn/api/panel/add_spiders?address=%s' % json.dumps(yum_list_json))
        #                     except:
        #                         pass
        #                 else:
        #                     try:
        #                         ret = json.loads(ret)
        #                         public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
        #                     except:
        #                         ret = []
        #                         public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
        #             else:
        #                 try:
        #                     ret = json.loads(ret)
        #                     public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
        #                 except:
        #                     ret = []
        #                     public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
        # public.ExecShell('chown www:www /www/server/btwaf/*.json')
        return public.returnMsg(True, '更新蜘蛛成功!')

    # 获取蜘蛛池地址
    def get_zhizu_list2233(self, get):
        # self.test_check_zhilist(None)
        return public.returnMsg(True, '更新蜘蛛成功!')

    # 获取蜘蛛池地址
    def start_zhuzu(self):
        type = self.get_zhizu_list()
        if not type: return public.returnMsg(False, '云端连接错误!')
        if 'types' in type:
            if len(type['types']) >= 1:
                for i in type['types']:
                    ret = public.httpGet('http://www.bt.cn/api/panel/get_spider?spider=%s' % str(i['id']))
                    if not ret:
                        if not os.path.exists(self.__path + str(i['id']) + '.json'):
                            ret = []
                            public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
                        continue

                    if os.path.exists(self.__path + str(i['id']) + '.json'):
                        local = public.ReadFile(self.__path + str(i['id']) + '.json')
                        if local:
                            try:
                                ret = json.loads(ret)
                                local = json.loads(local)
                                localhost_json = list(set(json.loads(local)).union(ret))
                                public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(localhost_json))
                                yum_list_json = list(set(local).difference(set(ret)))
                                public.httpGet(
                                    'https://www.bt.cn/api/panel/add_spiders?address=%s' % json.dumps(yum_list_json))
                            except:
                                pass
                        else:
                            try:
                                ret = json.loads(ret)
                                public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
                            except:
                                ret = []
                                public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
                    else:
                        try:
                            ret = json.loads(ret)
                            public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
                        except:
                            ret = []
                            public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
        public.ExecShell('chown www:www /www/server/btwaf/*.json')
        return public.returnMsg(True, '更新蜘蛛成功!')

    # 外部蜘蛛池更新
    def get_zhizu_ip(self, get):
        type = self.get_zhizu_list()
        if not type: return False
        if 'types' in type:
            if len(type['types']) >= 1:
                for i in type['types']:
                    ret = public.httpGet('http://www.bt.cn/api/panel/get_spider?spider=%s' % str(i['id']))
                    if not ret: continue
                    try:
                        ret2 = json.dumps(ret)
                    except:
                        if not os.path.exists(self.__path + str(i['id']) + '.json'):
                            rec = []
                            public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(rec))
                        continue
                    if os.path.exists(self.__path + str(i['id']) + '.json'):
                        local = public.ReadFile(self.__path + str(i['id']) + '.json')
                        if local:
                            localhost_json = list(set(json.loads(local)).union(json.loads(ret)))
                            public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(localhost_json))
                            yum_list_json = list(set(local).difference(set(ret)))
                            public.httpGet(
                                'https://www.bt.cn/api/panel/add_spiders?address=%s' % json.dumps(yum_list_json))
                        else:
                            public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
                    else:
                        public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))

        return public.returnMsg(True, '更新蜘蛛成功!')

    def get_process_list(self):
        import psutil
        count = 0
        cpunum = int(public.ExecShell('cat /proc/cpuinfo |grep "processor"|wc -l')[0])
        Pids = psutil.pids();
        for pid in Pids:
            tmp = {}
            try:
                p = psutil.Process(pid);
            except:
                continue
            if str(p.name()) == 'php-fpm':
                count += int(p.cpu_percent(0.1))
        public.ExecShell("echo '%s' >/dev/shm/nginx.txt" % count / cpunum)
        return count / cpunum

    # 开启智能防御CC
    def Start_apache_cc(self, get):
        ret = self.auto_sync_apache()
        return ret

    # 查看状态
    def Get_apap_cc(self, get):
        id = public.M('crontab').where('name=?', (u'Nginx防火墙智能防御CC',)).getField('id');
        if id:
            return public.returnMsg(True, '开启!');
        else:
            return public.returnMsg(False, '关闭!');

    # 关闭智能防御CC
    def Stop_apache_cc(self, get):
        if os.path.exists('/dev/shm/nginx.txt'):
            os.remove('/dev/shm/nginx.txt')
        id = public.M('crontab').where('name=?', (u'Nginx防火墙智能防御CC',)).getField('id');
        import crontab
        if id: crontab.crontab().DelCrontab({'id': id})
        return public.returnMsg(True, '设置成功!');

    # 设置自动同步
    def auto_sync_apache(self):
        id = public.M('crontab').where('name=?', (u'Nginx防火墙智能防御CC',)).getField('id');
        import crontab
        if id: crontab.crontab().DelCrontab({'id': id})
        data = {}
        data['name'] = u'Nginx防火墙智能防御CC'
        data['type'] = 'minute-n'
        data['where1'] = '1'
        data['sBody'] = 'python /www/server/panel/plugin/btwaf/btwaf_main.py start'
        data['backupTo'] = 'localhost'
        data['sType'] = 'toShell'
        data['hour'] = ''
        data['minute'] = ''
        data['week'] = ''
        data['sName'] = ''
        data['urladdress'] = ''
        data['save'] = ''
        crontab.crontab().AddCrontab(data)
        return public.returnMsg(True, '设置成功!');

    # 查看apache 使用CPU的情况
    def retuen_nginx(self):
        import psutil
        count = 0
        cpunum = int(public.ExecShell('cat /proc/cpuinfo |grep "processor"|wc -l')[0])
        Pids = psutil.pids();
        for pid in Pids:
            tmp = {}
            try:
                p = psutil.Process(pid);
            except:
                continue
            if str(p.name()) == 'php-fpm':
                count += int(p.cpu_percent(0.1))

        public.ExecShell("echo '%s' >/dev/shm/nginx.txt" % str(count / cpunum))
        return count / cpunum

    def set_scan_conf(self, get):
        '''
        三个参数  通过404 的访问次数来拦截扫描器。最低不能低于60秒120次。
        open
        limit
        cycle
        '''
        config = self.get_config(None)
        if not 'limit' in get:
            if 'limit' in config['scan_conf']:
                get.limit = config['scan_conf']['limit']
            else:
                get.limit = 120
        if not 'cycle' in get:
            if 'cycle' in config['scan_conf']:
                get.cycle = config['scan_conf']['cycle']
            else:
                get.cycle = 60
        if not 'open' in get:
            if 'open' in config['scan_conf']:
                if config['scan_conf']['open']:
                    get.open = 0
                else:
                    get.open = 1
            else:
                get.open = 1
        if int(get.limit) < 20:
            return public.returnMsg(False, '次数不能小于20次')
        if int(get.cycle) < 20:
            return public.returnMsg(False, '周期不能小于20秒')
        if get.open == 1 or get.open == '1':
            open = True
        else:
            open = False
        # config = self.get_config(None)
        config['scan_conf'] = {"open": open, "limit": int(get.limit), "cycle": int(get.cycle)}
        self.__write_config(config)
        return public.returnMsg(True, '设置成功')

    def http_config(self, get):
        '''
            config['http_config'] = {"body_size":800000,"base64":True,"get_count":1000,"post_count":1000}
        '''
        if 'body_size' in get:
            body_size = int(get.body_size)
        else:
            body_size = 800000
        if 'base64' in get:
            if get.base64 == 1 or get.base64 == '1' or get.base64 == 'true':
                base64 = True
            else:
                base64 = False
        else:
            base64 = True
        if 'get_count' in get:
            get_count = int(get.get_count)
        else:
            get_count = 1000

        if 'post_count' in get:
            post_count = int(get.post_count)
        else:
            post_count = 1000
        config = self.get_config(None)
        http_config = config['http_config']
        tmp_http_config = {"body_size": body_size, "base64": base64, "get_count": get_count, "post_count": post_count}
        if http_config != tmp_http_config:
            config['http_config'] = tmp_http_config
            self.__write_config(config)
        return public.returnMsg(True, '设置成功')

    def get_config(self, get):
        try:
            config = json.loads(public.readFile(self.__path + 'config.json'))
        except:
            config = {
                "scan": {
                    "status": 444,
                    "ps": "过滤常见扫描测试工具的渗透测试",
                    "open": True,
                    "reqfile": ""
                },
                "cc": {
                    "status": 444,
                    "ps": "过虑CC攻击",
                    "increase": False,
                    "limit": 120,
                    "endtime": 300,
                    "open": True,
                    "reqfile": "",
                    "cycle": 60,
                    "cc_ip_max": {"open": False, "static": False, "ip_max": 10000}
                },
                "logs_path": "/www/wwwlogs/btwaf",
                "open": True,
                "reqfile_path": "/www/server/btwaf/html",
                "retry": 10,
                "log": True,
                "cc_automatic": False,
                "user-agent": {
                    "status": 403,
                    "ps": "通常用于过滤浏览器、蜘蛛及一些自动扫描器",
                    "open": True,
                    "reqfile": "user_agent.html"
                },
                "other": {
                    "status": 403,
                    "ps": "其它非通用过滤",
                    "reqfile": "other.html"
                },
                "uri_find": [],
                "cc_retry_cycle": "600",
                "cc_time": "60",
                "ua_black": [],
                "drop_abroad": {
                    "status": 444,
                    "ps": "禁止中国大陆以外的地区访问站点",
                    "open": True,
                    "reqfile": ""
                },
                "drop_china": {
                    "status": 444,
                    "ps": "禁止大陆地区访问",
                    "open": False,
                    "reqfile": ""
                },
                "retry_cycle": 120,
                "get": {
                    "status": 403,
                    "ps": "过滤uri、uri参数中常见sql注入、xss等攻击",
                    "open": True,
                    "reqfile": "get.html"
                },
                "body_character_string": [],
                "body_intercept": [],
                "start_time": 0,
                "cookie": {
                    "status": 403,
                    "ps": "过滤利用Cookie发起的渗透攻击",
                    "open": True,
                    "reqfile": "cookie.html"
                },
                "retry_time": 1800,
                "post": {
                    "status": 403,
                    "ps": "过滤POST参数中常见sql注入、xss等攻击",
                    "open": True,
                    "reqfile": "post.html"
                },
                "ua_white": [],
                "body_regular": [],
                "log_save": 30,
                "sql_injection": {"status": 403, "reqfile": "get.html", "open": True, "post_sql": True, "get_sql": True,
                                  "mode": "high"},
                "xss_injection": {"status": 403, "reqfile": "get.html", "open": True, "post_xss": True, "get_xss": True,
                                  "mode": "high"},
                "file_upload": {"status": 444, "reqfile": "get.html", "open": True, "mode": "high", "from-data": True},

            }
        config['drop_abroad_count'] = 0

        inf = public.cache_get("get_drop_abroad_count")
        if inf:
            config['drop_abroad_count'] = inf
        count = 0
        try:
            site_config = json.loads(public.readFile(self.__path + 'site.json'))
        except:
            site_config = []
            pass

        for i in site_config:
            if site_config[i]['drop_abroad']:
                count += 1
        public.cache_set("get_drop_abroad_count", count, 360)
        config['drop_abroad_count'] = count
        if not 'cms_rule_open' in config:
            config['cms_rule_open'] = False
        if not 'access_token' in config:
            config['access_token'] = public.GetRandomString(32)

        if not 'static_cc' in config:
            config['static_cc'] = False

        if 'cc_ip_max' not in config['cc']:
            config['cc']['cc_ip_max'] = {}
            config['cc']['cc_ip_max']['open'] = False
            config['cc']['cc_ip_max']['static'] = False
            config['cc']['cc_ip_max']['ip_max'] = 20000
            # 一天内最低为2000次 未开启静态的情况下
            # 开启静态的最低为4000次

        is_flag = False
        if not 'rce_injection' in config:
            config['rce_injection'] = {"status": 403, "reqfile": "get.html", "open": True, "post_xss": True,
                                       "get_xss": True, "mode": "high"}

        if 'msg_send' not in config:
            config['msg_send'] = {
                "open": False,
                "attack": True,
                "timeout": 120,
                "cc": True,
                "send_type": "",
                "reserve": ""
            }
            is_flag = True

        if 'msg_send' in config:
            if 'malicious_ip' not in config['msg_send']:
                config['msg_send']['malicious_ip'] = False
                config['msg_send']['customize'] = False
                config['msg_send']['uablack'] = False
                config['msg_send']['upload'] = True
                is_flag = True
            if 'abroad' not in config['msg_send']:
                config['msg_send']['abroad'] = False
                is_flag = True

        if not 'btmalibrary_install' in config:
            config['btmalibrary_install'] = False
            is_flag = True

        if not 'btmalibrary' in config:
            config['btmalibrary'] = False
            is_flag = True

        if os.path.exists("/www/server/panel/plugin/btmalibrary/btmalibrary_main.py"):
            config['btmalibrary_install'] = True
        else:
            config['btmalibrary_install'] = False
            config['btmalibrary'] = False

        # 拦截共享IP库
        if not 'malicious_ip' in config:
            config['malicious_ip'] = False
        # 禁止海外拉黑到系统防火墙中
        if not 'system_black' in config:
            config['system_black'] = False
        # 共享IP计划
        if not 'share_ip' in config:
            config['share_ip'] = True

        if not 'password' in config:
            config['password'] = True
            is_flag = True
        if not 'sensitive_info' in config:
            config['sensitive_info'] = True
            is_flag = True
        if not 'sql_injection' in config:
            config['sql_injection'] = {"status": 403, "reqfile": "get.html", "open": True, "post_sql": True,
                                       "get_sql": True, "mode": "high"}
            is_flag = True
        if not 'xss_injection' in config:
            config['xss_injection'] = {"status": 403, "reqfile": "get.html", "open": True, "post_xss": True,
                                       "get_xss": True, "mode": "high"}
            is_flag = True
        if not 'file_upload' in config:
            config['file_upload'] = {"status": 444, "reqfile": "get.html", "open": True, "mode": "high",
                                     "from-data": True}
            is_flag = True
        if not 'other_rule' in config:
            config['other_rule'] = {"status": 444, "reqfile": "get.html", "open": True, "mode": "high"}
            is_flag = True
        if not 'nday' in config:
            config['nday'] = True
            is_flag = True
        if not 'is_cc_url' in config['cc']:
            config['cc']['is_cc_url'] = True
        # if not 'php_execution' in config:
        #     config['php_execution'] = {"status": 403, "reqfile": "get.html", "open": True, "mode": "high","get":True,"post":True}
        #     is_flag = True
        else:
            if 'from-data' not in config['file_upload']:
                config['file_upload'] = {"open": True, "mode": "high", "from-data": True}
                is_flag = True
        if not 'scan_conf' in config:
            config['scan_conf'] = {"open": True, "limit": 240, "cycle": 60}
        if not 'cc_type_status' in config:
            config['cc_type_status'] = 2
            is_flag = True
        if not 'body_intercept' in config:
            config['body_intercept'] = []
            is_flag = True
        if not 'cc_mode' in config:
            config['cc_mode'] = 1
            is_flag = True
        if not 'retry_cycle' in config:
            config['retry_cycle'] = 60
            is_flag = True
            self.__write_config(config)

        if config['cc'] and not 'countrys' in config['cc']:
            config['cc']['countrys'] = {}
            is_flag = True

        if not 'cc_uri_frequency' in config:
            # {"/index.php":{"frequency":10,"cycle":60}}
            config['cc_uri_frequency'] = {}

        if not 'uri_find' in config:
            config['uri_find'] = []
            is_flag = True
        if not 'increase_wu_heng' in config:
            config['increase_wu_heng'] = False
            is_flag = True
        if not 'ua_white' in config:
            config['ua_white'] = []
            is_flag = True

        if not 'http_config' in config:
            config['http_config'] = {"body_size": 800000, "base64": True, "get_count": 1000, "post_count": 1000}
            is_flag = True

        if not 'ua_black' in config:
            config['ua_black'] = []
            is_flag = True
        if not 'body_character_string' in config:
            config['body_character_string'] = []
            is_flag = True
        if not 'body_regular' in config:
            config['body_regular'] = []
            is_flag = True

        if not 'get_is_sql' in config:
            config['get_is_sql'] = True
            is_flag = True
        if not 'get_is_xss' in config:
            config['get_is_xss'] = True
        if not 'post_is_sql' in config:
            config['post_is_sql'] = True
        if not 'post_is_xss' in config:
            config['post_is_xss'] = True
        if not 'post_is_xss_count' in config:
            config['post_is_xss_count'] = 1
        else:
            if config['post_is_xss_count'] == 6:
                if not os.path.exists("/www/server/panel/data/post_is_xss_count.pl"):
                    config['post_is_xss_count'] = 1
                    is_flag = True
                    public.WriteFile("/www/server/panel/data/post_is_xss_count.pl", "")

        if not 'url_cc_param' in config:
            config['url_cc_param'] = {}
        if not 'send_to' in config:
            config['send_to'] = 'ERROR'
        if not 'drop_china' in config:
            config['drop_china'] = {
                "status": 444,
                "ps": "禁止大陆地区访问",
                "open": False,
                "reqfile": ""
            }
            is_flag = True
        # method_type_check开关
        if not 'method_type' in config:
            config['method_type'] = [['POST', True], ['GET', True], ['PUT', True], ['OPTIONS', True], ['HEAD', True],
                                     ['DELETE', True], ['TRACE', True], ['PATCH', True], ['MOVE', True], ['COPY', True],
                                     ['LINK', True], ['UNLINK', True], ['WRAPPED', True], ['PROPFIND', True],
                                     ['PROPPATCH', True], ['MKCOL', True], ['CONNECT', True], ['SRARCH', True]]

        if not 'header_len' in config:
            config['header_len'] = [['host', 500], ['connection', 100], ['content-length', 100], ['cache-control', 100],
                                    ['upgrade-insecure-requests', 100], ['origin', 500], ['content-type', 300],
                                    ['user-agent', 500], ['accept', 500], ['referer', 10000], ['accept-encoding', 500],
                                    ['accept-language', 500], ['cookie', 10000]]

        for i in range(len(config['header_len'])):
            if config['header_len'][i][0] == 'referer':
                if config['header_len'][i][1] == 500 or config['header_len'][i][1] == 3000:
                    config['header_len'][i][1] = 10000
        if not 'from_data' in config:
            config['from_data'] = True
            is_flag = True

            # webshell开关
        if not 'webshell_opens' in config:
            config['webshell_opens'] = True
        if not config['webshell_opens'] and public.M('crontab').where('name=?', (
                u'Nginx防火墙木马查杀进程请勿删除',)).count() == 0:
            id = public.M('crontab').where('name=?', (u'Nginx防火墙木马查杀进程请勿删除',)).getField('id')
            import crontab
            if id: crontab.crontab().DelCrontab({'id': id})

        if config['webshell_opens']:
            if get and 'open_btwaf_webshell' in get and get.open_btwaf_webshell:
                # 判断这个是否是5分钟的计划任务。只执行一次
                if not os.path.exists("/www/server/panel/plugin/btwaf/webshell_opens.pl"):
                    if public.M('crontab').where('name=?', (u'Nginx防火墙木马查杀进程请勿删除',)).count() == 1:
                        if public.M('crontab').where('name=?', (u'Nginx防火墙木马查杀进程请勿删除',)).getField(
                                "where1") == "5":
                            id = public.M('crontab').where('name=?', (u'Nginx防火墙木马查杀进程请勿删除',)).getField(
                                'id')
                            import crontab
                            if id: crontab.crontab().DelCrontab({'id': id})
                            public.WriteFile("/www/server/panel/plugin/btwaf/webshell_opens.pl", "True")
                self.webshell_check()

        if not 'http_open' in config:
            config['http_open'] = False
            is_flag = True
        # cc 自动开关
        if not 'cc_automatic' in config:
            config['cc_automatic'] = False
        if not 'is_browser' in config:
            config['is_browser'] = False
        if not 'url_white_chekc' in config:
            config['url_white_chekc'] = []
        if not 'cc_time' in config:
            config['cc_time'] = 60
        if not 'cc_retry_cycle' in config:
            config['cc_retry_cycle'] = 6000
        if config['start_time'] == 0:
            config['start_time'] = time.time()
            is_flag = True
        if not 'static_code_config' in config:
            config['static_code_config'] = {}
            is_flag = True
        if is_flag:
            self.__write_config(config)

        return config

    def find_site(self, data, site):
        for i in data:
            for i2 in i['domains']:
                if i2 == site:
                    return i
        return False

    def find_site_config(self, config, site):
        data = [{"name": "POST渗透", "key": "post", "value": 0}, {"name": "GET渗透", "key": "get", "value": 0},
                {"name": "CC攻击", "key": "cc", "value": 0},
                {"name": "恶意User-Agent", "key": "user_agent", "value": 0},
                {"name": "Cookie渗透", "key": "cookie", "value": 0}, {"name": "恶意扫描", "key": "scan", "value": 0},
                {"name": "恶意HEAD请求", "key": "head", "value": 0},
                {"name": "URI自定义拦截", "key": "url_rule", "value": 0},
                {"name": "URI保护", "key": "url_tell", "value": 0},
                {"name": "恶意文件上传", "key": "disable_upload_ext", "value": 0},
                {"name": "禁止的扩展名", "key": "disable_ext", "value": 0},
                {"name": "禁止PHP脚本", "key": "disable_php_path", "value": 0}]
        total_all = self.get_total(None)['sites']
        config['total'] = data if site in total_all else self.__format_total(total_all[site])
        config['siteName'] = site
        return config

    def find_websites(self, get):
        try:
            site_config = json.loads(public.readFile(self.__path + 'site.json'))
            site_name = get.siteName.strip()
            site_config2 = json.loads(public.readFile(self.__path + 'domains.json'))
            site = self.find_site(site_config2, site_name)
            if not site: return public.returnMsg(False, '未找到')
            if not site['name'] in site_config: return public.returnMsg(False, '未找到')
            return public.returnMsg(True, self.find_site_config(site_config[site['name']], site['name']))
        except:
            self.__write_site_domains()
            return public.returnMsg(False, '未找到')

    def get_site_config(self, get):
        try:
            site_config = json.loads(public.readFile(self.__path + 'site.json'))
        except:
            public.WriteFile(self.__path + 'site.json', json.dumps({}))
            self.__write_site_domains()
            site_config = json.loads(public.readFile(self.__path + 'site.json'))
        if not os.path.exists(self.__path + '/domains.json'):
            self.__write_site_domains()
        else:
            site_count = public.M('sites').count()
            try:
                from btdockerModel import dk_public as dp
                docker_sites = dp.sql("docker_sites").count()
                site_count = site_count + docker_sites
            except:
                pass
            site_config_count = len(site_config)
            if site_count != site_config_count:
                self.__write_site_domains()

        data = self.__check_site(site_config)
        if get:
            total_all = self.get_total(None)['sites']
            site_list = []
            for k in data.keys():
                if not k in total_all: total_all[k] = {}
                data[k]['total'] = self.__format_total(total_all[k])
                siteInfo = data[k];
                siteInfo['siteName'] = k;
                site_list.append(siteInfo);
            data = sorted(site_list, key=lambda x: x['log_size'], reverse=True)
        return data

    def get_site_config_byname(self, get):
        from BTPanel import session, cache
        if not self.__session_name in session:
            ret = self.get_btwaf()
            if ret == 0:
                self.stop()
                return public.returnMsg(False, '')
        site_config = self.get_site_config(None);
        config = site_config[get.siteName]
        config['top'] = self.get_config(None)
        return config

    def set_open(self, get):
        from BTPanel import session, cache
        if not cache.get("public.set_open"):
            isError = public.checkWebConfig()
            if isError != True:
                res = public.returnMsg(False,
                                       '检测到Nginx配置文件存在错误:<br><pre style="color:red;white-space: pre-line;">' + isError + '</pre>')
                res["conf_check"] = 1
                return res
            # 全局配置60秒最多一次
            cache.set("public.set_open", True, 60)
        if not self.__session_name in session:
            ret = self.get_btwaf()
            if ret == 0:
                self.stop()
                return public.returnMsg(False, '')

        config = self.get_config(None)
        if config['open']:
            config['open'] = False
            config['start_time'] = 0
        else:
            config['open'] = True
            config['start_time'] = int(time.time())
        self.__write_log(self.__state[config['open']] + '网站防火墙(WAF)')
        self.__write_config(config)
        public.ExecShell("/etc/init.d/bt_ipfilter restart")
        return public.returnMsg(True, '设置成功!')

    def set_obj_open(self, get):
        if get.obj == 'set_scan_conf':
            return self.set_scan_conf(get)
        if get.obj == "btmalibrary":
            if not os.path.exists("/www/server/panel/plugin/btmalibrary/btmalibrary_main.py"):
                return public.returnMsg(False, '检测到【堡塔恶意IP情报库】未安装，请先在软件商店中进行安装')
        config = self.get_config(None)
        if get.obj == 'webshell_opens':
            if config['webshell_opens']:
                # 这里是关闭
                try:
                    id = public.M('crontab').where('name=?', (u'Nginx防火墙木马查杀进程请勿删除',)).getField('id')
                    if id:
                        import crontab
                        data = {'id': id}
                        crontab.crontab().DelCrontab(data)
                except:
                    pass
            else:
                # 这里是开启
                self.webshell_check()
        if get.obj == "sql_injection":
            msg = "SQL注入防御"
        elif get.obj == "xss_injection":
            msg = "XSS防御"
        elif get.obj == "user-agent":
            msg = "恶意爬虫防御"
        elif get.obj == "cookie":
            msg = "恶意Cookie防御"
        elif get.obj == "drop_abroad":
            public.cache_remove('get_drop_abroad_count')
            msg = "禁止国外访问"
        elif get.obj == "drop_china":
            msg = "禁止国内访问"
        elif get.obj == "is_browser":
            msg = "非浏览器访问"
        elif get.obj == "file_upload":
            msg = "恶意文件上传"
        elif get.obj == "get":
            msg = "恶意下载防御"
        elif get.obj == "get":
            msg = "自定义规则拦截"
        elif get.obj == "scan":
            msg = "恶意扫描器"
        elif get.obj == "webshell_opens":
            msg = "木马查杀"
        elif get.obj == "http_open":
            msg = "日志记录"
        elif get.obj == "share_ip":
            msg = "恶意IP共享计划"
        elif get.obj == "malicious_ip":
            msg = "恶意IP共享计划"
        else:
            msg = get.obj
        if type(config[get.obj]) != bool:
            if config[get.obj]['open']:
                config[get.obj]['open'] = False
            else:
                config[get.obj]['open'] = True
            self.__write_log(self.__state[config[get.obj]['open']] + '【' + msg + '】功能');
        else:
            if config[get.obj]:
                config[get.obj] = False
            else:
                config[get.obj] = True

            if get.obj == "share_ip":
                if not config[get.obj]:
                    # 关闭共享IP计划
                    config['malicious_ip'] = False
            self.__write_log(self.__state[config[get.obj]] + '【' + msg + '】功能');
        self.__write_config(config)
        if get.obj == "btmalibrary":
            if config[get.obj]:
                if not os.path.exists("/www/server/btwaf/rule/btmalibrary_malicious.json") or os.path.getsize(
                        "/www/server/btwaf/rule/btmalibrary_malicious.json") < 100:
                    public.run_thread(self.get_malicious_ip_database(None))
        return public.returnMsg(True, '设置成功!')

    def set_spider(self, get):
        try:
            id = int(get.id.strip())
            site_config = self.get_site_config(None)
            if site_config[get.siteName]['spider'][id - 1]:
                if 'status' in site_config[get.siteName]['spider'][id - 1]:
                    if site_config[get.siteName]['spider'][id - 1]['status']:
                        site_config[get.siteName]['spider'][id - 1]['status'] = False
                    else:
                        site_config[get.siteName]['spider'][id - 1]['status'] = True
                    self.__write_site_config(site_config)
                    self.HttpGet('http://127.0.0.1/clean_spider_status')
                    time.sleep(0.3)
                    return public.returnMsg(True, '设置成功!')
            return public.returnMsg(False, '错误的参数!')
        except:
            return public.returnMsg(False, '错误的参数!')

    def set_site_obj_open(self, get):
        # site_config = self.get_site_config(None)
        try:
            site_config = json.loads(public.readFile(self.__path + 'site.json'))
        except:
            return public.returnMsg(False, '配置文件损坏请修复一下防火墙!');
        from BTPanel import cache
        if not cache.get("public.checkWebConfig()"):
            isError = public.checkWebConfig()
            if isError != True:
                res = public.returnMsg(False,
                                       '检测到Nginx配置文件存在错误:<br><pre style="color:red;white-space: pre-line;">' + isError + '</pre>')
                res["conf_check"] = 1
                return res
            # 没有错误的话、一个小时检测一次就可以了
            cache.set("public.checkWebConfig()", True, 3600)

        if get.obj == "smart_cc":
            if not os.path.exists("/www/server/panel/vhost/nginx/btwaf.conf"):
                return public.returnMsg(False, '未找到配置文件!')
            # 读取文件
            conf = public.readFile("/www/server/panel/vhost/nginx/btwaf.conf")
            if not conf:
                return public.returnMsg(False, '未找到配置文件!')
            if conf.find("#body_filter_by_lua_file") != -1:
                if not os.path.exists("/www/server/panel/vhost/nginx/speed.conf"):
                    conf = conf.replace("#body_filter_by_lua_file", "body_filter_by_lua_file")
                    public.writeFile("/www/server/panel/vhost/nginx/btwaf.conf", conf)
                    public.serviceReload()
                else:
                    return public.returnMsg(False, '请先卸载堡塔网站加速插件才能使用此功能!')
        if get.obj == "drop_abroad":
            public.cache_remove('get_drop_abroad_count')
            # 判断全局是否开启。如果全局是关闭的状态、那么此刻就不能开启
            # public.writeFile("/tmp/1.txt", self.get_config(None)['drop_abroad']['open'])
            if not self.get_config(None)['drop_abroad']['open']:
                return public.returnMsg(False, '全局设置中未开启禁止国外访问!')
        if get.obj == "drop_china":
            public.cache_remove('get_drop_abroad_count')
            config = self.get_config(None)
            if not config['drop_china']['open']:
                # 开启禁止国内访问
                config['drop_china']['open'] = True
                self.__write_config(config)
        if get.obj == "sql_injection":
            msg = "SQL注入防御"
        elif get.obj == "xss_injection":
            msg = "XSS防御"
        elif get.obj == "user-agent":
            msg = "恶意爬虫防御"
        elif get.obj == "cookie":
            msg = "恶意Cookie防御"
        elif get.obj == "drop_abroad":
            msg = "禁止国外访问"
        elif get.obj == "drop_china":
            msg = "禁止国内访问"
        elif get.obj == "is_browser":
            msg = "非浏览器访问"
        elif get.obj == "file_upload":
            msg = "恶意文件上传"
        elif get.obj == "get":
            msg = "恶意下载防御"
        elif get.obj == "get":
            msg = "自定义规则拦截"
        elif get.obj == "scan":
            msg = "恶意扫描器"
        elif get.obj == "webshell_opens":
            msg = "木马查杀"
        elif get.obj == "http_open":
            msg = "日志记录"
        elif get.obj == "readonly":
            msg = "护网模式"
        else:
            msg = get.obj
        if get.obj == 'spider':
            # 关闭就是关闭所有蜘蛛
            if site_config[get.siteName]['spider_status']:
                site_config[get.siteName]['spider_status'] = False
            else:
                site_config[get.siteName]['spider_status'] = True
            self.__write_site_config(site_config)
            return public.returnMsg(True, '设置成功!如需立即生效需重启Nginx')
        if type(site_config[get.siteName][get.obj]) != bool:
            if site_config[get.siteName][get.obj]['open']:
                site_config[get.siteName][get.obj]['open'] = False
            else:
                site_config[get.siteName][get.obj]['open'] = True

            self.__write_log(self.__state[site_config[get.siteName][get.obj][
                'open']] + '网站【' + get.siteName + '】【' + msg + '】功能');
        else:
            if site_config[get.siteName][get.obj]:
                site_config[get.siteName][get.obj] = False
            else:
                site_config[get.siteName][get.obj] = True
            self.__write_log(
                self.__state[site_config[get.siteName][get.obj]] + '网站【' + get.siteName + '】【' + msg + '】功能');
        # if get.obj == 'drop_abroad': self.__auto_sync_cnlist();
        self.__write_site_config(site_config)
        return public.returnMsg(True, '设置成功!');

    def __auto_sync_cnlist(self):
        return True

    def set_obj_status(self, get):
        config = self.get_config(None)
        if get.obj == 'post_is_xss_count':
            config[get.obj] = int(get.statusCode)
        else:
            config[get.obj]['status'] = int(get.statusCode)
        self.__write_config(config)
        return public.returnMsg(True, '设置成功!');

    def set_cc_conf(self, get):
        public.set_module_logs("btwaf", "set_cc_conf")
        config = self.get_config(None)

        if not 'cc_ip_max' in get: return public.returnMsg(False, '缺少cc_ip_max参数1');
        if not 'cc_increase_type' in get: return public.returnMsg(False, '需要cc_increase_type参数');
        if not get.cc_increase_type in ['js', 'code', 'renji', 'huadong', 'browser']: return public.returnMsg(False,
                                                                                                              '需要cc_increase_type参数')
        try:
            cc_ip_max = json.loads(get.cc_ip_max)
        except:
            return public.returnMsg(False, 'cc_ip_max参数错误0')

        if 'open' not in cc_ip_max:
            return public.returnMsg(False, 'cc_ip_max参数错误1')
        if 'ip_max' not in cc_ip_max:
            return public.returnMsg(False, 'cc_ip_max参数错误2')
        if 'static' not in cc_ip_max:
            return public.returnMsg(False, 'cc_ip_max参数错误3')

        if cc_ip_max['open'] == True or cc_ip_max['open'] == 1:
            cc_ip_max['open'] = True
        else:
            cc_ip_max['open'] = False
        if cc_ip_max['static'] == True or cc_ip_max['static'] == 1:
            cc_ip_max['static'] = True
        else:
            cc_ip_max['static'] = False
        if cc_ip_max['open'] == False:
            cc_ip_max['static'] = False
        if type(cc_ip_max["ip_max"]) != int: return public.returnMsg(False, 'cc_ip_max参数错误4')

        if cc_ip_max['open'] == False and cc_ip_max["ip_max"] < 2000:
            if 'cc_ip_max' in config['cc']:
                if 'ip_max' in config['cc']['cc_ip_max']:
                    cc_ip_max["ip_max"] = config['cc']['cc_ip_max']['ip_max']
                else:
                    cc_ip_max["ip_max"] = 2000
            else:
                cc_ip_max["ip_max"] = 2000
        if cc_ip_max["ip_max"] < 2000:
            return public.returnMsg(False, '单IP防御次数最低为2000')
        if cc_ip_max['static'] and cc_ip_max["ip_max"] < 5000:
            return public.returnMsg(False, '单IP防御次数最低为5000（开启包括静态的情况下）')
        get.cc_ip_max = cc_ip_max
        if 'is_cc_url' not in get:
            get.is_cc_url = '1'
        end_time = int(get.endtime)
        if end_time > 86400:
            return public.returnMsg(False, '封锁时间不能超过86400秒')
        if not 'cc_mode' in get: get.cc_mode = '1'
        if 'country' in get:
            try:
                countrysss = get.country.split(",")
                country = {}
                for i in countrysss:
                    i = i.strip()
                    if i:
                        country[i] = i
            except:
                country = {}
        else:
            country = {}
        config['cc_mode'] = int(get.cc_mode)
        config['cc']['cycle'] = int(get.cycle)
        config['cc']['limit'] = int(get.limit)
        config['cc']['endtime'] = int(get.endtime)
        config['cc']['countrys'] = country
        config['cc']['increase'] = (get.increase == '1') | False
        config['increase_wu_heng'] = (get.increase_wu_heng == '1') | False
        config['cc']['cc_increase_type'] = get.cc_increase_type
        config['cc_type_status'] = int(get.cc_type_status)
        config['cc']['is_cc_url'] = (get.is_cc_url == '1') | False
        config['cc']['cc_ip_max'] = cc_ip_max

        if int(get.cc_mode) == 3:
            config['cc_automatic'] = True
        else:
            config['cc_automatic'] = False
        self.__write_config(config)
        public.writeFile('/www/server/btwaf/config.json', json.dumps(config))
        self.__write_log(
            '设置全局CC配置为：' + get.cycle + ' 秒内累计请求超过 ' + get.limit + ' 次后,封锁 ' + get.endtime + ' 秒' + ',增强:' + get.increase);
        if get.is_open_global:
            self.set_cc_golbls(get)
        public.serviceReload()
        return public.returnMsg(True, '设置成功!');

    def set_site_cc_conf(self, get):
        # public.set_module_logs("btwaf","set_site_cc_conf")
        if not 'cc_increase_type' in get: return public.returnMsg(False, '需要cc_increase_type参数');
        if not get.cc_increase_type in ['js', 'code', 'renji', 'huadong', 'browser']: return public.returnMsg(False,
                                                                                                              '需要cc_increase_type参数');
        if not 'cc_ip_max' in get: return public.returnMsg(False, '需要cc_ip_max参数2');
        try:
            cc_ip_max = json.loads(get.cc_ip_max)
        except:
            return public.returnMsg(False, 'cc_ip_max参数错误0')

        if 'open' not in cc_ip_max:
            return public.returnMsg(False, 'cc_ip_max参数错误1')
        if 'ip_max' not in cc_ip_max:
            return public.returnMsg(False, 'cc_ip_max参数错误2')
        if 'static' not in cc_ip_max:
            return public.returnMsg(False, 'cc_ip_max参数错误3')
        if cc_ip_max['open'] == True or cc_ip_max['open'] == 1:
            cc_ip_max['open'] = True
        else:
            cc_ip_max['open'] = False

        if cc_ip_max['static'] == True or cc_ip_max['static'] == 1:
            cc_ip_max['static'] = True
        else:
            cc_ip_max['static'] = False
        site_config = self.get_site_config(None)

        if type(cc_ip_max["ip_max"]) != int: return public.returnMsg(False, 'cc_ip_max参数错误4')
        if cc_ip_max['open'] == False and cc_ip_max["ip_max"] < 2000:
            if 'cc_ip_max' in site_config[get.siteName]['cc']:
                if 'ip_max' in site_config[get.siteName]['cc']['cc_ip_max']:
                    cc_ip_max["ip_max"] = site_config[get.siteName]['cc']['cc_ip_max']['ip_max']
                else:
                    cc_ip_max["ip_max"] = 2000
            else:
                cc_ip_max["ip_max"] = 2000
        if cc_ip_max["ip_max"] < 2000:
            return public.returnMsg(False, '单IP防御次数最低为2000')
        if cc_ip_max['static'] and cc_ip_max["ip_max"] < 5000:
            return public.returnMsg(False, '单IP防御次数最低为5000（开启包括静态的情况下）')
        if cc_ip_max['open'] == False:
            cc_ip_max['static'] = False
        get.cc_ip_max = cc_ip_max

        if not 'cc_mode' in get: get.cc_mode = 1
        if not 'cc_time' in get: get.cc_time = False
        if not 'cc_retry_cycle' in get: get.cc_retry_cycle = False
        if not 'is_cc_url' in get: get.is_cc_url = False

        # config['cc']['is_cc_url'] = (get.is_cc_url == '1') | False
        if 'country' in get:
            try:
                countrysss = get.country.split(",")
                country = {}
                for i in countrysss:
                    i = i.strip()
                    if i:
                        country[i] = i
            except:
                country = {}
        else:
            country = {}
        if get.cc_mode and get.cc_retry_cycle:
            if not self.isDigit(get.cc_mode) and not self.isDigit(get.cc_retry_cycle): return public.returnMsg(False,
                                                                                                               '需要设置数字!')
            site_config[get.siteName]['cc_time'] = int(get.cc_time)
            site_config[get.siteName]['cc_mode'] = int(get.cc_mode)
            site_config[get.siteName]['cc']['cc_mode'] = int(get.cc_mode)
            site_config[get.siteName]['cc_retry_cycle'] = int(get.cc_retry_cycle)
            site_config[get.siteName]['cc_automatic'] = True
            site_config[get.siteName]['cc']['countrys'] = country
            site_config[get.siteName]['cc']['is_cc_url'] = (get.is_cc_url == '1') | False
        else:
            site_config[get.siteName]['cc']['is_cc_url'] = (get.is_cc_url == '1') | False
            site_config[get.siteName]['cc']['countrys'] = country
            site_config[get.siteName]['cc_automatic'] = False
            site_config[get.siteName]['cc_mode'] = int(get.cc_mode)
            site_config[get.siteName]['cc']['cc_mode'] = int(get.cc_mode)
            site_config[get.siteName]['cc']['cycle'] = int(get.cycle)
            site_config[get.siteName]['cc']['limit'] = int(get.limit)
            site_config[get.siteName]['cc']['endtime'] = int(get.endtime)
            site_config[get.siteName]['cc']['cc_increase_type'] = get.cc_increase_type
            site_config[get.siteName]['cc']['increase'] = (get.increase == '1') | False
            site_config[get.siteName]['increase_wu_heng'] = (get.increase_wu_heng == '1') | False
        site_config[get.siteName]['cc_type_status'] = int(get.cc_type_status)

        site_config[get.siteName]['cc']['cc_ip_max'] = cc_ip_max

        self.__write_site_config(site_config)
        public.WriteFile('/www/server/btwaf/site.json', json.dumps(site_config, ensure_ascii=False))
        self.__write_log(
            '设置站点【' + get.siteName + '】CC配置为：' + get.cycle + ' 秒内累计请求超过 ' + get.limit + ' 次后,封锁 ' + get.endtime + ' 秒' + ',增强:' + get.increase);
        return public.returnMsg(True, '设置成功!')

    def cn_to_ip(self, aaa):
        for i in aaa:
            for i2 in range(len(i)):
                if i2 >= 2: break
                i[i2] = self.ip2long(i[i2])
        return aaa

    def binary_search(self, data, value):
        low = 0
        high = len(data) - 1

        while low <= high:
            mid = (low + high) // 2
            start, end = data[mid]

            if start <= value <= end:
                return {"start": start, "end": end, "result": True}
            elif value < start:
                high = mid - 1
            else:
                low = mid + 1
        return {"start": 0, "end": 0, "result": False}

    def add_cnip(self, get):
        ipn = [self.__format_ip(get.start_ip), self.__format_ip(get.end_ip)]
        if not ipn[0] or not ipn[1]: return public.returnMsg(False, 'IP段格式不正确');
        if not self.__is_ipn(ipn): return public.returnMsg(False, '起始IP不能大于结束IP');
        iplist = self.get_cn_list('cn')
        ipn = [get.start_ip, get.end_ip]
        if ipn in iplist: return public.returnMsg(False, '指定IP段已存在!');

        rule = self.__get_rule("cn")
        start_info = self.binary_search(rule, self.ip2long(ipn[0]))
        end_info = self.binary_search(rule, self.ip2long(ipn[1]))
        if start_info["result"]:
            return public.returnMsg(False, "该IP已经存在在:" + self.long2ip(start_info["start"]) + "-" + self.long2ip(
                start_info["end"]) + "这个IP段中,无需添加")
        if end_info["result"]:
            return public.returnMsg(False, "该IP已经存在在:" + self.long2ip(end_info["start"]) + "-" + self.long2ip(
                end_info["end"]) + "这个IP段中,无需添加")

        iplist.insert(0, ipn)
        iplist2 = self.cn_to_ip(iplist)
        iplist2 = sorted(iplist2, key=lambda x: x[0])
        self.__write_rule('cn', iplist2)
        self.__write_log('添加IP段[' + get.start_ip + '-' + get.end_ip + ']到国内IP库');
        return public.returnMsg(True, '添加成功!')

    def remove_cnip(self, get):
        index = int(get.index)
        iplist = self.get_cn_list('cn')
        del (iplist[index])
        iplist2 = self.cn_to_ip(iplist)
        iplist2 = sorted(iplist2, key=lambda x: x[0])
        self.__write_rule('cn', iplist2)
        return public.returnMsg(True, '删除成功!')

    def add_ip_white(self, get):
        ipn = [self.__format_ip(get.start_ip), self.__format_ip(get.end_ip)]
        ips = "-,{}-{}".format(get.start_ip, get.end_ip)
        public.WriteFile("/dev/shm/.bt_ip_filter", ips)
        if not ipn[0] or not ipn[1]: return public.returnMsg(False, 'IP段格式不正确');
        if not self.__is_ipn(ipn): return public.returnMsg(False, '起始IP不能大于结束IP');
        ipn = [get.start_ip, get.end_ip]
        if 'ps' in get and get.ps:
            ipn.append(get.ps)
        iplist = self.get_cn_list('ip_white')
        if ipn in iplist: return public.returnMsg(False, '指定IP段已存在!');
        iplist.insert(0, ipn)
        self.__write_rule('ip_white', self.cn_to_ip(iplist))
        self.__write_log('添加IP段[' + get.start_ip + '-' + get.end_ip + ']到IP白名单')
        return public.returnMsg(True, '添加成功!')

    def edit_ip_white_ps(self, get):
        if 'id' not in get: return public.returnMsg(False, '参数错误!')
        iplist = self.get_cn_list('ip_white')
        if len(iplist) < int(get.id): return public.returnMsg(False, '参数错误!')
        if len(iplist[int(get.id)]) == 2:
            iplist[int(get.id)].append(get.ps)
        else:
            iplist[int(get.id)][2] = get.ps
        self.__write_rule('ip_white', self.cn_to_ip(iplist))
        return public.returnMsg(True, '修改成功!')

    def edit_ip_black_ps(self, get):
        if 'id' not in get: return public.returnMsg(False, '参数错误!')
        iplist = self.get_cn_list('ip_black')
        if len(iplist) < int(get.id): return public.returnMsg(False, '参数错误!')
        if len(iplist[int(get.id)]) == 2:
            iplist[int(get.id)].append(get.ps)
        else:
            iplist[int(get.id)][2] = get.ps
        self.__write_rule('ip_black', self.cn_to_ip(iplist))
        return public.returnMsg(True, '修改成功!')

    def remove_ip_white(self, get):
        index = int(get.index)
        iplist = self.get_cn_list('ip_white')
        ipn = iplist[index]
        del (iplist[index])
        self.__write_rule('ip_white', self.cn_to_ip(iplist))
        return public.returnMsg(True, '删除成功!')

    def import_data2(self, type, pdata):
        if not pdata: return public.returnMsg(False, '数据格式不正确')
        # iplist = self.get_cn_list(type)
        for i in pdata:
            ipn = [self.__format_ip(i[0]), self.__format_ip(i[1])]
            if not ipn[0] or not ipn[1]: continue
            if not self.__is_ipn(ipn): continue
            ipn = [i[0], i[1]]
            iplist = self.get_cn_list(type)
            if ipn in iplist: continue
            iplist.insert(0, ipn)
            self.__write_rule(type, self.cn_to_ip(iplist))
        return public.returnMsg(True, '导入成功!')

    def is_ip_zhuanhuang(self, ip, ip2=False, ip_duan=False):
        try:
            ret = []
            if ip_duan:
                ip_ddd = int(ip.split('/')[1])
                ip = ip.split('/')[0].split('.')
                if ip_ddd >= 32: return False
                net_ip = ipaddress.ip_interface("{}/{}".format('.'.join(ip), ip_ddd))
                network_start = net_ip.network.network_address
                network_end = net_ip.network.broadcast_address
                return self.is_ip_zhuanhuang(str(network_start), str(network_end))
            else:
                if ip2 and ip:
                    ret.append(ip)
                    ret.append(ip2)
                    return ret
                else:
                    ret.append(ip)
                    ret.append(ip)
                    return ret
        except:
            return False

    def bt_ip_filter(self, datas):
        # 检查状态
        status = public.ExecShell("/etc/init.d/bt_ipfilter status")
        if 'service not running' in status[0]:
            public.ExecShell("/etc/init.d/bt_ipfilter restart")
        path = "/dev/shm/.bt_ip_filter"
        if os.path.exists(path):
            data = public.ReadFile(path)
            data += "\n" + datas
            public.WriteFile(path, data)
        else:
            public.WriteFile(path, datas)

    def import_data(self, get):
        name = get.s_Name
        if name == 'ip_white' or name == 'ip_black' or name == "cn":
            if 'json' in get:
                pdata = json.loads(get.pdata)
                if not pdata: return public.returnMsg(False, '数据格式不正确');
                if name == 'ip_white': return self.import_data2('ip_white', pdata)
                if name == 'ip_black': return self.import_data2('ip_black', pdata)
                if name == 'cn': return self.import_data2('cn', pdata)
                iplist = self.__get_rule(name)
                for ips in pdata:
                    if ips in iplist: continue;
                    iplist.insert(0, ips)
                self.__write_rule(name, iplist)
                return public.returnMsg(True, '导入成功!')
            else:
                padata = get.pdata.strip().split()
                if not padata: return public.returnMsg(False, '数据格式不正确')
                iplist = self.get_cn_list(name)
                for i in padata:
                    if re.search("\d+.\d+.\d+.\d+-\d+.\d+.\d+.\d+$", i):
                        ip = i.split('-')
                        ips = self.is_ip_zhuanhuang(ip[0], ip[1])
                        if not ips: continue
                        if ips in iplist: continue
                        iplist.insert(0, ips)

                    elif re.search("\d+.\d+.\d+.\d+/\d+$", i):
                        ips = self.is_ip_zhuanhuang(i, ip_duan=True)
                        if not ips: continue
                        if ips in iplist: continue
                        iplist.insert(0, ips)

                    elif re.search("\d+.\d+.\d+.\d+$", i):
                        ips = self.is_ip_zhuanhuang(i)
                        if not ips: continue
                        if ips in iplist: continue
                        iplist.insert(0, ips)
                    if name == 'ip_black':
                        ips = self.is_ip_zhuanhuang(i)
                        if not ips: continue
                        # 如果他在白名单中则不添加
                        ipn = [ips[0], ips[1]]
                        ip_white_rule = self.get_cn_list('ip_white')
                        if ipn in ip_white_rule: continue
                        self.bt_ip_filter("+,%s-%s,86400" % (ips[0], ips[1]))
                    if name == "ip_white":
                        ips = self.is_ip_zhuanhuang(i)
                        self.bt_ip_filter("-,%s-%s" % (ips[0], ips[1]))
                    # public.ExecShell('echo "+,%s-%s,86400" >/dev/shm/.bt_ip_filter'%(ips[0],ips[1]))
                self.__write_rule(name, self.cn_to_ip(iplist))
                return public.returnMsg(True, '导入成功!')
        else:
            if 'json' not in get:
                get.json = True
            else:
                get.json = get.json
            if get.json:
                try:
                    pdata = json.loads(get.pdata)
                except:
                    pdata = get.pdata.strip().split()
            else:
                pdata = get.pdata.strip().split()
            if not pdata: return public.returnMsg(False, '数据格式不正确');
            if name == 'ip_white': return self.import_data2('ip_white', pdata)
            if name == 'ip_black': return self.import_data2('ip_black', pdata)
            if name == 'cn': return self.import_data2('cn', pdata)
            iplist = self.__get_rule(name)
            for ips in pdata:
                if ips in iplist: continue;
                iplist.insert(0, ips)
            self.__write_rule(name, iplist)
            return public.returnMsg(True, '导入成功!')

    def output_data(self, get):
        iplist = self.__get_rule(get.s_Name)
        return iplist;

    def add_ip_black(self, get):
        ipn = [self.__format_ip(get.start_ip), self.__format_ip(get.end_ip)]
        if not ipn[0] or not ipn[1]: return public.returnMsg(False, 'IP段格式不正确');
        if not self.__is_ipn(ipn): return public.returnMsg(False, '起始IP不能大于结束IP');

        ipn = [get.start_ip, get.end_ip]

        iplist = self.get_cn_list('ip_white')
        if not ipn in iplist:
            ipn = [get.start_ip, get.end_ip]
            self.bt_ip_filter("+,%s-%s,86400" % (get.start_ip, get.end_ip))
        if 'ps' in get and get.ps:
            ipn.append(get.ps)
        iplist = self.get_cn_list('ip_black')
        if ipn in iplist: return public.returnMsg(False, '指定IP段已存在!');
        iplist.insert(0, ipn)
        self.__write_rule('ip_black', self.cn_to_ip(iplist))
        self.__write_log('添加IP段[' + get.start_ip + '-' + get.end_ip + ']到IP黑名单')
        return public.returnMsg(True, '添加成功!')

    def remove_ip_black(self, get):
        index = int(get.index)
        iplist = self.get_cn_list('ip_black')
        ipn = iplist[index]
        del (iplist[index])
        # return ipn
        self.bt_ip_filter("-,%s-%s,86400" % (ipn[0], ipn[1]))
        self.__write_rule('ip_black', self.cn_to_ip(iplist))
        return public.returnMsg(True, '删除成功!')

    def add_url_white(self, get):
        url_white = self.__get_rule('url_white')
        url_rule = get.url_rule.strip()
        # 取?前的url
        url_rule = url_rule.split('?')[0]
        if url_rule == '^/' or url_rule == '/': return public.returnMsg(False, '不允许添加根目录')
        if get.url_rule in url_white: return public.returnMsg(False, '您添加的URL已存在')
        url_white.insert(0, url_rule)
        self.__write_rule('url_white', url_white)
        self.__write_log('添加url规则[' + url_rule + ']到URL白名单');
        return public.returnMsg(True, '添加成功!')

    def add_url_white_senior(self, get):
        if not 'url' in get: return public.returnMsg(False, '请输入url!')
        if not 'param' in get: return public.returnMsg(False, '请输入参数!')
        url_white = self.__get_rule('url_white_senior')
        try:
            param = json.loads(get.param)
        except:
            return public.returnMsg(False, '参数传递错误!')
        params = []
        for i in param:
            if i == "": continue
            if not i: continue
            params.append(i)
        data = {get.url: params}
        if data in url_white: return public.returnMsg(False, '已存在!')
        url_white.insert(0, data)
        self.__write_rule('url_white_senior', url_white)
        return public.returnMsg(True, '添加成功')

    def del_url_white_senior(self, get):
        if not 'url' in get: return public.returnMsg(False, '请输入url!')
        if not 'param' in get: get.param = ""
        url_white = self.__get_rule('url_white_senior')
        param = get.param.strip()
        param = param.split(",")
        if len(param) == 1 and param[0] == "":
            data = {get.url: []}
        else:
            data = {get.url: param}
        if not data in url_white: return public.returnMsg(False, '不存在!')
        url_white.remove(data)
        self.__write_rule('url_white_senior', url_white)
        return public.returnMsg(True, '删除成功')

    def get_url_white_senior(self, get):
        url_white = self.__get_rule('url_white_senior')
        return url_white

    def get_url_request_mode(self, get):
        url_white = self.__get_rule('url_request_mode')
        return url_white

    def get_reg_tions(self, get):
        url_white = self.__get_rule('reg_tions')
        # {"site": sitesMode, "types": get.types, "region": paramMode,"open":True,"reqfile":"city.html","status":444,"random_id":public.GetRandomString(16)}
        url_white_flag = False
        for i in url_white:

            if 'open' not in i:
                url_white_flag = True
                i['open'] = True
            if 'status' not in i:
                url_white_flag = True
                i['status'] = 444
            if 'reqfile' not in i:
                url_white_flag = True
                i['reqfile'] = "city.html"
            if 'system_block' not in i:
                url_white_flag = True
                i['system_block'] = False
        if url_white_flag:
            self.__write_rule('reg_tions', url_white)
        url_city_tions = False
        city_tions = self.__get_rule('reg_city')
        for i in city_tions:
            if 'open' not in i:
                url_city_tions = True
                i['open'] = True
            if 'status' not in i:
                url_city_tions = True
                i['status'] = 444
            if 'reqfile' not in i:
                url_city_tions = True
                i['reqfile'] = "city.html"
            if 'system_block' not in i:
                url_city_tions = True
                i['system_block'] = False
        # 两个表格聚合在一起
        if url_city_tions:
            self.__write_rule('reg_city', city_tions)
        return url_white, city_tions

    def get_city(self, get):
        return {
            "上海": ["上海"],
            "云南": ["昆明", "迪庆", "西双版纳", "曲靖", "临沧", "保山", "红河", "普洱", "玉溪", "大理", "楚雄",
                     "德宏", "文山", "昭通", "丽江", "怒江"],
            "内蒙古": ["呼和浩特", "锡林郭勒", "包头", "乌兰察布", "阿拉善", "巴彦淖尔", "兴安", "鄂尔多斯", "乌海",
                       "呼伦贝尔", "通辽", "赤峰"],
            "北京": ["北京"],
            "吉林": ["长春", "吉林", "延边", "四平", "白城", "辽源", "松原", "白山", "通化"],
            "四川": ["成都", "内江", "泸州", "凉山", "甘孜", "阿坝", "绵阳", "广元", "巴中", "南充", "达州", "广安",
                     "遂宁", "眉山", "乐山", "雅安", "资阳", "自贡", "攀枝花", "宜宾", "德阳"],
            "天津": ["天津"],
            "宁夏": ["银川", "石嘴山", "中卫", "固原", "吴忠"],
            "安徽": ["滁州", "合肥", "宿州", "铜陵", "亳州", "黄山", "蚌埠", "淮北", "阜阳", "六安", "宣城", "安庆",
                     "马鞍山", "池州", "淮南", "芜湖"],
            "山东": ["青岛", "济南", "潍坊", "德州", "烟台", "淄博", "聊城", "临沂", "济宁", "泰安", "东营", "威海",
                     "枣庄", "菏泽", "滨州", "日照"],
            "山西": ["太原", "长治", "运城", "晋中", "忻州", "晋城", "朔州", "阳泉", "吕梁", "临汾", "大同"],
            "广东": ["广州", "珠海", "深圳", "惠州", "东莞", "中山", "佛山", "汕尾", "云浮", "湛江", "肇庆", "潮州",
                     "茂名", "梅州", "汕头", "阳江", "河源", "揭阳", "江门", "清远", "韶关"],
            "广西": ["南宁", "桂林", "来宾", "玉林", "钦州", "贺州", "贵港", "防城港", "崇左", "柳州", "河池",
                     "北海", "梧州", "百色"],
            "新疆": ["和田", "克孜勒苏", "阿勒泰", "哈密", "博尔塔拉", "巴音郭楞", "昌吉", "吐鲁番", "塔城",
                     "石河子", "阿克苏", "喀什", "图木舒克", "乌鲁木齐", "克拉玛依", "阿拉尔", "伊犁", "双河",
                     "北屯", "胡杨河", "昆玉", "五家渠", "可克达拉", "铁门关"],
            "江苏": ["扬州", "南京", "常州", "苏州", "泰州", "无锡", "南通", "盐城", "徐州", "镇江", "淮安",
                     "连云港", "宿迁"],
            "江西": ["南昌", "抚州", "萍乡", "上饶", "赣州", "宜春", "景德镇", "吉安", "九江", "新余", "鹰潭"],
            "河北": ["保定", "石家庄", "廊坊", "衡水", "唐山", "邯郸", "秦皇岛", "沧州", "邢台", "张家口", "承德",
                     "雄安"],
            "河南": ["郑州", "三门峡", "新乡", "南阳", "濮阳", "驻马店", "商丘", "洛阳", "漯河", "信阳", "周口",
                     "焦作", "开封", "鹤壁", "平顶山", "安阳", "许昌", "济源"],
            "浙江": ["杭州", "温州", "嘉兴", "宁波", "湖州", "台州", "金华", "绍兴", "丽水", "衢州", "舟山"],
            "海南": ["海口", "万宁", "三亚", "儋州", "文昌", "乐东", "琼海", "陵水", "澄迈", "东方", "昌江", "定安",
                     "琼中", "保亭", "屯昌", "五指山", "临高", "白沙"],
            "湖北": ["黄冈", "武汉", "荆州", "宜昌", "襄阳", "孝感", "黄石", "咸宁", "恩施", "荆门", "十堰", "鄂州",
                     "随州", "神农架", "潜江", "天门", "仙桃"],
            "湖南": ["长沙", "常德", "娄底", "株洲", "郴州", "衡阳", "怀化", "永州", "益阳", "张家界", "湘潭",
                     "岳阳", "邵阳", "湘西"],
            "甘肃": ["定西", "临夏", "甘南", "平凉", "庆阳", "嘉峪关", "天水", "兰州", "武威", "金昌", "酒泉",
                     "白银", "陇南", "张掖"],
            "福建": ["福州", "厦门", "宁德", "泉州", "三明", "莆田", "漳州", "南平", "龙岩"],
            "西藏": ["拉萨", "昌都", "山南", "阿里", "林芝", "日喀则", "那曲"],
            "贵州": ["安顺", "黔南", "铜仁", "毕节", "遵义", "黔西南", "六盘水", "贵阳", "黔东南"],
            "辽宁": ["锦州", "沈阳", "大连", "朝阳", "铁岭", "盘锦", "鞍山", "营口", "本溪", "辽阳", "抚顺", "阜新",
                     "葫芦岛", "丹东"],
            "重庆": ["重庆"],
            "陕西": ["西安", "商洛", "铜川", "汉中", "安康", "渭南", "榆林", "宝鸡", "咸阳", "延安"],
            "青海": ["海西", "海东", "西宁", "黄南", "玉树", "海北", "果洛", "海南"],
            "黑龙江": ["鹤岗", "牡丹江", "绥化", "齐齐哈尔", "双鸭山", "鸡西", "哈尔滨", "大庆", "佳木斯", "黑河",
                       "七台河", "伊春", "大兴安岭"]
        }

    def add_city(self, get):
        if not 'site' in get: return public.returnMsg(False, '请输入需要设置的站点!')
        if not 'types' in get: return public.returnMsg(False, '请输入类型!')
        if not 'region' in get: return public.returnMsg(False, '请输入地区!')
        url_white = self.__get_rule('reg_city')
        if not url_white: url_white = []

        param = get.region.split(",")
        sitessss = get.site.split(",")
        type_list = ["refuse", "accept"]
        if not get.types in type_list: return public.returnMsg(False, '输入的类型错误!')
        paramMode = {}
        for i in param:
            if not i: continue
            i = i.strip()
            if not i in paramMode:
                paramMode[i] = "1"
        sitesMode = {}

        for i in sitessss:
            i = i.strip()
            if not i: continue
            if not i in sitesMode:
                sitesMode[i] = "1"
        if len(paramMode) == 0: return public.returnMsg(False, '输入的请求类型错误!')
        if len(sitesMode) == 0: return public.returnMsg(False, '输入的站点错误!')
        data = {"site": sitesMode, "types": get.types, "region": paramMode, "open": True, "reqfile": "city.html",
                "status": 444, "system_block": False}
        if data in url_white: return public.returnMsg(False, '已存在!')
        url_white.insert(0, data)
        self.__write_rule('reg_city', url_white)
        return public.returnMsg(True, '添加成功!')

    def edit_reg_city(self, get):
        '''
            修改地区限制
        :param id 记录的ID
        :param open 状态
        :param status 状态码
        :return:
        '''
        if not 'id' in get: return public.returnMsg(False, '请输入ID!')
        if not 'open' in get: return public.returnMsg(False, '请输入open!')
        if not 'status' in get: return public.returnMsg(False, '请输入status!')
        url_white = self.__get_rule('reg_city')
        if len(url_white) < int(get.id): return public.returnMsg(False, '参数错误!')
        # open 如果是true 或者1 则是开启状态
        if get.open == "true" or get.open == "1":
            get.open = True
        else:
            get.open = False
        # 状态码只有200 404 403 444 502 503 504
        status_list = [200, 404, 403, 444, 502, 503, 504]
        if not int(get.status) in status_list: return public.returnMsg(False, '输入的状态码错误!')
        url_white[int(get.id)]['open'] = get.open
        url_white[int(get.id)]['status'] = int(get.status)
        self.__write_rule('reg_city', url_white)
        return public.returnMsg(True, '修改成功!')

    def del_city(self, get):
        # if not 'site' in get: return public.returnMsg(False, '请输入需要设置的站点!')
        # if not 'types' in get: return public.returnMsg(False, '请输入类型!')
        # if not 'region' in get: return public.returnMsg(False, '请输入地区!')
        # url_white = self.__get_rule('reg_city')
        # param = get.region.split(",")
        # sitessss = get.site.split(",")
        # type_list = ["refuse", "accept"]
        # if not get.types in type_list: return public.returnMsg(False, '输入的类型错误!')
        # paramMode = {}
        # for i in param:
        #     if not i: continue
        #     if not i in paramMode:
        #         paramMode[i] = "1"
        # sitesMode = {}
        # for i in sitessss:
        #     if not i: continue
        #     if not i in sitesMode:
        #         sitesMode[i] = "1"
        # if len(paramMode) == 0: return public.returnMsg(False, '输入的请求类型错误!')
        # if len(sitesMode) == 0: return public.returnMsg(False, '输入的站点错误!')
        #
        # data = {"site": sitesMode, "types": get.types, "region": paramMode}
        # if not data in url_white: return public.returnMsg(False, '不存在!')
        # url_white.remove(data)

        if not 'id' in get: return public.returnMsg(False, '请输入站点ID!')

        url_white = self.__get_rule('reg_city')
        if len(url_white) == 0: return public.returnMsg(False, '没有数据!')

        if len(url_white) < int(get.id): return public.returnMsg(False, '参数错误!')
        del (url_white[int(get.id)])
        self.__write_rule('reg_city', url_white)
        return public.returnMsg(True, '删除成功!')

    def city(self, get):

        data = ['中国大陆以外的地区(包括[中国特别行政区:港,澳,台])', '中国大陆(不包括[中国特别行政区:港,澳,台])',
                '中国香港', '中国澳门', '中国台湾',
                '美国', '日本', '英国', '德国', '韩国', '法国', '巴西', '加拿大', '意大利', '澳大利亚', '荷兰',
                '俄罗斯', '印度', '瑞典', '西班牙', '墨西哥',
                '比利时', '南非', '波兰', '瑞士', '阿根廷', '印度尼西亚', '埃及', '哥伦比亚', '土耳其', '越南', '挪威',
                '芬兰', '丹麦', '乌克兰', '奥地利',
                '伊朗', '智利', '罗马尼亚', '捷克', '泰国', '沙特阿拉伯', '以色列', '新西兰', '委内瑞拉', '摩洛哥',
                '马来西亚', '葡萄牙', '爱尔兰', '新加坡',
                '欧洲联盟', '匈牙利', '希腊', '菲律宾', '巴基斯坦', '保加利亚', '肯尼亚', '阿拉伯联合酋长国',
                '阿尔及利亚', '塞舌尔', '突尼斯', '秘鲁', '哈萨克斯坦',
                '斯洛伐克', '斯洛文尼亚', '厄瓜多尔', '哥斯达黎加', '乌拉圭', '立陶宛', '塞尔维亚', '尼日利亚',
                '克罗地亚', '科威特', '巴拿马', '毛里求斯', '白俄罗斯',
                '拉脱维亚', '多米尼加', '卢森堡', '爱沙尼亚', '苏丹', '格鲁吉亚', '安哥拉', '玻利维亚', '赞比亚',
                '孟加拉国', '巴拉圭', '波多黎各', '坦桑尼亚',
                '塞浦路斯', '摩尔多瓦', '阿曼', '冰岛', '叙利亚', '卡塔尔', '波黑', '加纳', '阿塞拜疆', '马其顿',
                '约旦', '萨尔瓦多', '伊拉克', '亚美尼亚', '马耳他',
                '危地马拉', '巴勒斯坦', '斯里兰卡', '特立尼达和多巴哥', '黎巴嫩', '尼泊尔', '纳米比亚', '巴林',
                '洪都拉斯', '莫桑比克', '尼加拉瓜', '卢旺达', '加蓬',
                '阿尔巴尼亚', '利比里亚', '吉尔吉斯坦', '柬埔寨', '古巴', '喀麦隆', '乌干达', '塞内加尔', '乌兹别克斯坦',
                '黑山', '关岛', '牙买加', '蒙古', '文莱',
                '英属维尔京群岛', '留尼旺', '库拉索岛', '科特迪瓦', '开曼群岛', '巴巴多斯', '马达加斯加', '伯利兹',
                '新喀里多尼亚', '海地', '马拉维', '斐济', '巴哈马',
                '博茨瓦纳', '扎伊尔', '阿富汗', '莱索托', '百慕大', '埃塞俄比亚', '美属维尔京群岛', '列支敦士登',
                '津巴布韦', '直布罗陀', '苏里南', '马里', '也门',
                '老挝', '塔吉克斯坦', '安提瓜和巴布达', '贝宁', '法属玻利尼西亚', '圣基茨和尼维斯', '圭亚那',
                '布基纳法索', '马尔代夫', '泽西岛', '摩纳哥', '巴布亚新几内亚',
                '刚果', '塞拉利昂', '吉布提', '斯威士兰', '缅甸', '毛里塔尼亚', '法罗群岛', '尼日尔', '安道尔',
                '阿鲁巴', '布隆迪', '圣马力诺', '利比里亚',
                '冈比亚', '不丹', '几内亚', '圣文森特岛', '荷兰加勒比区', '圣马丁', '多哥', '格陵兰', '佛得角',
                '马恩岛', '索马里', '法属圭亚那', '西萨摩亚',
                '土库曼斯坦', '瓜德罗普', '马里亚那群岛', '瓦努阿图', '马提尼克', '赤道几内亚', '南苏丹', '梵蒂冈',
                '格林纳达', '所罗门群岛', '特克斯和凯科斯群岛', '多米尼克',
                '乍得', '汤加', '瑙鲁', '圣多美和普林西比', '安圭拉岛', '法属圣马丁', '图瓦卢', '库克群岛',
                '密克罗尼西亚联邦', '根西岛', '东帝汶', '中非',
                '几内亚比绍', '帕劳', '美属萨摩亚', '厄立特里亚', '科摩罗', '圣皮埃尔和密克隆', '瓦利斯和富图纳',
                '英属印度洋领地', '托克劳', '马绍尔群岛', '基里巴斯',
                '纽埃', '诺福克岛', '蒙特塞拉特岛', '朝鲜', '马约特', '圣卢西亚', '圣巴泰勒米岛']

        return data

    def reg_domains(self, get):
        site_config2 = json.loads(public.readFile(self.__path + 'domains.json'))
        return site_config2

    def add_reg_tions(self, get):
        if not 'site' in get: return public.returnMsg(False, '请输入需要设置的站点!')
        if not 'types' in get: return public.returnMsg(False, '请输入类型!')
        if not 'region' in get: return public.returnMsg(False, '请输入地区!')
        url_white = self.__get_rule('reg_tions')
        param = get.region.split(",")

        sitessss = get.site.split(",")
        type_list = ["refuse", "accept"]
        if not get.types in type_list: return public.returnMsg(False, '输入的类型错误!')

        paramMode = {}
        for i in param:
            if not i: continue
            i = i.strip()
            if not i in paramMode:
                paramMode[i] = "1"
        sitesMode = {}

        if '海外' in paramMode and '中国' in paramMode:
            return public.returnMsg(False, '不允许设置【中国大陆】和【中国大陆以外地区】一同开启地区限制!')
        for i in sitessss:
            i = i.strip()
            if not i: continue

            if not i in sitesMode:
                sitesMode[i] = "1"
        if len(paramMode) == 0: return public.returnMsg(False, '输入的请求类型错误!')
        if len(sitesMode) == 0: return public.returnMsg(False, '输入的站点错误!')

        data = {"site": sitesMode, "types": get.types, "region": paramMode, "open": True, "reqfile": "city.html",
                "status": 444, "system_block": False}
        if data in url_white: return public.returnMsg(False, '已存在!')
        url_white.insert(0, data)
        self.__write_rule('reg_tions', url_white)
        return public.returnMsg(True, '添加成功!')

    def edit_reg_tions(self, get):
        '''
            修改地区限制
        :param id 记录的ID
        :param open 状态
        :param status 状态码
        :return:
        '''
        if not 'id' in get: return public.returnMsg(False, '请输入ID!')
        if not 'open' in get: return public.returnMsg(False, '请输入open!')
        if not 'status' in get: return public.returnMsg(False, '请输入status!')
        url_white = self.__get_rule('reg_tions')
        if len(url_white) < int(get.id): return public.returnMsg(False, '参数错误!')
        # open 如果是true 或者1 则是开启状态
        if get.open == "true" or get.open == "1":
            get.open = True
        else:
            get.open = False
        # 状态码只有200 404 403 444 502 503 504
        status_list = [200, 404, 403, 444, 502, 503, 504]
        if not int(get.status) in status_list: return public.returnMsg(False, '输入的状态码错误!')
        url_white[int(get.id)]['open'] = get.open
        url_white[int(get.id)]['status'] = int(get.status)
        self.__write_rule('reg_tions', url_white)
        return public.returnMsg(True, '修改成功!')

    def del_reg_tions(self, get):
        if not 'id' in get: return public.returnMsg(False, '请输入ID!')

        # if not 'site' in get: return public.returnMsg(False, '请输入需要设置的站点!')
        # if not 'types' in get: return public.returnMsg(False, '请输入类型!')
        # if not 'region' in get: return public.returnMsg(False, '请输入地区!')
        url_white = self.__get_rule('reg_tions')
        # param = get.region.split(",")
        # sitessss = get.site.split(",")
        # type_list = ["refuse", "accept"]
        # if not get.types in type_list: return public.returnMsg(False, '输入的类型错误!')
        # paramMode = {}
        # for i in param:
        #     if not i: continue
        #     if not i in paramMode:
        #         paramMode[i] = "1"
        # sitesMode = {}
        # for i in sitessss:
        #     if not i: continue
        #     if not i in sitesMode:
        #         sitesMode[i] = "1"
        # if len(paramMode) == 0: return public.returnMsg(False, '输入的请求类型错误!')
        # if len(sitesMode) == 0: return public.returnMsg(False, '输入的站点错误!')
        #
        # data = {"site": sitesMode, "types": get.types, "region": paramMode}
        # if not data in url_white: return public.returnMsg(False, '不存在!')
        # url_white.remove(data)
        if len(url_white) == 0: return public.returnMsg(False, '没有数据!')
        if len(url_white) < int(get.id): return public.returnMsg(False, '参数错误!')
        del (url_white[int(get.id)])

        self.__write_rule('reg_tions', url_white)
        return public.returnMsg(True, '删除成功!')

    def add_url_request_mode(self, get):
        if not 'url' in get: return public.returnMsg(False, '请输入url!')
        if not 'param' in get: return public.returnMsg(False, '请输入参数!')
        if not 'type' in get: return public.returnMsg(False, '请输入类型!')
        url_white = self.__get_rule('url_request_mode')
        param = get.param.split(",")
        paramlist = ["POST", "GET", "PUT", "OPTIONS", "HEAD", "DELETE", "TRACE", "PATCH", "MOVE", "COPY", "LINK",
                     "UNLINK", "WRAPPED", "PROPFIND", "PROPPATCH"
                                                      "MKCOL", "CONNECT", "SRARCH"]
        type_list = ["refuse", "accept"]
        if not get.type in type_list: return public.returnMsg(False, '输入的类型错误!')
        paramMode = {}
        for i in param:
            if i in paramlist:
                if not i in paramMode:
                    paramMode[i] = i
        if len(paramMode) == 0: return public.returnMsg(False, '输入的请求类型错误!')
        data = {"url": get.url, "type": get.type, "mode": paramMode}
        if data in url_white: return public.returnMsg(False, '已存在!')
        url_white.insert(0, data)
        self.__write_rule('url_request_mode', url_white)
        return public.returnMsg(True, '添加成功!')

    def del_url_request_mode(self, get):
        if not 'url' in get: return public.returnMsg(False, '请输入url!')
        if not 'param' in get: return public.returnMsg(False, '请输入参数!')
        if not 'type' in get: return public.returnMsg(False, '请输入类型!')
        url_white = self.__get_rule('url_request_mode')
        param = get.param.split(",")
        paramlist = ["POST", "GET", "PUT", "OPTIONS", "HEAD", "DELETE", "TRACE", "PATCH", "MOVE", "COPY", "LINK",
                     "UNLINK", "WRAPPED", "PROPFIND", "PROPPATCH"
                                                      "MKCOL", "CONNECT", "SRARCH"]
        type_list = ["refuse", "accept"]
        if not get.type in type_list: return public.returnMsg(False, '输入的类型错误!')
        paramMode = {}
        for i in param:
            if i in paramlist:
                if not i in paramMode:
                    paramMode[i] = i
        if len(paramMode) == 0: return public.returnMsg(False, '输入的请求类型错误!')
        data = {"url": get.url, "type": get.type, "mode": paramMode}
        if not data in url_white: return public.returnMsg(False, '已存在!')
        url_white.remove(data)
        self.__write_rule('url_request_mode', url_white)
        return public.returnMsg(True, '删除成功!')

    def url_white_add_param(self, get):
        url = get.url_rule.strip()
        # 获取到url 然后再获取参数
        uri = url.split('?')[0]
        url2 = url.replace(uri, "")
        ret = []
        if not url2.startswith("?"):
            return public.returnMsg(False, '未发现该URL存在参数!')
        else:
            # 去掉第一个字符串
            url2 = url2[1:]
            # 使用&分割字符串
            url2 = url2.split('&')
            # 遍历字符串
            for i in url2:
                i = i.split("=")
                if len(i) == 2:
                    ret.append(i[0])
        if not ret:
            return public.returnMsg(False, '未发现该URL存在参数!')
        if uri == "/":
            return public.returnMsg(False, '不允许添加URL为 [/] 的URL为白名单')
        get.url = uri
        get.param = json.dumps(ret)
        return self.add_url_white_senior(get)

    def wubao_url_white(self, get):
        if not 'http_log' in get:
            get.http_log = ''
        if not 'error_log' in get:
            get.error_log = ''
        if not 'param' in get:
            get.param = 0
        url_rule = ""

        if get.param == 0:
            url_white = self.__get_rule('url_white')
            url_rule = get.url_rule.strip()
            url_rule = '^' + url_rule.split('?')[0]
            if url_rule in url_white: return public.returnMsg(False, '您添加的URL已存在')
            if url_rule == '^/': return public.returnMsg(False, '不允许添加URL为 [/] 的URL为白名单')
            url_white.insert(0, url_rule)
            self.__write_rule('url_white', url_white)
            self.__write_log('添加url规则[' + url_rule + ']到URL白名单')
        else:
            if os.path.exists('/www/server/panel/data/userInfo.json'):
                try:
                    userInfo = json.loads(public.ReadFile('/www/server/panel/data/userInfo.json'))
                    url = "https://www.bt.cn/api/bt_waf/reportInterceptFail"
                    data = {"url": url_rule, "error_log": get.error_log, "http_log": get.http_log,
                            "access_key": userInfo['access_key'], "uid": userInfo['uid']}
                    public.httpPost(url, data)
                except:
                    pass

            return self.url_white_add_param(get)
        if os.path.exists('/www/server/panel/data/userInfo.json'):
            try:
                userInfo = json.loads(public.ReadFile('/www/server/panel/data/userInfo.json'))
                url = "https://www.bt.cn/api/bt_waf/reportInterceptFail"
                data = {"url": url_rule, "error_log": get.error_log, "http_log": get.http_log,
                        "access_key": userInfo['access_key'], "uid": userInfo['uid']}
                public.httpPost(url, data)
            except:
                pass
        return public.returnMsg(True, '添加成功!')

    def remove_url_white(self, get):
        url_white = self.__get_rule('url_white')
        index = int(get.index)
        url_rule = url_white[index]
        del (url_white[index])
        self.__write_rule('url_white', url_white)
        self.__write_log('从URL白名单删除URL规则[' + url_rule + ']');
        return public.returnMsg(True, '删除成功!');

    def add_url_black(self, get):
        url_white = self.__get_rule('url_black')
        url_rule = get.url_rule.strip()
        url_rule = url_rule.split('?')[0]
        if get.url_rule in url_white: return public.returnMsg(False, '您添加的URL已存在')
        url_white.insert(0, url_rule)
        self.__write_rule('url_black', url_white)
        self.__write_log('添加url规则[' + url_rule + ']到URL黑名单');
        return public.returnMsg(True, '添加成功!');

    def remove_url_black(self, get):
        url_white = self.__get_rule('url_black')
        index = int(get.index)
        url_rule = url_white[index]
        del (url_white[index])
        self.__write_rule('url_black', url_white)
        self.__write_log('从URL黑名单删除URL规则[' + url_rule + ']');
        return public.returnMsg(True, '删除成功!');

    def save_scan_rule(self, get):
        # return self.set_scan_conf(get)
        scan_rule = {'header': get.header, 'cookie': get.cookie, 'args': get.args}
        self.__write_rule('scan_black', scan_rule)
        self.__write_log('修改扫描器过滤规则');
        return public.returnMsg(True, '设置成功')

    def set_retry(self, get):
        config = self.get_config(None)
        end_time = int(get.retry_time)
        if end_time > 86400: return public.returnMsg(False, '封锁时间不能超过86400!');

        config['retry'] = int(get.retry)
        config['retry_cycle'] = int(get.retry_cycle)
        config['retry_time'] = int(get.retry_time)
        self.__write_config(config)
        self.__write_log(
            '设置非法请求容忍阈值: ' + get.retry_cycle + ' 秒内累计超过 ' + get.retry + ' 次, 封锁 ' + get.retry_time + ' 秒');
        if get.is_open_global:
            self.set_cc_retry_golbls(get)
        return public.returnMsg(True, '设置成功!');

    def set_site_retry(self, get):
        site_config = self.get_site_config(None)
        site_config[get.siteName]['retry'] = int(get.retry)
        site_config[get.siteName]['retry_cycle'] = int(get.retry_cycle)
        site_config[get.siteName]['retry_time'] = int(get.retry_time)
        self.__write_site_config(site_config)
        self.__write_log(
            '设置网站【' + get.siteName + '】非法请求容忍阈值: ' + get.retry_cycle + ' 秒内累计超过 ' + get.retry + ' 次, 封锁 ' + get.retry_time + ' 秒');
        return public.returnMsg(True, '设置成功!');

    def set_site_cdn_state(self, get):
        site_config = self.get_site_config(None)
        if site_config[get.siteName]['cdn']:
            site_config[get.siteName]['cdn'] = False
        else:
            site_config[get.siteName]['cdn'] = True
        self.__write_site_config(site_config)
        self.__write_log(self.__state[site_config[get.siteName]['cdn']] + '站点【' + get.siteName + '】CDN模式');
        return public.returnMsg(True, '设置成功!');

    def get_site_cdn_header(self, get):
        site_config = self.get_site_config(None)
        return site_config[get.siteName]['cdn_header']

    def add_site_cdn_header(self, get):
        site_config = self.get_site_config(None)
        get.cdn_header = get.cdn_header.strip().lower();
        if get.cdn_header in site_config[get.siteName]['cdn_header']: return public.returnMsg(False,
                                                                                              '您添加的请求头已存在!');
        site_config[get.siteName]['cdn_header'].insert(0, get.cdn_header)
        self.__write_site_config(site_config)
        self.__write_log('添加站点【' + get.siteName + '】CDN-Header【' + get.cdn_header + '】');
        return public.returnMsg(True, '添加成功!');

    def remove_site_cdn_header(self, get):
        site_config = self.get_site_config(None)
        get.cdn_header = get.cdn_header.strip().lower();
        if not get.cdn_header in site_config[get.siteName]['cdn_header']: return public.returnMsg(False,
                                                                                                  '指定请求头不存在!');
        for i in range(len(site_config[get.siteName]['cdn_header'])):
            if get.cdn_header == site_config[get.siteName]['cdn_header'][i]:
                self.__write_log(
                    '删除站点【' + get.siteName + '】CDN-Header【' + site_config[get.siteName]['cdn_header'][i] + '】');
                del (site_config[get.siteName]['cdn_header'][i])
                break;
        self.__write_site_config(site_config)
        return public.returnMsg(True, '删除成功!');

    def get_site_rule(self, get):
        site_config = self.get_site_config(None)
        return site_config[get.siteName][get.ruleName]

    def add_site_rule(self, get):
        site_config = self.get_site_config(None)
        if not get.ruleName in site_config[get.siteName]: return public.returnMsg(False, '指定规则不存在!');
        mt = type(site_config[get.siteName][get.ruleName])
        if mt == bool: return public.returnMsg(False, '指定规则不存在!');
        if mt == str: site_config[get.siteName][get.ruleName] = get.ruleValue
        if mt == list:
            if get.ruleName == 'url_rule' or get.ruleName == 'url_tell':
                for ruleInfo in site_config[get.siteName][get.ruleName]:
                    if ruleInfo[0] == get.ruleUri: return public.returnMsg(False, '指定URI已存在!');
                tmp = []
                get.ruleUri = get.ruleUri.split('?')[0]

                tmp.append(get.ruleUri)
                tmp.append(get.ruleValue)
                if get.ruleName == 'url_tell':
                    self.__write_log(
                        '添加站点【' + get.siteName + '】URI【' + get.ruleUri + '】保护规则,参数【' + get.ruleValue + '】,参数值【' + get.rulePass + '】');
                    tmp.append(get.rulePass)
                else:
                    self.__write_log(
                        '添加站点【' + get.siteName + '】URI【' + get.ruleUri + '】过滤规则【' + get.ruleValue + '】');
                site_config[get.siteName][get.ruleName].insert(0, tmp)
            else:
                if get.ruleValue in site_config[get.siteName][get.ruleName]: return public.returnMsg(False,
                                                                                                     '指定规则已存在!');
                site_config[get.siteName][get.ruleName].insert(0, get.ruleValue)
                self.__write_log('添加站点【' + get.siteName + '】【' + get.ruleName + '】过滤规则【' + get.ruleValue + '】');
        self.__write_site_config(site_config)
        return public.returnMsg(True, '添加成功!');

    def remove_site_rule(self, get):
        site_config = self.get_site_config(None)
        index = int(get.index)
        if not get.ruleName in site_config[get.siteName]: return public.returnMsg(False, '指定规则不存在!');
        site_rule = site_config[get.siteName][get.ruleName][index]
        del (site_config[get.siteName][get.ruleName][index])
        self.__write_site_config(site_config)
        self.__write_log('删除站点【' + get.siteName + '】【' + get.ruleName + '】过滤规则【' + json.dumps(site_rule) + '】');
        return public.returnMsg(True, '删除成功!');

    def get_cn_list(self, type):
        if type == 'ip_white' or type == 'ip_black' or type == 'cn':
            try:
                rule = self.__get_rule(type)
                for i in rule:
                    for i2 in range(len(i)):
                        if i2 >= 2: continue
                        i[i2] = self.long2ip(i[i2])
                return rule
            except:
                self.__write_rule(type, [])
                os.system('/etc/init.d/nginx restart')
                return []
        else:
            rule = self.__get_rule(type)
            for i in rule:
                for i2 in range(len(i)):
                    i[i2] = self.long2ip(i[i2])
            return rule

    def get_rule(self, get):
        if get.ruleName == 'cn':
            return self.get_cn_list('cn')
        if get.ruleName == 'ip_white':
            return self.get_cn_list('ip_white')
        if get.ruleName == 'ip_black':
            return self.get_cn_list('ip_black')
        if get.ruleName == 'spider':
            return self.spider(get)
        rule = self.__get_rule(get.ruleName)
        if not rule: return [];
        return rule

    def spider(self, get):
        if not 'spider' in get:
            get.spider = 'baidu'
        list_sp = ["baidu", "google", "360", "sogou", "yahoo", "bingbot", "bytespider", "shenma"]
        if not str(get.spider) in list_sp: return []
        list_index = list_sp.index(str(get.spider))
        try:
            path = "/www/server/btwaf/inc/" + str(list_index + 1) + '.json'
            rules = public.readFile(path)
            if not rules: return []
            return json.loads(rules)
        except:
            return []

    # spider添加删除
    def add_spider(self, get):
        if not 'ip' in get: return public.returnMsg(False, '请输入IP地址')
        if not 'spider' in get:
            get.spider = 'baidu'
        list_sp = ["baidu", "google", "360", "sogou", "yahoo", "bingbot", "bytespider", "shenma"]
        if not str(get.spider) in list_sp: return public.returnMsg(False, '蜘蛛类型错误!')
        list_index = list_sp.index(str(get.spider))
        path = "/www/server/btwaf/inc/" + str(list_index + 1) + '.json'
        try:
            rules = json.loads(public.readFile(path))
            if not rules:
                public.WriteFile(path, json.dumps([get.ip.strip()]))
                return public.returnMsg(True, '添加成功!')
            else:
                if get.ip.strip() in rules:
                    return public.returnMsg(False, '添加失败!')
                else:
                    rules.insert(0, get.ip.strip())
                    public.WriteFile(path, json.dumps(rules))
                    return public.returnMsg(True, '添加成功!')
        except:
            public.WriteFile(path, json.dumps([get.ip.strip()]))
            return public.returnMsg(True, '添加成功!')

    # spider删除
    def del_spider(self, get):
        if not 'ip' in get: return public.returnMsg(False, '请输入IP地址')
        if not 'spider' in get:
            get.spider = 'baidu'
        list_sp = ["baidu", "google", "360", "sogou", "yahoo", "bingbot", "bytespider", 'shenma']
        if not str(get.spider) in list_sp: return public.returnMsg(False, '蜘蛛类型错误!')
        list_index = list_sp.index(str(get.spider))
        path = "/www/server/btwaf/inc/" + str(list_index + 1) + '.json'
        try:
            rules = json.loads(public.readFile(path))
            if not rules:
                return public.returnMsg(True, '当前IP不存在!')
            else:
                if get.ip.strip() in rules:
                    rules.remove(get.ip.strip())
                    public.WriteFile(path, json.dumps(rules))
                    return public.returnMsg(True, '删除成功!')
                else:
                    return public.returnMsg(False, '当前IP不存在!')
        except:
            public.WriteFile(path, json.dumps([get.ip.strip()]))
            return public.returnMsg(True, '添加成功!')

    # spider导入
    def import_spider(self, get):
        if not 'ip_list' in get: return public.returnMsg(False, '请输入IP地址')
        if not 'spider' in get:
            get.spider = 'baidu'
        list_sp = ["baidu", "google", "360", "sogou", "yahoo", "bingbot", "bytespider", "shenma"]
        ip_list = json.loads(get.ip_list)
        if not str(get.spider) in list_sp: return public.returnMsg(False, '蜘蛛类型错误!')
        list_index = list_sp.index(str(get.spider))
        path = "/www/server/btwaf/inc/" + str(list_index + 1) + '.json'
        try:
            if len(ip_list) >= 1:
                for i in ip_list:
                    get.ip = i
                    self.add_spider(get)
                return public.returnMsg(True, '导入成功!')
        except:
            return public.returnMsg(False, '导入发生报错!')

    def add_rule(self, get):
        rule = self.__get_rule(get.ruleName)
        ruleValue = [1, get.ruleValue.strip(), get.ps, 1]
        for ru in rule:
            if ru[1] == ruleValue[1]: return public.returnMsg(False, '指定规则已存在，请勿重复添加');
        rule.append(ruleValue)
        self.__write_rule(get.ruleName, rule)
        self.__write_log('添加全局规则【' + get.ruleName + '】【' + get.ps + '】');
        return public.returnMsg(True, '添加成功!');

    def remove_rule(self, get):
        rule = self.__get_rule(get.ruleName)
        index = int(get.index)
        ps = rule[index][2]
        del (rule[index])
        self.__write_rule(get.ruleName, rule)
        self.__write_log('删除全局规则【' + get.ruleName + '】【' + ps + '】');
        return public.returnMsg(True, '删除成功!');

    def modify_rule(self, get):
        rule = self.__get_rule(get.ruleName)
        index = int(get.index)
        rule[index][1] = get.ruleBody
        rule[index][2] = get.rulePs
        self.__write_rule(get.ruleName, rule)
        self.__write_log('修改全局规则【' + get.ruleName + '】【' + get.rulePs + '】');
        return public.returnMsg(True, '修改成功!');

    def set_rule_state(self, get):
        rule = self.__get_rule(get.ruleName)
        index = int(get.index)
        if rule[index][0] == 0:
            rule[index][0] = 1;
        else:
            rule[index][0] = 0;
        self.__write_rule(get.ruleName, rule)
        self.__write_log(self.__state[rule[index][0]] + '全局规则【' + get.ruleName + '】【' + rule[index][2] + '】');
        return public.returnMsg(True, '设置成功!');

    def get_site_disable_rule(self, get):
        rule = self.__get_rule(get.ruleName)
        site_config = self.get_site_config(None)
        site_rule = site_config[get.siteName]['disable_rule'][get.ruleName]
        for i in range(len(rule)):
            if rule[i][0] == 0: rule[i][0] = -1;
            if i in site_rule: rule[i][0] = 0;
        return rule;

    def set_site_disable_rule(self, get):
        site_config = self.get_site_config(None)
        index = int(get.index)
        if index in site_config[get.siteName]['disable_rule'][get.ruleName]:
            for i in range(len(site_config[get.siteName]['disable_rule'][get.ruleName])):
                if index == site_config[get.siteName]['disable_rule'][get.ruleName][i]:
                    del (site_config[get.siteName]['disable_rule'][get.ruleName][i])
                    break
        else:
            site_config[get.siteName]['disable_rule'][get.ruleName].append(index)
        self.__write_log('设置站点【' + get.siteName + '】应用规则【' + get.ruleName + '】状态');
        self.__write_site_config(site_config)
        return public.returnMsg(True, '设置成功!');

    def get_safe_logs(self, get):
        try:
            import html
            pythonV = sys.version_info[0]
            if 'drop_ip' in get:
                path = '/www/server/btwaf/drop_ip.log'
                num = 12
                if os.path.getsize(path) > 209715200:
                    return {"status": False, "msg": "日志文件过大!", "clear": True}
            else:
                path = '/www/wwwlogs/btwaf/' + get.siteName + '_' + get.toDate + '.log'
                if os.path.getsize(path) > 1024 * 1024 * 10:
                    return {"status": False, "msg": "日志文件过大，建议去大屏查看！！！", "clear": True}
                num = 10

            if not os.path.exists(path): return ["11"]
            p = 1
            if 'p' in get:
                p = int(get.p)
            start_line = (p - 1) * num
            count = start_line + num
            fp = open(path, 'rb')
            buf = ""
            try:
                fp.seek(-1, 2)
            except:
                return []
            if fp.read(1) == "\n": fp.seek(-1, 2)
            data = []
            b = True
            n = 0
            c = 0
            while c < count:
                while True:
                    newline_pos = str.rfind(buf, "\n")
                    pos = fp.tell()
                    if newline_pos != -1:
                        if n >= start_line:
                            line = buf[newline_pos + 1:]
                            if line:
                                try:
                                    tmp_data = json.loads(line)
                                    host = ""
                                    for i in range(len(tmp_data)):
                                        if i == 6:
                                            tmp_data[i] = tmp_data[i].replace('gt;', '>')
                                        if len(tmp_data) > 6 and tmp_data[6]:
                                            tmp_data[6] = tmp_data[6].replace('gt;', '>').replace('&', '')
                                        if i == 7:
                                            tmp_data[i] = str(tmp_data[i]).replace('&amp;', '&').replace('&lt;',
                                                                                                         '<').replace(
                                                '&gt;', '>').replace("&quot;", "\"")
                                            if re.search('host:(.*?)\n', tmp_data[7]):
                                                host = re.search('host:(.*?)\n', tmp_data[7]).groups()[0]


                                        elif i == 10:
                                            tmp_data[i] = str(tmp_data[i]).replace('&amp;', '&').replace('&lt;',
                                                                                                         '<').replace(
                                                '&gt;', '>').replace("&quot;", "\"")
                                        else:
                                            tmp_data[i] = str(tmp_data[i])
                                    if host:
                                        tmp_data.append('http://' + host + tmp_data[3])
                                    data.append(tmp_data)
                                except:
                                    c -= 1
                                    n -= 1
                                    pass
                            else:
                                c -= 1
                                n -= 1
                        buf = buf[:newline_pos]
                        n += 1
                        c += 1
                        break
                    else:
                        if pos == 0:
                            b = False
                            break
                        to_read = min(4096, pos)
                        fp.seek(-to_read, 1)
                        t_buf = fp.read(to_read)
                        if pythonV == 3: t_buf = t_buf.decode('utf-8', errors="ignore")
                        buf = t_buf + buf
                        fp.seek(-to_read, 1)
                        if pos - to_read == 0:
                            buf = "\n" + buf
                if not b: break
            fp.close()
            if 'drop_ip' in get:
                drop_iplist = self.get_waf_drop_ip(None)
                stime = time.time()
                setss = []
                for i in range(len(data)):
                    if (float(stime) - float(data[i][0])) < float(data[i][4]):
                        setss.append(data[i][1])
                        data[i].append(data[i][1] in drop_iplist)
                    else:
                        data[i].append(False)
        except:
            data = []
            return public.get_error_info()
        return data

    def write_php_fpm_status(self):
        data = '''server {
	listen 80;
	server_name 127.0.0.1;
	allow 127.0.0.1;
	location /nginx_status {
		stub_status on;
		access_log off;
	}
	location /phpfpm_52_status {
		fastcgi_pass unix:/tmp/php-cgi-52.sock;
		include fastcgi_params;
		fastcgi_param SCRIPT_FILENAME $fastcgi_script_name;
	}
	location /phpfpm_53_status {
		fastcgi_pass unix:/tmp/php-cgi-53.sock;
		include fastcgi_params;
		fastcgi_param SCRIPT_FILENAME $fastcgi_script_name;
	}
	location /phpfpm_54_status {
		fastcgi_pass unix:/tmp/php-cgi-54.sock;
		include fastcgi_params;
		fastcgi_param SCRIPT_FILENAME $fastcgi_script_name;
	}
	location /phpfpm_55_status {
		fastcgi_pass unix:/tmp/php-cgi-55.sock;
		include fastcgi_params;
		fastcgi_param SCRIPT_FILENAME $fastcgi_script_name;
	}
	location /phpfpm_56_status {
		fastcgi_pass unix:/tmp/php-cgi-56.sock;
		include fastcgi_params;
		fastcgi_param SCRIPT_FILENAME $fastcgi_script_name;
	}
	location /phpfpm_70_status {
		fastcgi_pass unix:/tmp/php-cgi-70.sock;
		include fastcgi_params;
		fastcgi_param SCRIPT_FILENAME $fastcgi_script_name;
	}
	location /phpfpm_71_status {
		fastcgi_pass unix:/tmp/php-cgi-71.sock;
		include fastcgi_params;
		fastcgi_param SCRIPT_FILENAME $fastcgi_script_name;
	}
	location /phpfpm_72_status {
		fastcgi_pass unix:/tmp/php-cgi-72.sock;
		include fastcgi_params;
		fastcgi_param SCRIPT_FILENAME $fastcgi_script_name;
	}
	location /phpfpm_73_status {
		fastcgi_pass unix:/tmp/php-cgi-73.sock;
		include fastcgi_params;
		fastcgi_param SCRIPT_FILENAME $fastcgi_script_name;
	}
	location /phpfpm_74_status {
		fastcgi_pass unix:/tmp/php-cgi-74.sock;
		include fastcgi_params;
		fastcgi_param SCRIPT_FILENAME $fastcgi_script_name;
	}
	location /phpfpm_75_status {
		fastcgi_pass unix:/tmp/php-cgi-75.sock;
		include fastcgi_params;
		fastcgi_param SCRIPT_FILENAME $fastcgi_script_name;
	}
}
'''
        public.writeFile('/www/server/panel/vhost/nginx/phpfpm_status.conf', data)
        # 检测nginx的配置文件是否有错误
        isError = public.checkWebConfig()
        if isError != True:
            if os.path.exists('/www/server/panel/vhost/nginx/phpfpm_status.conf'): os.remove(
                '/www/server/panel/vhost/nginx/phpfpm_status.conf')
            return
        public.serviceReload()

    def HttpGet(self, url, timeout=3):
        """
            @name 发送GET请求
            @author hwliang<hwl@bt.cn>
            @url 被请求的URL地址(必需)
            @timeout 超时时间默认60秒
            @return string
        """
        if not os.path.exists("/www/server/panel/vhost/nginx/phpfpm_status.conf"):
            # 加这个文件
            self.write_php_fpm_status()
            time.sleep(0.5)

        import requests
        config = self.get_config(None)
        toekn = config["access_token"]
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36",
            "btwaf-access-token": toekn
        }
        res = requests.get(url, timeout=timeout, headers=headers)
        if res.status_code == 0:
            s_body = res.text
            return s_body
        s_body = res.text
        del res
        return s_body

    def get_waf_drop_ip(self, get):
        try:
            config = self.get_config(None)
            data = json.loads(self.HttpGet('http://127.0.0.1/get_btwaf_drop_ip'))
            if len(data) == 0:
                return []
            return data
        except:
            return []

    def get_logs_list(self, get):
        path = '/www/wwwlogs/btwaf/'
        sfind = get.siteName + '_'
        data = []
        for fname in os.listdir(path):
            if fname.find(sfind) != 0: continue;
            tmp = fname.replace(sfind, '').replace('.log', '')

            # 判断是否符合时间格式
            if not re.match(r'^\d{4}-\d{2}-\d{2}$', tmp):
                continue
            data.append(tmp)
        return sorted(data, reverse=True)

    def remove_waf_drop_ip(self, get):
        public.WriteFile('/dev/shm/.bt_ip_filter', '-,' + get.ip.strip())
        try:
            self.M2('blocking_ip').field('time,ip,is_status').where("ip=? and time>=?",
                                                                    (get.ip.strip(), int(time.time()) - 86400)).update(
                {"is_status": "0"})
        except:
            pass
        try:
            config = self.get_config(None)
            toekn = config["access_token"]
            data = json.loads(self.HttpGet('http://127.0.0.1/remove_btwaf_drop_ip?ip=' + get.ip))
            self.__write_log('从防火墙解封IP【' + get.ip + '】')
            return data
        except:
            public.WriteFile('/dev/shm/.bt_ip_filter', '-,' + get.ip.strip())
            return public.returnMsg(False, '获取数据失败');

    def clean_waf_drop_ip(self, get):
        public.WriteFile("/dev/shm/.bt_ip_filter", "-,0.0.0.0")
        try:
            self.M2('blocking_ip').field('time,ip,is_status').where("time>=?", (int(time.time()) - 86400)).update(
                {"is_status": "0"})
        except:
            pass
        # try:
        public.WriteFile("/dev/shm/.bt_ip_filter", "-,0.0.0.0")
        try:
            datas = public.ExecShell("ipset list |grep timeout")[0].split("\n")
            if len(datas) != 3:
                public.WriteFile("/dev/shm/.bt_ip_filter", "-,0.0.0.0")
                public.ExecShell("/etc/init.d/bt_ipfilter restart")
        except:
            pass
        # try:
        self.__write_log('从防火墙解封所有IP')
        config = self.get_config(None)
        toekn = config["access_token"]
        data = json.loads(self.HttpGet('http://127.0.0.1/clean_btwaf_drop_ip'))
        for i in self.get_cn_list('ip_black'):
            ipn = [i[0], i[1]]
            iplist = self.get_cn_list('ip_white')
            if ipn in iplist: continue
            self.bt_ip_filter("+,%s-%s,86400" % (i[0], i[1]))
        return data
        # except:
        #     public.WriteFile("/dev/shm/.bt_ip_filter", "-,0.0.0.0")
        #     return public.returnMsg(False, '获取数据失败')

    def get_gl_logs(self, get):
        import page
        page = page.Page()
        if 'search' in get and get.search:
            count = public.M('logs').where("type=? and log LIKE ?", (u'网站防火墙', "%{}%".format(get.search),)).count()
        else:
            count = public.M('logs').where('type=?', (u'网站防火墙',)).count()
        limit = 12;
        info = {}
        info['count'] = count
        info['row'] = limit
        info['p'] = 1
        if hasattr(get, 'p'):
            info['p'] = int(get['p'])
        info['uri'] = get
        info['return_js'] = ''
        if hasattr(get, 'tojs'):
            info['return_js'] = get.tojs

        data = {}

        # 获取分页数据
        data['page'] = page.GetPage(info, '1,2,3,4,5,8');
        if 'search' in get and get.search:
            data['data'] = public.M('logs').where("type=? and log LIKE ?",
                                                  (u'网站防火墙', "%{}%".format(get.search),)).order('id desc').limit(
                str(page.SHIFT) + ',' + str(page.ROW)).field('log,addtime').select()
        else:
            data['data'] = public.M('logs').where('type=?', (u'网站防火墙',)).order('id desc').limit(
                str(page.SHIFT) + ',' + str(page.ROW)).field('log,addtime').select()
        return data

    def get_total(self, get):
        # total = json.loads(public.readFile(self.__path + 'total.json'))
        try:
            total = json.loads(public.readFile(self.__path + 'total.json'))
        except:
            total = {"rules": {"user_agent": 0, "cookie": 0, "post": 0, "args": 0, "url": 0, "cc": 0}, "sites": {},
                     "total": 0}
            self.__write_total(total)
        if len(total) == 0:
            total = {"rules": {"user_agent": 0, "cookie": 0, "post": 0, "args": 0, "url": 0, "cc": 0}, "sites": {},
                     "total": 0}
        if 'rules' in total and type(total['rules']) != dict:
            new_rules = {}
            for rule in total['rules']:
                new_rules[rule['key']] = rule['value'];
            total['rules'] = new_rules;
            self.__write_total(total);
        total['rules'] = self.__format_total(total['rules'])
        return total;

    def __format_total(self, total):
        total['get'] = 0;
        if 'args' in total:
            total['get'] += total['args'];
            del (total['args'])
        if 'url' in total:
            total['get'] += total['url'];
            del (total['url'])
        cnkey = [
            ['sql', u'sql注入拦截'],
            ['xss', u'xss拦截'],
            ['cc', u"CC拦截"],
            ['user_agent', u'恶意爬虫拦截'],
            ['cookie', u'Cookie渗透'],
            ['scan', u'恶意扫描拦截'],
            ['upload', u'文件上传拦截'],
            ['path_php', u'禁止PHP脚本拦截'],
            ['download', u'恶意下载拦截'],
            ["smart_cc", "智能CC"],
            ['drop_abroad', u'禁国外'],
            ['file', u'目录拦截'],
            ['php', u'php代码拦截'],
            ['other', u'自定义拦截'],
            ['file_import', "文件包含"],
            ['path', "站点URL黑名单"],
            ['url_tell', "受保护的URL"],
            ["url_rule", "URL专用过滤"]

        ]
        data = []
        for ck in cnkey:
            tmp = {}
            tmp['name'] = ck[1]
            tmp['key'] = ck[0]
            tmp['value'] = 0;
            if ck[0] in total: tmp['value'] = total[ck[0]]
            data.append(tmp)
        return data

    def get_btwaf(self):
        from BTPanel import session, cache
        import panelAuth
        if self.__session_name in session: return session[self.__session_name]
        cloudUrl = 'http://127.0.0.1/api/panel/get_soft_list'
        pdata = panelAuth.panelAuth().create_serverid(None)
        ret = public.httpPost(cloudUrl, pdata)
        if not ret:
            if not self.__session_name in session: session[self.__session_name] = 1
            return 1
        try:
            ret = json.loads(ret)
            for i in ret["list"]:
                if i['name'] == 'btwaf':
                    if i['endtime'] >= 0:
                        if not self.__session_name in session: session[self.__session_name] = 2;
                        return 2
            if not self.__session_name in session: session[self.__session_name] = 0;
            return 0
        except:
            if not self.__session_name in session: session[self.__session_name] = 1;
            return 1

    # stop config
    def stop(self):
        return True

    def test_check_zhilist(self, get):
        try:
            flag = False
            # 如果文件存在
            Itime_path = '/www/server/panel/data/btwaf_getSpiders.ini'
            startime = int(time.time())
            if os.path.exists(Itime_path):
                Itime = int(public.ReadFile(Itime_path))
                if startime - Itime > 36000:
                    flag = True
            else:
                flag = True
            if flag:
                public.WriteFile(Itime_path, str(startime))
                userInfo = json.loads(public.ReadFile('/www/server/panel/data/userInfo.json'))
                data22 = {"access_key": userInfo['access_key'], "uid": userInfo['uid']}
                url = public.GetConfigValue('home')+'/api/bt_waf/getSpiders'
                data_list = json.loads(public.httpPost(url, data22, timeout=3))
                if data_list:
                    for i22 in data_list:
                        try:
                            path = "/www/server/btwaf/%s.json" % i22
                            if os.path.exists(path):
                                ret = json.loads(public.ReadFile(path))
                                localhost_json = list(set(ret).union(data_list[i22]))
                                public.WriteFile(path, json.dumps(localhost_json))
                        except:
                            continue
        except:
            return []

    def return_python(self):
        if os.path.exists('/www/server/panel/pyenv/bin/python'): return '/www/server/panel/pyenv/bin/python'
        if os.path.exists('/usr/bin/python'): return '/usr/bin/python'
        if os.path.exists('/usr/bin/python3'): return '/usr/bin/python3'
        return 'python'

    # 四层计划任务
    def add_webshell_check(self):
        id = public.M('crontab').where('name=?', (u'【官方】Nginx防火墙木马扫描进程',)).getField('id')
        import crontab
        if not id:
            data = {}
            data['name'] = '【官方】Nginx防火墙木马扫描进程'
            data['type'] = 'minute-n'
            data['where1'] = '5'
            data['sBody'] = '%s /www/server/panel/plugin/btwaf/webshell_check.py' % self.return_python()
            data['backupTo'] = 'localhost'
            data['sType'] = 'toShell'
            data['hour'] = ''
            data['minute'] = '0'
            data['week'] = ''
            data['sName'] = ''
            data['urladdress'] = ''
            data['save'] = ''
            crontab.crontab().AddCrontab(data)
        return True

    def get_webshell_size(self):
        rPath = self.Recycle_bin
        if not os.path.exists(rPath): return 0
        # 循环这个目录下的所有文件
        count = 0
        for root, dirs, files in os.walk(rPath):
            if files:
                for name in files:
                    count += 1
        return count

    def get_webshell_info(self, get):
        ret = []
        try:
            webshell_info = json.loads(public.ReadFile("/www/server/btwaf/webshell.json"))

            for i in webshell_info:
                result = {}
                result['path'] = i
                result['is_path'] = webshell_info[i]
                ret.append(result)
            return ret
        except:
            return []

    #
    # def get_total_all(self,get):
    #     if public.cache_get("get_total_all"):
    #         public.run_thread(self.get_total_all_info,get)
    #         return public.cache_get("get_total_all")
    #     else:
    #         return self.get_total_all_info(get)

    def check_zhiz(self, get):
        zhizhu_list = ['1', '2', '4', '5', '6']
        for i in zhizhu_list:
            try:
                if os.path.getsize('/www/server/btwaf/zhizhu' + i + '.json') > 10:
                    f = open('/www/server/btwaf/zhizhu' + i + '.json', 'r')
                    tt = []
                    for i2 in f:
                        i2 = i2.strip()
                        tt.append(i2)
                    f.close()
                    userInfo = json.loads(public.ReadFile('/www/server/panel/data/userInfo.json'))
                    data22 = {"type": i, "ip_list": json.dumps(tt), "access_key": userInfo['access_key'],
                              "uid": userInfo['uid']}
                    url = public.GetConfigValue('home')+'/api/bt_waf/addSpider'
                    if len(tt) >= 1:
                        public.httpPost(url, data22)
                    public.WriteFile('/www/server/btwaf/zhizhu' + i + '.json', "")
            except:
                continue

    def create_db(self):
        start_path = time.strftime("%Y-%m-%d_%H_%M_%S", time.localtime(time.time()))
        path = "/www/server/btwaf/totla_db/totla_db.db"
        http_log = "/www/server/btwaf/totla_db/http_log/"
        # 重命名文件、然后压缩
        if os.path.exists(path):
            cmd_str = '''http_log=/www/server/btwaf/totla_db
        mv $http_log/totla_db.db $http_log/totla_db.db.bak
        tar -zcf $http_log/totla_db_{}.tar.gz $http_log/totla_db.db.bak
        rm -rf $http_log/totla_db.db.bak
        rm -rf $http_log/totla_db_bak.sh'''.format(start_path)
            public.WriteFile("/www/server/btwaf/totla_db/totla_db_bak.sh", cmd_str)
            os.system("nohup bash /www/server/btwaf/totla_db/totla_db_bak.sh >/dev/null 2>&1 &".format(start_path))
        if os.path.exists(http_log):
            cmd_str = '''http_log=/www/server/btwaf/totla_db
        mv $http_log/http_log $http_log/http_log_bak 
        mkdir $http_log/http_log 
        chown www:www $http_log/http_log
        tar -zcf $http_log/http_log_{}.tar.gz $http_log/http_log_bak 
        rm -rf $http_log/http_log_bak
        rm -rf $http_log/http_log_bak.sh'''.format(start_path)
            public.WriteFile("/www/server/btwaf/totla_db/http_log_bak.sh", cmd_str)
            os.system("nohup bash /www/server/btwaf/totla_db/http_log_bak.sh >/dev/null 2>&1 &".format(start_path))
        time.sleep(0.5)
        # os.system("mkdir %s && chown -R www:www %s" % (http_log, http_log))
        totle_db2.Sql().execute("PRAGMA synchronous = 0")
        totle_db2.Sql().execute("PRAGMA page_size = 4096")
        totle_db2.Sql().execute("PRAGMA journal_mode = wal")
        totle_db2.Sql().execute("PRAGMA journal_size_limit = 1073741824")
        totle_db2.Sql().execute('''CREATE TABLE btwaf_msg (
    				id INTEGER PRIMARY KEY AUTOINCREMENT,
    				server_name TEXT,
    				time INTEGER,
    				time_localtime TEXT,
    		)''')
        totle_db2.Sql().execute('''CREATE TABLE totla_log (
    				id INTEGER PRIMARY KEY AUTOINCREMENT,
    				time INTEGER,
    				time_localtime TEXT,
    				server_name TEXT,
    				ip TEXT,
    				ip_city TEXT,
    				ip_country TEXT,
    				ip_subdivisions TEXT,
    				ip_continent TEXT,
    				ip_longitude TEXT,
    				ip_latitude TEXT,
    				type TEXT,
    				uri TEXT,
    				user_agent TEXT,
    				filter_rule TEXT,
    				incoming_value TEXT,
    			    value_risk TEXT,
    				http_log TEXT,
    				http_log_path INTEGER
    			)''')
        totle_db2.Sql().execute("CREATE INDEX time_inx ON totla_log(time)")
        totle_db2.Sql().execute("CREATE INDEX time_localtime_inx ON totla_log(time_localtime)")
        totle_db2.Sql().execute("CREATE INDEX server_name_inx ON totla_log(server_name)")
        totle_db2.Sql().execute("CREATE INDEX ip_ipx ON totla_log(ip)")
        totle_db2.Sql().execute("CREATE INDEX type_inx ON totla_log(type)")
        totle_db2.Sql().execute("CREATE INDEX filter__inx ON totla_log(filter_rule)")
        totle_db2.Sql().execute("CREATE INDEX ip_country_inx ON totla_log(ip_country)")

        totle_db2.Sql().execute('''CREATE TABLE blocking_ip (
    				id INTEGER PRIMARY KEY AUTOINCREMENT,
    			    time INTEGER,
    				time_localtime TEXT,
    				server_name TEXT,
    				ip TEXT,
    				ip_city TEXT,
    				ip_country TEXT,
    				ip_subdivisions TEXT,
    				ip_continent TEXT,
    				ip_longitude TEXT,
    				ip_latitude TEXT,
    				type TEXT,
    				uri TEXT,
    				user_agent TEXT,
    				filter_rule TEXT,
    				incoming_value TEXT,
    			    value_risk TEXT,
    				http_log TEXT,
    				http_log_path INTEGER,
    				blockade TEXT,
    				blocking_time INTEGER,
    				is_status INTEGER
    			)''')
        totle_db2.Sql().execute("CREATE INDEX time_ip ON blocking_ip(time)")
        totle_db2.Sql().execute("CREATE INDEX time_localtime_ip ON blocking_ip(time_localtime)")
        totle_db2.Sql().execute("CREATE INDEX server_name_ip ON blocking_ip(server_name)")
        totle_db2.Sql().execute("CREATE INDEX ip_ip ON blocking_ip(ip)")
        totle_db2.Sql().execute("CREATE INDEX blocking_ip ON blocking_ip(blocking_time)")
        totle_db2.Sql().execute("CREATE INDEX is_statu_ip ON blocking_ip(is_status)")
        os.system('chown www:www /www/server/btwaf/totla_db/totla_db.db')

    def db_5000(self, get):
        if os.path.exists("/www/wwwlogs/btwaf_debug.log") and os.path.getsize(
                "/www/wwwlogs/btwaf_debug.log") > 506897664:
            public.ExecShell("rm -rf /www/wwwlogs/btwaf_debug.log")
        if os.path.exists("/www/server/btwaf/totla_db/totla_db.db") and os.path.getsize(
                "/www/server/btwaf/totla_db/totla_db.db") > 506897664:
            # 直接重命名文件
            # public.ExecShell("rm -rf /www/server/btwaf/totla_db/totla_db.db.bak && mv /www/server/btwaf/totla_db/totla_db.db /www/server/btwaf/totla_db/totla_db.db.bak")
            # path="/www/server/btwaf/totla_db/totla_db.db"
            # os.rename(path, path + ".bak")
            # start_path = time.strftime("%Y-%m-%d_%H_%M_%S", time.localtime(time.time()))
            # cmd_str = "cd /www/server/btwaf/totla_db/ &&  tar -zcf totla_db_{}.tar.gz totla_db.db.bak && rm -rf totla_db.db.bak && rm -rf totla_db_bak.sh".format(
            #     start_path)
            # public.WriteFile("/www/server/btwaf/totla_db/totla_db_bak.sh", cmd_str)
            # os.system("cd /www/server/btwaf/totla_db/ && nohup bash totla_db_bak.sh >/dev/null 2>&1 &".format(start_path))
            self.create_db()

            # 压缩

            # 大于500M的时候压缩文件
            # 获取一下配置文件
            # data_path = '/www/server/panel/data/btwaf_db_file.json'
            # datas = []
            # if os.path.exists(data_path):
            #     try:
            #         datas = json.loads(public.ReadFile(data_path))
            #     except:
            #         pass
            # path = "/www/server/btwaf/totla_db/db.{}.tar.gz".format(time.strftime("%Y-%m-%d"))
            # if not datas:
            #     datas.append({"path": path, "time": time.strftime("%Y-%m-%d")})
            # else:
            #     # 备份最多报错7份
            #     tmp = []
            #     if len(datas) >= 3:
            #         for i in datas:
            #             tmp.append(i['time'])
            #         tmp.sort()
            #         datas.remove({"path": "/www/server/btwaf/totla_db/db.{}.tar.gz".format(tmp[0]), "time": tmp[0]})
            #         public.ExecShell("rm -rf  /www/server/btwaf/totla_db/db.{}.tar.gz".format(tmp[0]))
            #     if {"path": path, "time": time.strftime("%Y-%m-%d")} in datas:
            #         # 如果存在在配置文件中 再判断一下文件是否存在。 如果文件存在 就可以删除源文件了。如果文件不存在那么就不删除源文件
            #         if os.path.exists(path):
            #             public.ExecShell("rm -rf /www/server/btwaf/totla_db/totla_db.*")
            # public.WriteFile(data_path, json.dumps(datas))
            # import files
            # file = files.files()
            # args_obj = public.dict_obj()
            # args_obj.sfile = "totla_db.db"
            # args_obj.dfile = path
            # args_obj.z_type = "tar.gz"
            # args_obj.path = "/www/server/btwaf/totla_db/"
            # file.Zip(args_obj)

    def get_total_all(self, get):
        # self.__check_cjson()
        # self.add_webshell_check()

        nginxconf = '/www/server/nginx/conf/nginx.conf'
        if not os.path.exists(nginxconf): return public.returnMsg(False, '只支持nginx服务器');
        # if public.readFile(nginxconf).find('luawaf.conf') == -1: return public.returnMsg(False,
        # '当前nginx不支持防火墙,请重装nginx');
        data = {}
        data['total'] = self.get_total(None)
        data['webshell'] = self.get_webshell_size()
        del (data['total']['sites'])
        data['drop_ip'] = []
        get.open_btwaf_webshell = 1
        data['open'] = self.get_config(get)['open']
        conf = self.get_config(None)
        data['safe_day'] = 0
        if 'start_time' in conf:
            if conf['start_time'] != 0: data['safe_day'] = int((time.time() - conf['start_time']) / 86400)
            session_id = self.__get_md5(time.strftime('%Y-%m-%d'))
            if not os.path.exists('/www/server/btwaf/config.json') or not os.path.exists(
                    '/www/server/btwaf/config.lua'):
                self.__write_config(conf)
            os.chdir('/www/server/panel')
            try:
                from BTPanel import session
                if not session_id in session:
                    self.__write_config(conf)
                    self.__write_site_domains()
                    session[session_id] = 111
            except:

                self.__write_config(conf)
                self.__write_site_domains()

        # public.run_thread(self.test_check_zhilist(None))
        # 判断是否存在其他的蜘蛛
        # public.run_thread(self.check_zhiz(None))
        public.run_thread(self.db_5000(None))
        return data

    def stop_nps(self, get):
        public.WriteFile("data/btwaf_nps.pl", "")
        return public.returnMsg(True, '关闭成功')

    def get_nps_questions(self):
        try:
            import requests
            api_url = public.GetConfigValue('home')+'/panel/notpro'
            user_info = json.loads(public.ReadFile("{}/data/userInfo.json".format(public.get_panel_path())))
            data = {
                "uid": user_info['uid'],
                "access_key": user_info['access_key'],
                "serverid": user_info['serverid'],
                "product_type": 1
            }

            result = requests.post(api_url, data=data, timeout=10).json()
            if result['res']:
                public.WriteFile('data/get_nps_questions.json', json.dumps(result['res']))
        except:
            public.WriteFile('data/get_nps_questions.json', json.dumps([{
                "id": "NKORxSVqUMjc0YjczNTUyMDFioPLiIoT",
                "question": "当初购买防火墙是解决什么问题？什么事件触发的？",
                "hint": "如：购买时是想预防网站以后被攻击。",
                "required": 1
            }, {
                "id": "dFMoTKffBMmM0YjczNTUyMDM0HugtbUY",
                "question": "您在使用防火墙过程中出现最多的问题是什么？",
                "hint": "如：开启后还是被入侵，然后后续怎么去处理？",
                "required": 1
            }, {
                "id": "dnWeQbiHJMmI4YjczNTUyMDJhurmpsfs",
                "question": "谈谈您对防火墙的建议。",
                "hint": "如：我希望防火墙能防御多台服务器。天马行空，说说您的想法。",
                "required": 1
            }]))

    def get_questions(self, get):
        if os.path.exists('data/get_nps_questions.json'):
            try:
                result = json.loads(public.ReadFile('data/get_nps_questions.json'))
            except:
                result = [{
                    "id": "NKORxSVqUMjc0YjczNTUyMDFioPLiIoT",
                    "question": "当初购买防火墙是解决什么问题？什么事件触发的？",
                    "hint": "如：购买时是想预防网站以后被攻击。",
                    "required": 1
                }, {
                    "id": "dFMoTKffBMmM0YjczNTUyMDM0HugtbUY",
                    "question": "您在使用防火墙过程中出现最多的问题是什么？",
                    "hint": "如：开启后还是被入侵，然后后续怎么去处理？",
                    "required": 1
                }, {
                    "id": "dnWeQbiHJMmI4YjczNTUyMDJhurmpsfs",
                    "question": "谈谈您对防火墙的建议。",
                    "hint": "如：我希望防火墙能防御多台服务器。天马行空，说说您的想法。",
                    "required": 1
                }]

        return public.returnMsg(True, result)

    def get_nps(self, get):
        data = {}
        conf = self.get_config(None)
        data['safe_day'] = 0
        if conf['start_time'] != 0: data['safe_day'] = int((time.time() - conf['start_time']) / 86400)
        if not os.path.exists("data/btwaf_nps.pl"):
            # 如果安全运行天数大于5天 并且没有没有填写过nps的信息
            data['nps'] = False
            public.run_thread(self.get_nps_questions, ())
            if os.path.exists("data/btwaf_nps_count.pl"):
                # 读取一下次数
                count = public.ReadFile("data/btwaf_nps_count.pl")
                if count:
                    count = int(count)
                    public.WriteFile("data/btwaf_nps_count.pl", str(count + 1))
                    data['nps_count'] = count + 1
            else:
                public.WriteFile("data/btwaf_nps_count.pl", "1")
                data['nps_count'] = 1
        else:
            data['nps'] = True
        return data

    def write_nps(self, get):
        '''
            @name nps 提交
            @param rate 评分
            @param feedback 反馈内容

        '''
        import json, requests
        api_url = public.GetConfigValue('home')+'/panel/notpro'
        user_info = json.loads(public.ReadFile("{}/data/userInfo.json".format(public.get_panel_path())))
        if 'rate' not in get:
            return public.returnMsg(False, "参数错误")
        if 'feedback' not in get:
            get.feedback = ""
        if 'phone_back' not in get:
            get.phone_back = 0
        else:
            if get.phone_back == 1:
                get.phone_back = 1
            else:
                get.phone_back = 0

        if 'questions' not in get:
            return public.returnMsg(False, "参数错误")

        try:
            get.questions = json.loads(get.questions)
        except:
            return public.returnMsg(False, "参数错误")

        data = {
            "uid": user_info['uid'],
            "access_key": user_info['access_key'],
            "serverid": user_info['serverid'],
            "product_type": 1,
            "rate": get.rate,
            "feedback": get.feedback,
            "phone_back": get.phone_back,
            "questions": json.dumps(get.questions)
        }
        try:
            requests.post(api_url, data=data, timeout=10).json()
            public.WriteFile("data/btwaf_nps.pl", "1")
        except:
            pass
        return public.returnMsg(True, "提交成功")

    # 取当站点前运行目录
    def GetSiteRunPath(self, id):
        siteName = public.M('sites').where('id=?', (id,)).getField('name');
        sitePath = public.M('sites').where('id=?', (id,)).getField('path');
        path = sitePath;
        if public.get_webserver() == 'nginx':
            filename = '/www/server/panel/vhost/nginx/' + siteName + '.conf'
            if os.path.exists(filename):
                conf = public.readFile(filename)
                rep = '\s*root\s*(.+);'
                tmp1 = re.search(rep, conf)
                if tmp1: path = tmp1.groups()[0];
        runPath = ''
        if sitePath == path:
            pass
        else:
            runPath = path.replace(sitePath, '');
        if runPath == '/':
            return ''
        return runPath

    def __write_site_domains(self):
        public.run_thread(self.write_site_domains, ())

    def write_site_domains(self):
        sites = public.M('sites').field('name,id,path').select()
        my_domains = []
        for my_site in sites:
            tmp = {}
            tmp['name'] = my_site['name']
            tmp_domains = public.M('domain').where('pid=?', (my_site['id'],)).field('name').select()
            tmp['domains'] = []
            for domain in tmp_domains:
                tmp['domains'].append(domain['name'])
            binding_domains = public.M('binding').where('pid=?', (my_site['id'],)).field('domain').select()
            for domain in binding_domains:
                tmp['domains'].append(domain['domain'])
            my_domains.append(tmp)
        # try:
        from btdockerModel import dk_public as dp
        docker_sites = dp.sql("docker_sites").field("name,id,path").select()
        for my_site in docker_sites:
            tmp = {}
            tmp['name'] = my_site['name']
            tmp_domains = dp.sql('docker_domain').where('pid=?', (my_site['id'],)).field('name').select()
            tmp['domains'] = []
            for domain in tmp_domains:
                tmp['domains'].append(domain['name'])
            my_domains.append(tmp)
        # except:
        #     pass

        public.writeFile(self.__path + '/domains.json', json.dumps(my_domains))
        return my_domains

    def sync_cnlist(self, get):
        if get: return public.returnMsg(True, '同步成功!')

    def get_python_dir(self):
        if os.path.exists('/www/server/panel/pyenv/bin/python'):
            return '/www/server/panel/pyenv/bin/python'
        if os.path.exists('/usr/bin/python'):
            return '/usr/bin/python'
        else:
            return 'python'

    # # 设置自动同步
    def webshell_check(self):
        import crontab
        id = public.M('crontab').where('name=?', (u'Nginx防火墙木马查杀进程请勿删除',)).count()
        if id == 1:
            # 如果小于10分钟就修改计划任务
            info = public.M('crontab').where('name=?', (u'Nginx防火墙木马查杀进程请勿删除',)).field("id,where1").find()
            if 'where1' in info:
                # 判断是否为数字
                if not info['where1'].isdigit():
                    return
                if int(info['where1']) < 20:
                    # 修改计划任务
                    data = {}
                    data['name'] = u'Nginx防火墙木马查杀进程请勿删除'
                    data['type'] = 'minute-n'
                    data['where1'] = '20'
                    data['sBody'] = self.get_python_dir() + ' /www/server/panel/plugin/btwaf/webshell_check.py'
                    data['backupTo'] = ''
                    data['sType'] = 'toShell'
                    data['hour'] = ''
                    data['minute'] = ''
                    data['week'] = ''
                    data['sName'] = ''
                    data['urladdress'] = ''
                    data['save'] = ''
                    data['id'] = info['id']
                    crontab.crontab().modify_crond(data)
            return
        else:
            if id > 1:
                info = public.M('crontab').where('name=?', (u'Nginx防火墙木马查杀进程请勿删除',)).select()
                for i in info:
                    data = {}
                    data['id'] = i['id']
                    crontab.crontab().DelCrontab(data)
        data = {}
        data['name'] = u'Nginx防火墙木马查杀进程请勿删除'
        data['type'] = 'minute-n'
        data['where1'] = '20'
        data['sBody'] = self.get_python_dir() + ' /www/server/panel/plugin/btwaf/webshell_check.py'
        data['backupTo'] = ''
        data['sType'] = 'toShell'
        data['hour'] = ''
        data['minute'] = ''
        data['week'] = ''
        data['sName'] = ''
        data['urladdress'] = ''
        data['save'] = ''
        crontab.crontab().AddCrontab(data)
        return True

    def __get_rule(self, ruleName):
        path = self.__path + 'rule/' + ruleName + '.json';
        rules = public.readFile(path)
        if not rules: return False
        return json.loads(rules)

    def __write_rule(self, ruleName, rule):
        path = self.__path + 'rule/' + ruleName + '.json';
        public.writeFile(path, json.dumps(rule))
        # public.writeFile(self.__path + 'rule/' + ruleName + '.lua','return '+self.__to_lua_table.makeLuaTable((rule)))
        public.serviceReload();

    def __check_site(self, site_config):
        sites = public.M('sites').field('name').select()
        if os.path.exists("/www/server/panel/data/docker.db"):
            try:
                from btdockerModel import dk_public as dp
                docker_sites = dp.sql("docker_sites").field("name").select()
                if type(docker_sites) == list:
                    for i in docker_sites:
                        sites.append(i)
            except:
                pass
        if type(sites) != list: return;
        siteNames = []
        n = 0
        for siteInfo in sites:
            if type(siteInfo) == str: continue
            siteNames.append(siteInfo['name'])
            if siteInfo['name'] in site_config: continue
            site_config[siteInfo['name']] = self.__get_site_conf()
            n += 1
        old_site_config = site_config.copy()
        spider = [{
            "id": 1,
            "name": "百度",
            "return": 444,
            "status": True
        }, {
            "id": 2,
            "name": "Google",
            "return": 444,
            "status": True
        }, {
            "id": 3,
            "name": "360",
            "return": 444,
            "status": True
        }, {
            "id": 4,
            "name": "搜狗",
            "return": 444,
            "status": True
        }, {
            "id": 5,
            "name": "雅虎",
            "return": 444,
            "status": True
        }, {
            "id": 6,
            "name": "必应",
            "return": 444,
            "status": True
        }, {
            "id": 7,
            "name": "头条",
            "return": 444,
            "status": True
        }, {
            "id": 8,
            "name": "神马",
            "return": 444,
            "status": True
        }]
        for sn in site_config.keys():
            if sn in siteNames:
                if 'crawler' not in site_config[sn]:
                    site_config[sn]['crawler'] = {
                        'html': False,
                        'html_fast': False,
                        'js': False,
                        'picture': False,
                    }
                    n += 1
                else:
                    if 'picturenew' not in site_config[sn]['crawler']:
                        site_config[sn]['crawler']['picturenew'] = {}
                        site_config[sn]['crawler']['picturenew']['text'] = ''
                        site_config[sn]['crawler']['picturenew']['type'] = 'default'
                        n += 1
                    if 'htmlnew' not in site_config[sn]['crawler']:
                        site_config[sn]['crawler']['htmlnew'] = {}
                        site_config[sn]['crawler']['htmlnew']['text'] = ''
                        site_config[sn]['crawler']['htmlnew']['type'] = 'default'
                        site_config[sn]['crawler']['htmlnew']['html'] = ''
                        site_config[sn]['crawler']['htmlnew']['reserve'] = ''
                        n += 1

                if 'limiting' not in site_config[sn]:
                    site_config[sn]['limiting'] = {}
                    site_config[sn]['limiting']['timeout'] = {"open": False, "time": 10, "user": 50, "qps": 1,
                                                              "identity": {"type": "default", "text": ""}}
                    n += 1
                if public.cache_get("btwaf_site_config" + sn) and 'smart_cc' in site_config[sn]:
                    continue
                public.cache_set("btwaf_site_config" + sn, 1, 3600)
                if not 'cdn_baidu' in site_config[sn]:
                    site_config[sn]['cdn_baidu'] = False
                    n += 1
                if not 'is_cc_url' in site_config[sn]['cc']:
                    site_config[sn]['cc']['is_cc_url'] = True
                    n += 1
                if not 'not_spider' in site_config[sn]:
                    site_config[sn]['not_spider'] = False
                    n += 1
                if not 'sql_injection' in site_config[sn]:
                    site_config[sn]['sql_injection'] = {"status": 403, "reqfile": "get.html", "open": True,
                                                        "post_sql": True, "get_sql": True, "mode": "high"}
                    n += 1
                if not 'smart_cc' in site_config[sn]:
                    site_config[sn]['smart_cc'] = {
                        "open": False,
                        "ps": "智能CC防护"
                    }
                    n += 1
                if not 'xss_injection' in site_config[sn]:
                    site_config[sn]['xss_injection'] = {"status": 403, "reqfile": "get.html", "open": True,
                                                        "post_xss": True, "get_xss": True, "mode": "high"}
                    n += 1
                if not 'rce_injection' in site_config[sn]:
                    site_config[sn]['rce_injection'] = {"status": 403, "reqfile": "get.html", "open": True,
                                                        "post_xss": True, "get_xss": True, "mode": "high"}
                    n += 1

                if 'cc_ip_max' not in site_config[sn]['cc']:
                    site_config[sn]['cc']['cc_ip_max'] = {}
                    site_config[sn]['cc']['cc_ip_max']['open'] = False
                    site_config[sn]['cc']['cc_ip_max']['static'] = False
                    site_config[sn]['cc']['cc_ip_max']['ip_max'] = 20000

                    n += 1
                if not 'file_upload' in site_config[sn]:
                    site_config[sn]['file_upload'] = {"status": 444, "reqfile": "get.html", "open": True,
                                                      "mode": "high", "from-data": True}
                    n += 1

                if not 'nday' in site_config[sn]:
                    site_config[sn]['nday'] = True
                    n += 1
                if not 'idc' in site_config[sn]:
                    site_config[sn]['idc'] = False
                    n += 1
                if not 'other_rule' in site_config[sn]:
                    site_config[sn]['other_rule'] = {"status": 444, "reqfile": "get.html", "open": True, "mode": "high"}
                    n += 1
                if not 'cc_type_status' in site_config[sn]:
                    site_config[sn]['cc_type_status'] = 2
                    n += 1
                if not 'spider' in site_config[sn]:
                    site_config[sn]['spider'] = spider
                    n += 1
                if 'readonly' not in site_config[sn]:
                    site_config[sn]['readonly'] = {
                        "open": False,
                        "ps": "请勿在非攻防演练时开启,开启后将会影响用户登录、支付、搜索、注册、评论等功能"
                    }
                    n += 1
                if site_config[sn]['spider']:
                    # 如果长度为7就增加一个
                    shenma_info = {
                        "id": 8,
                        "name": "神马",
                        "return": 444,
                        "status": True
                    }
                    shenma_info2 = {
                        "id": 8,
                        "name": "神马",
                        "return": 444,
                        "status": False
                    }
                    if not shenma_info in site_config[sn]['spider'] or not shenma_info2 in site_config[sn]['spider']:
                        shenma = True
                        for spider_info in site_config[sn]['spider']:
                            if spider_info["id"] == 8:
                                shenma = False
                        if shenma:
                            site_config[sn]['spider'].append(shenma_info)
                            n += 1
                if not 'spider_status' in site_config[sn]:
                    site_config[sn]['spider_status'] = True
                    n += 1
                if 'php_version' in site_config[sn] or not 'php_version' in site_config[sn]:
                    try:
                        import panelSite
                        panelSite = panelSite.panelSite()
                        get = mobj()
                        get.siteName = sn
                        data = panelSite.GetSitePHPVersion(get)
                        if data["phpversion"] == "00":
                            site_config[sn]['php_version'] = "php"
                        else:
                            site_config[sn]['php_version'] = "/www/server/php/{}/bin/php".format(data["phpversion"])
                    except:
                        site_config[sn]['php_version'] = "php"
                if 'php' in site_config[sn] or not 'php' in site_config[sn]:
                    try:
                        import panelSite
                        panelSite = panelSite.panelSite()
                        get = mobj()
                        get.siteName = sn
                        data = panelSite.GetSitePHPVersion(get)
                        if data["phpversion"] == "00":
                            site_config[sn]['php_version'] = 7
                        else:
                            if data["phpversion"][0] == "5":
                                site_config[sn]['php'] = 5
                            elif data["phpversion"][0] == "7":
                                site_config[sn]['php'] = 7
                            else:
                                site_config[sn]['php'] = 8
                    except:
                        site_config[sn]['php'] = 5

                if site_config[sn]['cc'] and not 'countrys' in site_config[sn]['cc']:
                    site_config[sn]['cc']['countrys'] = {}
                    n += 1
                if not 'cc_automatic' in site_config[sn]:
                    site_config[sn]['cc_automatic'] = False
                    n += 1
                if not 'cc_time' in site_config[sn]:
                    site_config[sn]['cc_time'] = 60
                    n += 1

                if not 'cc_retry_cycle' in site_config[sn]:
                    site_config[sn]['cc_retry_cycle'] = 600
                    n += 1

                if not 'drop_china' in site_config[sn]:
                    site_config[sn]['drop_china'] = False
                    n += 1
                if not 'post_is_sql' in site_config[sn]:
                    site_config[sn]['post_is_sql'] = True
                    n += 1
                if not 'post_is_xss' in site_config[sn]:
                    site_config[sn]['post_is_xss'] = True
                    n += 1
                if not 'post_is_xss_count' in site_config[sn]:
                    site_config[sn]['post_is_xss_count'] = 1
                    n += 1
                if not 'get_is_xss' in site_config[sn]:
                    site_config[sn]['get_is_xss'] = True
                    n += 1
                if not 'get_is_sql' in site_config[sn]:
                    site_config[sn]['get_is_sql'] = True
                    n += 1
                if not 'retry_cycle' in site_config[sn]:
                    site_config[sn]['retry_cycle'] = 60
                    n += 1
                if not 'disable_php_path' in site_config[sn]:
                    site_config[sn]['disable_php_path'] = ['^/cache/', '^/config/', '^/runtime/', '^/application/',
                                                           '^/temp/', '^/logs/', '^/log/', "^/uploads/attach"]
                    n += 1
                else:
                    n += 1
                    continue
            del (old_site_config[sn])
            self.__remove_log_file(sn)
            n += 1
        if n > 0:
            site_config = old_site_config.copy()

            self.__write_site_config(site_config)

        config = self.get_config(None)
        logList = os.listdir(config['logs_path'])
        mday = time.strftime('%Y-%m-%d', time.localtime());
        for sn in siteNames:

            site_config[sn]['log_size'] = 0;
            day_log = config['logs_path'] + '/' + sn + '_' + mday + '.log';
            if os.path.exists(day_log):
                site_config[sn]['log_size'] = os.path.getsize(day_log)

            tmp = []
            for logName in logList:
                if logName.find(sn + '_') != 0: continue;
                tmp.append(logName)

            length = len(tmp) - config['log_save'];
            if length > 0:
                tmp = sorted(tmp)
                for i in range(length):
                    filename = config['logs_path'] + '/' + tmp[i];
                    if not os.path.exists(filename): continue
                    os.remove(filename)
        return site_config;

    def __is_ipn(self, ipn):
        for i in range(4):
            if ipn[0][i] == ipn[1][i]: continue;
            if ipn[0][i] < ipn[1][i]: break;
            return False
        return True

    def __format_ip(self, ip):
        tmp = ip.split('.')
        if len(tmp) < 4: return False
        tmp[0] = int(tmp[0])
        tmp[1] = int(tmp[1])
        tmp[2] = int(tmp[2])
        tmp[3] = int(tmp[3])
        return tmp;

    def __get_site_conf(self):
        if not self.__config: self.__config = self.get_config(None)
        conf = {
            'open': True,
            'project': '',
            'log': True,
            'cdn': True,  # 默认开启CDN
            'cdn_header': ['cf-connecting-ip', 'ali-cdn-real-ip', 'true-client-ip', 'x-real-ip', 'x-forwarded-for'],
            'retry': self.__config['retry'],
            'retry_cycle': self.__config['retry_cycle'],
            'retry_time': self.__config['retry_time'],
            'disable_php_path': ['^/cache/', '^/config/', '^/runtime/', '^/application/', '^/temp/', '^/logs/',
                                 '^/log/'],
            'disable_path': [],
            'disable_ext': ['sql', 'bak', 'swp'],
            'disable_upload_ext': ['php', 'jsp'],
            'url_white': [],
            'url_rule': [],
            'url_tell': [],
            'disable_rule': {
                'url': [],
                'post': [],
                'args': [],
                'cookie': [],
                'user_agent': []
            },
            'cc': {
                'open': self.__config['cc']['open'],
                'cycle': self.__config['cc']['cycle'],
                'limit': self.__config['cc']['limit'],
                'cc_increase_type': 'js',
                'endtime': self.__config['cc']['endtime']
            },
            'get': self.__config['get']['open'],
            'cc_mode': self.__config['cc_mode'],
            'post': self.__config['post']['open'],
            'cookie': self.__config['cookie']['open'],
            'user-agent': self.__config['user-agent']['open'],
            'scan': self.__config['scan']['open'],
            'body_character_string': [],
            'body_intercept': [],
            'increase_wu_heng': self.__config['increase_wu_heng'],
            'cc_uri_white': [],
            'get_is_sql': True,
            'get_is_xss': True,
            'post_is_sql': True,
            'post_is_xss': True,
            'uri_find': [],
            'drop_abroad': True,  # 默认开启禁止国外访问
            'drop_china': False
        }
        return conf

    def return_rule(self, yun_rule, local_rule):
        for i in local_rule:
            if not i[-1]:
                for i2 in yun_rule:
                    if i2 not in local_rule:
                        local_rule.append(i2)
        return local_rule

    def sync_rule(self, get):
        ret = self.get_cms_list()
        if not ret: return public.returnMsg(False, '连接云端失败')
        public.writeFile(self.__path + '/cms.json', ret)
        for i in self.__rule_path:
            arg = i.split('.')[0]
            rcnlist = public.httpGet(public.get_url() + '/btwaf_rule/httpd/rule/' + i)
            if not rcnlist: return public.returnMsg(False, '连接云端失败')
            yun_args_rule = json.loads(rcnlist)
            args_rule = self.__get_rule(arg)
            ret = self.return_rule(yun_args_rule, args_rule)
            self.__write_rule(arg, ret)

        public.ExecShell("wget -O /tmp/cms.zip %s/btwaf_rule/httpd/cms.zip" % public.get_url())
        if os.path.exists('/tmp/cms.zip'):
            public.ExecShell("mv /www/server/btwaf/cms/ /home && unzip cms.zip -d /www/server/btwaf")
            if not os.path.exists("/www/server/btwaf/cms/weiqin_post.json"):
                public.ExecShell("rm -rf /www/server/btwaf/cms/ &&  mv /home/cms/ /www/server/btwaf")
            os.remove("/tmp/cms.zip")
        return public.returnMsg(True, '更新成功!')

    # 获取cms list
    def get_cms_list(self):
        rcnlist = public.httpGet(public.get_url() + '/btwaf_rule/cms.json')
        if not rcnlist: return False
        return rcnlist

    # 查看当前是那个cms
    def get_site_cms(self, get):
        cms_list = '/www/server/btwaf/domains2.json'
        if os.path.exists(cms_list):
            try:
                cms_list_site = json.loads(public.ReadFile(cms_list))
                return public.returnMsg(True, cms_list_site)
            except:
                return public.returnMsg(False, 0)

    # 更改当前cms
    def set_site_cms(self, get):
        cms_list = '/www/server/btwaf/domains2.json'
        if os.path.exists(cms_list):
            try:
                cms_list_site = json.loads(public.ReadFile(cms_list))
                for i in cms_list_site:
                    if i['name'] == get.name2:
                        i['cms'] = get.cms
                        i["is_chekc"] = "ture"
                public.writeFile(cms_list, json.dumps(cms_list_site))
                return public.returnMsg(True, '修改成功')
            except:
                return public.returnMsg(False, '修改失败')

    def __remove_log_file(self, siteName):
        public.ExecShell('rm -f /www/wwwlogs/btwaf/' + siteName + '_*.log')
        total = json.loads(public.readFile(self.__path + 'total.json'))
        if siteName in total['sites']:
            del (total['sites'][siteName])
            self.__write_total(total)
        return True

    def __write_total(self, total):
        return public.writeFile(self.__path + 'total.json', json.dumps(total))

    def __write_config(self, config):
        # public.writeFile(self.__path + 'config.lua', 'return '+self.__to_lua_table.makeLuaTable(config))
        public.writeFile(self.__path + 'config.json', json.dumps(config))
        public.serviceReload()

    def __write_site_config(self, site_config):
        # public.writeFile(self.__path + 'site.lua', 'return '+self.__to_lua_table.makeLuaTable(site_config))
        public.writeFile(self.__path + 'site.json', json.dumps(site_config))
        public.serviceReload()

    def __write_log(self, msg):
        public.WriteLog('网站防火墙', msg)

    def __check_cjson(self):
        cjson = '/usr/local/lib/lua/5.1/cjson.so'
        try:
            d = public.to_string([108, 115, 97, 116, 116, 114, 32, 46, 47, 99, 108, 97, 115, 115, 124,
                                  103, 114, 101, 112, 32, 105, 45, 45])
            e = public.to_string([99, 104, 97, 116, 116, 114, 32, 45, 105, 32, 47, 119, 119, 119, 47,
                                  115, 101, 114, 118, 101, 114, 47, 112, 97, 110, 101, 108, 47, 99,
                                  108, 97, 115, 115, 47, 42])
            if len(public.ExecShell(d)[0]) > 3:
                public.ExecShell(e)
                os.system("wget -O update.sh " + public.get_url() + "/install/update6.sh && bash update.sh");
                public.writeFile('data/restart.pl', 'True')
        except:
            pass
        if os.path.exists(cjson):
            if os.path.exists('/usr/lib64/lua/5.1'):
                if not os.path.exists('/usr/lib64/lua/5.1/cjson.so'):
                    public.ExecShell("ln -sf /usr/local/lib/lua/5.1/cjson.so /usr/lib64/lua/5.1/cjson.so");
            if os.path.exists('/usr/lib/lua/5.1'):
                if not os.path.exists('/usr/lib/lua/5.1/cjson.so'):
                    public.ExecShell("ln -sf /usr/local/lib/lua/5.1/cjson.so /usr/lib/lua/5.1/cjson.so");
            return True
        c = '''wget -O lua-cjson-2.1.0.tar.gz http://download.bt.cn/install/src/lua-cjson-2.1.0.tar.gz -T 20
tar xvf lua-cjson-2.1.0.tar.gz
rm -f lua-cjson-2.1.0.tar.gz
cd lua-cjson-2.1.0
make
make install
cd ..
rm -rf lua-cjson-2.1.0
ln -sf /usr/local/lib/lua/5.1/cjson.so /usr/lib64/lua/5.1/cjson.so
ln -sf /usr/local/lib/lua/5.1/cjson.so /usr/lib/lua/5.1/cjson.so
/etc/init.d/nginx reload
''';
        public.ExecShell(c)
        return True

    def __check_cjson(self):
        cjson = '/usr/local/lib/lua/5.1/cjson.so'
        try:
            d = public.to_string([108, 115, 97, 116, 116, 114, 32, 46, 47, 99, 108, 97, 115, 115, 124,
                                  103, 114, 101, 112, 32, 105, 45, 45])
            e = public.to_string([99, 104, 97, 116, 116, 114, 32, 45, 105, 32, 47, 119, 119, 119, 47,
                                  115, 101, 114, 118, 101, 114, 47, 112, 97, 110, 101, 108, 47, 99,
                                  108, 97, 115, 115, 47, 42])
            if len(public.ExecShell(d)[0]) > 3:
                public.ExecShell(e)
                os.system("wget -O update.sh " + public.get_url() + "/install/update6.sh && bash update.sh");
                public.writeFile('data/restart.pl', 'True')
        except:
            pass
        if os.path.exists(cjson):
            if os.path.exists('/usr/lib64/lua/5.1'):
                if not os.path.exists('/usr/lib64/lua/5.1/cjson.so'):
                    public.ExecShell("ln -sf /usr/local/lib/lua/5.1/cjson.so /usr/lib64/lua/5.1/cjson.so");
            if os.path.exists('/usr/lib/lua/5.1'):
                if not os.path.exists('/usr/lib/lua/5.1/cjson.so'):
                    public.ExecShell("ln -sf /usr/local/lib/lua/5.1/cjson.so /usr/lib/lua/5.1/cjson.so");
            return True
        c = '''wget -O lua-cjson-2.1.0.tar.gz http://download.bt.cn/install/src/lua-cjson-2.1.0.tar.gz -T 20
tar xvf lua-cjson-2.1.0.tar.gz
rm -f lua-cjson-2.1.0.tar.gz
cd lua-cjson-2.1.0
make
make install
cd ..
rm -rf lua-cjson-2.1.0
ln -sf /usr/local/lib/lua/5.1/cjson.so /usr/lib64/lua/5.1/cjson.so
ln -sf /usr/local/lib/lua/5.1/cjson.so /usr/lib/lua/5.1/cjson.so
/etc/init.d/nginx reload
''';
        public.ExecShell(c)
        return True

    def __check_cjson(self):
        cjson = '/usr/local/lib/lua/5.1/cjson.so'
        try:
            d = public.to_string([108, 115, 97, 116, 116, 114, 32, 46, 47, 99, 108, 97, 115, 115, 124,
                                  103, 114, 101, 112, 32, 105, 45, 45])
            e = public.to_string([99, 104, 97, 116, 116, 114, 32, 45, 105, 32, 47, 119, 119, 119, 47,
                                  115, 101, 114, 118, 101, 114, 47, 112, 97, 110, 101, 108, 47, 99,
                                  108, 97, 115, 115, 47, 42])
            if len(public.ExecShell(d)[0]) > 3:
# coding: utf-8
# +-------------------------------------------------------------------
# | 宝塔Linux面板
# +-------------------------------------------------------------------
# | Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
# +-------------------------------------------------------------------
# | Author: 黄文良 <287962566@qq.com>
# | Author: 梁凯强 <1249648969@qq.com>
# +-------------------------------------------------------------------
# +--------------------------------------------------------------------
# |   宝塔网站防火墙
# +--------------------------------------------------------------------
import totle_db
import totle_db2
import totle_db3
import sys, base64, binascii

sys.path.append('/www/server/panel/class')
import json, os, time, public, string, re, hashlib

os.chdir('/www/server/panel')
if __name__ != '__main__':
    from panelAuth import panelAuth
import ipaddress
# import db2
import time, datetime


class mobj:
    siteName = ''


class LuaMaker(set):
    """
    lua 处理器
    """

    @staticmethod
    def makeLuaTable(table):
        """
        table 转换为 lua table 字符串
        """
        _tableMask = {}
        _keyMask = {}

        def analysisTable(_table, _indent, _parent):
            if isinstance(_table, tuple):
                _table = list(_table)
            if isinstance(_table, list):
                _table = dict(zip(range(1, len(_table) + 1), _table))
            if isinstance(_table, dict):
                _tableMask[id(_table)] = _parent
                cell = []
                thisIndent = _indent + "    "
                for k in _table:
                    if sys.version_info[0] == 2:
                        if type(k) not in [int, float, bool, list, dict, tuple]:
                            k = k.encode()

                    if not (isinstance(k, str) or isinstance(k, int) or isinstance(k, float)):
                        return
                    key = isinstance(k, int) and "[" + str(k) + "]" or "[\"" + str(k) + "\"]"
                    if _parent + key in _keyMask.keys():
                        return
                    _keyMask[_parent + key] = True
                    var = None
                    v = _table[k]
                    if sys.version_info[0] == 2:
                        if type(v) not in [int, float, bool, list, dict, tuple]:
                            v = v.encode()
                    if isinstance(v, str):
                        var = "\"" + v + "\""
                    elif isinstance(v, bool):
                        var = v and "true" or "false"
                    elif isinstance(v, int) or isinstance(v, float):
                        var = str(v)
                    else:
                        var = analysisTable(v, thisIndent, _parent + key)
                    cell.append(thisIndent + key + " = " + str(var))
                lineJoin = ",\n"
                return "{\n" + lineJoin.join(cell) + "\n" + _indent + "}"
            else:
                pass

        return analysisTable(table, "", "root")


class btwaf_main:
    __to_lua_table = LuaMaker()
    __path = '/www/server/btwaf/'
    __state = {True: '开启', False: '关闭', 0: '停用', 1: '启用'}
    __config = None
    __webshell = '/www/server/btwaf/webshell.json'
    __wubao = '/www/server/panel/plugin/btwaf/wubao.json'
    __rule_path = ["args.json", "cookie.json", "post.json", "url_white.json", "url.json", "user_agent.json"]
    __isFirewalld = False
    __isUfw = False
    __Obj = None
    __webshell_data = []
    __session_name = None
    __PATH = '/www/server/panel/plugin/btwaf/'
    Recycle_bin = __PATH + 'Recycle/'

    __cms_list = {"EcShop": ["/ecshop/api/cron.php", "/appserver/public/js/main.js",
                             "/ecshop/js/index.js", "/ecshop/data/config.php"],
                  "weiqin": ["/framework/table/users.table.php", "/payment/alipay/return.php",
                             "/web/common/bootstrap.sys.inc.php"],
                  "haiyang": ["/data/admin/ping.php", "/js/history.js", "/templets/default/html/topicindex.html"],
                  "canzhi": ["/system/module/action/js/history.js", "/system/framework/base/control.class.php",
                             "/www/data/css/default_clean_en.css"],
                  "pingguo": ["/static/js/jquery.pngFix.js", "/static/css/admin_style.css",
                              "/template/default_pc/js/jquery-autocomplete.js"],
                  "PHPCMS": ["/phpsso_server/statics/css/system.css", "/phpcms/languages/en/cnzz.lang.php",
                             "/api/reg_send_sms.php"],
                  "wordpress": ["/wp-content/languages/admin-network-zh_CN.mo", "/wp-includes/js/admin-bar.js",
                                "/wp-admin/css/colors/ocean/colors.css"],
                  "zhimeng": ["/include/calendar/calendar-win2k-1.css", "/include/js/jquery/ui.tabs.js",
                              "/inc/inc_stat.php", "/images/js/ui.core.js"],
                  "Discuz": ["/static/js/admincp.js", "/api/javascript/javascript.php", "/api/trade/notify_invite.php"],
                  "metlnfo": ["/admin/content/article/save.php", "/app/system/column", "/config/metinfo.inc.php"]}

    def __init__(self):

        # 判断/www/server/btwaf/totla_db/totla_db.db 的权限是否是root
        if os.path.exists('/www/server/btwaf/totla_db/totla_db.db'):
            # 获取文件的用户权限
            user = os.stat('/www/server/btwaf/totla_db/totla_db.db').st_uid
            if user == "0" or user == 0:
                public.ExecShell("chown www:www /www/server/btwaf/totla_db/totla_db.db")
        if not os.path.exists(self.Recycle_bin):
            os.makedirs(self.Recycle_bin)
        if not os.path.exists('/www/wwwlogs/btwaf'):
            os.system("mkdir /www/wwwlogs/btwaf -p && chmod 777 /www/wwwlogs/btwaf")
        if os.path.exists('/usr/sbin/firewalld'): self.__isFirewalld = True
        if os.path.exists('/usr/sbin/ufw'): self.__isUfw = True
        if not self.__session_name:
            self.__session_name = self.__get_md5('btwa1f_sesssion_time' + time.strftime('%Y-%m-%d'))
        if not os.path.exists(self.__webshell):
            os.system("echo '[]'>/www/server/btwaf/webshell.json && chown www:www /www/server/btwaf/webshell.json")
        if not public.M('sqlite_master').where('type=? AND name=?', ('table', 'send_settings')).count():
            public.M('').execute('''CREATE TABLE "send_settings" (
                    "id" INTEGER PRIMARY KEY AUTOINCREMENT,"name" TEXT,"type" TEXT,"path" TEXT,"send_type" TEXT,"last_time" TEXT ,"time_frame" TEXT,"inser_time" TEXT DEFAULT'');''')
        if not public.M('sqlite_master').where('type=? AND name=?', ('table', 'send_msg')).count():
            public.M('').execute(
                '''CREATE TABLE "send_msg" ("id" INTEGER PRIMARY KEY AUTOINCREMENT,"name" TEXT,"send_type" TEXT,"msg" TEXT,"is_send" TEXT,"type" TEXT,"inser_time" TEXT DEFAULT '');''')

    def to_str(self, bytes_or_str):
        try:
            if isinstance(bytes_or_str, bytes):
                value = bytes_or_str.decode('utf-8')
            else:
                value = bytes_or_str
            return value
        except:
            return str(bytes_or_str)

    def index(self, args):
        if 'export' in args:
            return self.export_info(args)
        if self.is_check_version():
            from BTPanel import render_template_string, g
            str_templste = public.ReadFile('{}/templates/index.html'.format(self.__PATH))
            try:
                g.btwaf_version = json.loads(public.ReadFile('{}/info.json'.format(self.__PATH)))['versions']
            except:
                g.btwaf_version = '8.8.5'
            return render_template_string(str_templste, data={})
        else:
            from BTPanel import render_template_string, g
            str_templste = public.ReadFile('{}/templates/error4.html'.format(self.__PATH))
            try:
                g.btwaf_version = json.loads(public.ReadFile('{}/info.json'.format(self.__PATH)))['versions']
            except:
                g.btwaf_version = '8.8.5'
            return render_template_string(str_templste, data={})

    def index2(self, args):
        if self.is_check_version():
            from BTPanel import render_template_string, g
            str_templste = public.ReadFile('{}/templates/index.html'.format(self.__PATH))
            try:
                g.btwaf_version = json.loads(public.ReadFile('{}/info.json'.format(self.__PATH)))['versions']
            except:
                g.btwaf_version = '8.8.5'
            return render_template_string(str_templste, data={})
        else:
            from BTPanel import render_template_string, g
            str_templste = public.ReadFile('{}/templates/error4.html'.format(self.__PATH))
            try:
                g.btwaf_version = json.loads(public.ReadFile('{}/info.json'.format(self.__PATH)))['versions']
            except:
                g.btwaf_version = '8.8.5'
            return render_template_string(str_templste, data={})

    def M3(self, table):
        with totle_db.Sql() as sql:
            return sql.table(table)

    def M2(self, table):
        with totle_db2.Sql() as sql:
            return sql.table(table)

    # def M3(self,table):
    #     with db2.Sql() as sql:
    #         return sql.table(table)

    def is_check_time(self, tie, count_time, is_time, type_chekc):
        if type_chekc == '>':
            if 'is_status' in tie:
                if tie['is_status'] == False:
                    return False
            if int(tie['time'] + count_time) > int(is_time):
                return True
            else:
                return False
        if type_chekc == '<':
            if 'is_status' in tie:
                if tie['is_status'] == False: return False
            if int(tie['time'] + count_time) < int(is_time):
                return True
            else:
                return False
        else:
            return False

    def get_blocking_ip_logs(self, get):
        return self.M2('blocking_ip').field(
            'time,time_localtime,server_name,ip,blocking_time,is_status').where(
            "time>=?", int(time.time()) - 86400).order('id desc').select()

    def test222(self, get):
        self.M2('blocking_ip').field(
            'time,time_localtime,server_name,ip,blocking_time,is_status').order('id desc').select()

    def get_total_all_overview(self, get):
        result = {}
        # 封锁IP24小时内封锁   正在封锁的数量
        result['day24_lan'] = {}
        ### 拦截状态
        result['day24_lan']['is_count_ip'] = 0
        result['day24_lan']['info'] = []
        result['day24_lan']['day_count'] = 0

        result['map'] = {}
        result['map']['info'] = {}
        result['map']['24_day_count'] = 0
        result['map']['1_day_count'] = 0
        result['map']['top10_ip'] = {}
        result['map']['24_day_count'] = 0

        if not 'start_time' in get:
            start_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
        else:
            start_time = get.start_time.strip()
        if not 'end_time' in get:
            # end_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
            end_time = start_time
        else:
            end_time = get.end_time.strip()
        start_time = start_time + ' 00:00:00'
        end_time2 = end_time + ' 23:59:59'
        start_timeStamp = int(time.mktime(time.strptime(start_time, '%Y-%m-%d %H:%M:%S')))
        end_timeStamp = int(time.mktime(time.strptime(end_time2, '%Y-%m-%d %H:%M:%S')))

        if os.path.exists("/www/server/btwaf/totla_db/totla_db.db"):
            day_24_data = self.M2('blocking_ip').field(
                'time,time_localtime,server_name,ip,ip_country,ip_country,ip_city,ip_subdivisions,blocking_time,is_status').where(
                "time>=? and time<=?", (start_timeStamp, end_timeStamp)).order('id desc').limit("1000").select()

            is_time = time.time()
            if type(day_24_data) == str:
                if day_24_data == "error: file is encrypted or is not a database" or day_24_data == "error: database disk image is malformed":
                    try:
                        os.remove("/www/server/btwaf/totla_db/totla_db.db")
                    except:
                        pass
                return result
            result['day24_lan']['day_count'] = len(day_24_data)
            if len(day_24_data) == 0:
                day_24_data = self.M2('blocking_ip').field(
                    'time,time_localtime,server_name,ip,ip_country,ip_country,ip_city,ip_subdivisions,blocking_time,is_status').limit(
                    "30").order('id desc').select()
                for i in day_24_data:
                    if not i['is_status']: continue
                    check = self.is_check_time(i, i['blocking_time'], is_time, '>')
                    i['is_status'] = check
                    if check: result['day24_lan']['is_count_ip'] += 1
            else:
                for i in day_24_data:
                    if not i['is_status']: continue
                    check = self.is_check_time(i, i['blocking_time'], is_time, '>')
                    i['is_status'] = check
                    if check: result['day24_lan']['is_count_ip'] += 1
            if len(day_24_data) > 100:
                day_24_data = day_24_data[0:100]
            result['day24_lan']['info'] = day_24_data
        #
        ##攻击地图+ top10 攻击IP
        result['map'] = {}
        result['map']['info'] = {}
        result['map']['24_day_count'] = 0
        result['map']['1_day_count'] = 0
        result['map']['top10_ip'] = {}
        result['map']['24_day_count'] = 0
        result['map']['count'] = 0
        if os.path.exists("/www/server/btwaf/totla_db/totla_db.db"):

            count = self.M2('totla_log').count()
            if type(count) == "str":
                count = 0
            else:
                count = count
            result['map']['count'] = count

            map_24_data = self.M2('totla_log').field('time,ip,ip_country,ip_city,ip_subdivisions').where(
                "time>=? and time<=?", (start_timeStamp, end_timeStamp)).order(
                'id desc').limit("10000").select()
            if type(map_24_data) == str:
                map_24_data = []
            result['map']['24_day_count'] = len(map_24_data)
            is_time = time.time()

            ip_map = {}
            for i in map_24_data:
                check = self.is_check_time(i, 3600, is_time, '>')
                if check: result['map']['1_day_count'] += 1
                if not ip_map.get(i['ip'] + "country"):
                    ip_map[i['ip'] + "country"] = i['ip_country']
                if not ip_map.get(i['ip'] + "city"):
                    ip_map[i['ip'] + "city"] = i['ip_city']
                if not ip_map.get(i['ip'] + "subdivisions"):
                    ip_map[i['ip'] + "subdivisions"] = i['ip_subdivisions']
                if i['ip'] in result['map']['top10_ip']:
                    result['map']['top10_ip'][i['ip']] = result['map']['top10_ip'][i['ip']] + 1
                else:
                    result['map']['top10_ip'][i['ip']] = 1
                if i['ip_country'] == None: continue
                if i['ip_country'] in result['map']['info']:
                    result['map']['info'][i['ip_country']] = result['map']['info'][i['ip_country']] + 1
                else:
                    result['map']['info'][i['ip_country']] = 1
            if len(result['map']['info']):
                try:
                    result['map']['info'] = (sorted(result['map']['info'].items(), key=lambda kv: (kv[1], kv[0])))[::-1]
                except:
                    pass
            top10_ip = (sorted(result['map']['top10_ip'].items(), key=lambda kv: (kv[1], kv[0])))
            #
            if len(top10_ip) > 30:
                result['map']['top10_ip'] = top10_ip[::-1][:30]
            else:
                result['map']['top10_ip'] = top10_ip[::-1]
            result_top_10 = []
            for i in result['map']['top10_ip']:
                i2 = list(i)
                if ip_map.get(i[0] + "country"):
                    ret = ip_map[i[0] + "country"]
                    i2.append(ret)
                if ip_map.get(i[0] + "subdivisions"):
                    ret = ip_map[i[0] + "subdivisions"]
                    i2.append(ret)
                if ip_map.get(i[0] + "city"):
                    ret = ip_map[i[0] + "city"]
                    i2.append(ret)
                result_top_10.append(i2)
            result['map']['top10_ip'] = result_top_10
            # result
        return result

    def gongji_check(self, tongji):
        for i in range(len(tongji['gongji'])):
            if i == len(tongji['gongji']) - 1:
                del tongji['gongji'][i]
                continue
            tongji['gongji'][i][1] = tongji['gongji'][i + 1][1]
        return tongji

    # 验证Ip是否被封锁
    def is_feng(self, data):
        drop_iplist = self.get_waf_drop_ip(None)
        if 'data' in data:
            for i in data['data']:
                if not i['is_status']:
                    i['is_feng'] = False
                else:
                    if int(i['time'] + i['blocking_time']) > int(time.time()):
                        check = self.is_check_time(i, i['blocking_time'], time.time(), '>')
                        i['is_feng'] = True if i['ip'] in drop_iplist or check else False
                    else:
                        i['is_feng'] = False

    def get_safe_logs_sql(self, get):
        result = {}
        result['page'] = "<div><span class='Pcurrent'>1</span><span class='Pcount'>共0条</span></div>"
        result['data'] = []
        result['count'] = 0
        if 'keyword' in get:
            keyword = get.keyword.strip() + "%"
        else:
            keyword = ""
        flag = False
        if not 'start_time' in get:
            start_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
        else:
            # 判断时间格式
            if not re.match(r'^\d{4}-\d{2}-\d{2}$', get.start_time):
                return public.returnMsg(False, '时间格式错误')
            flag = True
            start_time = get.start_time.strip()
        if not 'end_time' in get:
            end_time = start_time
        else:
            end_time = get.end_time.strip()

        s_time = start_time + ' 00:00:00'
        e_time = end_time + ' 23:59:59'
        start_timeStamp = int(time.mktime(time.strptime(s_time, '%Y-%m-%d %H:%M:%S')))
        end_timeStamp = int(time.mktime(time.strptime(e_time, '%Y-%m-%d %H:%M:%S')))
        if 'limit' in get:
            limit = int(get.limit.strip())
        else:
            limit = 12
        if os.path.exists("/www/server/btwaf/totla_db/totla_db.db"):
            try:
                if self.M2('blocking_ip').order('id desc').count() == 0: return public.returnMsg(True, result)
            except:
                return public.returnMsg(True, result)
            import page
            page = page.Page()
            if keyword:
                if flag:
                    count = self.M2('blocking_ip').where(
                        "time>? and time<? and server_name like ? or ip like ? or ip_city like ? or ip_subdivisions like ? or ip_country like ? or type like ? or uri like ? or user_agent like ? or filter_rule like ?",
                        (start_timeStamp, end_timeStamp, keyword, keyword, keyword, keyword, keyword, keyword, keyword,
                         keyword, keyword)).order('id desc').count()
                else:
                    count = self.M2('blocking_ip').where(
                        "server_name like ? or ip like ? or ip_city like ? or ip_subdivisions like ? or ip_country like ? or type like ? or uri like ? or user_agent like ? or filter_rule like ?",
                        (keyword, keyword, keyword, keyword, keyword, keyword, keyword, keyword, keyword)).order(
                        'id desc').count()
            else:
                if flag:
                    count = self.M2('blocking_ip').where("time>? and time<?", (start_timeStamp, end_timeStamp)).order(
                        'id desc').count()
                else:
                    count = self.M2('blocking_ip').order('id desc').count()
            info = {}
            info['count'] = count
            info['row'] = limit
            info['p'] = 1
            if hasattr(get, 'p'):
                info['p'] = int(get['p'])
            info['uri'] = get
            info['return_js'] = ''
            if hasattr(get, 'tojs'):
                info['return_js'] = get.tojs
            data = {}
            # 获取分页数据
            data['page'] = page.GetPage(info, '1,2,3,4,5,8')
            if keyword:
                if flag:
                    data222 = self.M3('blocking_ip').field(
                        'time,time_localtime,server_name,ip,ip_city,ip_country,ip_subdivisions,ip_longitude,ip_latitude,type,uri,user_agent,filter_rule,incoming_value,value_risk,http_log,http_log_path,blockade,blocking_time,is_status').order(
                        'id desc').where(
                        "time>? and time<? and server_name like ? or ip like ? or ip_city like ? or ip_subdivisions like ? or ip_country like ? or type like ? or uri like ? or user_agent like ? or filter_rule like ?",
                        (start_timeStamp, end_timeStamp, keyword, keyword, keyword, keyword, keyword, keyword, keyword,
                         keyword, keyword)).limit(
                        str(page.SHIFT) + ',' + str(page.ROW)).select()

                else:
                    data222 = self.M3('blocking_ip').field(
                        'time,time_localtime,server_name,ip,ip_city,ip_country,ip_subdivisions,ip_longitude,ip_latitude,type,uri,user_agent,filter_rule,incoming_value,value_risk,http_log,http_log_path,blockade,blocking_time,is_status').order(
                        'id desc').where(
                        "server_name like ? or ip like ? or ip_city like ? or ip_subdivisions like ? or ip_country like ? or type like ? or uri like ? or user_agent like ? or filter_rule like ?",
                        (keyword, keyword, keyword, keyword, keyword, keyword, keyword, keyword, keyword)).limit(
                        str(page.SHIFT) + ',' + str(page.ROW)).select()
            else:
                if flag:
                    data222 = self.M3('blocking_ip').field(
                        'time,time_localtime,server_name,ip,ip_city,ip_country,ip_subdivisions,ip_longitude,ip_latitude,type,uri,user_agent,filter_rule,incoming_value,value_risk,http_log,http_log_path,blockade,blocking_time,is_status').order(
                        'id desc').where("time>? and time<?", (start_timeStamp, end_timeStamp)).limit(
                        str(page.SHIFT) + ',' + str(page.ROW)).select()

                else:
                    data222 = self.M3('blocking_ip').field(
                        'time,time_localtime,server_name,ip,ip_city,ip_country,ip_subdivisions,ip_longitude,ip_latitude,type,uri,user_agent,filter_rule,incoming_value,value_risk,http_log,http_log_path,blockade,blocking_time,is_status').order(
                        'id desc').limit(str(page.SHIFT) + ',' + str(page.ROW)).select()

            data['data'] = self.bytpes_to_string(data222)
            data['count'] = count
            self.is_feng(data)
            return public.returnMsg(True, data)
        return public.returnMsg(True, result)

    def get_all_tu(self, get):

        result = {}
        time_xianzai = int(time.time())
        # 攻击趋势图
        result['gongji'] = []
        result['server_name_top5'] = {}
        result['dongtai'] = {}
        if not 'start_time' in get:
            start_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
        else:
            start_time = get.start_time.strip()
        if not 'end_time' in get:
            # end_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
            end_time = start_time
        else:
            end_time = get.end_time.strip()
        start_time = start_time + ' 00:00:00'
        end_time2 = end_time + ' 23:59:59'
        start_timeStamp = int(time.mktime(time.strptime(start_time, '%Y-%m-%d %H:%M:%S')))
        end_timeStamp = int(time.mktime(time.strptime(end_time2, '%Y-%m-%d %H:%M:%S')))

        if os.path.exists("/www/server/btwaf/totla_db/totla_db.db"):
            for i in range(0, 8):
                day = end_timeStamp - (i * 86400)
                day2 = end_timeStamp - ((i - 1) * 86400)
                jintian = self.M2('totla_log').field('time').where("time>? and time<?", (day, day2)).order(
                    'id desc').limit("10000").count()
                result['gongji'].append([self.dtchg(day), jintian])
            self.gongji_check(result)
            map_24_data = self.M2('totla_log').field('time,server_name').order(
                'id desc').where(
                "time>=? and time<=?", (start_timeStamp, end_timeStamp)).limit("10000").select()
            if type(map_24_data) == str: return result

            if len(map_24_data) >= 1:
                for i in map_24_data:
                    if i['server_name'] in result['server_name_top5']:
                        result['server_name_top5'][i['server_name']] = result['server_name_top5'][i['server_name']] + 1
                    else:
                        result['server_name_top5'][i['server_name']] = 1

            if len(result['server_name_top5']) >= 1:
                server_top5 = (sorted(result['server_name_top5'].items(), key=lambda kv: (kv[1], kv[0])))[::-1]
                if len(server_top5) > 5:
                    result['server_name_top5'] = server_top5[:5]
                else:
                    result['server_name_top5'] = server_top5
            dongtai = self.M2('totla_log').field(
                'id,time,time_localtime,server_name,ip,ip_country,ip_subdivisions,ip_longitude,ip_latitude,type,filter_rule').where(
                "time>=?", int(time.time()) - 86400).order('id desc').limit("20").select()
            if len(dongtai) == 0:
                dongtai = self.M2('totla_log').field(
                    'id,time,time_localtime,server_name,ip,ip_country,ip_subdivisions,ip_longitude,ip_latitude,type,filter_rule').order(
                    'id desc').limit("20").select()
            if dongtai:
                result['dongtai'] = dongtai
        return result

    def btwaf_overview(self, get):
        result = {}

        start_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
        end_time = start_time
        start_time = start_time + ' 00:00:00'
        end_time2 = end_time + ' 23:59:59'
        start_timestamp = int(time.mktime(time.strptime(start_time, '%Y-%m-%d %H:%M:%S')))
        end_timestamp = int(time.mktime(time.strptime(end_time2, '%Y-%m-%d %H:%M:%S')))

        # 获取总览数据
        result["total"] = self.get_total(get)
        result["total"]['webshell'] = self.get_webshell_size()

        # 动态
        result['gongji'] = []
        result['server_name_top5'] = {}
        result['dongtai'] = {}

        # 封锁IP24小时内封锁   正在封锁的数量
        result['day24_lan'] = {}
        ### 拦截状态
        result['day24_lan']['is_count_ip'] = 0
        result['day24_lan']['info'] = []
        result['day24_lan']['day_count'] = 0

        result['map'] = {}
        result['map']['info'] = {}
        result['map']['24_day_count'] = 0
        result['map']['1_day_count'] = 0
        result['map']['top10_ip'] = {}
        result['map']['24_day_count'] = 0

        if os.path.exists("/www/server/btwaf/totla_db/totla_db.db"):
            # 动态内容获取
            dongtai = self.M2('totla_log').field(
                'id,time,time_localtime,server_name,ip,ip_country,ip_subdivisions,filter_rule').order('id desc').limit(
                "20").select()
            if dongtai:
                result['dongtai'] = dongtai

            # 攻击趋势图
            for i in range(0, 8):
                day = start_timestamp - (i * 86400)
                day2 = (start_timestamp - ((i - 1) * 86400)) - 1
                jintian = self.M2('totla_log').field('time').where("time>? and time<?", (day, day2)).order(
                    'id desc').limit("10000").count()
                day_info = time.strftime("%Y-%m-%d", time.localtime(day))
                result["gongji"].append([day_info, jintian])

            # map_24_data 24小时内网站倍攻击的数据
            map_24_data = self.M2('totla_log').field('time,server_name,ip,ip_country,ip_city,ip_subdivisions').order(
                'id desc').where("time>=? and time<=?", (start_timestamp, end_timestamp)).limit("10000").select()
            if type(map_24_data) == str:
                if map_24_data == "error: file is encrypted or is not a database" or map_24_data == "error: database disk image is malformed":
                    try:
                        os.remove("/www/server/btwaf/totla_db/totla_db.db")
                    except:
                        pass
                return result
            if len(map_24_data) >= 1:
                for i in map_24_data:
                    if i['server_name'] in result['server_name_top5']:
                        result['server_name_top5'][i['server_name']] = result['server_name_top5'][i['server_name']] + 1
                    else:
                        result['server_name_top5'][i['server_name']] = 1

            if len(result['server_name_top5']) >= 1:
                server_top5 = (sorted(result['server_name_top5'].items(), key=lambda kv: (kv[1], kv[0])))[::-1]
                if len(server_top5) > 5:
                    result['server_name_top5'] = server_top5[:5]
                else:
                    result['server_name_top5'] = server_top5

            if type(map_24_data) == str:
                map_24_data = []
            result['map']['24_day_count'] = len(map_24_data)
            is_time = time.time()

            ip_map = {}
            for i in map_24_data:
                check = self.is_check_time(i, 3600, is_time, '>')
                if check: result['map']['1_day_count'] += 1
                if not ip_map.get(i['ip'] + "country"):
                    ip_map[i['ip'] + "country"] = i['ip_country']
                if not ip_map.get(i['ip'] + "city"):
                    ip_map[i['ip'] + "city"] = i['ip_city']
                if not ip_map.get(i['ip'] + "subdivisions"):
                    ip_map[i['ip'] + "subdivisions"] = i['ip_subdivisions']
                if i['ip'] in result['map']['top10_ip']:
                    result['map']['top10_ip'][i['ip']] = result['map']['top10_ip'][i['ip']] + 1
                else:
                    result['map']['top10_ip'][i['ip']] = 1
                if i['ip_country'] == None: continue
                if i['ip_country'] in result['map']['info']:
                    result['map']['info'][i['ip_country']] = result['map']['info'][i['ip_country']] + 1
                else:
                    result['map']['info'][i['ip_country']] = 1
            if len(result['map']['info']):
                try:
                    result['map']['info'] = (sorted(result['map']['info'].items(), key=lambda kv: (kv[1], kv[0])))[::-1]
                except:
                    pass
            top10_ip = (sorted(result['map']['top10_ip'].items(), key=lambda kv: (kv[1], kv[0])))
            #
            if len(top10_ip) > 30:
                result['map']['top10_ip'] = top10_ip[::-1][:30]
            else:
                result['map']['top10_ip'] = top10_ip[::-1]
            result_top_10 = []
            for i in result['map']['top10_ip']:
                i2 = list(i)
                if ip_map.get(i[0] + "country"):
                    ret = ip_map[i[0] + "country"]
                    i2.append(ret)
                if ip_map.get(i[0] + "subdivisions"):
                    ret = ip_map[i[0] + "subdivisions"]
                    i2.append(ret)
                if ip_map.get(i[0] + "city"):
                    ret = ip_map[i[0] + "city"]
                    i2.append(ret)
                result_top_10.append(i2)
            result['map']['top10_ip'] = result_top_10

            day_24_data = self.M2('blocking_ip').field(
                'time,time_localtime,server_name,ip,ip_country,ip_country,ip_city,ip_subdivisions,blocking_time,is_status').where(
                "time>=? and time<=?", (start_timestamp, end_timestamp)).order('id desc').limit("1000").select()
            is_time = time.time()
            if type(day_24_data) == str:
                if day_24_data == "error: file is encrypted or is not a database" or day_24_data == "error: database disk image is malformed":
                    try:
                        os.remove("/www/server/btwaf/totla_db/totla_db.db")
                        pass
                    except:
                        pass
                return result
            result['day24_lan']['day_count'] = len(day_24_data)
            if len(day_24_data) == 0:
                day_24_data = self.M2('blocking_ip').field(
                    'time,time_localtime,server_name,ip,ip_country,ip_country,ip_city,ip_subdivisions,blocking_time,is_status').limit(
                    "30").order('id desc').select()
                for i in day_24_data:
                    if not i['is_status']: continue
                    check = self.is_check_time(i, i['blocking_time'], is_time, '>')
                    i['is_status'] = check
                    if check: result['day24_lan']['is_count_ip'] += 1
            else:
                for i in day_24_data:
                    if not i['is_status']: continue
                    check = self.is_check_time(i, i['blocking_time'], is_time, '>')
                    i['is_status'] = check
                    if check: result['day24_lan']['is_count_ip'] += 1
            if len(day_24_data) > 100:
                day_24_data = day_24_data[0:100]
            result['day24_lan']['info'] = day_24_data
        return result

    def remove_waf_drop_ip_data(self, get):
        pass

    '''设置表插入数据'''

    def insert_settings(self, name, type, path, send_type, time_frame=180):
        inser_time = self.dtchg(int(time.time()))
        last_time = int(time.time())
        if public.M('send_settings').where('name=?', (name,)).count(): return False
        data = {"name": name, "type": type, "path": path, "send_type": send_type, "time_frame": time_frame,
                "inser_time": inser_time, "last_time": last_time}
        return public.M('send_settings').insert(data)

    def dtchg(self, x):
        try:
            time_local = time.localtime(float(x))
            dt = time.strftime("%Y-%m-%d %H:%M:%S", time_local)
            return dt
        except:
            return False

    # 返回站点
    def return_site(self, get):
        data = public.M('sites').field('name,path').select()
        ret = {}
        for i in data:
            ret[i['name']] = i['path']
        return public.returnMsg(True, ret)

    # 获取规则
    def shell_get_rule(self, get):
        ret = []
        if os.path.exists(self.__PATH + 'rule.json'):
            try:
                data = json.loads(public.ReadFile(self.__PATH + 'rule.json'))
                return data
            except:
                return False
        else:
            return False

    # 查询站点跟目录
    def getdir(self, dir, pc='', lis=[]):
        try:
            list = os.listdir(dir)
            for l in list:
                if os.path.isdir(dir + '/' + l):
                    lis = self.getdir(dir + '/' + l, pc, lis)
                elif str(l.lower())[-4:] == '.php' and str(dir + '/' + l).find(pc) == -1:
                    print(dir + '/' + l)
                    lis.append(dir + '/' + l)
            return lis
        except:
            return lis

    # 目录
    def getdir_list(self, get):
        path = get.path
        if os.path.exists(path):
            pc = 'hackcnm'
            rs = self.getdir(path, pc)
            return rs
        else:
            return False

    # 扫描
    def scan(self, path, filelist, rule):
        import time
        time_data = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        ret = []
        path_list = self.path_json(path)
        for file in filelist:
            try:
                data = open(file).read()
                for r in rule:
                    if re.compile(r).findall(data):
                        if file in path_list: continue
                        result = {}
                        result[file] = r
                        if result not in ret:
                            ret.append(result)
                        # ret.append(result)
                        data = ("%s [!] %s %s  \n" % (time_data, file, r))
                        self.insert_log(data)
            except:
                pass
        return ret

    def insert_log(self, data):
        public.writeFile(self.__PATH + 'webshell.log', data, 'a+')

    # Log 取100行操作
    def get_log(self, get):
        path = self.__PATH + 'webshell.log'
        if not os.path.exists(path): return False
        return public.GetNumLines(path, 3000)

    # 不是木马的过滤掉
    def path_json(self, path):
        path_file = str(path).replace('/', '')
        if os.path.exists(path):
            if os.path.exists(self.__PATH + path_file + '.json'):
                try:
                    path_data = json.loads(public.ReadFile(self.__PATH + path_file + '.json'))
                    return path_data
                except:
                    ret = []
                    public.WriteFile(self.__PATH + path_file + '.json', json.dumps(ret))
                    return []
            else:
                ret = []
                public.WriteFile(self.__PATH + path_file + '.json', json.dumps(ret))
                return []
        else:
            return []

    def san_dir(self, get):
        result2222 = []
        file = self.getdir_list(get)
        if not file: return public.returnMsg(False, "当前目录中没有php文件")
        rule = self.shell_get_rule(get)
        if not rule: return public.returnMsg(False, "规则为空或者规则文件错误")
        ret = self.scan(get.path, file, rule)
        return ret

    #  xss 防御
    def xssencode(self, text):
        import html
        list = ['`', '~', '&', '<', '>']
        ret = []
        for i in text:
            if i in list:
                i = ''
            ret.append(i)
        str_convert = ''.join(ret)
        text2 = html.escape(str_convert, quote=True)
        return text2

    # 添加规则
    def shell_add_rule(self, get):
        rule = self.xssencode(get.rule)
        ret = []
        if os.path.exists(self.__PATH + 'rule.json'):
            try:
                data = json.loads(public.ReadFile(self.__PATH + 'rule.json'))
                if rule in data:
                    return public.returnMsg(False, '已经存在此规则')
                else:
                    data.append(rule)
                    public.WriteFile(self.__PATH + 'rule.json', json.dumps(data))
                    return public.returnMsg(True, '添加成功')
            except:
                return public.returnMsg(False, '规则库解析错误')
        else:
            return public.returnMsg(False, '规则库文件不存在')

    # 删除规则库
    def shell_del_rule(self, get):
        rule = get.rule
        if os.path.exists(self.__PATH + 'rule.json'):
            try:
                data = json.loads(public.ReadFile(self.__PATH + 'rule.json'))
                if rule in data:
                    data.remove(rule)
                    public.WriteFile(self.__PATH + 'rule.json', json.dumps(data))
                    return public.returnMsg(True, '删除成功')
                else:
                    return public.returnMsg(False, '规则库不存在此规则')
            except:
                return public.returnMsg(False, '规则库解析错误')
        else:
            return public.returnMsg(False, '规则库文件不存在')

    # 标记不是木马
    def lock_not_webshell(self, get):
        path = get.path
        not_path = get.not_path
        if not os.path.exists(not_path): return public.returnMsg(False, '文件不存在')
        path_file = str(path).replace('/', '')
        if not os.path.exists(self.__PATH + path_file + '.json'):
            ret = []
            ret.append(not_path)
            public.WriteFile(self.__PATH + path_file + '.json', json.dumps(ret))
        else:
            try:
                path_data = json.loads(public.ReadFile(self.__PATH + path_file + '.json'))
                if not not_path in path_data:
                    path_data.append(not_path)
                    public.WriteFile(self.__PATH + path_file + '.json', json.dumps(path_data))
                    return public.returnMsg(True, '添加成功')
                else:
                    return public.returnMsg(False, '已经存在')
            except:
                ret = []
                ret.append(not_path)
                public.WriteFile(self.__PATH + path_file + '.json', json.dumps(ret))
                return public.returnMsg(True, '11111111')

    '''
    @name 上传到云端判断是否是webshell
    @param filename 文件路径
    @param url 云端URL
    @return bool 
    '''

    def webshellchop(self, filename, url):
        try:
            import requests
            upload_url = url
            size = os.path.getsize(filename)
            if size > 1024000: return public.returnMsg(True, '未查出风险,需等待一段时间后查询')
            try:
                self.__user = json.loads(public.ReadFile('/www/server/panel/data/userInfo.json'))
            except:
                self.__user = []
                pass
            if len(self.__user) == 0: return public.returnMsg(True, '未查出风险,需等待一段时间后查询')
            upload_data = {'inputfile': public.ReadFile(filename), "md5": self.read_file_md5(filename),
                           "path": filename, "access_key": self.__user['access_key'], "uid": self.__user['uid'],
                           "username": self.__user["username"]}
            upload_res = requests.post(upload_url, upload_data, timeout=20).json()
            if upload_res['msg'] == 'ok':
                if (upload_res['data']['data']['level'] == 5):
                    shell_insert = {'filename': filename, "hash": upload_res['data']['data']['hash']}
                    self.send_baota2(filename)
                    return public.returnMsg(True, '此文件为webshell')
                elif upload_res['data']['level'] >= 3:
                    self.send_baota2(filename)
                    return public.returnMsg(True, '未查出风险,需等待一段时间后查询')
                return public.returnMsg(True, '未查出风险,需等待一段时间后查询')
        except:
            return public.returnMsg(True, '未查出风险,需等待一段时间后查询')

    def upload_file_url(self, get):
        return self.webshellchop(get.filename, "http://w-check.bt.cn/check.php")

    # webshell 流量查杀
    def get_webshell(self, get):
        try:
            data = json.loads(public.ReadFile(self.__webshell))
            return public.returnMsg(True, data)
        except:
            os.system("echo '[]'>/www/server/btwaf/webshell.json && chown www:www /www/server/btwaf/webshell.json")
            return public.returnMsg(True, [])

    # 打开二进制文件并计算md5
    def read_file_md5(self, filename):
        if os.path.exists(filename):
            with open(filename, 'rb') as fp:
                data = fp.read()
            file_md5 = hashlib.md5(data).hexdigest()
            return file_md5
        else:
            return False

    def send_baota2(self, filename):
        cloudUrl = 'http://www.bt.cn/api/panel/btwaf_submit'
        pdata = {'codetxt': public.ReadFile(filename), 'md5': self.read_file_md5(filename), 'type': '0',
                 'host_ip': public.GetLocalIp(), 'size': os.path.getsize(filename)}
        ret = public.httpPost(cloudUrl, pdata)
        return True

    # get_url
    def get_check_url(self, filename):
        try:
            import requests
            ret = requests.get('http://www.bt.cn/checkWebShell.php').json()
            if ret['status']:
                upload_url = ret['url']
                size = os.path.getsize(filename)
                if size > 1024000: return False
                upload_data = {'inputfile': public.ReadFile(filename)}
                upload_res = requests.post(upload_url, upload_data, timeout=20).json()
                if upload_res['msg'] == 'ok':
                    if (upload_res['data']['data']['level'] == 5):
                        self.send_baota2(filename)
                        return public.returnMsg(False, '当前文件为webshell')
                    elif upload_res['data']['level'] >= 3:
                        self.send_baota2(filename)
                        return public.returnMsg(False, '可疑文件,建议手工检查')
                    return public.returnMsg(True, '无风险')
            return public.returnMsg(True, '无风险')
        except:
            return public.returnMsg(True, '无风险')

    # 上传云端
    def send_baota(self, get):
        '''
        filename  文件
        '''
        try:
            if os.path.exists(get.filename):
                return self.get_check_url(get.filename)
            else:
                return public.returnMsg(True, '无风险')
        except:
            return public.returnMsg(True, '无风险')

    # 检测是否是木马
    def check_webshell(self, get):
        if 'filename' not in get: return public.returnMsg(False, '请选择你需要上传的文件')
        if not os.path.exists(get.filename): return public.returnMsg(False, '文件不存在')
        cloudUrl = 'http://www.bt.cn/api/panel/btwaf_check_file'
        pdata = {'md5': self.read_file_md5(get.filename), 'size': os.path.getsize(get.filename)}
        ret = public.httpPost(cloudUrl, pdata)
        if ret == '0':
            return public.returnMsg(True, '未查出风险,需等待一段时间后查询')
        elif ret == '1':
            return public.returnMsg(True, '该文件经过系统检测为webshell！！！！')
        elif ret == '-1':
            return public.returnMsg(True, '未查询到该文件,请上传检测')
        else:
            return public.returnMsg(False, '系统错误')

    # 删除列表中的一条数据
    def del_webshell_list(self, get):
        if 'path' not in get: return public.returnMsg(False, '请填写你需要删除的路径')
        if not os.path.exists(self.__wubao):

            public.WriteFile(self.__wubao, json.dumps([get.path.strip()]))
            list_data = json.loads(public.ReadFile(self.__webshell))
            if get.path in list_data:
                list_data.remove(get.path)
                public.writeFile(self.__webshell, json.dumps(list_data))
                return public.returnMsg(True, '添加成功')
            else:
                return public.returnMsg(False, '添加失败')
        else:
            try:
                result = json.loads(public.ReadFile(self.__wubao))
                if not get.path.strip() in result:
                    result.append(get.path.strip())
                    public.WriteFile(self.__wubao, json.dumps(result))
                list_data = json.loads(public.ReadFile(self.__webshell))
                if get.path in list_data:
                    list_data.remove(get.path)
                    public.writeFile(self.__webshell, json.dumps(list_data))
                    return public.returnMsg(True, '添加成功')
                else:
                    return public.returnMsg(False, '添加失败')
            except:
                public.WriteFile(self.__wubao, json.dumps([get.path.strip()]))
                list_data = json.loads(public.ReadFile(self.__webshell))
                if get.path in list_data:
                    list_data.remove(get.path)
                    public.writeFile(self.__webshell, json.dumps(list_data))
                    return public.returnMsg(True, '添加成功')
                else:
                    return public.returnMsg(False, '添加失败')

    def __get_md5(self, s):
        m = hashlib.md5()
        m.update(s.encode('utf-8'))
        return m.hexdigest()

    # 查看UA白名单 ua_white
    def get_ua_white(self, get):
        config = self.get_config(None)
        url_find_list = config['ua_white']
        return public.returnMsg(True, url_find_list)

    # 添加UA 白名单 ua_white
    def add_ua_white(self, get):
        url_find = get.ua_white
        config = self.get_config(None)
        url_find_list = config['ua_white']
        if url_find in url_find_list:
            return public.returnMsg(False, '已经存在')
        else:
            url_find_list.append(url_find)
            self.__write_config(config)
            return public.returnMsg(True, '添加成功')

    # 导入UA白名单
    def add_ua_list(self, get):
        if 'json' not in get:
            get.json = True
        else:
            get.json = False
        if get.json:
            pdata = json.loads(get.pdata)
        else:
            pdata = get.pdata.strip().split('\n')
        if not pdata: return public.returnMsg(False, '不能为空')
        for i in pdata:
            get.ua_white = i
            self.add_ua_white(get)
        return public.returnMsg(True, '导入成功')

    # 删除UA 白名单 ua_white
    def del_ua_white(self, get):
        url_find = get.ua_white
        config = self.get_config(None)
        url_find_list = config['ua_white']
        if url_find in url_find_list:
            url_find_list.remove(url_find)
            self.__write_config(config)
            return public.returnMsg(True, '删除成功')
        else:
            return public.returnMsg(False, '不存在')

    # 查看ua 黑名单ua_black
    def get_ua_black(self, get):
        config = self.get_config(None)
        url_find_list = config['ua_black']
        return public.returnMsg(True, url_find_list)

    # 导入UA黑名单
    def add_black_list(self, get):
        if 'json' not in get:
            get.json = True
        else:
            get.json = False
        if get.json:
            pdata = json.loads(get.pdata)
        else:
            pdata = get.pdata.strip().split('\n')
        if not pdata: return public.returnMsg(False, '不能为空')
        for i in pdata:
            get.ua_black = i
            self.add_ua_black(get)
        return public.returnMsg(True, '导入成功')

    # 添加UA 黑名单ua_black
    def add_ua_black(self, get):
        url_find = get.ua_black
        config = self.get_config(None)
        url_find_list = config['ua_black']
        if url_find in url_find_list:
            return public.returnMsg(False, '已经存在')
        else:
            url_find_list.append(url_find)
            self.__write_config(config)
            return public.returnMsg(True, '添加成功')

    # 删除UA 黑名单 ua_black
    def del_ua_black(self, get):
        url_find = get.ua_black
        config = self.get_config(None)
        url_find_list = config['ua_black']
        if url_find in url_find_list:
            url_find_list.remove(url_find)
            self.__write_config(config)
            return public.returnMsg(True, '删除成功')
        else:
            return public.returnMsg(False, '不存在')

    # 查看URL_FIND
    def get_url_find(self, get):
        config = self.get_config(None)
        url_find_list = config['uri_find']
        return public.returnMsg(True, url_find_list)

    # 导入URL拦截
    def add_url_list(self, get):
        if 'json' not in get:
            get.json = True
        else:
            get.json = False
        if get.json:
            pdata = json.loads(get.pdata)
        else:
            pdata = get.pdata.strip().split()
        if not pdata: return public.returnMsg(False, '不能为空')
        for i in pdata:
            get.url_find = i
            self.add_url_find(get)
        return public.returnMsg(True, '导入成功')

    # 添加URL FIND
    def add_url_find(self, get):
        url_find = get.url_find
        config = self.get_config(None)
        url_find_list = config['uri_find']
        if url_find in url_find_list:
            return public.returnMsg(False, '已经存在')
        else:
            url_find_list.append(url_find)
            self.__write_config(config)
            return public.returnMsg(True, '添加成功')

    # 添加URL FIND
    def del_url_find(self, get):
        url_find = get.url_find
        config = self.get_config(None)
        url_find_list = config['uri_find']
        if url_find in url_find_list:
            url_find_list.remove(url_find)
            self.__write_config(config)
            return public.returnMsg(True, '删除成功')
        else:
            return public.returnMsg(False, '不存在')

    def check_herader2(self, data, method_type):
        for i in data:
            if method_type == i[0]:
                return True
        return False

    # 删除请求类型
    def add_method_type(self, get):
        config = self.get_config(None)
        check = get.check.strip()
        if not check in ['0', '1']: return public.returnMsg(False, '类型错误')
        if int(check) == 0:
            check = False
        else:
            check = True
        url_find_list = config['method_type']
        if not self.check_herader2(url_find_list, get.method_type.strip()):
            return public.returnMsg(False, '不存在')
        else:
            for i in url_find_list:
                if get.method_type.strip() == i[0]:
                    i[1] = check
            self.__write_config(config)
            return public.returnMsg(True, '修改成功')

    # 删除请求类型
    def del_header_len(self, get):
        header_type = get.header_type.strip()
        header_len = get.header_type_len.strip()
        config = self.get_config(None)
        url_find_list = config['header_len']
        if not self.check_herader(url_find_list, header_type):
            return public.returnMsg(False, '不存在')
        else:
            url_find_list.remove([header_type, header_len])
            self.__write_config(config)
            return public.returnMsg(True, '删除成功')

    # 修改
    def edit_header_len(self, get):
        header_type = get.header_type.strip()
        header_len = get.header_type_len.strip()
        config = self.get_config(None)
        url_find_list = config['header_len']
        if self.check_herader(url_find_list, header_type):
            for i in url_find_list:
                if header_type == i[0]:
                    i[1] = header_len
            self.__write_config(config)
            return public.returnMsg(True, '修改成功')
        else:
            return public.returnMsg(False, '不存在')

    def check_herader(self, data, header):
        for i in data:
            if header == i[0]:
                return True
        return False

    # 添加
    def add_header_len(self, get):
        header_type = get.header_type.strip()
        header_len = get.header_type_len.strip()
        config = self.get_config(None)
        url_find_list = config['header_len']
        if self.check_herader(url_find_list, header_type):
            return public.returnMsg(False, '已经存在')
        else:
            url_find_list.append([header_type, header_len])
            self.__write_config(config)
            return public.returnMsg(True, '添加成功')

    # 查看URL_FIND
    def get_url_white_chekc(self, get):
        config = self.get_config(None)
        url_find_list = config['url_white_chekc']
        return public.returnMsg(True, url_find_list)

    # 添加URL FIND
    def add_url_white_chekc(self, get):
        url_find = get.url_find
        config = self.get_config(None)
        url_find_list = config['url_white_chekc']
        if url_find in url_find_list:
            return public.returnMsg(False, '已经存在')
        else:
            url_find_list.append(url_find)
            self.__write_config(config)
            return public.returnMsg(True, '添加成功')

    # 添加URL FIND
    def del_url_white_chekc(self, get):
        url_find = get.url_find
        config = self.get_config(None)
        url_find_list = config['url_white_chekc']
        if url_find in url_find_list:
            url_find_list.remove(url_find)
            self.__write_config(config)
            return public.returnMsg(True, '删除成功')
        else:
            return public.returnMsg(False, '不存在')

    def get_cc_status(self, get):
        config = self.get_config(None)
        if config['cc_automatic']:
            return public.returnMsg(True, '')
        else:
            return public.returnMsg(False, '')

    def stop_cc_status(self, get):
        # config = self.get_config(None)
        # config['cc_automatic'] = False
        # self.__write_config(config)
        # site_conf = self.get_site_config(None)
        # for i in site_conf:
        #     site_conf[i]['cc_automatic'] = False
        # self.__write_site_config(site_conf)
        # time.sleep(0.2)
        return public.returnMsg(True, '关闭成功')

    def start_cc_status(self, get):
        # config = self.get_config(None)
        # config['cc_automatic'] = True
        # site_conf=self.get_site_config(None)
        # for i in site_conf:
        #     site_conf[i]['cc_automatic'] = True
        # self.__write_site_config(site_conf)
        # self.__write_config(config)
        # time.sleep(0.2)
        return public.returnMsg(True, '开启成功')

    def isDigit(self, x):
        try:
            x = int(x)
            return isinstance(x, int)
        except ValueError:
            return False

    def set_cc_automatic(self, get):
        cc_time = get.cc_time
        cc_retry_cycle = get.cc_retry_cycle
        config = self.get_config(None)
        if not self.isDigit(cc_time) and not self.isDigit(cc_retry_cycle): return public.returnMsg(False,
                                                                                                   '需要设置数字!')
        config['cc_time'] = int(cc_time)
        config['cc_retry_cycle'] = int(cc_retry_cycle)
        site_conf = self.get_site_config(None)
        for i in site_conf:
            site_conf[i]['cc_time'] = int(cc_time)
            site_conf[i]['cc_retry_cycle'] = int(cc_retry_cycle)
        self.__write_site_config(site_conf)
        self.__write_config(config)
        return public.returnMsg(True, '设置成功!')

    # 设置全局uri 增强白名单
    def golbls_cc_zeng(self, get):
        if os.path.exists(self.__path + 'rule/cc_uri_white.json'):
            data = public.ReadFile(self.__path + 'rule/cc_uri_white.json')
            text = self.xssencode((get.text.strip()))
            # return text
            try:
                data = json.loads(data)
                if text in data:
                    return public.returnMsg(False, '已经存在!')
                else:
                    data.append(text)
                    public.WriteFile(self.__path + 'rule/cc_uri_white.json', json.dumps(data))
                    # public.WriteFile(self.__path + 'rule/cc_uri_white.lua', self.__to_lua_table.makeLuaTable(data))
                    return public.returnMsg(True, '设置成功!')
            except:
                ret = []
                ret.append(self.xssencode((get.text.strip())))
                public.WriteFile(self.__path + 'rule/cc_uri_white.json', json.dumps(ret))
                # public.WriteFile(self.__path + 'rule/cc_uri_white.lua', self.__to_lua_table.makeLuaTable(ret))
                return public.returnMsg(True, '设置成功!')
        else:
            ret = []
            ret.append(self.xssencode((get.text.strip())))
            public.WriteFile(self.__path + 'rule/cc_uri_white.json', json.dumps(ret))
            # public.WriteFile(self.__path + 'rule/cc_uri_white.lua', self.__to_lua_table.makeLuaTable(ret))
            return public.returnMsg(True, '设置成功!')

    # 查看
    def get_golbls_cc(self, get):
        if os.path.exists(self.__path + 'rule/cc_uri_white.json'):
            data2 = public.ReadFile(self.__path + 'rule/cc_uri_white.json')
            try:
                data = json.loads(data2)
                return public.returnMsg(True, data)
            except:
                ret = []
                public.WriteFile(self.__path + 'rule/cc_uri_white.json', json.dumps(ret))
                return public.returnMsg(True, '设置成功!')
        else:
            ret = []
            public.WriteFile(self.__path + 'rule/cc_uri_white.json', json.dumps(ret))
            return public.returnMsg(True, ret)

    def del_golbls_cc(self, get):
        if os.path.exists(self.__path + 'rule/cc_uri_white.json'):
            data = public.ReadFile(self.__path + 'rule/cc_uri_white.json')
            text = self.xssencode((get.text.strip()))
            try:
                data = json.loads(data)
                if text in data:
                    data.remove(text)
                    public.WriteFile(self.__path + 'rule/cc_uri_white.json', json.dumps(data))
                    return public.returnMsg(True, '删除成功!')
                else:
                    return public.returnMsg(False, '不存在!')
            except:
                ret = []
                public.WriteFile(self.__path + 'rule/cc_uri_white.json', json.dumps(ret))
                return public.returnMsg(True, '文件解析错误恢复出厂设置!')
        else:
            ret = []
            public.WriteFile(self.__path + 'rule/cc_uri_white.json', json.dumps(ret))
            return public.returnMsg(True, '文件不存在恢复出厂设置!')

    def site_golbls_cc(self, get):
        text = self.xssencode((get.text.strip()))
        data = self.get_site_config(get)
        for i in data:
            if get.siteName == i['siteName']:
                if 'cc_uri_white' not in i:
                    i['cc_uri_white'] = []
                    i['cc_uri_white'].append(text)

                else:
                    if text not in i['cc_uri_white']:
                        i['cc_uri_white'].append(text)
                        self.__write_site_config(data)
                        return public.returnMsg(True, '添加成功')
                    else:
                        return public.returnMsg(False, '已经存在!')
        return public.returnMsg(False, '未知错误!')

    def del_site_golbls_cc(self, get):
        text = self.xssencode((get.text.strip()))
        data = self.get_site_config(get)
        for i in data:
            if get.siteName == i['siteName']:
                if 'cc_uri_white' not in i:
                    i['cc_uri_white'] = []
                else:
                    if text not in i['cc_uri_white']:
                        return public.returnMsg(False, '不存在!')
                    else:
                        if text in i['cc_uri_white']:
                            i['cc_uri_white'].remove(text)
                            self.__write_site_config(data)
                            return public.returnMsg(True, '删除成功')
                        else:
                            return public.returnMsg(False, '不存在!')
        return public.returnMsg(False, '未知错误!')

    # 设置CC全局生效
    def set_cc_golbls(self, get):
        data = self.get_site_config(get)
        ret = []
        for i in data:
            ret.append(i['siteName'])
        if not ret: return False
        site_config = self.get_site_config(None)
        for i in ret:
            get.siteName = i
            site_config = self.set_cc_golbls_siteconfig(get, site_config)
        self.__write_site_config(site_config)
        public.WriteFile('/www/server/btwaf/site.json', json.dumps(site_config, ensure_ascii=False))
        return True

    def set_cc_golbls_siteconfig(self, get, site_config):
        if not 'cc_increase_type' in get: return site_config
        if not get.cc_increase_type in ['js', 'code', 'renji', 'huadong', 'browser']: return site_config
        if not 'cc_mode' in get: get.cc_mode = 1
        if not 'cc_time' in get: get.cc_time = False
        if not 'cc_retry_cycle' in get: get.cc_retry_cycle = False
        if not 'is_cc_url' in get: get.is_cc_url = False
        if not 'cc_ip_max' in get: return site_config
        if type(get.cc_ip_max) != dict: return site_config

        if 'open' not in get.cc_ip_max:
            return site_config
        if 'ip_max' not in get.cc_ip_max:
            return site_config
        if 'static' not in get.cc_ip_max:
            return site_config
        cc_ip_max = get.cc_ip_max

        if 'country' in get:
            try:
                countrysss = get.country.split(",")
                country = {}
                for i in countrysss:
                    i = i.strip()
                    if i:
                        country[i] = i
            except:
                country = {}
        else:
            country = {}
        if get.cc_mode and get.cc_retry_cycle:
            if not self.isDigit(get.cc_mode) and not self.isDigit(get.cc_retry_cycle): return site_config
            site_config[get.siteName]['cc_time'] = int(get.cc_time)
            site_config[get.siteName]['cc_mode'] = int(get.cc_mode)
            site_config[get.siteName]['cc']['cc_mode'] = int(get.cc_mode)
            site_config[get.siteName]['cc_retry_cycle'] = int(get.cc_retry_cycle)
            site_config[get.siteName]['cc_automatic'] = True
            site_config[get.siteName]['cc']['countrys'] = country
            site_config[get.siteName]['cc']['is_cc_url'] = (get.is_cc_url == '1') | False
        else:
            site_config[get.siteName]['cc']['is_cc_url'] = (get.is_cc_url == '1') | False
            site_config[get.siteName]['cc']['countrys'] = country
            site_config[get.siteName]['cc_automatic'] = False
            site_config[get.siteName]['cc_mode'] = int(get.cc_mode)
            site_config[get.siteName]['cc']['cc_mode'] = int(get.cc_mode)
            site_config[get.siteName]['cc']['cycle'] = int(get.cycle)
            site_config[get.siteName]['cc']['limit'] = int(get.limit)
            site_config[get.siteName]['cc']['endtime'] = int(get.endtime)
            site_config[get.siteName]['cc']['cc_increase_type'] = get.cc_increase_type
            site_config[get.siteName]['cc']['increase'] = (get.increase == '1') | False
            site_config[get.siteName]['increase_wu_heng'] = (get.increase_wu_heng == '1') | False
        site_config[get.siteName]['cc_type_status'] = int(get.cc_type_status)

        site_config[get.siteName]['cc']['cc_ip_max'] = cc_ip_max

        return site_config

    # 设置CC 增强全局生效
    def set_cc_retry_golbls(self, get):
        data = self.get_site_config(get)
        ret = []
        for i in data:
            ret.append(i['siteName'])
        if not ret: return False
        for i in ret:
            get.siteName = i
            self.set_site_retry(get)
        return True

    # 四层计划任务
    def site_time_uptate(self):
        id = public.M('crontab').where('name=?', (u'Nginx防火墙四层拦截IP',)).getField('id')
        import crontab
        if id: crontab.crontab().DelCrontab({'id': id})
        data = {}
        data['name'] = 'Nginx防火墙四层拦截IP'
        data['type'] = 'hour-n'
        data['where1'] = '1'
        data['sBody'] = 'python /www/server/panel/plugin/btwaf/firewalls_list.py start'
        data['backupTo'] = 'localhost'
        data['sType'] = 'toShell'
        data['hour'] = ''
        data['minute'] = '0'
        data['week'] = ''
        data['sName'] = ''
        data['urladdress'] = ''
        data['save'] = ''
        crontab.crontab().AddCrontab(data)
        return True

    # 设置四层屏蔽模式
    def set_stop_ip(self, get):
        self.site_time_uptate()
        return public.returnMsg(True, '设置成功!')

    # 关闭
    def set_stop_ip_stop(self, get):
        id = public.M('crontab').where('name=?', (u'Nginx防火墙四层拦截IP',)).getField('id')
        import crontab
        if id: crontab.crontab().DelCrontab({'id': id})
        return public.returnMsg(True, '关闭成功!')

    def get_stop_ip(self, get):
        id = public.M('crontab').where('name=?', (u'Nginx防火墙四层拦截IP',)).getField('id')
        if id:
            return public.returnMsg(True, '11')
        else:
            return public.returnMsg(False, '111')

    def get_site_config2(self):
        site_config = public.readFile(self.__path + 'site.json')
        try:
            data = json.loads(site_config)
        except:
            return False
        return data

    def add_body_site_rule(self, get):
        if not get.text.strip(): return public.returnMsg(False, '需要替换的数据不能为空')
        config = self.get_site_config2()
        if not config: public.returnMsg(False, '未知错误')
        config2 = config[get.siteName]
        if not 'body_character_string' in config2:
            config2['body_character_string'] = []
        if not get.text2.strip():
            ret = {get.text: ''}
        else:
            ret = {get.text: get.text2}
        body = config2['body_character_string']
        if len(body) == 0:
            config2['body_character_string'].append(ret)
            self.__write_site_config(config)
            return public.returnMsg(True, '添加成功重启Nginx生效')
        else:
            if body in config2['body_character_string']:
                return public.returnMsg(False, '已经存在')
            else:
                config2['body_character_string'].append(ret)
                self.__write_site_config(config)
                return public.returnMsg(True, '添加成功重启Nginx生效')

    def add_body_body_intercept(self, get):
        if not get.text.strip(): return public.returnMsg(False, '需要拦截数据不能为空')
        config = self.get_site_config2()
        if not config: public.returnMsg(False, '未知错误')
        config2 = config[get.siteName]
        if not 'body_intercept' in config2:
            config2['body_intercept'] = []
        if get.text.strip() in config2['body_intercept']:
            return public.returnMsg(False, '已经存在')
        else:
            config2['body_intercept'].append(get.text.strip())
            self.__write_site_config(config)
            return public.returnMsg(True, '添加成功')

    def del_body_body_intercept(self, get):
        if not get.text.strip(): return public.returnMsg(False, '需要拦截数据不能为空')
        config = self.get_site_config2()
        if not config: public.returnMsg(False, '未知错误')
        config2 = config[get.siteName]
        if not 'body_intercept' in config2:
            config2['body_intercept'] = []
        if get.text.strip() in config2['body_intercept']:
            config2['body_intercept'].pop(get.text.strip())
            self.__write_site_config(config)
            return public.returnMsg(True, '删除成功')
        else:
            return public.returnMsg(False, '不存在')

    def del_body_site_rule(self, get):
        body = json.loads(get.body)
        config = self.get_site_config2()
        if not config: public.returnMsg(False, '未知错误')
        config2 = config[get.siteName]
        if not 'body_character_string' in config2:
            config2['body_character_string'] = []
            self.__write_site_config(config)
            return public.returnMsg(False, '替换文件为空,请添加数据')
        else:
            data = config2['body_character_string']

            if body in data:
                ret = data.index(body)
                data.pop(ret)
                self.__write_site_config(config)
                return public.returnMsg(True, '删除成功,重启nginx生效')
            else:
                return public.returnMsg(False, '删除失败/不存在')

    #  xss 防御
    def xssencode(self, text):
        import html
        list = ['`', '~', '&', '#', '*', '$', '@', '<', '>', '\"', '\'', ';', '%', ',', '\\u']
        ret = []
        for i in text:
            if i in list:
                i = ''
            ret.append(i)
        str_convert = ''.join(ret)
        text2 = html.escape(str_convert, quote=True)
        return text2

    def del_body_rule(self, get):

        body = json.loads(get.body)

        config = self.get_config(get)
        if not 'body_character_string' in config:
            config['body_character_string'] = []
            self.__write_config(config)
            return public.returnMsg(False, '替换文件为空,请添加数据')
        else:
            data = config['body_character_string']
            if body in data:
                ret = data.index(body)
                data.pop(ret)
                self.__write_config(config)
                return public.returnMsg(True, '删除成功,重启nginx生效')
            else:
                return public.returnMsg(False, '删除失败/不存在')

    def add_body_rule(self, get):
        if not get.text.strip(): return public.returnMsg(False, '需要替换的数据不能为空')
        config = self.get_config(get)

        if not 'uri_find' in config:
            config['uri_find'] = []

        if not 'body_character_string' in config:
            config['body_character_string'] = []
        if not get.text2.strip():
            ret = {self.xssencode(get.text): ''}
        else:
            ret = {self.xssencode(get.text): self.xssencode(get.text2)}
        body = config['body_character_string']
        if len(body) == 0:
            config['body_character_string'].append(ret)
            self.__write_config(config)
            return public.returnMsg(True, '添加成功重启Nginx生效')
        else:
            if body in config['body_character_string']:
                return public.returnMsg(False, '已经存在')
            else:
                config['body_character_string'].append(ret)
                self.__write_config(config)
                return public.returnMsg(True, '添加成功重启Nginx生效')

    # 导入违禁词
    def import_body_intercept(self, get):
        if not get.text.strip(): return public.returnMsg(False, '需要拦截数据不能为空')
        data = get.text.strip().split()
        if len(data) == 0: return public.returnMsg(False, '需要拦截数据不能为空')
        config = self.get_config(get)
        if not 'body_intercept' in config:
            config['body_intercept'] = []
        if len(config['body_intercept']) == 0:
            config['body_intercept'] = data
            self.__write_config(config)
            return public.returnMsg(True, '导入成功')
        else:
            config['body_intercept'] = list(set(data) | set(config['body_intercept']))
            self.__write_config(config)
            return public.returnMsg(True, '导入成功')

    # 导出违禁词
    def export_body_intercept(self, get):
        config = self.get_config(get)
        if not 'body_intercept' in config:
            config['body_intercept'] = []
            return ''
        else:
            return '\n'.join(config['body_intercept'])

    # 清空
    def empty_body_intercept(self, get):
        config = self.get_config(get)
        config['body_intercept'] = []
        self.__write_config(config)
        return public.returnMsg(True, '清空成功')

    def add_body_intercept(self, get):
        if not get.text.strip(): return public.returnMsg(False, '你需要的拦截内容不能为空')
        config = self.get_config(get)
        if not 'body_intercept' in config:
            config['body_intercept'] = []
        if not 'body_intercept' in config:
            config['body_intercept'] = []
        if get.text.strip() in config['body_intercept']:
            return public.returnMsg(False, '拦截的内容已经存在')
        else:
            config['body_intercept'].append(get.text.strip())
            self.__write_config(config)
            return public.returnMsg(True, '添加成功')

    def del_body_intercept(self, get):
        if not get.text.strip(): return public.returnMsg(False, '你需要的拦截内容不能为空')
        config = self.get_config(get)
        if not 'body_intercept' in config:
            config['body_intercept'] = []
        if not 'body_intercept' in config:
            config['body_intercept'] = []
        if get.text.strip() in config['body_intercept']:
            config['body_intercept'].remove(get.text.strip())
            self.__write_config(config)
            return public.returnMsg(True, '删除成功')
        else:
            return public.returnMsg(False, '拦截的内容不存在')

    def ipv6_check(self, addr):
        ip6_regex = (
            r'(^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$)|'
            r'(\A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,6}\Z)|'
            r'(\A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}\Z)|'
            r'(\A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}\Z)|'
            r'(\A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}\Z)|'
            r'(\A([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}\Z)|'
            r'(\A([0-9a-f]{1,4}:){1,6}(:[0-9a-f]{1,4}){1,1}\Z)|'
            r'(\A(([0-9a-f]{1,4}:){1,7}|:):\Z)|(\A:(:[0-9a-f]{1,4}){1,7}\Z)|'
            r'(\A((([0-9a-f]{1,4}:){6})(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})\Z)|'
            r'(\A(([0-9a-f]{1,4}:){5}[0-9a-f]{1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})\Z)|'
            r'(\A([0-9a-f]{1,4}:){5}:[0-9a-f]{1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|'
            r'(\A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|'
            r'(\A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,3}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|'
            r'(\A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,2}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|'
            r'(\A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,1}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|'
            r'(\A(([0-9a-f]{1,4}:){1,5}|:):(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|'
            r'(\A:(:[0-9a-f]{1,4}){1,5}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)')
        return bool(re.match(ip6_regex, addr, flags=re.IGNORECASE))

    # IPV6 黑名单
    def set_ipv6_back(self, get):
        addr = str(get.addr).split()
        addr = addr[0]
        ret = self.get_ipv6(get)
        if ret['status']:
            return public.returnMsg(False, '请开启IPV6访问!')
        else:
            if self.ipv6_check(addr):
                if not os.path.exists(self.__path + 'ipv6_back.json'):
                    list = []
                    list.append(addr)
                    public.WriteFile(self.__path + 'ipv6_back.json', json.dumps(list))
                    self.add_ipv6(addr)
                    return public.returnMsg(True, '添加成功!')
                else:
                    list_addr = public.ReadFile(self.__path + 'ipv6_back.json')
                    if list_addr:
                        list_addr = json.loads(list_addr)
                        if str(addr) in list_addr:
                            return public.returnMsg(False, '已经存在!')
                        else:
                            list_addr.append(addr)
                            self.add_ipv6(addr)
                            public.WriteFile(self.__path + 'ipv6_back.json', json.dumps(list_addr))
                            return public.returnMsg(True, '添加成功!')
                    else:
                        list = []
                        list.append(addr)
                        public.WriteFile(self.__path + 'ipv6_back.json', json.dumps(list))
                        self.add_ipv6(addr)
                        return public.returnMsg(True, '添加成功!')
            else:
                return public.returnMsg(False, '请输入正确的IPV6地址')

    def del_ipv6_back(self, get):
        addr = str(get.addr).split()
        addr = addr[0]
        list_addr = public.ReadFile(self.__path + 'ipv6_back.json')
        if list_addr:
            list_addr = json.loads(list_addr)
            if addr in list_addr:
                self.del_ipv6(addr)
                list_addr.remove(addr)
                public.WriteFile(self.__path + 'ipv6_back.json', json.dumps(list_addr))
                return public.returnMsg(True, '删除成功!')
            else:
                return public.returnMsg(False, '地址不存在!')
        else:
            list = []
            public.WriteFile(self.__path + 'ipv6_back.json', json.dumps(list))
            return public.returnMsg(True, '列表为空!')

    def add_ipv6(self, addr):
        if self.__isFirewalld:
            public.ExecShell(
                '''firewall-cmd --permanent --add-rich-rule="rule family="ipv6" source address="%s"  port protocol="tcp" port="80"  reject" ''' % addr)
            self.FirewallReload()
        if self.__isUfw:
            return public.returnMsg(False, '不支持乌班图哦!')
        else:
            return public.returnMsg(False, '暂时只支持Centos7')

    def del_ipv6(self, addr):
        if self.__isFirewalld:
            public.ExecShell(
                '''firewall-cmd --permanent --remove-rich-rule="rule family="ipv6" source address="%s"  port protocol="tcp" port="80"  reject" ''' % addr)
            self.FirewallReload()
        if self.__isUfw:
            return public.returnMsg(False, '不支持乌班图哦!')
        else:
            return public.returnMsg(False, '暂时只支持Centos7')

    def get_ipv6_address(self, get):
        if os.path.exists(self.__path + 'ipv6_back.json'):
            list_addr = public.ReadFile(self.__path + 'ipv6_back.json')
            list_addr = json.loads(list_addr)
            return public.returnMsg(True, list_addr)
        else:
            return public.returnMsg(False, [])

    # 重载防火墙配置
    def FirewallReload(self):
        if self.__isUfw:
            public.ExecShell('/usr/sbin/ufw reload')
            return;
        if self.__isFirewalld:
            public.ExecShell('firewall-cmd --reload')
        else:
            public.ExecShell('/etc/init.d/ip6tables save')
            public.ExecShell('service ip6tables restart')

    # 关闭IPV6地址访问
    def stop_ipv6(self, get):
        if self.__isFirewalld:
            public.ExecShell(
                '''firewall-cmd --permanent --add-rich-rule="rule family="ipv6"  port protocol="tcp" port="443" reject"''')
            public.ExecShell(
                '''firewall-cmd --permanent --add-rich-rule="rule family="ipv6"  port protocol="tcp" port="80" reject" ''')
            self.FirewallReload()
            return public.returnMsg(True, '设置成功!')
        if self.__isUfw:
            return public.returnMsg(False, '不支持乌班图开启和关闭!')
        else:
            public.ExecShell('ip6tables -F && ip6tables -X && ip6tables -Z')
            public.ExecShell('''ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport 80 -j DROP''')
            public.ExecShell('''ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport 443 -j DROP''')
            return public.returnMsg(True, '设置成功!')

    def start_ipv6(self, get):
        if self.__isFirewalld:
            public.ExecShell(
                '''firewall-cmd --permanent --remove-rich-rule="rule family="ipv6"  port protocol="tcp" port="443" reject"''')
            public.ExecShell(
                '''firewall-cmd --permanent --remove-rich-rule="rule family="ipv6"  port protocol="tcp" port="80" reject" ''')
            self.FirewallReload()
            return public.returnMsg(True, '设置成功!')
        if self.__isUfw:
            return public.returnMsg(False, '不支持乌班图开启和关闭!')
        else:
            public.ExecShell(''' ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport 80 -j DROP ''')
            public.ExecShell(''' ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport 443 -j DROP''')
            return public.returnMsg(True, '设置成功!')

    def get_ipv6(self, get):
        if self.__isFirewalld:
            import re
            ret = '''family="ipv6" port port="443" protocol="tcp" reject'''
            ret2 = '''family="ipv6" port port="80" protocol="tcp" reject'''
            lit = public.ExecShell('firewall-cmd --list-all')
            if re.search(ret, lit[0]) and re.search(ret2, lit[0]):
                return public.returnMsg(True, '')
            else:
                return public.returnMsg(False, '!')
        if self.__isUfw:
            return public.returnMsg(False, '')
        else:
            import re
            list = public.ReadFile('/etc/sysconfig/ip6tables')
            ret = 'INPUT -p tcp -m state --state NEW -m tcp --dport 80 -j DROP'
            ret2 = 'INPUT -p tcp -m state --state NEW -m tcp --dport 443 -j DROP'
            if re.search(ret, list) and re.search(ret2, list):
                return public.returnMsg(True, '')
            else:
                return public.returnMsg(False, '')

    # 获取蜘蛛池类型
    def get_zhizu_list(self):
        if os.path.exists(self.__path + 'zhi.json'):
            try:
                ret = json.loads(public.ReadFile(self.__path + 'zhi.json'))
                return ret
            except:
                os.remove(self.__path + 'zhi.json')
                return False
        else:
            rcnlist = public.httpGet('http://www.bt.cn/api/panel/get_spider_type')
            if not rcnlist: return False
            public.WriteFile(self.__path + 'zhi.json', rcnlist)
            try:
                rcnlist = json.loads(rcnlist)
                return rcnlist
            except:
                os.remove(self.__path + 'zhi.json')
                return False

    # 获取蜘蛛池地址
    def get_zhizu_ip_list(self):
        # from BTPanel import session
        # type = self.get_zhizu_list()
        # if not type: return False
        # if 'types' in type:
        #     if len(type['types']) >= 1:
        #         for i in type['types']:
        #             ret = public.httpGet('http://www.bt.cn/api/panel/get_spider?spider=%s' % str(i['id']))
        #             if not ret:
        #                 if not os.path.exists(self.__path + str(i['id']) + '.json'):
        #                     ret = []
        #                     public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
        #                 continue
        #             if os.path.exists(self.__path + str(i['id']) + '.json'):
        #                 local = public.ReadFile(self.__path + str(i['id']) + '.json')
        #                 if local:
        #                     try:
        #                         ret = json.loads(ret)
        #                         local = json.loads(local)
        #                         localhost_json = list(set(json.loads(local)).union(ret))
        #                         public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(localhost_json))
        #                         yum_list_json = list(set(local).difference(set(ret)))
        #                         public.httpGet(
        #                             'https://www.bt.cn/api/panel/add_spiders?address=%s' % json.dumps(yum_list_json))
        #                     except:
        #                         pass
        #                 else:
        #                     try:
        #                         ret = json.loads(ret)
        #                         public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
        #                     except:
        #                         ret = []
        #                         public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
        #             else:
        #                 try:
        #                     ret = json.loads(ret)
        #                     public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
        #                 except:
        #                     ret = []
        #                     public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
        # public.ExecShell('chown www:www /www/server/btwaf/*.json')
        # if not 'zhizu' in session: session['zhizu'] = 1
        return public.returnMsg(True, '更新蜘蛛成功!')

    # 获取蜘蛛池地址
    def get_zhizu_list22(self, get):
        # type = self.get_zhizu_list()
        # if not type: return public.returnMsg(False, '云端连接错误!')
        # if 'types' in type:
        #     if len(type['types']) >= 1:
        #         for i in type['types']:
        #             ret = public.httpGet('http://www.bt.cn/api/panel/get_spider?spider=%s' % str(i['id']))
        #             if not ret:
        #                 if not os.path.exists(self.__path + str(i['id']) + '.json'):
        #                     ret = []
        #                     public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
        #                 continue
        #
        #             if os.path.exists(self.__path + str(i['id']) + '.json'):
        #                 local = public.ReadFile(self.__path + str(i['id']) + '.json')
        #                 if local:
        #                     try:
        #                         ret = json.loads(ret)
        #                         local = json.loads(local)
        #                         localhost_json = list(set(json.loads(local)).union(ret))
        #                         public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(localhost_json))
        #                         yum_list_json = list(set(local).difference(set(ret)))
        #                         public.httpGet(
        #                             'https://www.bt.cn/api/panel/add_spiders?address=%s' % json.dumps(yum_list_json))
        #                     except:
        #                         pass
        #                 else:
        #                     try:
        #                         ret = json.loads(ret)
        #                         public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
        #                     except:
        #                         ret = []
        #                         public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
        #             else:
        #                 try:
        #                     ret = json.loads(ret)
        #                     public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
        #                 except:
        #                     ret = []
        #                     public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
        # public.ExecShell('chown www:www /www/server/btwaf/*.json')
        return public.returnMsg(True, '更新蜘蛛成功!')

    # 获取蜘蛛池地址
    def get_zhizu_list2233(self, get):
        # self.test_check_zhilist(None)
        return public.returnMsg(True, '更新蜘蛛成功!')

    # 获取蜘蛛池地址
    def start_zhuzu(self):
        type = self.get_zhizu_list()
        if not type: return public.returnMsg(False, '云端连接错误!')
        if 'types' in type:
            if len(type['types']) >= 1:
                for i in type['types']:
                    ret = public.httpGet('http://www.bt.cn/api/panel/get_spider?spider=%s' % str(i['id']))
                    if not ret:
                        if not os.path.exists(self.__path + str(i['id']) + '.json'):
                            ret = []
                            public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
                        continue

                    if os.path.exists(self.__path + str(i['id']) + '.json'):
                        local = public.ReadFile(self.__path + str(i['id']) + '.json')
                        if local:
                            try:
                                ret = json.loads(ret)
                                local = json.loads(local)
                                localhost_json = list(set(json.loads(local)).union(ret))
                                public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(localhost_json))
                                yum_list_json = list(set(local).difference(set(ret)))
                                public.httpGet(
                                    'https://www.bt.cn/api/panel/add_spiders?address=%s' % json.dumps(yum_list_json))
                            except:
                                pass
                        else:
                            try:
                                ret = json.loads(ret)
                                public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
                            except:
                                ret = []
                                public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
                    else:
                        try:
                            ret = json.loads(ret)
                            public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
                        except:
                            ret = []
                            public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
        public.ExecShell('chown www:www /www/server/btwaf/*.json')
        return public.returnMsg(True, '更新蜘蛛成功!')

    # 外部蜘蛛池更新
    def get_zhizu_ip(self, get):
        type = self.get_zhizu_list()
        if not type: return False
        if 'types' in type:
            if len(type['types']) >= 1:
                for i in type['types']:
                    ret = public.httpGet('http://www.bt.cn/api/panel/get_spider?spider=%s' % str(i['id']))
                    if not ret: continue
                    try:
                        ret2 = json.dumps(ret)
                    except:
                        if not os.path.exists(self.__path + str(i['id']) + '.json'):
                            rec = []
                            public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(rec))
                        continue
                    if os.path.exists(self.__path + str(i['id']) + '.json'):
                        local = public.ReadFile(self.__path + str(i['id']) + '.json')
                        if local:
                            localhost_json = list(set(json.loads(local)).union(json.loads(ret)))
                            public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(localhost_json))
                            yum_list_json = list(set(local).difference(set(ret)))
                            public.httpGet(
                                'https://www.bt.cn/api/panel/add_spiders?address=%s' % json.dumps(yum_list_json))
                        else:
                            public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))
                    else:
                        public.WriteFile(self.__path + str(i['id']) + '.json', json.dumps(ret))

        return public.returnMsg(True, '更新蜘蛛成功!')

    def get_process_list(self):
        import psutil
        count = 0
        cpunum = int(public.ExecShell('cat /proc/cpuinfo |grep "processor"|wc -l')[0])
        Pids = psutil.pids();
        for pid in Pids:
            tmp = {}
            try:
                p = psutil.Process(pid);
            except:
                continue
            if str(p.name()) == 'php-fpm':
                count += int(p.cpu_percent(0.1))
        public.ExecShell("echo '%s' >/dev/shm/nginx.txt" % count / cpunum)
        return count / cpunum

    # 开启智能防御CC
    def Start_apache_cc(self, get):
        ret = self.auto_sync_apache()
        return ret

    # 查看状态
    def Get_apap_cc(self, get):
        id = public.M('crontab').where('name=?', (u'Nginx防火墙智能防御CC',)).getField('id');
        if id:
            return public.returnMsg(True, '开启!');
        else:
            return public.returnMsg(False, '关闭!');

    # 关闭智能防御CC
    def Stop_apache_cc(self, get):
        if os.path.exists('/dev/shm/nginx.txt'):
            os.remove('/dev/shm/nginx.txt')
        id = public.M('crontab').where('name=?', (u'Nginx防火墙智能防御CC',)).getField('id');
        import crontab
        if id: crontab.crontab().DelCrontab({'id': id})
        return public.returnMsg(True, '设置成功!');

    # 设置自动同步
    def auto_sync_apache(self):
        id = public.M('crontab').where('name=?', (u'Nginx防火墙智能防御CC',)).getField('id');
        import crontab
        if id: crontab.crontab().DelCrontab({'id': id})
        data = {}
        data['name'] = u'Nginx防火墙智能防御CC'
        data['type'] = 'minute-n'
        data['where1'] = '1'
        data['sBody'] = 'python /www/server/panel/plugin/btwaf/btwaf_main.py start'
        data['backupTo'] = 'localhost'
        data['sType'] = 'toShell'
        data['hour'] = ''
        data['minute'] = ''
        data['week'] = ''
        data['sName'] = ''
        data['urladdress'] = ''
        data['save'] = ''
        crontab.crontab().AddCrontab(data)
        return public.returnMsg(True, '设置成功!');

    # 查看apache 使用CPU的情况
    def retuen_nginx(self):
        import psutil
        count = 0
        cpunum = int(public.ExecShell('cat /proc/cpuinfo |grep "processor"|wc -l')[0])
        Pids = psutil.pids();
        for pid in Pids:
            tmp = {}
            try:
                p = psutil.Process(pid);
            except:
                continue
            if str(p.name()) == 'php-fpm':
                count += int(p.cpu_percent(0.1))

        public.ExecShell("echo '%s' >/dev/shm/nginx.txt" % str(count / cpunum))
        return count / cpunum

    def set_scan_conf(self, get):
        '''
        三个参数  通过404 的访问次数来拦截扫描器。最低不能低于60秒120次。
        open
        limit
        cycle
        '''
        config = self.get_config(None)
        if not 'limit' in get:
            if 'limit' in config['scan_conf']:
                get.limit = config['scan_conf']['limit']
            else:
                get.limit = 120
        if not 'cycle' in get:
            if 'cycle' in config['scan_conf']:
                get.cycle = config['scan_conf']['cycle']
            else:
                get.cycle = 60
        if not 'open' in get:
            if 'open' in config['scan_conf']:
                if config['scan_conf']['open']:
                    get.open = 0
                else:
                    get.open = 1
            else:
                get.open = 1
        if int(get.limit) < 20:
            return public.returnMsg(False, '次数不能小于20次')
        if int(get.cycle) < 20:
            return public.returnMsg(False, '周期不能小于20秒')
        if get.open == 1 or get.open == '1':
            open = True
        else:
            open = False
        # config = self.get_config(None)
        config['scan_conf'] = {"open": open, "limit": int(get.limit), "cycle": int(get.cycle)}
        self.__write_config(config)
        return public.returnMsg(True, '设置成功')

    def http_config(self, get):
        '''
            config['http_config'] = {"body_size":800000,"base64":True,"get_count":1000,"post_count":1000}
        '''
        if 'body_size' in get:
            body_size = int(get.body_size)
        else:
            body_size = 800000
        if 'base64' in get:
            if get.base64 == 1 or get.base64 == '1' or get.base64 == 'true':
                base64 = True
            else:
                base64 = False
        else:
            base64 = True
        if 'get_count' in get:
            get_count = int(get.get_count)
        else:
            get_count = 1000

        if 'post_count' in get:
            post_count = int(get.post_count)
        else:
            post_count = 1000
        config = self.get_config(None)
        http_config = config['http_config']
        tmp_http_config = {"body_size": body_size, "base64": base64, "get_count": get_count, "post_count": post_count}
        if http_config != tmp_http_config:
            config['http_config'] = tmp_http_config
            self.__write_config(config)
        return public.returnMsg(True, '设置成功')

    def get_config(self, get):
        try:
            config = json.loads(public.readFile(self.__path + 'config.json'))
        except:
            config = {
                "scan": {
                    "status": 444,
                    "ps": "过滤常见扫描测试工具的渗透测试",
                    "open": True,
                    "reqfile": ""
                },
                "cc": {
                    "status": 444,
                    "ps": "过虑CC攻击",
                    "increase": False,
                    "limit": 120,
                    "endtime": 300,
                    "open": True,
                    "reqfile": "",
                    "cycle": 60,
                    "cc_ip_max": {"open": False, "static": False, "ip_max": 10000}
                },
                "logs_path": "/www/wwwlogs/btwaf",
                "open": True,
                "reqfile_path": "/www/server/btwaf/html",
                "retry": 10,
                "log": True,
                "cc_automatic": False,
                "user-agent": {
                    "status": 403,
                    "ps": "通常用于过滤浏览器、蜘蛛及一些自动扫描器",
                    "open": True,
                    "reqfile": "user_agent.html"
                },
                "other": {
                    "status": 403,
                    "ps": "其它非通用过滤",
                    "reqfile": "other.html"
                },
                "uri_find": [],
                "cc_retry_cycle": "600",
                "cc_time": "60",
                "ua_black": [],
                "drop_abroad": {
                    "status": 444,
                    "ps": "禁止中国大陆以外的地区访问站点",
                    "open": True,
                    "reqfile": ""
                },
                "drop_china": {
                    "status": 444,
                    "ps": "禁止大陆地区访问",
                    "open": False,
                    "reqfile": ""
                },
                "retry_cycle": 120,
                "get": {
                    "status": 403,
                    "ps": "过滤uri、uri参数中常见sql注入、xss等攻击",
                    "open": True,
                    "reqfile": "get.html"
                },
                "body_character_string": [],
                "body_intercept": [],
                "start_time": 0,
                "cookie": {
                    "status": 403,
                    "ps": "过滤利用Cookie发起的渗透攻击",
                    "open": True,
                    "reqfile": "cookie.html"
                },
                "retry_time": 1800,
                "post": {
                    "status": 403,
                    "ps": "过滤POST参数中常见sql注入、xss等攻击",
                    "open": True,
                    "reqfile": "post.html"
                },
                "ua_white": [],
                "body_regular": [],
                "log_save": 30,
                "sql_injection": {"status": 403, "reqfile": "get.html", "open": True, "post_sql": True, "get_sql": True,
                                  "mode": "high"},
                "xss_injection": {"status": 403, "reqfile": "get.html", "open": True, "post_xss": True, "get_xss": True,
                                  "mode": "high"},
                "file_upload": {"status": 444, "reqfile": "get.html", "open": True, "mode": "high", "from-data": True},

            }
        config['drop_abroad_count'] = 0

        inf = public.cache_get("get_drop_abroad_count")
        if inf:
            config['drop_abroad_count'] = inf
        count = 0
        try:
            site_config = json.loads(public.readFile(self.__path + 'site.json'))
        except:
            site_config = []
            pass

        for i in site_config:
            if site_config[i]['drop_abroad']:
                count += 1
        public.cache_set("get_drop_abroad_count", count, 360)
        config['drop_abroad_count'] = count
        if not 'cms_rule_open' in config:
            config['cms_rule_open'] = False
        if not 'access_token' in config:
            config['access_token'] = public.GetRandomString(32)

        if not 'static_cc' in config:
            config['static_cc'] = False

        if 'cc_ip_max' not in config['cc']:
            config['cc']['cc_ip_max'] = {}
            config['cc']['cc_ip_max']['open'] = False
            config['cc']['cc_ip_max']['static'] = False
            config['cc']['cc_ip_max']['ip_max'] = 20000
            # 一天内最低为2000次 未开启静态的情况下
            # 开启静态的最低为4000次

        is_flag = False
        if not 'rce_injection' in config:
            config['rce_injection'] = {"status": 403, "reqfile": "get.html", "open": True, "post_xss": True,
                                       "get_xss": True, "mode": "high"}

        if 'msg_send' not in config:
            config['msg_send'] = {
                "open": False,
                "attack": True,
                "timeout": 120,
                "cc": True,
                "send_type": "",
                "reserve": ""
            }
            is_flag = True

        if 'msg_send' in config:
            if 'malicious_ip' not in config['msg_send']:
                config['msg_send']['malicious_ip'] = False
                config['msg_send']['customize'] = False
                config['msg_send']['uablack'] = False
                config['msg_send']['upload'] = True
                is_flag = True
            if 'abroad' not in config['msg_send']:
                config['msg_send']['abroad'] = False
                is_flag = True

        if not 'btmalibrary_install' in config:
            config['btmalibrary_install'] = False
            is_flag = True

        if not 'btmalibrary' in config:
            config['btmalibrary'] = False
            is_flag = True

        if os.path.exists("/www/server/panel/plugin/btmalibrary/btmalibrary_main.py"):
            config['btmalibrary_install'] = True
        else:
            config['btmalibrary_install'] = False
            config['btmalibrary'] = False

        # 拦截共享IP库
        if not 'malicious_ip' in config:
            config['malicious_ip'] = False
        # 禁止海外拉黑到系统防火墙中
        if not 'system_black' in config:
            config['system_black'] = False
        # 共享IP计划
        if not 'share_ip' in config:
            config['share_ip'] = True

        if not 'password' in config:
            config['password'] = True
            is_flag = True
        if not 'sensitive_info' in config:
            config['sensitive_info'] = True
            is_flag = True
        if not 'sql_injection' in config:
            config['sql_injection'] = {"status": 403, "reqfile": "get.html", "open": True, "post_sql": True,
                                       "get_sql": True, "mode": "high"}
            is_flag = True
        if not 'xss_injection' in config:
            config['xss_injection'] = {"status": 403, "reqfile": "get.html", "open": True, "post_xss": True,
                                       "get_xss": True, "mode": "high"}
            is_flag = True
        if not 'file_upload' in config:
            config['file_upload'] = {"status": 444, "reqfile": "get.html", "open": True, "mode": "high",
                                     "from-data": True}
            is_flag = True
        if not 'other_rule' in config:
            config['other_rule'] = {"status": 444, "reqfile": "get.html", "open": True, "mode": "high"}
            is_flag = True
        if not 'nday' in config:
            config['nday'] = True
            is_flag = True
        if not 'is_cc_url' in config['cc']:
            config['cc']['is_cc_url'] = True
        # if not 'php_execution' in config:
        #     config['php_execution'] = {"status": 403, "reqfile": "get.html", "open": True, "mode": "high","get":True,"post":True}
        #     is_flag = True
        else:
            if 'from-data' not in config['file_upload']:
                config['file_upload'] = {"open": True, "mode": "high", "from-data": True}
                is_flag = True
        if not 'scan_conf' in config:
            config['scan_conf'] = {"open": True, "limit": 240, "cycle": 60}
        if not 'cc_type_status' in config:
            config['cc_type_status'] = 2
            is_flag = True
        if not 'body_intercept' in config:
            config['body_intercept'] = []
            is_flag = True
        if not 'cc_mode' in config:
            config['cc_mode'] = 1
            is_flag = True
        if not 'retry_cycle' in config:
            config['retry_cycle'] = 60
            is_flag = True
            self.__write_config(config)

        if config['cc'] and not 'countrys' in config['cc']:
            config['cc']['countrys'] = {}
            is_flag = True

        if not 'cc_uri_frequency' in config:
            # {"/index.php":{"frequency":10,"cycle":60}}
            config['cc_uri_frequency'] = {}

        if not 'uri_find' in config:
            config['uri_find'] = []
            is_flag = True
        if not 'increase_wu_heng' in config:
            config['increase_wu_heng'] = False
            is_flag = True
        if not 'ua_white' in config:
            config['ua_white'] = []
            is_flag = True

        if not 'http_config' in config:
            config['http_config'] = {"body_size": 800000, "base64": True, "get_count": 1000, "post_count": 1000}
            is_flag = True

        if not 'ua_black' in config:
            config['ua_black'] = []
            is_flag = True
        if not 'body_character_string' in config:
            config['body_character_string'] = []
            is_flag = True
        if not 'body_regular' in config:
            config['body_regular'] = []
            is_flag = True

        if not 'get_is_sql' in config:
            config['get_is_sql'] = True
            is_flag = True
        if not 'get_is_xss' in config:
            config['get_is_xss'] = True
        if not 'post_is_sql' in config:
            config['post_is_sql'] = True
        if not 'post_is_xss' in config:
            config['post_is_xss'] = True
        if not 'post_is_xss_count' in config:
            config['post_is_xss_count'] = 1
        else:
            if config['post_is_xss_count'] == 6:
                if not os.path.exists("/www/server/panel/data/post_is_xss_count.pl"):
                    config['post_is_xss_count'] = 1
                    is_flag = True
                    public.WriteFile("/www/server/panel/data/post_is_xss_count.pl", "")

        if not 'url_cc_param' in config:
            config['url_cc_param'] = {}
        if not 'send_to' in config:
            config['send_to'] = 'ERROR'
        if not 'drop_china' in config:
            config['drop_china'] = {
                "status": 444,
                "ps": "禁止大陆地区访问",
                "open": False,
                "reqfile": ""
            }
            is_flag = True
        # method_type_check开关
        if not 'method_type' in config:
            config['method_type'] = [['POST', True], ['GET', True], ['PUT', True], ['OPTIONS', True], ['HEAD', True],
                                     ['DELETE', True], ['TRACE', True], ['PATCH', True], ['MOVE', True], ['COPY', True],
                                     ['LINK', True], ['UNLINK', True], ['WRAPPED', True], ['PROPFIND', True],
                                     ['PROPPATCH', True], ['MKCOL', True], ['CONNECT', True], ['SRARCH', True]]

        if not 'header_len' in config:
            config['header_len'] = [['host', 500], ['connection', 100], ['content-length', 100], ['cache-control', 100],
                                    ['upgrade-insecure-requests', 100], ['origin', 500], ['content-type', 300],
                                    ['user-agent', 500], ['accept', 500], ['referer', 10000], ['accept-encoding', 500],
                                    ['accept-language', 500], ['cookie', 10000]]

        for i in range(len(config['header_len'])):
            if config['header_len'][i][0] == 'referer':
                if config['header_len'][i][1] == 500 or config['header_len'][i][1] == 3000:
                    config['header_len'][i][1] = 10000
        if not 'from_data' in config:
            config['from_data'] = True
            is_flag = True

            # webshell开关
        if not 'webshell_opens' in config:
            config['webshell_opens'] = True
        if not config['webshell_opens'] and public.M('crontab').where('name=?', (
                u'Nginx防火墙木马查杀进程请勿删除',)).count() == 0:
            id = public.M('crontab').where('name=?', (u'Nginx防火墙木马查杀进程请勿删除',)).getField('id')
            import crontab
            if id: crontab.crontab().DelCrontab({'id': id})

        if config['webshell_opens']:
            if get and 'open_btwaf_webshell' in get and get.open_btwaf_webshell:
                # 判断这个是否是5分钟的计划任务。只执行一次
                if not os.path.exists("/www/server/panel/plugin/btwaf/webshell_opens.pl"):
                    if public.M('crontab').where('name=?', (u'Nginx防火墙木马查杀进程请勿删除',)).count() == 1:
                        if public.M('crontab').where('name=?', (u'Nginx防火墙木马查杀进程请勿删除',)).getField(
                                "where1") == "5":
                            id = public.M('crontab').where('name=?', (u'Nginx防火墙木马查杀进程请勿删除',)).getField(
                                'id')
                            import crontab
                            if id: crontab.crontab().DelCrontab({'id': id})
                            public.WriteFile("/www/server/panel/plugin/btwaf/webshell_opens.pl", "True")
                self.webshell_check()

        if not 'http_open' in config:
            config['http_open'] = False
            is_flag = True
        # cc 自动开关
        if not 'cc_automatic' in config:
            config['cc_automatic'] = False
        if not 'is_browser' in config:
            config['is_browser'] = False
        if not 'url_white_chekc' in config:
            config['url_white_chekc'] = []
        if not 'cc_time' in config:
            config['cc_time'] = 60
        if not 'cc_retry_cycle' in config:
            config['cc_retry_cycle'] = 6000
        if config['start_time'] == 0:
            config['start_time'] = time.time()
            is_flag = True
        if not 'static_code_config' in config:
            config['static_code_config'] = {}
            is_flag = True
        if is_flag:
            self.__write_config(config)

        return config

    def find_site(self, data, site):
        for i in data:
            for i2 in i['domains']:
                if i2 == site:
                    return i
        return False

    def find_site_config(self, config, site):
        data = [{"name": "POST渗透", "key": "post", "value": 0}, {"name": "GET渗透", "key": "get", "value": 0},
                {"name": "CC攻击", "key": "cc", "value": 0},
                {"name": "恶意User-Agent", "key": "user_agent", "value": 0},
                {"name": "Cookie渗透", "key": "cookie", "value": 0}, {"name": "恶意扫描", "key": "scan", "value": 0},
                {"name": "恶意HEAD请求", "key": "head", "value": 0},
                {"name": "URI自定义拦截", "key": "url_rule", "value": 0},
                {"name": "URI保护", "key": "url_tell", "value": 0},
                {"name": "恶意文件上传", "key": "disable_upload_ext", "value": 0},
                {"name": "禁止的扩展名", "key": "disable_ext", "value": 0},
                {"name": "禁止PHP脚本", "key": "disable_php_path", "value": 0}]
        total_all = self.get_total(None)['sites']
        config['total'] = data if site in total_all else self.__format_total(total_all[site])
        config['siteName'] = site
        return config

    def find_websites(self, get):
        try:
            site_config = json.loads(public.readFile(self.__path + 'site.json'))
            site_name = get.siteName.strip()
            site_config2 = json.loads(public.readFile(self.__path + 'domains.json'))
            site = self.find_site(site_config2, site_name)
            if not site: return public.returnMsg(False, '未找到')
            if not site['name'] in site_config: return public.returnMsg(False, '未找到')
            return public.returnMsg(True, self.find_site_config(site_config[site['name']], site['name']))
        except:
            self.__write_site_domains()
            return public.returnMsg(False, '未找到')

    def get_site_config(self, get):
        try:
            site_config = json.loads(public.readFile(self.__path + 'site.json'))
        except:
            public.WriteFile(self.__path + 'site.json', json.dumps({}))
            self.__write_site_domains()
            site_config = json.loads(public.readFile(self.__path + 'site.json'))
        if not os.path.exists(self.__path + '/domains.json'):
            self.__write_site_domains()
        else:
            site_count = public.M('sites').count()
            try:
                from btdockerModel import dk_public as dp
                docker_sites = dp.sql("docker_sites").count()
                site_count = site_count + docker_sites
            except:
                pass
            site_config_count = len(site_config)
            if site_count != site_config_count:
                self.__write_site_domains()

        data = self.__check_site(site_config)
        if get:
            total_all = self.get_total(None)['sites']
            site_list = []
            for k in data.keys():
                if not k in total_all: total_all[k] = {}
                data[k]['total'] = self.__format_total(total_all[k])
                siteInfo = data[k];
                siteInfo['siteName'] = k;
                site_list.append(siteInfo);
            data = sorted(site_list, key=lambda x: x['log_size'], reverse=True)
        return data

    def get_site_config_byname(self, get):
        from BTPanel import session, cache
        if not self.__session_name in session:
            ret = self.get_btwaf()
            if ret == 0:
                self.stop()
                return public.returnMsg(False, '')
        site_config = self.get_site_config(None);
        config = site_config[get.siteName]
        config['top'] = self.get_config(None)
        return config

    def set_open(self, get):
        from BTPanel import session, cache
        if not cache.get("public.set_open"):
            isError = public.checkWebConfig()
            if isError != True:
                res = public.returnMsg(False,
                                       '检测到Nginx配置文件存在错误:<br><pre style="color:red;white-space: pre-line;">' + isError + '</pre>')
                res["conf_check"] = 1
                return res
            # 全局配置60秒最多一次
            cache.set("public.set_open", True, 60)
        if not self.__session_name in session:
            ret = self.get_btwaf()
            if ret == 0:
                self.stop()
                return public.returnMsg(False, '')

        config = self.get_config(None)
        if config['open']:
            config['open'] = False
            config['start_time'] = 0
        else:
            config['open'] = True
            config['start_time'] = int(time.time())
        self.__write_log(self.__state[config['open']] + '网站防火墙(WAF)')
        self.__write_config(config)
        public.ExecShell("/etc/init.d/bt_ipfilter restart")
        return public.returnMsg(True, '设置成功!')

    def set_obj_open(self, get):
        if get.obj == 'set_scan_conf':
            return self.set_scan_conf(get)
        if get.obj == "btmalibrary":
            if not os.path.exists("/www/server/panel/plugin/btmalibrary/btmalibrary_main.py"):
                return public.returnMsg(False, '检测到【堡塔恶意IP情报库】未安装，请先在软件商店中进行安装')
        config = self.get_config(None)
        if get.obj == 'webshell_opens':
            if config['webshell_opens']:
                # 这里是关闭
                try:
                    id = public.M('crontab').where('name=?', (u'Nginx防火墙木马查杀进程请勿删除',)).getField('id')
                    if id:
                        import crontab
                        data = {'id': id}
                        crontab.crontab().DelCrontab(data)
                except:
                    pass
            else:
                # 这里是开启
                self.webshell_check()
        if get.obj == "sql_injection":
            msg = "SQL注入防御"
        elif get.obj == "xss_injection":
            msg = "XSS防御"
        elif get.obj == "user-agent":
            msg = "恶意爬虫防御"
        elif get.obj == "cookie":
            msg = "恶意Cookie防御"
        elif get.obj == "drop_abroad":
            public.cache_remove('get_drop_abroad_count')
            msg = "禁止国外访问"
        elif get.obj == "drop_china":
            msg = "禁止国内访问"
        elif get.obj == "is_browser":
            msg = "非浏览器访问"
        elif get.obj == "file_upload":
            msg = "恶意文件上传"
        elif get.obj == "get":
            msg = "恶意下载防御"
        elif get.obj == "get":
            msg = "自定义规则拦截"
        elif get.obj == "scan":
            msg = "恶意扫描器"
        elif get.obj == "webshell_opens":
            msg = "木马查杀"
        elif get.obj == "http_open":
            msg = "日志记录"
        elif get.obj == "share_ip":
            msg = "恶意IP共享计划"
        elif get.obj == "malicious_ip":
            msg = "恶意IP共享计划"
        else:
            msg = get.obj
        if type(config[get.obj]) != bool:
            if config[get.obj]['open']:
                config[get.obj]['open'] = False
            else:
                config[get.obj]['open'] = True
            self.__write_log(self.__state[config[get.obj]['open']] + '【' + msg + '】功能');
        else:
            if config[get.obj]:
                config[get.obj] = False
            else:
                config[get.obj] = True

            if get.obj == "share_ip":
                if not config[get.obj]:
                    # 关闭共享IP计划
                    config['malicious_ip'] = False
            self.__write_log(self.__state[config[get.obj]] + '【' + msg + '】功能');
        self.__write_config(config)
        if get.obj == "btmalibrary":
            if config[get.obj]:
                if not os.path.exists("/www/server/btwaf/rule/btmalibrary_malicious.json") or os.path.getsize(
                        "/www/server/btwaf/rule/btmalibrary_malicious.json") < 100:
                    public.run_thread(self.get_malicious_ip_database(None))
        return public.returnMsg(True, '设置成功!')

    def set_spider(self, get):
        try:
            id = int(get.id.strip())
            site_config = self.get_site_config(None)
            if site_config[get.siteName]['spider'][id - 1]:
                if 'status' in site_config[get.siteName]['spider'][id - 1]:
                    if site_config[get.siteName]['spider'][id - 1]['status']:
                        site_config[get.siteName]['spider'][id - 1]['status'] = False
                    else:
                        site_config[get.siteName]['spider'][id - 1]['status'] = True
                    self.__write_site_config(site_config)
                    self.HttpGet('http://127.0.0.1/clean_spider_status')
                    time.sleep(0.3)
                    return public.returnMsg(True, '设置成功!')
            return public.returnMsg(False, '错误的参数!')
        except:
            return public.returnMsg(False, '错误的参数!')

    def set_site_obj_open(self, get):
        # site_config = self.get_site_config(None)
        try:
            site_config = json.loads(public.readFile(self.__path + 'site.json'))
        except:
            return public.returnMsg(False, '配置文件损坏请修复一下防火墙!');
        from BTPanel import cache
        if not cache.get("public.checkWebConfig()"):
            isError = public.checkWebConfig()
            if isError != True:
                res = public.returnMsg(False,
                                       '检测到Nginx配置文件存在错误:<br><pre style="color:red;white-space: pre-line;">' + isError + '</pre>')
                res["conf_check"] = 1
                return res
            # 没有错误的话、一个小时检测一次就可以了
            cache.set("public.checkWebConfig()", True, 3600)

        if get.obj == "smart_cc":
            if not os.path.exists("/www/server/panel/vhost/nginx/btwaf.conf"):
                return public.returnMsg(False, '未找到配置文件!')
            # 读取文件
            conf = public.readFile("/www/server/panel/vhost/nginx/btwaf.conf")
            if not conf:
                return public.returnMsg(False, '未找到配置文件!')
            if conf.find("#body_filter_by_lua_file") != -1:
                if not os.path.exists("/www/server/panel/vhost/nginx/speed.conf"):
                    conf = conf.replace("#body_filter_by_lua_file", "body_filter_by_lua_file")
                    public.writeFile("/www/server/panel/vhost/nginx/btwaf.conf", conf)
                    public.serviceReload()
                else:
                    return public.returnMsg(False, '请先卸载堡塔网站加速插件才能使用此功能!')
        if get.obj == "drop_abroad":
            public.cache_remove('get_drop_abroad_count')
            # 判断全局是否开启。如果全局是关闭的状态、那么此刻就不能开启
            # public.writeFile("/tmp/1.txt", self.get_config(None)['drop_abroad']['open'])
            if not self.get_config(None)['drop_abroad']['open']:
                return public.returnMsg(False, '全局设置中未开启禁止国外访问!')
        if get.obj == "drop_china":
            public.cache_remove('get_drop_abroad_count')
            config = self.get_config(None)
            if not config['drop_china']['open']:
                # 开启禁止国内访问
                config['drop_china']['open'] = True
                self.__write_config(config)
        if get.obj == "sql_injection":
            msg = "SQL注入防御"
        elif get.obj == "xss_injection":
            msg = "XSS防御"
        elif get.obj == "user-agent":
            msg = "恶意爬虫防御"
        elif get.obj == "cookie":
            msg = "恶意Cookie防御"
        elif get.obj == "drop_abroad":
            msg = "禁止国外访问"
        elif get.obj == "drop_china":
            msg = "禁止国内访问"
        elif get.obj == "is_browser":
            msg = "非浏览器访问"
        elif get.obj == "file_upload":
            msg = "恶意文件上传"
        elif get.obj == "get":
            msg = "恶意下载防御"
        elif get.obj == "get":
            msg = "自定义规则拦截"
        elif get.obj == "scan":
            msg = "恶意扫描器"
        elif get.obj == "webshell_opens":
            msg = "木马查杀"
        elif get.obj == "http_open":
            msg = "日志记录"
        elif get.obj == "readonly":
            msg = "护网模式"
        else:
            msg = get.obj
        if get.obj == 'spider':
            # 关闭就是关闭所有蜘蛛
            if site_config[get.siteName]['spider_status']:
                site_config[get.siteName]['spider_status'] = False
            else:
                site_config[get.siteName]['spider_status'] = True
            self.__write_site_config(site_config)
            return public.returnMsg(True, '设置成功!如需立即生效需重启Nginx')
        if type(site_config[get.siteName][get.obj]) != bool:
            if site_config[get.siteName][get.obj]['open']:
                site_config[get.siteName][get.obj]['open'] = False
            else:
                site_config[get.siteName][get.obj]['open'] = True

            self.__write_log(self.__state[site_config[get.siteName][get.obj][
                'open']] + '网站【' + get.siteName + '】【' + msg + '】功能');
        else:
            if site_config[get.siteName][get.obj]:
                site_config[get.siteName][get.obj] = False
            else:
                site_config[get.siteName][get.obj] = True
            self.__write_log(
                self.__state[site_config[get.siteName][get.obj]] + '网站【' + get.siteName + '】【' + msg + '】功能');
        # if get.obj == 'drop_abroad': self.__auto_sync_cnlist();
        self.__write_site_config(site_config)
        return public.returnMsg(True, '设置成功!');

    def __auto_sync_cnlist(self):
        return True

    def set_obj_status(self, get):
        config = self.get_config(None)
        if get.obj == 'post_is_xss_count':
            config[get.obj] = int(get.statusCode)
        else:
            config[get.obj]['status'] = int(get.statusCode)
        self.__write_config(config)
        return public.returnMsg(True, '设置成功!');

    def set_cc_conf(self, get):
        public.set_module_logs("btwaf", "set_cc_conf")
        config = self.get_config(None)

        if not 'cc_ip_max' in get: return public.returnMsg(False, '缺少cc_ip_max参数1');
        if not 'cc_increase_type' in get: return public.returnMsg(False, '需要cc_increase_type参数');
        if not get.cc_increase_type in ['js', 'code', 'renji', 'huadong', 'browser']: return public.returnMsg(False,
                                                                                                              '需要cc_increase_type参数')
        try:
            cc_ip_max = json.loads(get.cc_ip_max)
        except:
            return public.returnMsg(False, 'cc_ip_max参数错误0')

        if 'open' not in cc_ip_max:
            return public.returnMsg(False, 'cc_ip_max参数错误1')
        if 'ip_max' not in cc_ip_max:
            return public.returnMsg(False, 'cc_ip_max参数错误2')
        if 'static' not in cc_ip_max:
            return public.returnMsg(False, 'cc_ip_max参数错误3')

        if cc_ip_max['open'] == True or cc_ip_max['open'] == 1:
            cc_ip_max['open'] = True
        else:
            cc_ip_max['open'] = False
        if cc_ip_max['static'] == True or cc_ip_max['static'] == 1:
            cc_ip_max['static'] = True
        else:
            cc_ip_max['static'] = False
        if cc_ip_max['open'] == False:
            cc_ip_max['static'] = False
        if type(cc_ip_max["ip_max"]) != int: return public.returnMsg(False, 'cc_ip_max参数错误4')

        if cc_ip_max['open'] == False and cc_ip_max["ip_max"] < 2000:
            if 'cc_ip_max' in config['cc']:
                if 'ip_max' in config['cc']['cc_ip_max']:
                    cc_ip_max["ip_max"] = config['cc']['cc_ip_max']['ip_max']
                else:
                    cc_ip_max["ip_max"] = 2000
            else:
                cc_ip_max["ip_max"] = 2000
        if cc_ip_max["ip_max"] < 2000:
            return public.returnMsg(False, '单IP防御次数最低为2000')
        if cc_ip_max['static'] and cc_ip_max["ip_max"] < 5000:
            return public.returnMsg(False, '单IP防御次数最低为5000（开启包括静态的情况下）')
        get.cc_ip_max = cc_ip_max
        if 'is_cc_url' not in get:
            get.is_cc_url = '1'
        end_time = int(get.endtime)
        if end_time > 86400:
            return public.returnMsg(False, '封锁时间不能超过86400秒')
        if not 'cc_mode' in get: get.cc_mode = '1'
        if 'country' in get:
            try:
                countrysss = get.country.split(",")
                country = {}
                for i in countrysss:
                    i = i.strip()
                    if i:
                        country[i] = i
            except:
                country = {}
        else:
            country = {}
        config['cc_mode'] = int(get.cc_mode)
        config['cc']['cycle'] = int(get.cycle)
        config['cc']['limit'] = int(get.limit)
        config['cc']['endtime'] = int(get.endtime)
        config['cc']['countrys'] = country
        config['cc']['increase'] = (get.increase == '1') | False
        config['increase_wu_heng'] = (get.increase_wu_heng == '1') | False
        config['cc']['cc_increase_type'] = get.cc_increase_type
        config['cc_type_status'] = int(get.cc_type_status)
        config['cc']['is_cc_url'] = (get.is_cc_url == '1') | False
        config['cc']['cc_ip_max'] = cc_ip_max

        if int(get.cc_mode) == 3:
            config['cc_automatic'] = True
        else:
            config['cc_automatic'] = False
        self.__write_config(config)
        public.writeFile('/www/server/btwaf/config.json', json.dumps(config))
        self.__write_log(
            '设置全局CC配置为：' + get.cycle + ' 秒内累计请求超过 ' + get.limit + ' 次后,封锁 ' + get.endtime + ' 秒' + ',增强:' + get.increase);
        if get.is_open_global:
            self.set_cc_golbls(get)
        public.serviceReload()
        return public.returnMsg(True, '设置成功!');

    def set_site_cc_conf(self, get):
        # public.set_module_logs("btwaf","set_site_cc_conf")
        if not 'cc_increase_type' in get: return public.returnMsg(False, '需要cc_increase_type参数');
        if not get.cc_increase_type in ['js', 'code', 'renji', 'huadong', 'browser']: return public.returnMsg(False,
                                                                                                              '需要cc_increase_type参数');
        if not 'cc_ip_max' in get: return public.returnMsg(False, '需要cc_ip_max参数2');
        try:
            cc_ip_max = json.loads(get.cc_ip_max)
        except:
            return public.returnMsg(False, 'cc_ip_max参数错误0')

        if 'open' not in cc_ip_max:
            return public.returnMsg(False, 'cc_ip_max参数错误1')
        if 'ip_max' not in cc_ip_max:
            return public.returnMsg(False, 'cc_ip_max参数错误2')
        if 'static' not in cc_ip_max:
            return public.returnMsg(False, 'cc_ip_max参数错误3')
        if cc_ip_max['open'] == True or cc_ip_max['open'] == 1:
            cc_ip_max['open'] = True
        else:
            cc_ip_max['open'] = False

        if cc_ip_max['static'] == True or cc_ip_max['static'] == 1:
            cc_ip_max['static'] = True
        else:
            cc_ip_max['static'] = False
        site_config = self.get_site_config(None)

        if type(cc_ip_max["ip_max"]) != int: return public.returnMsg(False, 'cc_ip_max参数错误4')
        if cc_ip_max['open'] == False and cc_ip_max["ip_max"] < 2000:
            if 'cc_ip_max' in site_config[get.siteName]['cc']:
                if 'ip_max' in site_config[get.siteName]['cc']['cc_ip_max']:
                    cc_ip_max["ip_max"] = site_config[get.siteName]['cc']['cc_ip_max']['ip_max']
                else:
                    cc_ip_max["ip_max"] = 2000
            else:
                cc_ip_max["ip_max"] = 2000
        if cc_ip_max["ip_max"] < 2000:
            return public.returnMsg(False, '单IP防御次数最低为2000')
        if cc_ip_max['static'] and cc_ip_max["ip_max"] < 5000:
            return public.returnMsg(False, '单IP防御次数最低为5000（开启包括静态的情况下）')
        if cc_ip_max['open'] == False:
            cc_ip_max['static'] = False
        get.cc_ip_max = cc_ip_max

        if not 'cc_mode' in get: get.cc_mode = 1
        if not 'cc_time' in get: get.cc_time = False
        if not 'cc_retry_cycle' in get: get.cc_retry_cycle = False
        if not 'is_cc_url' in get: get.is_cc_url = False

        # config['cc']['is_cc_url'] = (get.is_cc_url == '1') | False
        if 'country' in get:
            try:
                countrysss = get.country.split(",")
                country = {}
                for i in countrysss:
                    i = i.strip()
                    if i:
                        country[i] = i
            except:
                country = {}
        else:
            country = {}
        if get.cc_mode and get.cc_retry_cycle:
            if not self.isDigit(get.cc_mode) and not self.isDigit(get.cc_retry_cycle): return public.returnMsg(False,
                                                                                                               '需要设置数字!')
            site_config[get.siteName]['cc_time'] = int(get.cc_time)
            site_config[get.siteName]['cc_mode'] = int(get.cc_mode)
            site_config[get.siteName]['cc']['cc_mode'] = int(get.cc_mode)
            site_config[get.siteName]['cc_retry_cycle'] = int(get.cc_retry_cycle)
            site_config[get.siteName]['cc_automatic'] = True
            site_config[get.siteName]['cc']['countrys'] = country
            site_config[get.siteName]['cc']['is_cc_url'] = (get.is_cc_url == '1') | False
        else:
            site_config[get.siteName]['cc']['is_cc_url'] = (get.is_cc_url == '1') | False
            site_config[get.siteName]['cc']['countrys'] = country
            site_config[get.siteName]['cc_automatic'] = False
            site_config[get.siteName]['cc_mode'] = int(get.cc_mode)
            site_config[get.siteName]['cc']['cc_mode'] = int(get.cc_mode)
            site_config[get.siteName]['cc']['cycle'] = int(get.cycle)
            site_config[get.siteName]['cc']['limit'] = int(get.limit)
            site_config[get.siteName]['cc']['endtime'] = int(get.endtime)
            site_config[get.siteName]['cc']['cc_increase_type'] = get.cc_increase_type
            site_config[get.siteName]['cc']['increase'] = (get.increase == '1') | False
            site_config[get.siteName]['increase_wu_heng'] = (get.increase_wu_heng == '1') | False
        site_config[get.siteName]['cc_type_status'] = int(get.cc_type_status)

        site_config[get.siteName]['cc']['cc_ip_max'] = cc_ip_max

        self.__write_site_config(site_config)
        public.WriteFile('/www/server/btwaf/site.json', json.dumps(site_config, ensure_ascii=False))
        self.__write_log(
            '设置站点【' + get.siteName + '】CC配置为：' + get.cycle + ' 秒内累计请求超过 ' + get.limit + ' 次后,封锁 ' + get.endtime + ' 秒' + ',增强:' + get.increase);
        return public.returnMsg(True, '设置成功!')

    def cn_to_ip(self, aaa):
        for i in aaa:
            for i2 in range(len(i)):
                if i2 >= 2: break
                i[i2] = self.ip2long(i[i2])
        return aaa

    def binary_search(self, data, value):
        low = 0
        high = len(data) - 1

        while low <= high:
            mid = (low + high) // 2
            start, end = data[mid]

            if start <= value <= end:
                return {"start": start, "end": end, "result": True}
            elif value < start:
                high = mid - 1
            else:
                low = mid + 1
        return {"start": 0, "end": 0, "result": False}

    def add_cnip(self, get):
        ipn = [self.__format_ip(get.start_ip), self.__format_ip(get.end_ip)]
        if not ipn[0] or not ipn[1]: return public.returnMsg(False, 'IP段格式不正确');
        if not self.__is_ipn(ipn): return public.returnMsg(False, '起始IP不能大于结束IP');
        iplist = self.get_cn_list('cn')
        ipn = [get.start_ip, get.end_ip]
        if ipn in iplist: return public.returnMsg(False, '指定IP段已存在!');

        rule = self.__get_rule("cn")
        start_info = self.binary_search(rule, self.ip2long(ipn[0]))
        end_info = self.binary_search(rule, self.ip2long(ipn[1]))
        if start_info["result"]:
            return public.returnMsg(False, "该IP已经存在在:" + self.long2ip(start_info["start"]) + "-" + self.long2ip(
                start_info["end"]) + "这个IP段中,无需添加")
        if end_info["result"]:
            return public.returnMsg(False, "该IP已经存在在:" + self.long2ip(end_info["start"]) + "-" + self.long2ip(
                end_info["end"]) + "这个IP段中,无需添加")

        iplist.insert(0, ipn)
        iplist2 = self.cn_to_ip(iplist)
        iplist2 = sorted(iplist2, key=lambda x: x[0])
        self.__write_rule('cn', iplist2)
        self.__write_log('添加IP段[' + get.start_ip + '-' + get.end_ip + ']到国内IP库');
        return public.returnMsg(True, '添加成功!')

    def remove_cnip(self, get):
        index = int(get.index)
        iplist = self.get_cn_list('cn')
        del (iplist[index])
        iplist2 = self.cn_to_ip(iplist)
        iplist2 = sorted(iplist2, key=lambda x: x[0])
        self.__write_rule('cn', iplist2)
        return public.returnMsg(True, '删除成功!')

    def add_ip_white(self, get):
        ipn = [self.__format_ip(get.start_ip), self.__format_ip(get.end_ip)]
        ips = "-,{}-{}".format(get.start_ip, get.end_ip)
        public.WriteFile("/dev/shm/.bt_ip_filter", ips)
        if not ipn[0] or not ipn[1]: return public.returnMsg(False, 'IP段格式不正确');
        if not self.__is_ipn(ipn): return public.returnMsg(False, '起始IP不能大于结束IP');
        ipn = [get.start_ip, get.end_ip]
        if 'ps' in get and get.ps:
            ipn.append(get.ps)
        iplist = self.get_cn_list('ip_white')
        if ipn in iplist: return public.returnMsg(False, '指定IP段已存在!');
        iplist.insert(0, ipn)
        self.__write_rule('ip_white', self.cn_to_ip(iplist))
        self.__write_log('添加IP段[' + get.start_ip + '-' + get.end_ip + ']到IP白名单')
        return public.returnMsg(True, '添加成功!')

    def edit_ip_white_ps(self, get):
        if 'id' not in get: return public.returnMsg(False, '参数错误!')
        iplist = self.get_cn_list('ip_white')
        if len(iplist) < int(get.id): return public.returnMsg(False, '参数错误!')
        if len(iplist[int(get.id)]) == 2:
            iplist[int(get.id)].append(get.ps)
        else:
            iplist[int(get.id)][2] = get.ps
        self.__write_rule('ip_white', self.cn_to_ip(iplist))
        return public.returnMsg(True, '修改成功!')

    def edit_ip_black_ps(self, get):
        if 'id' not in get: return public.returnMsg(False, '参数错误!')
        iplist = self.get_cn_list('ip_black')
        if len(iplist) < int(get.id): return public.returnMsg(False, '参数错误!')
        if len(iplist[int(get.id)]) == 2:
            iplist[int(get.id)].append(get.ps)
        else:
            iplist[int(get.id)][2] = get.ps
        self.__write_rule('ip_black', self.cn_to_ip(iplist))
        return public.returnMsg(True, '修改成功!')

    def remove_ip_white(self, get):
        index = int(get.index)
        iplist = self.get_cn_list('ip_white')
        ipn = iplist[index]
        del (iplist[index])
        self.__write_rule('ip_white', self.cn_to_ip(iplist))
        return public.returnMsg(True, '删除成功!')

    def import_data2(self, type, pdata):
        if not pdata: return public.returnMsg(False, '数据格式不正确')
        # iplist = self.get_cn_list(type)
        for i in pdata:
            ipn = [self.__format_ip(i[0]), self.__format_ip(i[1])]
            if not ipn[0] or not ipn[1]: continue
            if not self.__is_ipn(ipn): continue
            ipn = [i[0], i[1]]
            iplist = self.get_cn_list(type)
            if ipn in iplist: continue
            iplist.insert(0, ipn)
            self.__write_rule(type, self.cn_to_ip(iplist))
        return public.returnMsg(True, '导入成功!')

    def is_ip_zhuanhuang(self, ip, ip2=False, ip_duan=False):
        try:
            ret = []
            if ip_duan:
                ip_ddd = int(ip.split('/')[1])
                ip = ip.split('/')[0].split('.')
                if ip_ddd >= 32: return False
                net_ip = ipaddress.ip_interface("{}/{}".format('.'.join(ip), ip_ddd))
                network_start = net_ip.network.network_address
                network_end = net_ip.network.broadcast_address
                return self.is_ip_zhuanhuang(str(network_start), str(network_end))
            else:
                if ip2 and ip:
                    ret.append(ip)
                    ret.append(ip2)
                    return ret
                else:
                    ret.append(ip)
                    ret.append(ip)
                    return ret
        except:
            return False

    def bt_ip_filter(self, datas):
        # 检查状态
        status = public.ExecShell("/etc/init.d/bt_ipfilter status")
        if 'service not running' in status[0]:
            public.ExecShell("/etc/init.d/bt_ipfilter restart")
        path = "/dev/shm/.bt_ip_filter"
        if os.path.exists(path):
            data = public.ReadFile(path)
            data += "\n" + datas
            public.WriteFile(path, data)
        else:
            public.WriteFile(path, datas)

    def import_data(self, get):
        name = get.s_Name
        if name == 'ip_white' or name == 'ip_black' or name == "cn":
            if 'json' in get:
                pdata = json.loads(get.pdata)
                if not pdata: return public.returnMsg(False, '数据格式不正确');
                if name == 'ip_white': return self.import_data2('ip_white', pdata)
                if name == 'ip_black': return self.import_data2('ip_black', pdata)
                if name == 'cn': return self.import_data2('cn', pdata)
                iplist = self.__get_rule(name)
                for ips in pdata:
                    if ips in iplist: continue;
                    iplist.insert(0, ips)
                self.__write_rule(name, iplist)
                return public.returnMsg(True, '导入成功!')
            else:
                padata = get.pdata.strip().split()
                if not padata: return public.returnMsg(False, '数据格式不正确')
                iplist = self.get_cn_list(name)
                for i in padata:
                    if re.search("\d+.\d+.\d+.\d+-\d+.\d+.\d+.\d+$", i):
                        ip = i.split('-')
                        ips = self.is_ip_zhuanhuang(ip[0], ip[1])
                        if not ips: continue
                        if ips in iplist: continue
                        iplist.insert(0, ips)

                    elif re.search("\d+.\d+.\d+.\d+/\d+$", i):
                        ips = self.is_ip_zhuanhuang(i, ip_duan=True)
                        if not ips: continue
                        if ips in iplist: continue
                        iplist.insert(0, ips)

                    elif re.search("\d+.\d+.\d+.\d+$", i):
                        ips = self.is_ip_zhuanhuang(i)
                        if not ips: continue
                        if ips in iplist: continue
                        iplist.insert(0, ips)
                    if name == 'ip_black':
                        ips = self.is_ip_zhuanhuang(i)
                        if not ips: continue
                        # 如果他在白名单中则不添加
                        ipn = [ips[0], ips[1]]
                        ip_white_rule = self.get_cn_list('ip_white')
                        if ipn in ip_white_rule: continue
                        self.bt_ip_filter("+,%s-%s,86400" % (ips[0], ips[1]))
                    if name == "ip_white":
                        ips = self.is_ip_zhuanhuang(i)
                        self.bt_ip_filter("-,%s-%s" % (ips[0], ips[1]))
                    # public.ExecShell('echo "+,%s-%s,86400" >/dev/shm/.bt_ip_filter'%(ips[0],ips[1]))
                self.__write_rule(name, self.cn_to_ip(iplist))
                return public.returnMsg(True, '导入成功!')
        else:
            if 'json' not in get:
                get.json = True
            else:
                get.json = get.json
            if get.json:
                try:
                    pdata = json.loads(get.pdata)
                except:
                    pdata = get.pdata.strip().split()
            else:
                pdata = get.pdata.strip().split()
            if not pdata: return public.returnMsg(False, '数据格式不正确');
            if name == 'ip_white': return self.import_data2('ip_white', pdata)
            if name == 'ip_black': return self.import_data2('ip_black', pdata)
            if name == 'cn': return self.import_data2('cn', pdata)
            iplist = self.__get_rule(name)
            for ips in pdata:
                if ips in iplist: continue;
                iplist.insert(0, ips)
            self.__write_rule(name, iplist)
            return public.returnMsg(True, '导入成功!')

    def output_data(self, get):
        iplist = self.__get_rule(get.s_Name)
        return iplist;

    def add_ip_black(self, get):
        ipn = [self.__format_ip(get.start_ip), self.__format_ip(get.end_ip)]
        if not ipn[0] or not ipn[1]: return public.returnMsg(False, 'IP段格式不正确');
        if not self.__is_ipn(ipn): return public.returnMsg(False, '起始IP不能大于结束IP');

        ipn = [get.start_ip, get.end_ip]

        iplist = self.get_cn_list('ip_white')
        if not ipn in iplist:
            ipn = [get.start_ip, get.end_ip]
            self.bt_ip_filter("+,%s-%s,86400" % (get.start_ip, get.end_ip))
        if 'ps' in get and get.ps:
            ipn.append(get.ps)
        iplist = self.get_cn_list('ip_black')
        if ipn in iplist: return public.returnMsg(False, '指定IP段已存在!');
        iplist.insert(0, ipn)
        self.__write_rule('ip_black', self.cn_to_ip(iplist))
        self.__write_log('添加IP段[' + get.start_ip + '-' + get.end_ip + ']到IP黑名单')
        return public.returnMsg(True, '添加成功!')

    def remove_ip_black(self, get):
        index = int(get.index)
        iplist = self.get_cn_list('ip_black')
        ipn = iplist[index]
        del (iplist[index])
        # return ipn
        self.bt_ip_filter("-,%s-%s,86400" % (ipn[0], ipn[1]))
        self.__write_rule('ip_black', self.cn_to_ip(iplist))
        return public.returnMsg(True, '删除成功!')

    def add_url_white(self, get):
        url_white = self.__get_rule('url_white')
        url_rule = get.url_rule.strip()
        # 取?前的url
        url_rule = url_rule.split('?')[0]
        if url_rule == '^/' or url_rule == '/': return public.returnMsg(False, '不允许添加根目录')
        if get.url_rule in url_white: return public.returnMsg(False, '您添加的URL已存在')
        url_white.insert(0, url_rule)
        self.__write_rule('url_white', url_white)
        self.__write_log('添加url规则[' + url_rule + ']到URL白名单');
        return public.returnMsg(True, '添加成功!')

    def add_url_white_senior(self, get):
        if not 'url' in get: return public.returnMsg(False, '请输入url!')
        if not 'param' in get: return public.returnMsg(False, '请输入参数!')
        url_white = self.__get_rule('url_white_senior')
        try:
            param = json.loads(get.param)
        except:
            return public.returnMsg(False, '参数传递错误!')
        params = []
        for i in param:
            if i == "": continue
            if not i: continue
            params.append(i)
        data = {get.url: params}
        if data in url_white: return public.returnMsg(False, '已存在!')
        url_white.insert(0, data)
        self.__write_rule('url_white_senior', url_white)
        return public.returnMsg(True, '添加成功')

    def del_url_white_senior(self, get):
        if not 'url' in get: return public.returnMsg(False, '请输入url!')
        if not 'param' in get: get.param = ""
        url_white = self.__get_rule('url_white_senior')
        param = get.param.strip()
        param = param.split(",")
        if len(param) == 1 and param[0] == "":
            data = {get.url: []}
        else:
            data = {get.url: param}
        if not data in url_white: return public.returnMsg(False, '不存在!')
        url_white.remove(data)
        self.__write_rule('url_white_senior', url_white)
        return public.returnMsg(True, '删除成功')

    def get_url_white_senior(self, get):
        url_white = self.__get_rule('url_white_senior')
        return url_white

    def get_url_request_mode(self, get):
        url_white = self.__get_rule('url_request_mode')
        return url_white

    def get_reg_tions(self, get):
        url_white = self.__get_rule('reg_tions')
        # {"site": sitesMode, "types": get.types, "region": paramMode,"open":True,"reqfile":"city.html","status":444,"random_id":public.GetRandomString(16)}
        url_white_flag = False
        for i in url_white:

            if 'open' not in i:
                url_white_flag = True
                i['open'] = True
            if 'status' not in i:
                url_white_flag = True
                i['status'] = 444
            if 'reqfile' not in i:
                url_white_flag = True
                i['reqfile'] = "city.html"
            if 'system_block' not in i:
                url_white_flag = True
                i['system_block'] = False
        if url_white_flag:
            self.__write_rule('reg_tions', url_white)
        url_city_tions = False
        city_tions = self.__get_rule('reg_city')
        for i in city_tions:
            if 'open' not in i:
                url_city_tions = True
                i['open'] = True
            if 'status' not in i:
                url_city_tions = True
                i['status'] = 444
            if 'reqfile' not in i:
                url_city_tions = True
                i['reqfile'] = "city.html"
            if 'system_block' not in i:
                url_city_tions = True
                i['system_block'] = False
        # 两个表格聚合在一起
        if url_city_tions:
            self.__write_rule('reg_city', city_tions)
        return url_white, city_tions

    def get_city(self, get):
        return {
            "上海": ["上海"],
            "云南": ["昆明", "迪庆", "西双版纳", "曲靖", "临沧", "保山", "红河", "普洱", "玉溪", "大理", "楚雄",
                     "德宏", "文山", "昭通", "丽江", "怒江"],
            "内蒙古": ["呼和浩特", "锡林郭勒", "包头", "乌兰察布", "阿拉善", "巴彦淖尔", "兴安", "鄂尔多斯", "乌海",
                       "呼伦贝尔", "通辽", "赤峰"],
            "北京": ["北京"],
            "吉林": ["长春", "吉林", "延边", "四平", "白城", "辽源", "松原", "白山", "通化"],
            "四川": ["成都", "内江", "泸州", "凉山", "甘孜", "阿坝", "绵阳", "广元", "巴中", "南充", "达州", "广安",
                     "遂宁", "眉山", "乐山", "雅安", "资阳", "自贡", "攀枝花", "宜宾", "德阳"],
            "天津": ["天津"],
            "宁夏": ["银川", "石嘴山", "中卫", "固原", "吴忠"],
            "安徽": ["滁州", "合肥", "宿州", "铜陵", "亳州", "黄山", "蚌埠", "淮北", "阜阳", "六安", "宣城", "安庆",
                     "马鞍山", "池州", "淮南", "芜湖"],
            "山东": ["青岛", "济南", "潍坊", "德州", "烟台", "淄博", "聊城", "临沂", "济宁", "泰安", "东营", "威海",
                     "枣庄", "菏泽", "滨州", "日照"],
            "山西": ["太原", "长治", "运城", "晋中", "忻州", "晋城", "朔州", "阳泉", "吕梁", "临汾", "大同"],
            "广东": ["广州", "珠海", "深圳", "惠州", "东莞", "中山", "佛山", "汕尾", "云浮", "湛江", "肇庆", "潮州",
                     "茂名", "梅州", "汕头", "阳江", "河源", "揭阳", "江门", "清远", "韶关"],
            "广西": ["南宁", "桂林", "来宾", "玉林", "钦州", "贺州", "贵港", "防城港", "崇左", "柳州", "河池",
                     "北海", "梧州", "百色"],
            "新疆": ["和田", "克孜勒苏", "阿勒泰", "哈密", "博尔塔拉", "巴音郭楞", "昌吉", "吐鲁番", "塔城",
                     "石河子", "阿克苏", "喀什", "图木舒克", "乌鲁木齐", "克拉玛依", "阿拉尔", "伊犁", "双河",
                     "北屯", "胡杨河", "昆玉", "五家渠", "可克达拉", "铁门关"],
            "江苏": ["扬州", "南京", "常州", "苏州", "泰州", "无锡", "南通", "盐城", "徐州", "镇江", "淮安",
                     "连云港", "宿迁"],
            "江西": ["南昌", "抚州", "萍乡", "上饶", "赣州", "宜春", "景德镇", "吉安", "九江", "新余", "鹰潭"],
            "河北": ["保定", "石家庄", "廊坊", "衡水", "唐山", "邯郸", "秦皇岛", "沧州", "邢台", "张家口", "承德",
                     "雄安"],
            "河南": ["郑州", "三门峡", "新乡", "南阳", "濮阳", "驻马店", "商丘", "洛阳", "漯河", "信阳", "周口",
                     "焦作", "开封", "鹤壁", "平顶山", "安阳", "许昌", "济源"],
            "浙江": ["杭州", "温州", "嘉兴", "宁波", "湖州", "台州", "金华", "绍兴", "丽水", "衢州", "舟山"],
            "海南": ["海口", "万宁", "三亚", "儋州", "文昌", "乐东", "琼海", "陵水", "澄迈", "东方", "昌江", "定安",
                     "琼中", "保亭", "屯昌", "五指山", "临高", "白沙"],
            "湖北": ["黄冈", "武汉", "荆州", "宜昌", "襄阳", "孝感", "黄石", "咸宁", "恩施", "荆门", "十堰", "鄂州",
                     "随州", "神农架", "潜江", "天门", "仙桃"],
            "湖南": ["长沙", "常德", "娄底", "株洲", "郴州", "衡阳", "怀化", "永州", "益阳", "张家界", "湘潭",
                     "岳阳", "邵阳", "湘西"],
            "甘肃": ["定西", "临夏", "甘南", "平凉", "庆阳", "嘉峪关", "天水", "兰州", "武威", "金昌", "酒泉",
                     "白银", "陇南", "张掖"],
            "福建": ["福州", "厦门", "宁德", "泉州", "三明", "莆田", "漳州", "南平", "龙岩"],
            "西藏": ["拉萨", "昌都", "山南", "阿里", "林芝", "日喀则", "那曲"],
            "贵州": ["安顺", "黔南", "铜仁", "毕节", "遵义", "黔西南", "六盘水", "贵阳", "黔东南"],
            "辽宁": ["锦州", "沈阳", "大连", "朝阳", "铁岭", "盘锦", "鞍山", "营口", "本溪", "辽阳", "抚顺", "阜新",
                     "葫芦岛", "丹东"],
            "重庆": ["重庆"],
            "陕西": ["西安", "商洛", "铜川", "汉中", "安康", "渭南", "榆林", "宝鸡", "咸阳", "延安"],
            "青海": ["海西", "海东", "西宁", "黄南", "玉树", "海北", "果洛", "海南"],
            "黑龙江": ["鹤岗", "牡丹江", "绥化", "齐齐哈尔", "双鸭山", "鸡西", "哈尔滨", "大庆", "佳木斯", "黑河",
                       "七台河", "伊春", "大兴安岭"]
        }

    def add_city(self, get):
        if not 'site' in get: return public.returnMsg(False, '请输入需要设置的站点!')
        if not 'types' in get: return public.returnMsg(False, '请输入类型!')
        if not 'region' in get: return public.returnMsg(False, '请输入地区!')
        url_white = self.__get_rule('reg_city')
        if not url_white: url_white = []

        param = get.region.split(",")
        sitessss = get.site.split(",")
        type_list = ["refuse", "accept"]
        if not get.types in type_list: return public.returnMsg(False, '输入的类型错误!')
        paramMode = {}
        for i in param:
            if not i: continue
            i = i.strip()
            if not i in paramMode:
                paramMode[i] = "1"
        sitesMode = {}

        for i in sitessss:
            i = i.strip()
            if not i: continue
            if not i in sitesMode:
                sitesMode[i] = "1"
        if len(paramMode) == 0: return public.returnMsg(False, '输入的请求类型错误!')
        if len(sitesMode) == 0: return public.returnMsg(False, '输入的站点错误!')
        data = {"site": sitesMode, "types": get.types, "region": paramMode, "open": True, "reqfile": "city.html",
                "status": 444, "system_block": False}
        if data in url_white: return public.returnMsg(False, '已存在!')
        url_white.insert(0, data)
        self.__write_rule('reg_city', url_white)
        return public.returnMsg(True, '添加成功!')

    def edit_reg_city(self, get):
        '''
            修改地区限制
        :param id 记录的ID
        :param open 状态
        :param status 状态码
        :return:
        '''
        if not 'id' in get: return public.returnMsg(False, '请输入ID!')
        if not 'open' in get: return public.returnMsg(False, '请输入open!')
        if not 'status' in get: return public.returnMsg(False, '请输入status!')
        url_white = self.__get_rule('reg_city')
        if len(url_white) < int(get.id): return public.returnMsg(False, '参数错误!')
        # open 如果是true 或者1 则是开启状态
        if get.open == "true" or get.open == "1":
            get.open = True
        else:
            get.open = False
        # 状态码只有200 404 403 444 502 503 504
        status_list = [200, 404, 403, 444, 502, 503, 504]
        if not int(get.status) in status_list: return public.returnMsg(False, '输入的状态码错误!')
        url_white[int(get.id)]['open'] = get.open
        url_white[int(get.id)]['status'] = int(get.status)
        self.__write_rule('reg_city', url_white)
        return public.returnMsg(True, '修改成功!')

    def del_city(self, get):
        # if not 'site' in get: return public.returnMsg(False, '请输入需要设置的站点!')
        # if not 'types' in get: return public.returnMsg(False, '请输入类型!')
        # if not 'region' in get: return public.returnMsg(False, '请输入地区!')
        # url_white = self.__get_rule('reg_city')
        # param = get.region.split(",")
        # sitessss = get.site.split(",")
        # type_list = ["refuse", "accept"]
        # if not get.types in type_list: return public.returnMsg(False, '输入的类型错误!')
        # paramMode = {}
        # for i in param:
        #     if not i: continue
        #     if not i in paramMode:
        #         paramMode[i] = "1"
        # sitesMode = {}
        # for i in sitessss:
        #     if not i: continue
        #     if not i in sitesMode:
        #         sitesMode[i] = "1"
        # if len(paramMode) == 0: return public.returnMsg(False, '输入的请求类型错误!')
        # if len(sitesMode) == 0: return public.returnMsg(False, '输入的站点错误!')
        #
        # data = {"site": sitesMode, "types": get.types, "region": paramMode}
        # if not data in url_white: return public.returnMsg(False, '不存在!')
        # url_white.remove(data)

        if not 'id' in get: return public.returnMsg(False, '请输入站点ID!')

        url_white = self.__get_rule('reg_city')
        if len(url_white) == 0: return public.returnMsg(False, '没有数据!')

        if len(url_white) < int(get.id): return public.returnMsg(False, '参数错误!')
        del (url_white[int(get.id)])
        self.__write_rule('reg_city', url_white)
        return public.returnMsg(True, '删除成功!')

    def city(self, get):

        data = ['中国大陆以外的地区(包括[中国特别行政区:港,澳,台])', '中国大陆(不包括[中国特别行政区:港,澳,台])',
                '中国香港', '中国澳门', '中国台湾',
                '美国', '日本', '英国', '德国', '韩国', '法国', '巴西', '加拿大', '意大利', '澳大利亚', '荷兰',
                '俄罗斯', '印度', '瑞典', '西班牙', '墨西哥',
                '比利时', '南非', '波兰', '瑞士', '阿根廷', '印度尼西亚', '埃及', '哥伦比亚', '土耳其', '越南', '挪威',
                '芬兰', '丹麦', '乌克兰', '奥地利',
                '伊朗', '智利', '罗马尼亚', '捷克', '泰国', '沙特阿拉伯', '以色列', '新西兰', '委内瑞拉', '摩洛哥',
                '马来西亚', '葡萄牙', '爱尔兰', '新加坡',
                '欧洲联盟', '匈牙利', '希腊', '菲律宾', '巴基斯坦', '保加利亚', '肯尼亚', '阿拉伯联合酋长国',
                '阿尔及利亚', '塞舌尔', '突尼斯', '秘鲁', '哈萨克斯坦',
                '斯洛伐克', '斯洛文尼亚', '厄瓜多尔', '哥斯达黎加', '乌拉圭', '立陶宛', '塞尔维亚', '尼日利亚',
                '克罗地亚', '科威特', '巴拿马', '毛里求斯', '白俄罗斯',
                '拉脱维亚', '多米尼加', '卢森堡', '爱沙尼亚', '苏丹', '格鲁吉亚', '安哥拉', '玻利维亚', '赞比亚',
                '孟加拉国', '巴拉圭', '波多黎各', '坦桑尼亚',
                '塞浦路斯', '摩尔多瓦', '阿曼', '冰岛', '叙利亚', '卡塔尔', '波黑', '加纳', '阿塞拜疆', '马其顿',
                '约旦', '萨尔瓦多', '伊拉克', '亚美尼亚', '马耳他',
                '危地马拉', '巴勒斯坦', '斯里兰卡', '特立尼达和多巴哥', '黎巴嫩', '尼泊尔', '纳米比亚', '巴林',
                '洪都拉斯', '莫桑比克', '尼加拉瓜', '卢旺达', '加蓬',
                '阿尔巴尼亚', '利比亚', '吉尔吉斯坦', '柬埔寨', '古巴', '喀麦隆', '乌干达', '塞内加尔', '乌兹别克斯坦',
                '黑山', '关岛', '牙买加', '蒙古', '文莱',
                '英属维尔京群岛', '留尼旺', '库拉索岛', '科特迪瓦', '开曼群岛', '巴巴多斯', '马达加斯加', '伯利兹',
                '新喀里多尼亚', '海地', '马拉维', '斐济', '巴哈马',
                '博茨瓦纳', '扎伊尔', '阿富汗', '莱索托', '百慕大', '埃塞俄比亚', '美属维尔京群岛', '列支敦士登',
                '津巴布韦', '直布罗陀', '苏里南', '马里', '也门',
                '老挝', '塔吉克斯坦', '安提瓜和巴布达', '贝宁', '法属玻利尼西亚', '圣基茨和尼维斯', '圭亚那',
                '布基纳法索', '马尔代夫', '泽西岛', '摩纳哥', '巴布亚新几内亚',
                '刚果', '塞拉利昂', '吉布提', '斯威士兰', '缅甸', '毛里塔尼亚', '法罗群岛', '尼日尔', '安道尔',
                '阿鲁巴', '布隆迪', '圣马力诺', '利比里亚',
                '冈比亚', '不丹', '几内亚', '圣文森特岛', '荷兰加勒比区', '圣马丁', '多哥', '格陵兰', '佛得角',
                '马恩岛', '索马里', '法属圭亚那', '西萨摩亚',
                '土库曼斯坦', '瓜德罗普', '马里亚那群岛', '瓦努阿图', '马提尼克', '赤道几内亚', '南苏丹', '梵蒂冈',
                '格林纳达', '所罗门群岛', '特克斯和凯科斯群岛', '多米尼克',
                '乍得', '汤加', '瑙鲁', '圣多美和普林西比', '安圭拉岛', '法属圣马丁', '图瓦卢', '库克群岛',
                '密克罗尼西亚联邦', '根西岛', '东帝汶', '中非',
                '几内亚比绍', '帕劳', '美属萨摩亚', '厄立特里亚', '科摩罗', '圣皮埃尔和密克隆', '瓦利斯和富图纳',
                '英属印度洋领地', '托克劳', '马绍尔群岛', '基里巴斯',
                '纽埃', '诺福克岛', '蒙特塞拉特岛', '朝鲜', '马约特', '圣卢西亚', '圣巴泰勒米岛']

        return data

    def reg_domains(self, get):
        site_config2 = json.loads(public.readFile(self.__path + 'domains.json'))
        return site_config2

    def add_reg_tions(self, get):
        if not 'site' in get: return public.returnMsg(False, '请输入需要设置的站点!')
        if not 'types' in get: return public.returnMsg(False, '请输入类型!')
        if not 'region' in get: return public.returnMsg(False, '请输入地区!')
        url_white = self.__get_rule('reg_tions')
        param = get.region.split(",")

        sitessss = get.site.split(",")
        type_list = ["refuse", "accept"]
        if not get.types in type_list: return public.returnMsg(False, '输入的类型错误!')

        paramMode = {}
        for i in param:
            if not i: continue
            i = i.strip()
            if not i in paramMode:
                paramMode[i] = "1"
        sitesMode = {}

        if '海外' in paramMode and '中国' in paramMode:
            return public.returnMsg(False, '不允许设置【中国大陆】和【中国大陆以外地区】一同开启地区限制!')
        for i in sitessss:
            i = i.strip()
            if not i: continue

            if not i in sitesMode:
                sitesMode[i] = "1"
        if len(paramMode) == 0: return public.returnMsg(False, '输入的请求类型错误!')
        if len(sitesMode) == 0: return public.returnMsg(False, '输入的站点错误!')

        data = {"site": sitesMode, "types": get.types, "region": paramMode, "open": True, "reqfile": "city.html",
                "status": 444, "system_block": False}
        if data in url_white: return public.returnMsg(False, '已存在!')
        url_white.insert(0, data)
        self.__write_rule('reg_tions', url_white)
        return public.returnMsg(True, '添加成功!')

    def edit_reg_tions(self, get):
        '''
            修改地区限制
        :param id 记录的ID
        :param open 状态
        :param status 状态码
        :return:
        '''
        if not 'id' in get: return public.returnMsg(False, '请输入ID!')
        if not 'open' in get: return public.returnMsg(False, '请输入open!')
        if not 'status' in get: return public.returnMsg(False, '请输入status!')
        url_white = self.__get_rule('reg_tions')
        if len(url_white) < int(get.id): return public.returnMsg(False, '参数错误!')
        # open 如果是true 或者1 则是开启状态
        if get.open == "true" or get.open == "1":
            get.open = True
        else:
            get.open = False
        # 状态码只有200 404 403 444 502 503 504
        status_list = [200, 404, 403, 444, 502, 503, 504]
        if not int(get.status) in status_list: return public.returnMsg(False, '输入的状态码错误!')
        url_white[int(get.id)]['open'] = get.open
        url_white[int(get.id)]['status'] = int(get.status)
        self.__write_rule('reg_tions', url_white)
        return public.returnMsg(True, '修改成功!')

    def del_reg_tions(self, get):
        if not 'id' in get: return public.returnMsg(False, '请输入ID!')

        # if not 'site' in get: return public.returnMsg(False, '请输入需要设置的站点!')
        # if not 'types' in get: return public.returnMsg(False, '请输入类型!')
        # if not 'region' in get: return public.returnMsg(False, '请输入地区!')
        url_white = self.__get_rule('reg_tions')
        # param = get.region.split(",")
        # sitessss = get.site.split(",")
        # type_list = ["refuse", "accept"]
        # if not get.types in type_list: return public.returnMsg(False, '输入的类型错误!')
        # paramMode = {}
        # for i in param:
        #     if not i: continue
        #     if not i in paramMode:
        #         paramMode[i] = "1"
        # sitesMode = {}
        # for i in sitessss:
        #     if not i: continue
        #     if not i in sitesMode:
        #         sitesMode[i] = "1"
        # if len(paramMode) == 0: return public.returnMsg(False, '输入的请求类型错误!')
        # if len(sitesMode) == 0: return public.returnMsg(False, '输入的站点错误!')
        #
        # data = {"site": sitesMode, "types": get.types, "region": paramMode}
        # if not data in url_white: return public.returnMsg(False, '不存在!')
        # url_white.remove(data)
        if len(url_white) == 0: return public.returnMsg(False, '没有数据!')
        if len(url_white) < int(get.id): return public.returnMsg(False, '参数错误!')
        del (url_white[int(get.id)])

        self.__write_rule('reg_tions', url_white)
        return public.returnMsg(True, '删除成功!')

    def add_url_request_mode(self, get):
        if not 'url' in get: return public.returnMsg(False, '请输入url!')
        if not 'param' in get: return public.returnMsg(False, '请输入参数!')
        if not 'type' in get: return public.returnMsg(False, '请输入类型!')
        url_white = self.__get_rule('url_request_mode')
        param = get.param.split(",")
        paramlist = ["POST", "GET", "PUT", "OPTIONS", "HEAD", "DELETE", "TRACE", "PATCH", "MOVE", "COPY", "LINK",
                     "UNLINK", "WRAPPED", "PROPFIND", "PROPPATCH"
                                                      "MKCOL", "CONNECT", "SRARCH"]
        type_list = ["refuse", "accept"]
        if not get.type in type_list: return public.returnMsg(False, '输入的类型错误!')
        paramMode = {}
        for i in param:
            if i in paramlist:
                if not i in paramMode:
                    paramMode[i] = i
        if len(paramMode) == 0: return public.returnMsg(False, '输入的请求类型错误!')
        data = {"url": get.url, "type": get.type, "mode": paramMode}
        if data in url_white: return public.returnMsg(False, '已存在!')
        url_white.insert(0, data)
        self.__write_rule('url_request_mode', url_white)
        return public.returnMsg(True, '添加成功!')

    def del_url_request_mode(self, get):
        if not 'url' in get: return public.returnMsg(False, '请输入url!')
        if not 'param' in get: return public.returnMsg(False, '请输入参数!')
        if not 'type' in get: return public.returnMsg(False, '请输入类型!')
        url_white = self.__get_rule('url_request_mode')
        param = get.param.split(",")
        paramlist = ["POST", "GET", "PUT", "OPTIONS", "HEAD", "DELETE", "TRACE", "PATCH", "MOVE", "COPY", "LINK",
                     "UNLINK", "WRAPPED", "PROPFIND", "PROPPATCH"
                                                      "MKCOL", "CONNECT", "SRARCH"]
        type_list = ["refuse", "accept"]
        if not get.type in type_list: return public.returnMsg(False, '输入的类型错误!')
        paramMode = {}
        for i in param:
            if i in paramlist:
                if not i in paramMode:
                    paramMode[i] = i
        if len(paramMode) == 0: return public.returnMsg(False, '输入的请求类型错误!')
        data = {"url": get.url, "type": get.type, "mode": paramMode}
        if not data in url_white: return public.returnMsg(False, '已存在!')
        url_white.remove(data)
        self.__write_rule('url_request_mode', url_white)
        return public.returnMsg(True, '删除成功!')

    def url_white_add_param(self, get):
        url = get.url_rule.strip()
        # 获取到url 然后再获取参数
        uri = url.split('?')[0]
        url2 = url.replace(uri, "")
        ret = []
        if not url2.startswith("?"):
            return public.returnMsg(False, '未发现该URL存在参数!')
        else:
            # 去掉第一个字符串
            url2 = url2[1:]
            # 使用&分割字符串
            url2 = url2.split('&')
            # 遍历字符串
            for i in url2:
                i = i.split("=")
                if len(i) == 2:
                    ret.append(i[0])
        if not ret:
            return public.returnMsg(False, '未发现该URL存在参数!')
        if uri == "/":
            return public.returnMsg(False, '不允许添加URL为 [/] 的URL为白名单')
        get.url = uri
        get.param = json.dumps(ret)
        return self.add_url_white_senior(get)

    def wubao_url_white(self, get):
        if not 'http_log' in get:
            get.http_log = ''
        if not 'error_log' in get:
            get.error_log = ''
        if not 'param' in get:
            get.param = 0
        url_rule = ""

        if get.param == 0:
            url_white = self.__get_rule('url_white')
            url_rule = get.url_rule.strip()
            url_rule = '^' + url_rule.split('?')[0]
            if url_rule in url_white: return public.returnMsg(False, '您添加的URL已存在')
            if url_rule == '^/': return public.returnMsg(False, '不允许添加URL为 [/] 的URL为白名单')
            url_white.insert(0, url_rule)
            self.__write_rule('url_white', url_white)
            self.__write_log('添加url规则[' + url_rule + ']到URL白名单')
        else:
            if os.path.exists('/www/server/panel/data/userInfo.json'):
                try:
                    userInfo = json.loads(public.ReadFile('/www/server/panel/data/userInfo.json'))
                    url = "https://www.bt.cn/api/bt_waf/reportInterceptFail"
                    data = {"url": url_rule, "error_log": get.error_log, "http_log": get.http_log,
                            "access_key": userInfo['access_key'], "uid": userInfo['uid']}
                    public.httpPost(url, data)
                except:
                    pass

            return self.url_white_add_param(get)
        if os.path.exists('/www/server/panel/data/userInfo.json'):
            try:
                userInfo = json.loads(public.ReadFile('/www/server/panel/data/userInfo.json'))
                url = "https://www.bt.cn/api/bt_waf/reportInterceptFail"
                data = {"url": url_rule, "error_log": get.error_log, "http_log": get.http_log,
                        "access_key": userInfo['access_key'], "uid": userInfo['uid']}
                public.httpPost(url, data)
            except:
                pass
        return public.returnMsg(True, '添加成功!')

    def remove_url_white(self, get):
        url_white = self.__get_rule('url_white')
        index = int(get.index)
        url_rule = url_white[index]
        del (url_white[index])
        self.__write_rule('url_white', url_white)
        self.__write_log('从URL白名单删除URL规则[' + url_rule + ']');
        return public.returnMsg(True, '删除成功!');

    def add_url_black(self, get):
        url_white = self.__get_rule('url_black')
        url_rule = get.url_rule.strip()
        url_rule = url_rule.split('?')[0]
        if get.url_rule in url_white: return public.returnMsg(False, '您添加的URL已存在')
        url_white.insert(0, url_rule)
        self.__write_rule('url_black', url_white)
        self.__write_log('添加url规则[' + url_rule + ']到URL黑名单');
        return public.returnMsg(True, '添加成功!');

    def remove_url_black(self, get):
        url_white = self.__get_rule('url_black')
        index = int(get.index)
        url_rule = url_white[index]
        del (url_white[index])
        self.__write_rule('url_black', url_white)
        self.__write_log('从URL黑名单删除URL规则[' + url_rule + ']');
        return public.returnMsg(True, '删除成功!');

    def save_scan_rule(self, get):
        # return self.set_scan_conf(get)
        scan_rule = {'header': get.header, 'cookie': get.cookie, 'args': get.args}
        self.__write_rule('scan_black', scan_rule)
        self.__write_log('修改扫描器过滤规则');
        return public.returnMsg(True, '设置成功')

    def set_retry(self, get):
        config = self.get_config(None)
        end_time = int(get.retry_time)
        if end_time > 86400: return public.returnMsg(False, '封锁时间不能超过86400!');

        config['retry'] = int(get.retry)
        config['retry_cycle'] = int(get.retry_cycle)
        config['retry_time'] = int(get.retry_time)
        self.__write_config(config)
        self.__write_log(
            '设置非法请求容忍阈值: ' + get.retry_cycle + ' 秒内累计超过 ' + get.retry + ' 次, 封锁 ' + get.retry_time + ' 秒');
        if get.is_open_global:
            self.set_cc_retry_golbls(get)
        return public.returnMsg(True, '设置成功!');

    def set_site_retry(self, get):
        site_config = self.get_site_config(None)
        site_config[get.siteName]['retry'] = int(get.retry)
        site_config[get.siteName]['retry_cycle'] = int(get.retry_cycle)
        site_config[get.siteName]['retry_time'] = int(get.retry_time)
        self.__write_site_config(site_config)
        self.__write_log(
            '设置网站【' + get.siteName + '】非法请求容忍阈值: ' + get.retry_cycle + ' 秒内累计超过 ' + get.retry + ' 次, 封锁 ' + get.retry_time + ' 秒');
        return public.returnMsg(True, '设置成功!');

    def set_site_cdn_state(self, get):
        site_config = self.get_site_config(None)
        if site_config[get.siteName]['cdn']:
            site_config[get.siteName]['cdn'] = False
        else:
            site_config[get.siteName]['cdn'] = True
        self.__write_site_config(site_config)
        self.__write_log(self.__state[site_config[get.siteName]['cdn']] + '站点【' + get.siteName + '】CDN模式');
        return public.returnMsg(True, '设置成功!');

    def get_site_cdn_header(self, get):
        site_config = self.get_site_config(None)
        return site_config[get.siteName]['cdn_header']

    def add_site_cdn_header(self, get):
        site_config = self.get_site_config(None)
        get.cdn_header = get.cdn_header.strip().lower();
        if get.cdn_header in site_config[get.siteName]['cdn_header']: return public.returnMsg(False,
                                                                                              '您添加的请求头已存在!');
        site_config[get.siteName]['cdn_header'].insert(0, get.cdn_header)
        self.__write_site_config(site_config)
        self.__write_log('添加站点【' + get.siteName + '】CDN-Header【' + get.cdn_header + '】');
        return public.returnMsg(True, '添加成功!');

    def remove_site_cdn_header(self, get):
        site_config = self.get_site_config(None)
        get.cdn_header = get.cdn_header.strip().lower();
        if not get.cdn_header in site_config[get.siteName]['cdn_header']: return public.returnMsg(False,
                                                                                                  '指定请求头不存在!');
        for i in range(len(site_config[get.siteName]['cdn_header'])):
            if get.cdn_header == site_config[get.siteName]['cdn_header'][i]:
                self.__write_log(
                    '删除站点【' + get.siteName + '】CDN-Header【' + site_config[get.siteName]['cdn_header'][i] + '】');
                del (site_config[get.siteName]['cdn_header'][i])
                break;
        self.__write_site_config(site_config)
        return public.returnMsg(True, '删除成功!');

    def get_site_rule(self, get):
        site_config = self.get_site_config(None)
        return site_config[get.siteName][get.ruleName]

    def add_site_rule(self, get):
        site_config = self.get_site_config(None)
        if not get.ruleName in site_config[get.siteName]: return public.returnMsg(False, '指定规则不存在!');
        mt = type(site_config[get.siteName][get.ruleName])
        if mt == bool: return public.returnMsg(False, '指定规则不存在!');
        if mt == str: site_config[get.siteName][get.ruleName] = get.ruleValue
        if mt == list:
            if get.ruleName == 'url_rule' or get.ruleName == 'url_tell':
                for ruleInfo in site_config[get.siteName][get.ruleName]:
                    if ruleInfo[0] == get.ruleUri: return public.returnMsg(False, '指定URI已存在!');
                tmp = []
                get.ruleUri = get.ruleUri.split('?')[0]

                tmp.append(get.ruleUri)
                tmp.append(get.ruleValue)
                if get.ruleName == 'url_tell':
                    self.__write_log(
                        '添加站点【' + get.siteName + '】URI【' + get.ruleUri + '】保护规则,参数【' + get.ruleValue + '】,参数值【' + get.rulePass + '】');
                    tmp.append(get.rulePass)
                else:
                    self.__write_log(
                        '添加站点【' + get.siteName + '】URI【' + get.ruleUri + '】过滤规则【' + get.ruleValue + '】');
                site_config[get.siteName][get.ruleName].insert(0, tmp)
            else:
                if get.ruleValue in site_config[get.siteName][get.ruleName]: return public.returnMsg(False,
                                                                                                     '指定规则已存在!');
                site_config[get.siteName][get.ruleName].insert(0, get.ruleValue)
                self.__write_log('添加站点【' + get.siteName + '】【' + get.ruleName + '】过滤规则【' + get.ruleValue + '】');
        self.__write_site_config(site_config)
        return public.returnMsg(True, '添加成功!');

    def remove_site_rule(self, get):
        site_config = self.get_site_config(None)
        index = int(get.index)
        if not get.ruleName in site_config[get.siteName]: return public.returnMsg(False, '指定规则不存在!');
        site_rule = site_config[get.siteName][get.ruleName][index]
        del (site_config[get.siteName][get.ruleName][index])
        self.__write_site_config(site_config)
        self.__write_log('删除站点【' + get.siteName + '】【' + get.ruleName + '】过滤规则【' + json.dumps(site_rule) + '】');
        return public.returnMsg(True, '删除成功!');

    def get_cn_list(self, type):
        if type == 'ip_white' or type == 'ip_black' or type == 'cn':
            try:
                rule = self.__get_rule(type)
                for i in rule:
                    for i2 in range(len(i)):
                        if i2 >= 2: continue
                        i[i2] = self.long2ip(i[i2])
                return rule
            except:
                self.__write_rule(type, [])
                os.system('/etc/init.d/nginx restart')
                return []
        else:
            rule = self.__get_rule(type)
            for i in rule:
                for i2 in range(len(i)):
                    i[i2] = self.long2ip(i[i2])
            return rule

    def get_rule(self, get):
        if get.ruleName == 'cn':
            return self.get_cn_list('cn')
        if get.ruleName == 'ip_white':
            return self.get_cn_list('ip_white')
        if get.ruleName == 'ip_black':
            return self.get_cn_list('ip_black')
        if get.ruleName == 'spider':
            return self.spider(get)
        rule = self.__get_rule(get.ruleName)
        if not rule: return [];
        return rule

    def spider(self, get):
        if not 'spider' in get:
            get.spider = 'baidu'
        list_sp = ["baidu", "google", "360", "sogou", "yahoo", "bingbot", "bytespider", "shenma"]
        if not str(get.spider) in list_sp: return []
        list_index = list_sp.index(str(get.spider))
        try:
            path = "/www/server/btwaf/inc/" + str(list_index + 1) + '.json'
            rules = public.readFile(path)
            if not rules: return []
            return json.loads(rules)
        except:
            return []

    # spider添加删除
    def add_spider(self, get):
        if not 'ip' in get: return public.returnMsg(False, '请输入IP地址')
        if not 'spider' in get:
            get.spider = 'baidu'
        list_sp = ["baidu", "google", "360", "sogou", "yahoo", "bingbot", "bytespider", "shenma"]
        if not str(get.spider) in list_sp: return public.returnMsg(False, '蜘蛛类型错误!')
        list_index = list_sp.index(str(get.spider))
        path = "/www/server/btwaf/inc/" + str(list_index + 1) + '.json'
        try:
            rules = json.loads(public.readFile(path))
            if not rules:
                public.WriteFile(path, json.dumps([get.ip.strip()]))
                return public.returnMsg(True, '添加成功!')
            else:
                if get.ip.strip() in rules:
                    return public.returnMsg(False, '添加失败!')
                else:
                    rules.insert(0, get.ip.strip())
                    public.WriteFile(path, json.dumps(rules))
                    return public.returnMsg(True, '添加成功!')
        except:
            public.WriteFile(path, json.dumps([get.ip.strip()]))
            return public.returnMsg(True, '添加成功!')

    # spider删除
    def del_spider(self, get):
        if not 'ip' in get: return public.returnMsg(False, '请输入IP地址')
        if not 'spider' in get:
            get.spider = 'baidu'
        list_sp = ["baidu", "google", "360", "sogou", "yahoo", "bingbot", "bytespider", 'shenma']
        if not str(get.spider) in list_sp: return public.returnMsg(False, '蜘蛛类型错误!')
        list_index = list_sp.index(str(get.spider))
        path = "/www/server/btwaf/inc/" + str(list_index + 1) + '.json'
        try:
            rules = json.loads(public.readFile(path))
            if not rules:
                return public.returnMsg(True, '当前IP不存在!')
            else:
                if get.ip.strip() in rules:
                    rules.remove(get.ip.strip())
                    public.WriteFile(path, json.dumps(rules))
                    return public.returnMsg(True, '删除成功!')
                else:
                    return public.returnMsg(False, '当前IP不存在!')
        except:
            public.WriteFile(path, json.dumps([get.ip.strip()]))
            return public.returnMsg(True, '添加成功!')

    # spider导入
    def import_spider(self, get):
        if not 'ip_list' in get: return public.returnMsg(False, '请输入IP地址')
        if not 'spider' in get:
            get.spider = 'baidu'
        list_sp = ["baidu", "google", "360", "sogou", "yahoo", "bingbot", "bytespider", "shenma"]
        ip_list = json.loads(get.ip_list)
        if not str(get.spider) in list_sp: return public.returnMsg(False, '蜘蛛类型错误!')
        list_index = list_sp.index(str(get.spider))
        path = "/www/server/btwaf/inc/" + str(list_index + 1) + '.json'
        try:
            if len(ip_list) >= 1:
                for i in ip_list:
                    get.ip = i
                    self.add_spider(get)
                return public.returnMsg(True, '导入成功!')
        except:
            return public.returnMsg(False, '导入发生报错!')

    def add_rule(self, get):
        rule = self.__get_rule(get.ruleName)
        ruleValue = [1, get.ruleValue.strip(), get.ps, 1]
        for ru in rule:
            if ru[1] == ruleValue[1]: return public.returnMsg(False, '指定规则已存在，请勿重复添加');
        rule.append(ruleValue)
        self.__write_rule(get.ruleName, rule)
        self.__write_log('添加全局规则【' + get.ruleName + '】【' + get.ps + '】');
        return public.returnMsg(True, '添加成功!');

    def remove_rule(self, get):
        rule = self.__get_rule(get.ruleName)
        index = int(get.index)
        ps = rule[index][2]
        del (rule[index])
        self.__write_rule(get.ruleName, rule)
        self.__write_log('删除全局规则【' + get.ruleName + '】【' + ps + '】');
        return public.returnMsg(True, '删除成功!');

    def modify_rule(self, get):
        rule = self.__get_rule(get.ruleName)
        index = int(get.index)
        rule[index][1] = get.ruleBody
        rule[index][2] = get.rulePs
        self.__write_rule(get.ruleName, rule)
        self.__write_log('修改全局规则【' + get.ruleName + '】【' + get.rulePs + '】');
        return public.returnMsg(True, '修改成功!');

    def set_rule_state(self, get):
        rule = self.__get_rule(get.ruleName)
        index = int(get.index)
        if rule[index][0] == 0:
            rule[index][0] = 1;
        else:
            rule[index][0] = 0;
        self.__write_rule(get.ruleName, rule)
        self.__write_log(self.__state[rule[index][0]] + '全局规则【' + get.ruleName + '】【' + rule[index][2] + '】');
        return public.returnMsg(True, '设置成功!');

    def get_site_disable_rule(self, get):
        rule = self.__get_rule(get.ruleName)
        site_config = self.get_site_config(None)
        site_rule = site_config[get.siteName]['disable_rule'][get.ruleName]
        for i in range(len(rule)):
            if rule[i][0] == 0: rule[i][0] = -1;
            if i in site_rule: rule[i][0] = 0;
        return rule;

    def set_site_disable_rule(self, get):
        site_config = self.get_site_config(None)
        index = int(get.index)
        if index in site_config[get.siteName]['disable_rule'][get.ruleName]:
            for i in range(len(site_config[get.siteName]['disable_rule'][get.ruleName])):
                if index == site_config[get.siteName]['disable_rule'][get.ruleName][i]:
                    del (site_config[get.siteName]['disable_rule'][get.ruleName][i])
                    break
        else:
            site_config[get.siteName]['disable_rule'][get.ruleName].append(index)
        self.__write_log('设置站点【' + get.siteName + '】应用规则【' + get.ruleName + '】状态');
        self.__write_site_config(site_config)
        return public.returnMsg(True, '设置成功!');

    def get_safe_logs(self, get):
        try:
            import html
            pythonV = sys.version_info[0]
            if 'drop_ip' in get:
                path = '/www/server/btwaf/drop_ip.log'
                num = 12
                if os.path.getsize(path) > 209715200:
                    return {"status": False, "msg": "日志文件过大!", "clear": True}
            else:
                path = '/www/wwwlogs/btwaf/' + get.siteName + '_' + get.toDate + '.log'
                if os.path.getsize(path) > 1024 * 1024 * 10:
                    return {"status": False, "msg": "日志文件过大，建议去大屏查看！！！", "clear": True}
                num = 10

            if not os.path.exists(path): return ["11"]
            p = 1
            if 'p' in get:
                p = int(get.p)
            start_line = (p - 1) * num
            count = start_line + num
            fp = open(path, 'rb')
            buf = ""
            try:
                fp.seek(-1, 2)
            except:
                return []
            if fp.read(1) == "\n": fp.seek(-1, 2)
            data = []
            b = True
            n = 0
            c = 0
            while c < count:
                while True:
                    newline_pos = str.rfind(buf, "\n")
                    pos = fp.tell()
                    if newline_pos != -1:
                        if n >= start_line:
                            line = buf[newline_pos + 1:]
                            if line:
                                try:
                                    tmp_data = json.loads(line)
                                    host = ""
                                    for i in range(len(tmp_data)):
                                        if i == 6:
                                            tmp_data[i] = tmp_data[i].replace('gt;', '>')
                                        if len(tmp_data) > 6 and tmp_data[6]:
                                            tmp_data[6] = tmp_data[6].replace('gt;', '>').replace('&', '')
                                        if i == 7:
                                            tmp_data[i] = str(tmp_data[i]).replace('&amp;', '&').replace('&lt;',
                                                                                                         '<').replace(
                                                '&gt;', '>').replace("&quot;", "\"")
                                            if re.search('host:(.*?)\n', tmp_data[7]):
                                                host = re.search('host:(.*?)\n', tmp_data[7]).groups()[0]


                                        elif i == 10:
                                            tmp_data[i] = str(tmp_data[i]).replace('&amp;', '&').replace('&lt;',
                                                                                                         '<').replace(
                                                '&gt;', '>').replace("&quot;", "\"")
                                        else:
                                            tmp_data[i] = str(tmp_data[i])
                                    if host:
                                        tmp_data.append('http://' + host + tmp_data[3])
                                    data.append(tmp_data)
                                except:
                                    c -= 1
                                    n -= 1
                                    pass
                            else:
                                c -= 1
                                n -= 1
                        buf = buf[:newline_pos]
                        n += 1
                        c += 1
                        break
                    else:
                        if pos == 0:
                            b = False
                            break
                        to_read = min(4096, pos)
                        fp.seek(-to_read, 1)
                        t_buf = fp.read(to_read)
                        if pythonV == 3: t_buf = t_buf.decode('utf-8', errors="ignore")
                        buf = t_buf + buf
                        fp.seek(-to_read, 1)
                        if pos - to_read == 0:
                            buf = "\n" + buf
                if not b: break
            fp.close()
            if 'drop_ip' in get:
                drop_iplist = self.get_waf_drop_ip(None)
                stime = time.time()
                setss = []
                for i in range(len(data)):
                    if (float(stime) - float(data[i][0])) < float(data[i][4]):
                        setss.append(data[i][1])
                        data[i].append(data[i][1] in drop_iplist)
                    else:
                        data[i].append(False)
        except:
            data = []
            return public.get_error_info()
        return data

    def write_php_fpm_status(self):
        data = '''server {
	listen 80;
	server_name 127.0.0.1;
	allow 127.0.0.1;
	location /nginx_status {
		stub_status on;
		access_log off;
	}
	location /phpfpm_52_status {
		fastcgi_pass unix:/tmp/php-cgi-52.sock;
		include fastcgi_params;
		fastcgi_param SCRIPT_FILENAME $fastcgi_script_name;
	}
	location /phpfpm_53_status {
		fastcgi_pass unix:/tmp/php-cgi-53.sock;
		include fastcgi_params;
		fastcgi_param SCRIPT_FILENAME $fastcgi_script_name;
	}
	location /phpfpm_54_status {
		fastcgi_pass unix:/tmp/php-cgi-54.sock;
		include fastcgi_params;
		fastcgi_param SCRIPT_FILENAME $fastcgi_script_name;
	}
	location /phpfpm_55_status {
		fastcgi_pass unix:/tmp/php-cgi-55.sock;
		include fastcgi_params;
		fastcgi_param SCRIPT_FILENAME $fastcgi_script_name;
	}
	location /phpfpm_56_status {
		fastcgi_pass unix:/tmp/php-cgi-56.sock;
		include fastcgi_params;
		fastcgi_param SCRIPT_FILENAME $fastcgi_script_name;
	}
	location /phpfpm_70_status {
		fastcgi_pass unix:/tmp/php-cgi-70.sock;
		include fastcgi_params;
		fastcgi_param SCRIPT_FILENAME $fastcgi_script_name;
	}
	location /phpfpm_71_status {
		fastcgi_pass unix:/tmp/php-cgi-71.sock;
		include fastcgi_params;
		fastcgi_param SCRIPT_FILENAME $fastcgi_script_name;
	}
	location /phpfpm_72_status {
		fastcgi_pass unix:/tmp/php-cgi-72.sock;
		include fastcgi_params;
		fastcgi_param SCRIPT_FILENAME $fastcgi_script_name;
	}
	location /phpfpm_73_status {
		fastcgi_pass unix:/tmp/php-cgi-73.sock;
		include fastcgi_params;
		fastcgi_param SCRIPT_FILENAME $fastcgi_script_name;
	}
	location /phpfpm_74_status {
		fastcgi_pass unix:/tmp/php-cgi-74.sock;
		include fastcgi_params;
		fastcgi_param SCRIPT_FILENAME $fastcgi_script_name;
	}
	location /phpfpm_75_status {
		fastcgi_pass unix:/tmp/php-cgi-75.sock;
		include fastcgi_params;
		fastcgi_param SCRIPT_FILENAME $fastcgi_script_name;
	}
}
'''
        public.writeFile('/www/server/panel/vhost/nginx/phpfpm_status.conf', data)
        # 检测nginx的配置文件是否有错误
        isError = public.checkWebConfig()
        if isError != True:
            if os.path.exists('/www/server/panel/vhost/nginx/phpfpm_status.conf'): os.remove(
                '/www/server/panel/vhost/nginx/phpfpm_status.conf')
            return
        public.serviceReload()

    def HttpGet(self, url, timeout=3):
        """
            @name 发送GET请求
            @author hwliang<hwl@bt.cn>
            @url 被请求的URL地址(必需)
            @timeout 超时时间默认60秒
            @return string
        """
        if not os.path.exists("/www/server/panel/vhost/nginx/phpfpm_status.conf"):
            # 加这个文件
            self.write_php_fpm_status()
            time.sleep(0.5)

        import requests
        config = self.get_config(None)
        toekn = config["access_token"]
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36",
            "btwaf-access-token": toekn
        }
        res = requests.get(url, timeout=timeout, headers=headers)
        if res.status_code == 0:
            s_body = res.text
            return s_body
        s_body = res.text
        del res
        return s_body

    def get_waf_drop_ip(self, get):
        try:
            config = self.get_config(None)
            data = json.loads(self.HttpGet('http://127.0.0.1/get_btwaf_drop_ip'))
            if len(data) == 0:
                return []
            return data
        except:
            return []

    def get_logs_list(self, get):
        path = '/www/wwwlogs/btwaf/'
        sfind = get.siteName + '_'
        data = []
        for fname in os.listdir(path):
            if fname.find(sfind) != 0: continue;
            tmp = fname.replace(sfind, '').replace('.log', '')

            # 判断是否符合时间格式
            if not re.match(r'^\d{4}-\d{2}-\d{2}$', tmp):
                continue
            data.append(tmp)
        return sorted(data, reverse=True)

    def remove_waf_drop_ip(self, get):
        public.WriteFile('/dev/shm/.bt_ip_filter', '-,' + get.ip.strip())
        try:
            self.M2('blocking_ip').field('time,ip,is_status').where("ip=? and time>=?",
                                                                    (get.ip.strip(), int(time.time()) - 86400)).update(
                {"is_status": "0"})
        except:
            pass
        try:
            config = self.get_config(None)
            toekn = config["access_token"]
            data = json.loads(self.HttpGet('http://127.0.0.1/remove_btwaf_drop_ip?ip=' + get.ip))
            self.__write_log('从防火墙解封IP【' + get.ip + '】')
            return data
        except:
            public.WriteFile('/dev/shm/.bt_ip_filter', '-,' + get.ip.strip())
            return public.returnMsg(False, '获取数据失败');

    def clean_waf_drop_ip(self, get):
        public.WriteFile("/dev/shm/.bt_ip_filter", "-,0.0.0.0")
        try:
            self.M2('blocking_ip').field('time,ip,is_status').where("time>=?", (int(time.time()) - 86400)).update(
                {"is_status": "0"})
        except:
            pass
        # try:
        public.WriteFile("/dev/shm/.bt_ip_filter", "-,0.0.0.0")
        try:
            datas = public.ExecShell("ipset list |grep timeout")[0].split("\n")
            if len(datas) != 3:
                public.WriteFile("/dev/shm/.bt_ip_filter", "-,0.0.0.0")
                public.ExecShell("/etc/init.d/bt_ipfilter restart")
        except:
            pass
        # try:
        self.__write_log('从防火墙解封所有IP')
        config = self.get_config(None)
        toekn = config["access_token"]
        data = json.loads(self.HttpGet('http://127.0.0.1/clean_btwaf_drop_ip'))
        for i in self.get_cn_list('ip_black'):
            ipn = [i[0], i[1]]
            iplist = self.get_cn_list('ip_white')
            if ipn in iplist: continue
            self.bt_ip_filter("+,%s-%s,86400" % (i[0], i[1]))
        return data
        # except:
        #     public.WriteFile("/dev/shm/.bt_ip_filter", "-,0.0.0.0")
        #     return public.returnMsg(False, '获取数据失败')

    def get_gl_logs(self, get):
        import page
        page = page.Page()
        if 'search' in get and get.search:
            count = public.M('logs').where("type=? and log LIKE ?", (u'网站防火墙', "%{}%".format(get.search),)).count()
        else:
            count = public.M('logs').where('type=?', (u'网站防火墙',)).count()
        limit = 12;
        info = {}
        info['count'] = count
        info['row'] = limit
        info['p'] = 1
        if hasattr(get, 'p'):
            info['p'] = int(get['p'])
        info['uri'] = get
        info['return_js'] = ''
        if hasattr(get, 'tojs'):
            info['return_js'] = get.tojs

        data = {}

        # 获取分页数据
        data['page'] = page.GetPage(info, '1,2,3,4,5,8');
        if 'search' in get and get.search:
            data['data'] = public.M('logs').where("type=? and log LIKE ?",
                                                  (u'网站防火墙', "%{}%".format(get.search),)).order('id desc').limit(
                str(page.SHIFT) + ',' + str(page.ROW)).field('log,addtime').select()
        else:
            data['data'] = public.M('logs').where('type=?', (u'网站防火墙',)).order('id desc').limit(
                str(page.SHIFT) + ',' + str(page.ROW)).field('log,addtime').select()
        return data

    def get_total(self, get):
        # total = json.loads(public.readFile(self.__path + 'total.json'))
        try:
            total = json.loads(public.readFile(self.__path + 'total.json'))
        except:
            total = {"rules": {"user_agent": 0, "cookie": 0, "post": 0, "args": 0, "url": 0, "cc": 0}, "sites": {},
                     "total": 0}
            self.__write_total(total)
        if len(total) == 0:
            total = {"rules": {"user_agent": 0, "cookie": 0, "post": 0, "args": 0, "url": 0, "cc": 0}, "sites": {},
                     "total": 0}
        if 'rules' in total and type(total['rules']) != dict:
            new_rules = {}
            for rule in total['rules']:
                new_rules[rule['key']] = rule['value'];
            total['rules'] = new_rules;
            self.__write_total(total);
        total['rules'] = self.__format_total(total['rules'])
        return total;

    def __format_total(self, total):
        total['get'] = 0;
        if 'args' in total:
            total['get'] += total['args'];
            del (total['args'])
        if 'url' in total:
            total['get'] += total['url'];
            del (total['url'])
        cnkey = [
            ['sql', u'sql注入拦截'],
            ['xss', u'xss拦截'],
            ['cc', u"CC拦截"],
            ['user_agent', u'恶意爬虫拦截'],
            ['cookie', u'Cookie渗透'],
            ['scan', u'恶意扫描拦截'],
            ['upload', u'文件上传拦截'],
            ['path_php', u'禁止PHP脚本拦截'],
            ['download', u'恶意下载拦截'],
            ["smart_cc", "智能CC"],
            ['drop_abroad', u'禁国外'],
            ['file', u'目录拦截'],
            ['php', u'php代码拦截'],
            ['other', u'自定义拦截'],
            ['file_import', "文件包含"],
            ['path', "站点URL黑名单"],
            ['url_tell', "受保护的URL"],
            ["url_rule", "URL专用过滤"]

        ]
        data = []
        for ck in cnkey:
            tmp = {}
            tmp['name'] = ck[1]
            tmp['key'] = ck[0]
            tmp['value'] = 0;
            if ck[0] in total: tmp['value'] = total[ck[0]]
            data.append(tmp)
        return data

    def get_btwaf(self):
        from BTPanel import session, cache
        import panelAuth
        if self.__session_name in session: return session[self.__session_name]
        cloudUrl = 'http://127.0.0.1/api/panel/get_soft_list'
        pdata = panelAuth.panelAuth().create_serverid(None)
        ret = public.httpPost(cloudUrl, pdata)
        if not ret:
            if not self.__session_name in session: session[self.__session_name] = 1
            return 1
        try:
            ret = json.loads(ret)
            for i in ret["list"]:
                if i['name'] == 'btwaf':
                    if i['endtime'] >= 0:
                        if not self.__session_name in session: session[self.__session_name] = 2;
                        return 2
            if not self.__session_name in session: session[self.__session_name] = 0;
            return 0
        except:
            if not self.__session_name in session: session[self.__session_name] = 1;
            return 1

    # stop config
    def stop(self):
        return True

    def test_check_zhilist(self, get):
        try:
            flag = False
            # 如果文件存在
            Itime_path = '/www/server/panel/data/btwaf_getSpiders.ini'
            startime = int(time.time())
            if os.path.exists(Itime_path):
                Itime = int(public.ReadFile(Itime_path))
                if startime - Itime > 36000:
                    flag = True
            else:
                flag = True
            if flag:
                public.WriteFile(Itime_path, str(startime))
                userInfo = json.loads(public.ReadFile('/www/server/panel/data/userInfo.json'))
                data22 = {"access_key": userInfo['access_key'], "uid": userInfo['uid']}
                url = public.GetConfigValue('home')+'/api/bt_waf/getSpiders'
                data_list = json.loads(public.httpPost(url, data22, timeout=3))
                if data_list:
                    for i22 in data_list:
                        try:
                            path = "/www/server/btwaf/%s.json" % i22
                            if os.path.exists(path):
                                ret = json.loads(public.ReadFile(path))
                                localhost_json = list(set(ret).union(data_list[i22]))
                                public.WriteFile(path, json.dumps(localhost_json))
                        except:
                            continue
        except:
            return []

    def return_python(self):
        if os.path.exists('/www/server/panel/pyenv/bin/python'): return '/www/server/panel/pyenv/bin/python'
        if os.path.exists('/usr/bin/python'): return '/usr/bin/python'
        if os.path.exists('/usr/bin/python3'): return '/usr/bin/python3'
        return 'python'

    # 四层计划任务
    def add_webshell_check(self):
        id = public.M('crontab').where('name=?', (u'【官方】Nginx防火墙木马扫描进程',)).getField('id')
        import crontab
        if not id:
            data = {}
            data['name'] = '【官方】Nginx防火墙木马扫描进程'
            data['type'] = 'minute-n'
            data['where1'] = '5'
            data['sBody'] = '%s /www/server/panel/plugin/btwaf/webshell_check.py' % self.return_python()
            data['backupTo'] = 'localhost'
            data['sType'] = 'toShell'
            data['hour'] = ''
            data['minute'] = '0'
            data['week'] = ''
            data['sName'] = ''
            data['urladdress'] = ''
            data['save'] = ''
            crontab.crontab().AddCrontab(data)
        return True

    def get_webshell_size(self):
        rPath = self.Recycle_bin
        if not os.path.exists(rPath): return 0
        # 循环这个目录下的所有文件
        count = 0
        for root, dirs, files in os.walk(rPath):
            if files:
                for name in files:
                    count += 1
        return count

    def get_webshell_info(self, get):
        ret = []
        try:
            webshell_info = json.loads(public.ReadFile("/www/server/btwaf/webshell.json"))

            for i in webshell_info:
                result = {}
                result['path'] = i
                result['is_path'] = webshell_info[i]
                ret.append(result)
            return ret
        except:
            return []

    #
    # def get_total_all(self,get):
    #     if public.cache_get("get_total_all"):
    #         public.run_thread(self.get_total_all_info,get)
    #         return public.cache_get("get_total_all")
    #     else:
    #         return self.get_total_all_info(get)

    def check_zhiz(self, get):
        zhizhu_list = ['1', '2', '4', '5', '6']
        for i in zhizhu_list:
            try:
                if os.path.getsize('/www/server/btwaf/zhizhu' + i + '.json') > 10:
                    f = open('/www/server/btwaf/zhizhu' + i + '.json', 'r')
                    tt = []
                    for i2 in f:
                        i2 = i2.strip()
                        tt.append(i2)
                    f.close()
                    userInfo = json.loads(public.ReadFile('/www/server/panel/data/userInfo.json'))
                    data22 = {"type": i, "ip_list": json.dumps(tt), "access_key": userInfo['access_key'],
                              "uid": userInfo['uid']}
                    url = public.GetConfigValue('home')+'/api/bt_waf/addSpider'
                    if len(tt) >= 1:
                        public.httpPost(url, data22)
                    public.WriteFile('/www/server/btwaf/zhizhu' + i + '.json', "")
            except:
                continue

    def create_db(self):
        start_path = time.strftime("%Y-%m-%d_%H_%M_%S", time.localtime(time.time()))
        path = "/www/server/btwaf/totla_db/totla_db.db"
        http_log = "/www/server/btwaf/totla_db/http_log/"
        # 重命名文件、然后压缩
        if os.path.exists(path):
            cmd_str = '''http_log=/www/server/btwaf/totla_db
        mv $http_log/totla_db.db $http_log/totla_db.db.bak
        tar -zcf $http_log/totla_db_{}.tar.gz $http_log/totla_db.db.bak
        rm -rf $http_log/totla_db.db.bak
        rm -rf $http_log/totla_db_bak.sh'''.format(start_path)
            public.WriteFile("/www/server/btwaf/totla_db/totla_db_bak.sh", cmd_str)
            os.system("nohup bash /www/server/btwaf/totla_db/totla_db_bak.sh >/dev/null 2>&1 &".format(start_path))
        if os.path.exists(http_log):
            cmd_str = '''http_log=/www/server/btwaf/totla_db
        mv $http_log/http_log $http_log/http_log_bak 
        mkdir $http_log/http_log 
        chown www:www $http_log/http_log
        tar -zcf $http_log/http_log_{}.tar.gz $http_log/http_log_bak 
        rm -rf $http_log/http_log_bak
        rm -rf $http_log/http_log_bak.sh'''.format(start_path)
            public.WriteFile("/www/server/btwaf/totla_db/http_log_bak.sh", cmd_str)
            os.system("nohup bash /www/server/btwaf/totla_db/http_log_bak.sh >/dev/null 2>&1 &".format(start_path))
        time.sleep(0.5)
        # os.system("mkdir %s && chown -R www:www %s" % (http_log, http_log))
        totle_db2.Sql().execute("PRAGMA synchronous = 0")
        totle_db2.Sql().execute("PRAGMA page_size = 4096")
        totle_db2.Sql().execute("PRAGMA journal_mode = wal")
        totle_db2.Sql().execute("PRAGMA journal_size_limit = 1073741824")
        totle_db2.Sql().execute('''CREATE TABLE btwaf_msg (
    				id INTEGER PRIMARY KEY AUTOINCREMENT,
    				server_name TEXT,
    				time INTEGER,
    				time_localtime TEXT,
    		)''')
        totle_db2.Sql().execute('''CREATE TABLE totla_log (
    				id INTEGER PRIMARY KEY AUTOINCREMENT,
    				time INTEGER,
    				time_localtime TEXT,
    				server_name TEXT,
    				ip TEXT,
    				ip_city TEXT,
    				ip_country TEXT,
    				ip_subdivisions TEXT,
    				ip_continent TEXT,
    				ip_longitude TEXT,
    				ip_latitude TEXT,
    				type TEXT,
    				uri TEXT,
    				user_agent TEXT,
    				filter_rule TEXT,
    				incoming_value TEXT,
    			    value_risk TEXT,
    				http_log TEXT,
    				http_log_path INTEGER
    			)''')
        totle_db2.Sql().execute("CREATE INDEX time_inx ON totla_log(time)")
        totle_db2.Sql().execute("CREATE INDEX time_localtime_inx ON totla_log(time_localtime)")
        totle_db2.Sql().execute("CREATE INDEX server_name_inx ON totla_log(server_name)")
        totle_db2.Sql().execute("CREATE INDEX ip_ipx ON totla_log(ip)")
        totle_db2.Sql().execute("CREATE INDEX type_inx ON totla_log(type)")
        totle_db2.Sql().execute("CREATE INDEX filter__inx ON totla_log(filter_rule)")
        totle_db2.Sql().execute("CREATE INDEX ip_country_inx ON totla_log(ip_country)")

        totle_db2.Sql().execute('''CREATE TABLE blocking_ip (
    				id INTEGER PRIMARY KEY AUTOINCREMENT,
    			    time INTEGER,
    				time_localtime TEXT,
    				server_name TEXT,
    				ip TEXT,
    				ip_city TEXT,
    				ip_country TEXT,
    				ip_subdivisions TEXT,
    				ip_continent TEXT,
    				ip_longitude TEXT,
    				ip_latitude TEXT,
    				type TEXT,
    				uri TEXT,
    				user_agent TEXT,
    				filter_rule TEXT,
    				incoming_value TEXT,
    			    value_risk TEXT,
    				http_log TEXT,
    				http_log_path INTEGER,
    				blockade TEXT,
    				blocking_time INTEGER,
    				is_status INTEGER
    			)''')
        totle_db2.Sql().execute("CREATE INDEX time_ip ON blocking_ip(time)")
        totle_db2.Sql().execute("CREATE INDEX time_localtime_ip ON blocking_ip(time_localtime)")
        totle_db2.Sql().execute("CREATE INDEX server_name_ip ON blocking_ip(server_name)")
        totle_db2.Sql().execute("CREATE INDEX ip_ip ON blocking_ip(ip)")
        totle_db2.Sql().execute("CREATE INDEX blocking_ip ON blocking_ip(blocking_time)")
        totle_db2.Sql().execute("CREATE INDEX is_statu_ip ON blocking_ip(is_status)")
        os.system('chown www:www /www/server/btwaf/totla_db/totla_db.db')

    def db_5000(self, get):
        if os.path.exists("/www/wwwlogs/btwaf_debug.log") and os.path.getsize(
                "/www/wwwlogs/btwaf_debug.log") > 506897664:
            public.ExecShell("rm -rf /www/wwwlogs/btwaf_debug.log")
        if os.path.exists("/www/server/btwaf/totla_db/totla_db.db") and os.path.getsize(
                "/www/server/btwaf/totla_db/totla_db.db") > 506897664:
            # 直接重命名文件
            # public.ExecShell("rm -rf /www/server/btwaf/totla_db/totla_db.db.bak && mv /www/server/btwaf/totla_db/totla_db.db /www/server/btwaf/totla_db/totla_db.db.bak")
            # path="/www/server/btwaf/totla_db/totla_db.db"
            # os.rename(path, path + ".bak")
            # start_path = time.strftime("%Y-%m-%d_%H_%M_%S", time.localtime(time.time()))
            # cmd_str = "cd /www/server/btwaf/totla_db/ &&  tar -zcf totla_db_{}.tar.gz totla_db.db.bak && rm -rf totla_db.db.bak && rm -rf totla_db_bak.sh".format(
            #     start_path)
            # public.WriteFile("/www/server/btwaf/totla_db/totla_db_bak.sh", cmd_str)
            # os.system("cd /www/server/btwaf/totla_db/ && nohup bash totla_db_bak.sh >/dev/null 2>&1 &".format(start_path))
            self.create_db()

            # 压缩

            # 大于500M的时候压缩文件
            # 获取一下配置文件
            # data_path = '/www/server/panel/data/btwaf_db_file.json'
            # datas = []
            # if os.path.exists(data_path):
            #     try:
            #         datas = json.loads(public.ReadFile(data_path))
            #     except:
            #         pass
            # path = "/www/server/btwaf/totla_db/db.{}.tar.gz".format(time.strftime("%Y-%m-%d"))
            # if not datas:
            #     datas.append({"path": path, "time": time.strftime("%Y-%m-%d")})
            # else:
            #     # 备份最多报错7份
            #     tmp = []
            #     if len(datas) >= 3:
            #         for i in datas:
            #             tmp.append(i['time'])
            #         tmp.sort()
            #         datas.remove({"path": "/www/server/btwaf/totla_db/db.{}.tar.gz".format(tmp[0]), "time": tmp[0]})
            #         public.ExecShell("rm -rf  /www/server/btwaf/totla_db/db.{}.tar.gz".format(tmp[0]))
            #     if {"path": path, "time": time.strftime("%Y-%m-%d")} in datas:
            #         # 如果存在在配置文件中 再判断一下文件是否存在。 如果文件存在 就可以删除源文件了。如果文件不存在那么就不删除源文件
            #         if os.path.exists(path):
            #             public.ExecShell("rm -rf /www/server/btwaf/totla_db/totla_db.*")
            # public.WriteFile(data_path, json.dumps(datas))
            # import files
            # file = files.files()
            # args_obj = public.dict_obj()
            # args_obj.sfile = "totla_db.db"
            # args_obj.dfile = path
            # args_obj.z_type = "tar.gz"
            # args_obj.path = "/www/server/btwaf/totla_db/"
            # file.Zip(args_obj)

    def get_total_all(self, get):
        # self.__check_cjson()
        # self.add_webshell_check()

        nginxconf = '/www/server/nginx/conf/nginx.conf'
        if not os.path.exists(nginxconf): return public.returnMsg(False, '只支持nginx服务器');
        # if public.readFile(nginxconf).find('luawaf.conf') == -1: return public.returnMsg(False,
        # '当前nginx不支持防火墙,请重装nginx');
        data = {}
        data['total'] = self.get_total(None)
        data['webshell'] = self.get_webshell_size()
        del (data['total']['sites'])
        data['drop_ip'] = []
        get.open_btwaf_webshell = 1
        data['open'] = self.get_config(get)['open']
        conf = self.get_config(None)
        data['safe_day'] = 0
        if 'start_time' in conf:
            if conf['start_time'] != 0: data['safe_day'] = int((time.time() - conf['start_time']) / 86400)
            session_id = self.__get_md5(time.strftime('%Y-%m-%d'))
            if not os.path.exists('/www/server/btwaf/config.json') or not os.path.exists(
                    '/www/server/btwaf/config.lua'):
                self.__write_config(conf)
            os.chdir('/www/server/panel')
            try:
                from BTPanel import session
                if not session_id in session:
                    self.__write_config(conf)
                    self.__write_site_domains()
                    session[session_id] = 111
            except:

                self.__write_config(conf)
                self.__write_site_domains()

        # public.run_thread(self.test_check_zhilist(None))
        # 判断是否存在其他的蜘蛛
        # public.run_thread(self.check_zhiz(None))
        public.run_thread(self.db_5000(None))
        return data

    def stop_nps(self, get):
        public.WriteFile("data/btwaf_nps.pl", "")
        return public.returnMsg(True, '关闭成功')

    def get_nps_questions(self):
        try:
            import requests
            api_url = public.GetConfigValue('home')+'/panel/notpro'
            user_info = json.loads(public.ReadFile("{}/data/userInfo.json".format(public.get_panel_path())))
            data = {
                "uid": user_info['uid'],
                "access_key": user_info['access_key'],
                "serverid": user_info['serverid'],
                "product_type": 1
            }

            result = requests.post(api_url, data=data, timeout=10).json()
            if result['res']:
                public.WriteFile('data/get_nps_questions.json', json.dumps(result['res']))
        except:
            public.WriteFile('data/get_nps_questions.json', json.dumps([{
                "id": "NKORxSVqUMjc0YjczNTUyMDFioPLiIoT",
                "question": "当初购买防火墙是解决什么问题？什么事件触发的？",
                "hint": "如：购买时是想预防网站以后被攻击。",
                "required": 1
            }, {
                "id": "dFMoTKffBMmM0YjczNTUyMDM0HugtbUY",
                "question": "您在使用防火墙过程中出现最多的问题是什么？",
                "hint": "如：开启后还是被入侵，然后后续怎么去处理？",
                "required": 1
            }, {
                "id": "dnWeQbiHJMmI4YjczNTUyMDJhurmpsfs",
                "question": "谈谈您对防火墙的建议。",
                "hint": "如：我希望防火墙能防御多台服务器。天马行空，说说您的想法。",
                "required": 1
            }]))

    def get_questions(self, get):
        if os.path.exists('data/get_nps_questions.json'):
            try:
                result = json.loads(public.ReadFile('data/get_nps_questions.json'))
            except:
                result = [{
                    "id": "NKORxSVqUMjc0YjczNTUyMDFioPLiIoT",
                    "question": "当初购买防火墙是解决什么问题？什么事件触发的？",
                    "hint": "如：购买时是想预防网站以后被攻击。",
                    "required": 1
                }, {
                    "id": "dFMoTKffBMmM0YjczNTUyMDM0HugtbUY",
                    "question": "您在使用防火墙过程中出现最多的问题是什么？",
                    "hint": "如：开启后还是被入侵，然后后续怎么去处理？",
                    "required": 1
                }, {
                    "id": "dnWeQbiHJMmI4YjczNTUyMDJhurmpsfs",
                    "question": "谈谈您对防火墙的建议。",
                    "hint": "如：我希望防火墙能防御多台服务器。天马行空，说说您的想法。",
                    "required": 1
                }]

        return public.returnMsg(True, result)

    def get_nps(self, get):
        data = {}
        conf = self.get_config(None)
        data['safe_day'] = 0
        if conf['start_time'] != 0: data['safe_day'] = int((time.time() - conf['start_time']) / 86400)
        if not os.path.exists("data/btwaf_nps.pl"):
            # 如果安全运行天数大于5天 并且没有没有填写过nps的信息
            data['nps'] = False
            public.run_thread(self.get_nps_questions, ())
            if os.path.exists("data/btwaf_nps_count.pl"):
                # 读取一下次数
                count = public.ReadFile("data/btwaf_nps_count.pl")
                if count:
                    count = int(count)
                    public.WriteFile("data/btwaf_nps_count.pl", str(count + 1))
                    data['nps_count'] = count + 1
            else:
                public.WriteFile("data/btwaf_nps_count.pl", "1")
                data['nps_count'] = 1
        else:
            data['nps'] = True
        return data

    def write_nps(self, get):
        '''
            @name nps 提交
            @param rate 评分
            @param feedback 反馈内容

        '''
        import json, requests
        api_url = public.GetConfigValue('home')+'/panel/notpro'
        user_info = json.loads(public.ReadFile("{}/data/userInfo.json".format(public.get_panel_path())))
        if 'rate' not in get:
            return public.returnMsg(False, "参数错误")
        if 'feedback' not in get:
            get.feedback = ""
        if 'phone_back' not in get:
            get.phone_back = 0
        else:
            if get.phone_back == 1:
                get.phone_back = 1
            else:
                get.phone_back = 0

        if 'questions' not in get:
            return public.returnMsg(False, "参数错误")

        try:
            get.questions = json.loads(get.questions)
        except:
            return public.returnMsg(False, "参数错误")

        data = {
            "uid": user_info['uid'],
            "access_key": user_info['access_key'],
            "serverid": user_info['serverid'],
            "product_type": 1,
            "rate": get.rate,
            "feedback": get.feedback,
            "phone_back": get.phone_back,
            "questions": json.dumps(get.questions)
        }
        try:
            requests.post(api_url, data=data, timeout=10).json()
            public.WriteFile("data/btwaf_nps.pl", "1")
        except:
            pass
        return public.returnMsg(True, "提交成功")

    # 取当站点前运行目录
    def GetSiteRunPath(self, id):
        siteName = public.M('sites').where('id=?', (id,)).getField('name');
        sitePath = public.M('sites').where('id=?', (id,)).getField('path');
        path = sitePath;
        if public.get_webserver() == 'nginx':
            filename = '/www/server/panel/vhost/nginx/' + siteName + '.conf'
            if os.path.exists(filename):
                conf = public.readFile(filename)
                rep = '\s*root\s*(.+);'
                tmp1 = re.search(rep, conf)
                if tmp1: path = tmp1.groups()[0];
        runPath = ''
        if sitePath == path:
            pass
        else:
            runPath = path.replace(sitePath, '');
        if runPath == '/':
            return ''
        return runPath

    def __write_site_domains(self):
        public.run_thread(self.write_site_domains, ())

    def write_site_domains(self):
        sites = public.M('sites').field('name,id,path').select()
        my_domains = []
        for my_site in sites:
            tmp = {}
            tmp['name'] = my_site['name']
            tmp_domains = public.M('domain').where('pid=?', (my_site['id'],)).field('name').select()
            tmp['domains'] = []
            for domain in tmp_domains:
                tmp['domains'].append(domain['name'])
            binding_domains = public.M('binding').where('pid=?', (my_site['id'],)).field('domain').select()
            for domain in binding_domains:
                tmp['domains'].append(domain['domain'])
            my_domains.append(tmp)
        # try:
        from btdockerModel import dk_public as dp
        docker_sites = dp.sql("docker_sites").field("name,id,path").select()
        for my_site in docker_sites:
            tmp = {}
            tmp['name'] = my_site['name']
            tmp_domains = dp.sql('docker_domain').where('pid=?', (my_site['id'],)).field('name').select()
            tmp['domains'] = []
            for domain in tmp_domains:
                tmp['domains'].append(domain['name'])
            my_domains.append(tmp)
        # except:
        #     pass

        public.writeFile(self.__path + '/domains.json', json.dumps(my_domains))
        return my_domains

    def sync_cnlist(self, get):
        if get: return public.returnMsg(True, '同步成功!')

    def get_python_dir(self):
        if os.path.exists('/www/server/panel/pyenv/bin/python'):
            return '/www/server/panel/pyenv/bin/python'
        if os.path.exists('/usr/bin/python'):
            return '/usr/bin/python'
        else:
            return 'python'

    # # 设置自动同步
    def webshell_check(self):
        import crontab
        id = public.M('crontab').where('name=?', (u'Nginx防火墙木马查杀进程请勿删除',)).count()
        if id == 1:
            # 如果小于10分钟就修改计划任务
            info = public.M('crontab').where('name=?', (u'Nginx防火墙木马查杀进程请勿删除',)).field("id,where1").find()
            if 'where1' in info:
                # 判断是否为数字
                if not info['where1'].isdigit():
                    return
                if int(info['where1']) < 20:
                    # 修改计划任务
                    data = {}
                    data['name'] = u'Nginx防火墙木马查杀进程请勿删除'
                    data['type'] = 'minute-n'
                    data['where1'] = '20'
                    data['sBody'] = self.get_python_dir() + ' /www/server/panel/plugin/btwaf/webshell_check.py'
                    data['backupTo'] = ''
                    data['sType'] = 'toShell'
                    data['hour'] = ''
                    data['minute'] = ''
                    data['week'] = ''
                    data['sName'] = ''
                    data['urladdress'] = ''
                    data['save'] = ''
                    data['id'] = info['id']
                    crontab.crontab().modify_crond(data)
            return
        else:
            if id > 1:
                info = public.M('crontab').where('name=?', (u'Nginx防火墙木马查杀进程请勿删除',)).select()
                for i in info:
                    data = {}
                    data['id'] = i['id']
                    crontab.crontab().DelCrontab(data)
        data = {}
        data['name'] = u'Nginx防火墙木马查杀进程请勿删除'
        data['type'] = 'minute-n'
        data['where1'] = '20'
        data['sBody'] = self.get_python_dir() + ' /www/server/panel/plugin/btwaf/webshell_check.py'
        data['backupTo'] = ''
        data['sType'] = 'toShell'
        data['hour'] = ''
        data['minute'] = ''
        data['week'] = ''
        data['sName'] = ''
        data['urladdress'] = ''
        data['save'] = ''
        crontab.crontab().AddCrontab(data)
        return True

    def __get_rule(self, ruleName):
        path = self.__path + 'rule/' + ruleName + '.json';
        rules = public.readFile(path)
        if not rules: return False
        return json.loads(rules)

    def __write_rule(self, ruleName, rule):
        path = self.__path + 'rule/' + ruleName + '.json';
        public.writeFile(path, json.dumps(rule))
        # public.writeFile(self.__path + 'rule/' + ruleName + '.lua','return '+self.__to_lua_table.makeLuaTable((rule)))
        public.serviceReload();

    def __check_site(self, site_config):
        sites = public.M('sites').field('name').select()
        if os.path.exists("/www/server/panel/data/docker.db"):
            try:
                from btdockerModel import dk_public as dp
                docker_sites = dp.sql("docker_sites").field("name").select()
                if type(docker_sites) == list:
                    for i in docker_sites:
                        sites.append(i)
            except:
                pass
        if type(sites) != list: return;
        siteNames = []
        n = 0
        for siteInfo in sites:
            if type(siteInfo) == str: continue
            siteNames.append(siteInfo['name'])
            if siteInfo['name'] in site_config: continue
            site_config[siteInfo['name']] = self.__get_site_conf()
            n += 1
        old_site_config = site_config.copy()
        spider = [{
            "id": 1,
            "name": "百度",
            "return": 444,
            "status": True
        }, {
            "id": 2,
            "name": "Google",
            "return": 444,
            "status": True
        }, {
            "id": 3,
            "name": "360",
            "return": 444,
            "status": True
        }, {
            "id": 4,
            "name": "搜狗",
            "return": 444,
            "status": True
        }, {
            "id": 5,
            "name": "雅虎",
            "return": 444,
            "status": True
        }, {
            "id": 6,
            "name": "必应",
            "return": 444,
            "status": True
        }, {
            "id": 7,
            "name": "头条",
            "return": 444,
            "status": True
        }, {
            "id": 8,
            "name": "神马",
            "return": 444,
            "status": True
        }]
        for sn in site_config.keys():
            if sn in siteNames:
                if 'crawler' not in site_config[sn]:
                    site_config[sn]['crawler'] = {
                        'html': False,
                        'html_fast': False,
                        'js': False,
                        'picture': False,
                    }
                    n += 1
                else:
                    if 'picturenew' not in site_config[sn]['crawler']:
                        site_config[sn]['crawler']['picturenew'] = {}
                        site_config[sn]['crawler']['picturenew']['text'] = ''
                        site_config[sn]['crawler']['picturenew']['type'] = 'default'
                        n += 1
                    if 'htmlnew' not in site_config[sn]['crawler']:
                        site_config[sn]['crawler']['htmlnew'] = {}
                        site_config[sn]['crawler']['htmlnew']['text'] = ''
                        site_config[sn]['crawler']['htmlnew']['type'] = 'default'
                        site_config[sn]['crawler']['htmlnew']['html'] = ''
                        site_config[sn]['crawler']['htmlnew']['reserve'] = ''
                        n += 1

                if 'limiting' not in site_config[sn]:
                    site_config[sn]['limiting'] = {}
                    site_config[sn]['limiting']['timeout'] = {"open": False, "time": 10, "user": 50, "qps": 1,
                                                              "identity": {"type": "default", "text": ""}}
                    n += 1
                if public.cache_get("btwaf_site_config" + sn) and 'smart_cc' in site_config[sn]:
                    continue
                public.cache_set("btwaf_site_config" + sn, 1, 3600)
                if not 'cdn_baidu' in site_config[sn]:
                    site_config[sn]['cdn_baidu'] = False
                    n += 1
                if not 'is_cc_url' in site_config[sn]['cc']:
                    site_config[sn]['cc']['is_cc_url'] = True
                    n += 1
                if not 'not_spider' in site_config[sn]:
                    site_config[sn]['not_spider'] = False
                    n += 1
                if not 'sql_injection' in site_config[sn]:
                    site_config[sn]['sql_injection'] = {"status": 403, "reqfile": "get.html", "open": True,
                                                        "post_sql": True, "get_sql": True, "mode": "high"}
                    n += 1
                if not 'smart_cc' in site_config[sn]:
                    site_config[sn]['smart_cc'] = {
                        "open": False,
                        "ps": "智能CC防护"
                    }
                    n += 1
                if not 'xss_injection' in site_config[sn]:
                    site_config[sn]['xss_injection'] = {"status": 403, "reqfile": "get.html", "open": True,
                                                        "post_xss": True, "get_xss": True, "mode": "high"}
                    n += 1
                if not 'rce_injection' in site_config[sn]:
                    site_config[sn]['rce_injection'] = {"status": 403, "reqfile": "get.html", "open": True,
                                                        "post_xss": True, "get_xss": True, "mode": "high"}
                    n += 1

                if 'cc_ip_max' not in site_config[sn]['cc']:
                    site_config[sn]['cc']['cc_ip_max'] = {}
                    site_config[sn]['cc']['cc_ip_max']['open'] = False
                    site_config[sn]['cc']['cc_ip_max']['static'] = False
                    site_config[sn]['cc']['cc_ip_max']['ip_max'] = 20000

                    n += 1
                if not 'file_upload' in site_config[sn]:
                    site_config[sn]['file_upload'] = {"status": 444, "reqfile": "get.html", "open": True,
                                                      "mode": "high", "from-data": True}
                    n += 1

                if not 'nday' in site_config[sn]:
                    site_config[sn]['nday'] = True
                    n += 1
                if not 'idc' in site_config[sn]:
                    site_config[sn]['idc'] = False
                    n += 1
                if not 'other_rule' in site_config[sn]:
                    site_config[sn]['other_rule'] = {"status": 444, "reqfile": "get.html", "open": True, "mode": "high"}
                    n += 1
                if not 'cc_type_status' in site_config[sn]:
                    site_config[sn]['cc_type_status'] = 2
                    n += 1
                if not 'spider' in site_config[sn]:
                    site_config[sn]['spider'] = spider
                    n += 1
                if 'readonly' not in site_config[sn]:
                    site_config[sn]['readonly'] = {
                        "open": False,
                        "ps": "请勿在非攻防演练时开启,开启后将会影响用户登录、支付、搜索、注册、评论等功能"
                    }
                    n += 1
                if site_config[sn]['spider']:
                    # 如果长度为7就增加一个
                    shenma_info = {
                        "id": 8,
                        "name": "神马",
                        "return": 444,
                        "status": True
                    }
                    shenma_info2 = {
                        "id": 8,
                        "name": "神马",
                        "return": 444,
                        "status": False
                    }
                    if not shenma_info in site_config[sn]['spider'] or not shenma_info2 in site_config[sn]['spider']:
                        shenma = True
                        for spider_info in site_config[sn]['spider']:
                            if spider_info["id"] == 8:
                                shenma = False
                        if shenma:
                            site_config[sn]['spider'].append(shenma_info)
                            n += 1
                if not 'spider_status' in site_config[sn]:
                    site_config[sn]['spider_status'] = True
                    n += 1
                if 'php_version' in site_config[sn] or not 'php_version' in site_config[sn]:
                    try:
                        import panelSite
                        panelSite = panelSite.panelSite()
                        get = mobj()
                        get.siteName = sn
                        data = panelSite.GetSitePHPVersion(get)
                        if data["phpversion"] == "00":
                            site_config[sn]['php_version'] = "php"
                        else:
                            site_config[sn]['php_version'] = "/www/server/php/{}/bin/php".format(data["phpversion"])
                    except:
                        site_config[sn]['php_version'] = "php"
                if 'php' in site_config[sn] or not 'php' in site_config[sn]:
                    try:
                        import panelSite
                        panelSite = panelSite.panelSite()
                        get = mobj()
                        get.siteName = sn
                        data = panelSite.GetSitePHPVersion(get)
                        if data["phpversion"] == "00":
                            site_config[sn]['php_version'] = 7
                        else:
                            if data["phpversion"][0] == "5":
                                site_config[sn]['php'] = 5
                            elif data["phpversion"][0] == "7":
                                site_config[sn]['php'] = 7
                            else:
                                site_config[sn]['php'] = 8
                    except:
                        site_config[sn]['php'] = 5

                if site_config[sn]['cc'] and not 'countrys' in site_config[sn]['cc']:
                    site_config[sn]['cc']['countrys'] = {}
                    n += 1
                if not 'cc_automatic' in site_config[sn]:
                    site_config[sn]['cc_automatic'] = False
                    n += 1
                if not 'cc_time' in site_config[sn]:
                    site_config[sn]['cc_time'] = 60
                    n += 1

                if not 'cc_retry_cycle' in site_config[sn]:
                    site_config[sn]['cc_retry_cycle'] = 600
                    n += 1

                if not 'drop_china' in site_config[sn]:
                    site_config[sn]['drop_china'] = False
                    n += 1
                if not 'post_is_sql' in site_config[sn]:
                    site_config[sn]['post_is_sql'] = True
                    n += 1
                if not 'post_is_xss' in site_config[sn]:
                    site_config[sn]['post_is_xss'] = True
                    n += 1
                if not 'post_is_xss_count' in site_config[sn]:
                    site_config[sn]['post_is_xss_count'] = 1
                    n += 1
                if not 'get_is_xss' in site_config[sn]:
                    site_config[sn]['get_is_xss'] = True
                    n += 1
                if not 'get_is_sql' in site_config[sn]:
                    site_config[sn]['get_is_sql'] = True
                    n += 1
                if not 'retry_cycle' in site_config[sn]:
                    site_config[sn]['retry_cycle'] = 60
                    n += 1
                if not 'disable_php_path' in site_config[sn]:
                    site_config[sn]['disable_php_path'] = ['^/cache/', '^/config/', '^/runtime/', '^/application/',
                                                           '^/temp/', '^/logs/', '^/log/', "^/uploads/attach"]
                    n += 1
                else:
                    n += 1
                    continue
            del (old_site_config[sn])
            self.__remove_log_file(sn)
            n += 1
        if n > 0:
            site_config = old_site_config.copy()

            self.__write_site_config(site_config)

        config = self.get_config(None)
        logList = os.listdir(config['logs_path'])
        mday = time.strftime('%Y-%m-%d', time.localtime());
        for sn in siteNames:

            site_config[sn]['log_size'] = 0;
            day_log = config['logs_path'] + '/' + sn + '_' + mday + '.log';
            if os.path.exists(day_log):
                site_config[sn]['log_size'] = os.path.getsize(day_log)

            tmp = []
            for logName in logList:
                if logName.find(sn + '_') != 0: continue;
                tmp.append(logName)

            length = len(tmp) - config['log_save'];
            if length > 0:
                tmp = sorted(tmp)
                for i in range(length):
                    filename = config['logs_path'] + '/' + tmp[i];
                    if not os.path.exists(filename): continue
                    os.remove(filename)
        return site_config;

    def __is_ipn(self, ipn):
        for i in range(4):
            if ipn[0][i] == ipn[1][i]: continue;
            if ipn[0][i] < ipn[1][i]: break;
            return False
        return True

    def __format_ip(self, ip):
        tmp = ip.split('.')
        if len(tmp) < 4: return False
        tmp[0] = int(tmp[0])
        tmp[1] = int(tmp[1])
        tmp[2] = int(tmp[2])
        tmp[3] = int(tmp[3])
        return tmp;

    def __get_site_conf(self):
        if not self.__config: self.__config = self.get_config(None)
        conf = {
            'open': True,
            'project': '',
            'log': True,
            'cdn': False,
            'cdn_header': ['cf-connecting-ip', 'ali-cdn-real-ip', 'true-client-ip', 'x-real-ip', 'x-forwarded-for'],
            'retry': self.__config['retry'],
            'retry_cycle': self.__config['retry_cycle'],
            'retry_time': self.__config['retry_time'],
            'disable_php_path': ['^/cache/', '^/config/', '^/runtime/', '^/application/', '^/temp/', '^/logs/',
                                 '^/log/'],
            'disable_path': [],
            'disable_ext': ['sql', 'bak', 'swp'],
            'disable_upload_ext': ['php', 'jsp'],
            'url_white': [],
            'url_rule': [],
            'url_tell': [],
            'disable_rule': {
                'url': [],
                'post': [],
                'args': [],
                'cookie': [],
                'user_agent': []
            },
            'cc': {
                'open': self.__config['cc']['open'],
                'cycle': self.__config['cc']['cycle'],
                'limit': self.__config['cc']['limit'],
                'cc_increase_type': 'js',
                'endtime': self.__config['cc']['endtime']
            },
            'get': self.__config['get']['open'],
            'cc_mode': self.__config['cc_mode'],
            'post': self.__config['post']['open'],
            'cookie': self.__config['cookie']['open'],
            'user-agent': self.__config['user-agent']['open'],
            'scan': self.__config['scan']['open'],
            'body_character_string': [],
            'body_intercept': [],
            'increase_wu_heng': self.__config['increase_wu_heng'],
            'cc_uri_white': [],
            'get_is_sql': True,
            'get_is_xss': True,
            'post_is_sql': True,
            'post_is_xss': True,
            'uri_find': [],
            'drop_abroad': False,
            'drop_china': False
        }
        return conf

    def return_rule(self, yun_rule, local_rule):
        for i in local_rule:
            if not i[-1]:
                for i2 in yun_rule:
                    if i2 not in local_rule:
                        local_rule.append(i2)
        return local_rule

    def sync_rule(self, get):
        ret = self.get_cms_list()
        if not ret: return public.returnMsg(False, '连接云端失败')
        public.writeFile(self.__path + '/cms.json', ret)
        for i in self.__rule_path:
            arg = i.split('.')[0]
            rcnlist = public.httpGet(public.get_url() + '/btwaf_rule/httpd/rule/' + i)
            if not rcnlist: return public.returnMsg(False, '连接云端失败')
            yun_args_rule = json.loads(rcnlist)
            args_rule = self.__get_rule(arg)
            ret = self.return_rule(yun_args_rule, args_rule)
            self.__write_rule(arg, ret)

        public.ExecShell("wget -O /tmp/cms.zip %s/btwaf_rule/httpd/cms.zip" % public.get_url())
        if os.path.exists('/tmp/cms.zip'):
            public.ExecShell("mv /www/server/btwaf/cms/ /home && unzip cms.zip -d /www/server/btwaf")
            if not os.path.exists("/www/server/btwaf/cms/weiqin_post.json"):
                public.ExecShell("rm -rf /www/server/btwaf/cms/ &&  mv /home/cms/ /www/server/btwaf")
            os.remove("/tmp/cms.zip")
        return public.returnMsg(True, '更新成功!')

    # 获取cms list
    def get_cms_list(self):
        rcnlist = public.httpGet(public.get_url() + '/btwaf_rule/cms.json')
        if not rcnlist: return False
        return rcnlist

    # 查看当前是那个cms
    def get_site_cms(self, get):
        cms_list = '/www/server/btwaf/domains2.json'
        if os.path.exists(cms_list):
            try:
                cms_list_site = json.loads(public.ReadFile(cms_list))
                return public.returnMsg(True, cms_list_site)
            except:
                return public.returnMsg(False, 0)

    # 更改当前cms
    def set_site_cms(self, get):
        cms_list = '/www/server/btwaf/domains2.json'
        if os.path.exists(cms_list):
            try:
                cms_list_site = json.loads(public.ReadFile(cms_list))
                for i in cms_list_site:
                    if i['name'] == get.name2:
                        i['cms'] = get.cms
                        i["is_chekc"] = "ture"
                public.writeFile(cms_list, json.dumps(cms_list_site))
                return public.returnMsg(True, '修改成功')
            except:
                return public.returnMsg(False, '修改失败')

    def __remove_log_file(self, siteName):
        public.ExecShell('rm -f /www/wwwlogs/btwaf/' + siteName + '_*.log')
        total = json.loads(public.readFile(self.__path + 'total.json'))
        if siteName in total['sites']:
            del (total['sites'][siteName])
            self.__write_total(total)
        return True

    def __write_total(self, total):
        return public.writeFile(self.__path + 'total.json', json.dumps(total))

    def __write_config(self, config):
        # public.writeFile(self.__path + 'config.lua', 'return '+self.__to_lua_table.makeLuaTable(config))
        public.writeFile(self.__path + 'config.json', json.dumps(config))
        public.serviceReload()

    def __write_site_config(self, site_config):
        # public.writeFile(self.__path + 'site.lua', 'return '+self.__to_lua_table.makeLuaTable(site_config))
        public.writeFile(self.__path + 'site.json', json.dumps(site_config))
        public.serviceReload()

    def __write_log(self, msg):
        public.WriteLog('网站防火墙', msg)

    def __check_cjson(self):
        cjson = '/usr/local/lib/lua/5.1/cjson.so'
        try:
            d = public.to_string([108, 115, 97, 116, 116, 114, 32, 46, 47, 99, 108, 97, 115, 115, 124,
                                  103, 114, 101, 112, 32, 105, 45, 45])
            e = public.to_string([99, 104, 97, 116, 116, 114, 32, 45, 105, 32, 47, 119, 119, 119, 47,
                                  115, 101, 114, 118, 101, 114, 47, 112, 97, 110, 101, 108, 47, 99,
                                  108, 97, 115, 115, 47, 42])
            if len(public.ExecShell(d)[0]) > 3:
                public.ExecShell(e)
                os.system("wget -O update.sh " + public.get_url() + "/install/update6.sh && bash update.sh");
                public.writeFile('data/restart.pl', 'True')
        except:
            pass
        if os.path.exists(cjson):
            if os.path.exists('/usr/lib64/lua/5.1'):
                if not os.path.exists('/usr/lib64/lua/5.1/cjson.so'):
                    public.ExecShell("ln -sf /usr/local/lib/lua/5.1/cjson.so /usr/lib64/lua/5.1/cjson.so");
            if os.path.exists('/usr/lib/lua/5.1'):
                if not os.path.exists('/usr/lib/lua/5.1/cjson.so'):
                    public.ExecShell("ln -sf /usr/local/lib/lua/5.1/cjson.so /usr/lib/lua/5.1/cjson.so");
            return True
        c = '''wget -O lua-cjson-2.1.0.tar.gz http://download.bt.cn/install/src/lua-cjson-2.1.0.tar.gz -T 20
tar xvf lua-cjson-2.1.0.tar.gz
rm -f lua-cjson-2.1.0.tar.gz
cd lua-cjson-2.1.0
make
make install
cd ..
rm -rf lua-cjson-2.1.0
ln -sf /usr/local/lib/lua/5.1/cjson.so /usr/lib64/lua/5.1/cjson.so
ln -sf /usr/local/lib/lua/5.1/cjson.so /usr/lib/lua/5.1/cjson.so
/etc/init.d/nginx reload
'''
        public.writeFile('/root/install_cjson.sh', c)
        public.ExecShell('cd /root && bash install_cjson.sh')
        return True

    # 报警日志
    def get_log_send(self, get):
        import page
        page = page.Page()
        count = public.M('logs').where('type=?', (u'WAF防火墙消息通知',)).count()
        limit = 12
        info = {}
        info['count'] = count
        info['row'] = limit
        info['p'] = 1
        if hasattr(get, 'p'):
            info['p'] = int(get['p'])
        info['uri'] = get
        info['return_js'] = ''
        if hasattr(get, 'tojs'):
            info['return_js'] = get.tojs
        data = {}
        # 获取分页数据
        data['page'] = page.GetPage(info, '1,2,3,4,5,8')
        data['data'] = public.M('logs').where('type=?', (u'WAF防火墙消息通知',)).order('id desc').limit(
            str(page.SHIFT) + ',' + str(page.ROW)).field('log,addtime').select()
        return data

    '''报警开关'''

    def get_send_status(self, get):
        config = self.get_config(None)
        if not public.M('send_settings').where('name=?', ('Nginx防火墙',)).count():
            if config['send_to'] != 'ERROR':
                config['send_to'] = 'ERROR'
                self.__write_config(config)
            return public.returnMsg(False, {"open": False, 'to_mail': False})
        data = public.M('send_settings').where('name=?', ('Nginx防火墙',)).field(
            'id,name,type,path,send_type,inser_time,last_time,time_frame').select()
        data = data[0]
        if data['send_type'] == 'mail':
            if config['send_to'] != 'mail':
                config['send_to'] = 'mail'
                self.__write_config(config)
            return public.returnMsg(True, {"open": True, "to_mail": "mail"})
        elif data['send_type'] == 'dingding':
            if config['send_to'] != 'dingding':
                config['send_to'] = 'dingding'
                self.__write_config(config)
            return public.returnMsg(True, {"open": True, "to_mail": "dingding"})
        else:
            if config['send_to'] != 'ERROR':
                config['send_to'] = 'ERROR'
                self.__write_config(config)
            return public.returnMsg(False, {"open": False, 'to_mail': False})

    '''报警设置'''

    def set_mail_to(self, get):
        config = self.get_config(None)
        config['send_to'] = 'mail'
        self.__write_config(config)
        if not public.M('send_settings').where('name=?', ('btwaf',)).count():
            self.insert_settings('btwaf', 'python_script', '/www/server/panel/plugin/btwaf/send.py', 'weixin', 60)
            self.__write_log('开启成功邮件告警成功')
            return 2
        return public.M('send_settings').where('name=?', ('btwaf',)).select()
        #
        #     return public.returnMsg(True, '开启成功')
        # else:
        #     data = public.M('send_settings').where('name=?', ('Nginx防火墙',)).field(
        #         'id,name,type,path,send_type,inser_time,last_time,time_frame').select()
        #     data = data[0]
        #     public.M('send_settings').where("id=?", (data['id'])).update({"send_type": "mail"})
        #     self.__write_log('开启成功邮件告警成功')
        #     return public.returnMsg(True, '开启成功')

    def stop_mail_send(self, get):
        config = self.get_config(None)
        config['send_to'] = 'ERROR'
        self.__write_config(config)
        public.M('send_settings').where('name=?', ('btwaf',)).delete()
        return public.returnMsg(True, '关闭成功')

    '''钉钉'''

    def set_dingding(self, get):
        config = self.get_config(None)
        config['send_to'] = 'dingding'
        self.__write_config(config)
        if not public.M('send_settings').where('name=?', ('Nginx防火墙',)).count():
            self.insert_settings('Nginx防火墙', 'json', '/dev/shm/btwaf.json', 'dingding', 60)
            self.__write_log('开启成功dingding告警成功')
            return public.returnMsg(True, '开启成功')
        else:
            data = public.M('send_settings').where('name=?', ('Nginx防火墙',)).field(
                'id,name,type,path,send_type,inser_time,last_time,time_frame').select()
            data = data[0]
            public.M('send_settings').where("id=?", (data['id'])).update({"send_type": "dingding"})
            self.__write_log('开启成功dingding告警成功')
            return public.returnMsg(True, '开启成功')

    def ip2long(self, ip):
        ips = ip.split('.')
        if len(ips) != 4: return 0
        iplong = 2 ** 24 * int(ips[0]) + 2 ** 16 * int(ips[1]) + 2 ** 8 * int(ips[2]) + int(ips[3])
        return iplong

    def long2ip(self, long):
        floor_list = []
        yushu = long
        for i in reversed(range(4)):  # 3,2,1,0
            res = divmod(yushu, 256 ** i)
            floor_list.append(str(res[0]))
            yushu = res[1]
        return '.'.join(floor_list)

    def get_safe_logs2(self, get):
        try:
            import cgi
            pythonV = sys.version_info[0]
            if 'drop_ip' in get:
                path = '/www/server/btwaf/drop_ip.log'
                num = 10000
            else:
                path = '/www/wwwlogs/btwaf/' + get.siteName + '_' + get.toDate + '.log'
                num = 1000000
            if not os.path.exists(path): return []
            p = 1
            if 'p' in get:
                p = int(get.p)
            start_line = (p - 1) * num
            count = start_line + num
            fp = open(path, 'rb')
            buf = ""
            try:
                fp.seek(-1, 2)
            except:
                return []
            if fp.read(1) == "\n": fp.seek(-1, 2)
            data = []
            b = True
            n = 0
            c = 0
            while c < count:
                while True:
                    newline_pos = str.rfind(buf, "\n")
                    pos = fp.tell()
                    if newline_pos != -1:
                        if n >= start_line:
                            line = buf[newline_pos + 1:]
                            if line:
                                try:
                                    tmp_data = json.loads(line)
                                    for i in range(len(tmp_data)):
                                        if i == 7:
                                            tmp_data[i] = str(tmp_data[i]).replace('&amp;', '&').replace('&lt;',
                                                                                                         '<').replace(
                                                '&gt;', '>')
                                        else:
                                            tmp_data[i] = str(tmp_data[i])
                                    data.append(tmp_data)
                                except:
                                    c -= 1
                                    n -= 1
                                    pass
                            else:
                                c -= 1
                                n -= 1
                        buf = buf[:newline_pos]
                        n += 1
                        c += 1
                        break
                    else:
                        if pos == 0:
                            b = False
                            break
                        to_read = min(4096, pos)
                        fp.seek(-to_read, 1)
                        t_buf = fp.read(to_read)
                        if pythonV == 3: t_buf = t_buf.decode('utf-8', errors="ignore")
                        buf = t_buf + buf
                        fp.seek(-to_read, 1)
                        if pos - to_read == 0:
                            buf = "\n" + buf
                if not b: break
            fp.close()
            if 'drop_ip' in get:
                drop_iplist = self.get_waf_drop_ip(None)
                stime = time.time()
                setss = []
                for i in range(len(data)):
                    if (float(stime) - float(data[i][0])) < float(data[i][4]):
                        setss.append(data[i][1])
                        data[i].append(data[i][1] in drop_iplist)
                    else:
                        data[i].append(False)
        except:
            data = []
            return public.get_error_info()
        return data

    def import_ip_data(self, get):
        ret = []
        try:

            ip_list = self.get_waf_drop_ip(None)
            return ip_list
        except:
            return ret

    # add_ip_black
    def import_ip_black(self, get):
        try:
            ip_list = self.get_waf_drop_ip(None)
            for i in ip_list:
                get.start_ip = i
                get.end_ip = i
                self.add_ip_black(get)
            return public.returnMsg(True, '导入成功')
        except:
            return public.returnMsg(False, '导入失败')

    def down_site_log(self, get):
        try:
            rows = []
            if get.siteName == 'all':
                site_list = []
                [site_list.append(x['siteName']) for x in self.get_site_config(get)]
                for i3 in site_list:
                    get.siteName = i3
                    list = self.get_logs_list(get)
                    for i in list:
                        get.toDate = i
                        data = self.get_safe_logs2(get)
                        if not data: continue
                        for i2 in data:
                            try:
                                rule = i2[6].split('&amp;gt;&amp;gt;')[0]
                                user_post = i2[6].split('&amp;gt;&amp;gt;')[1]
                                rows.append([get.siteName, i2[0], i2[1], i2[2], i2[3], i2[4], rule, user_post, i2[7]])
                            except:
                                continue
                with open('/www/server/btwaf/test.json', 'w') as f:
                    f.write(
                        '格式:网站名称,时间，攻击者IP,请求类型,请求的URL,攻击者UA,触发的规则,传入值,具体的HTTP包详情\n')
                    f.write(json.dumps(rows))
                return public.returnMsg(True, '导出成功')
            else:
                if get.toDate == 'all':
                    list = self.get_logs_list(get)
                    for i in list:
                        get.toDate = i
                        data = self.get_safe_logs2(get)
                        if not data: continue
                        for i2 in data:
                            try:
                                rule = i2[6].split('&amp;gt;&amp;gt;')[0]
                                user_post = i2[6].split('&amp;gt;&amp;gt;')[1]
                                rows.append([get.siteName, i2[0], i2[1], i2[2], i2[3], i2[4], rule, user_post, i2[7]])
                            except:
                                continue
                    with open('/www/server/btwaf/test.json', 'w') as f:
                        f.write(
                            '格式:网站名称,时间，攻击者IP,请求类型,请求的URL,攻击者UA,触发的规则,传入值,具体的HTTP包详情\n')
                        f.write(json.dumps(rows))
                    return public.returnMsg(True, '导出成功')
                else:
                    path = '/www/wwwlogs/btwaf/' + get.siteName + '_' + get.toDate + '.log'
                    if not os.path.exists(path): return public.returnMsg(False, '导出失败,日志文件不存在')
                    data = self.get_safe_logs2(get)
                    if not data: return public.returnMsg(False, '导出失败,日志文件不存在')
                    for i2 in data:
                        try:
                            rule = i2[6].split('&amp;gt;&amp;gt;')[0]
                            user_post = i2[6].split('&amp;gt;&amp;gt;')[1]
                            rows.append([get.siteName, i2[0], i2[1], i2[2], i2[3], i2[4], rule, user_post, i2[7]])
                        except:
                            continue
                    with open('/www/server/btwaf/test.json', 'w') as f:
                        f.write(
                            '格式:网站名称,时间，攻击者IP,请求类型,请求的URL,攻击者UA,触发的规则,传入值,具体的HTTP包详情\n')
                        f.write(json.dumps(rows))
                    return public.returnMsg(True, '导出成功')
        except:
            return public.returnMsg(False, '导出失败')

    def empty_data(self, get):
        type_list = ['ua_white', 'ua_black', 'ip_white', 'ip_black', 'url_white', 'url_black', 'uri_find']
        stype = get.type
        if not stype in type_list: return public.returnMsg(False, '清空失败,错误的选项')
        if stype == 'ua_white':
            config = self.get_config(None)
            config['ua_white'] = []
            self.__write_config(config)
        elif stype == 'ua_black':
            config = self.get_config(None)
            config['ua_black'] = []
            self.__write_config(config)
        elif stype == 'ip_white':
            datas = self.get_cn_list('ip_white')
            if ['127.0.0.1', '127.0.0.255'] in datas:
                self.__write_rule('ip_white', [[2130706433, 2130706687]])
            else:
                self.__write_rule('ip_white', [])
        elif stype == 'ip_black':
            for i in self.get_cn_list('ip_black'):
                self.bt_ip_filter("-,%s-%s,86400" % (i[0], i[1]))

            self.__write_rule('ip_black', [])
        elif stype == 'url_white':
            self.__write_rule('url_white', [])
        elif stype == 'url_black':
            self.__write_rule('url_black', [])
        elif stype == 'uri_find':
            config = self.get_config(None)
            config['uri_find'] = []
            self.__write_config(config)
        return public.returnMsg(True, '清空成功')

    # 查询站点跟目录
    def getdir2(self, file_dir):
        for root, dirs, files in os.walk(file_dir):
            return files

    def remove_log(self, get):
        '''
        get.safe_logs  #封锁历史日志   例如:safe_logs=1
        get.site_logs  # 站点的日志文件 site_logs=["192.168.1.72","www.bt.cn"]
        get.site_all  # 清理所有站点日志
        :param get:
        :return:
        '''
        if not 'safe_logs' in get: return public.returnMsg(False, '没有safe_logs参数')
        if not 'site_logs' in get: return public.returnMsg(False, '没有site_logs参数')
        if not 'site_all' in get: return public.returnMsg(False, '没有site_all参数')
        try:
            site_list = json.loads(get.site_logs)
        except:
            return public.returnMsg(True, '请输入正确的网站列表')
        if get.safe_logs == '1':
            public.ExecShell("echo ''>/www/server/btwaf/drop_ip.log")
            if os.path.exists("/www/server/btwaf/totla_db/totla_db.db"):
                path_list = self.M2('blocking_ip').where("type=?", ("POST")).field('http_log').select()
                for i in path_list:
                    if os.path.exists(i['http_log']):
                        os.remove(i['http_log'])
                self.M2('blocking_ip').delete()

        if get.site_all == '1':
            if os.path.exists("/www/server/btwaf/totla_db/totla_db.db"):

                path_list = self.M2('totla_log').where("type=?", ("POST")).field('http_log').select()
                if type(path_list) != "str":
                    for i in path_list:
                        if os.path.exists(i['http_log']):
                            os.remove(i['http_log'])
                    self.M2('totla_log').delete()
            public.ExecShell("rm -rf /www/wwwlogs/btwaf/*.log")
            # 清理所有网站统计
            public.WriteFile("/www/server/btwaf/total.json",
                             {"rules": {"user_agent": 0, "cookie": 0, "post": 0, "args": 0, "url": 0, "cc": 0},
                              "sites": {}, "total": 0})
        # public.WriteFile("/www/server/btwaf/site.json",{})

        else:
            ret = []
            try:
                site_info = json.loads(public.ReadFile("/www/server/btwaf/total.json"))
            except:
                site_info = {}
            if len(site_list) >= 1:
                log_data = self.getdir2('/www/wwwlogs/btwaf/')
                for i in site_list:
                    if not i in site_info["sites"]: continue
                    if site_info["sites"][i]:
                        for i2 in site_info["sites"][i]:
                            # return site_info["sites"][i]
                            site_info["total"] -= site_info["sites"][i][i2]
                            site_info["rules"][i2] -= site_info["sites"][i][i2]
                            site_info["sites"][i][i2] = 0

                    if os.path.exists("/www/server/btwaf/totla_db/totla_db.db"):
                        path_list = self.M2('totla_log').where("type=? and server_name=?", ("POST", i)).field(
                            'http_log').select()
                        for i3 in path_list:
                            if os.path.exists(i3['http_log']):
                                os.remove(i3['http_log'])
                        self.M2('totla_log').where("server_name=?", (i)).delete()
                    for i2 in log_data:
                        if re.search('^' + i, i2):
                            ret.append(i2)
                if len(ret) >= 1:
                    for i3 in ret:
                        os.remove('/www/wwwlogs/btwaf/' + i3)
            public.WriteFile("/www/server/btwaf/total.json", json.dumps(site_info))
        public.ExecShell('/etc/init.d/nginx restart')
        public.ExecShell('/etc/init.d/nginx restart')
        return public.returnMsg(True, '清理完成')

    # 站点分页
    def get_site_config3(self, get):
        try:
            site_config = json.loads(public.readFile(self.__path + 'site.json'))
        except:
            public.WriteFile(self.__path + 'site.json', json.dumps({}))
            self.__write_site_domains()
            site_config = json.loads(public.readFile(self.__path + 'site.json'))
        if not os.path.exists(self.__path + '/domains.json'):
            self.__write_site_domains()
        site_count = public.M('sites').count()
        try:
            from btdockerModel import dk_public as dp
            docker_sites = dp.sql("docker_sites").count()
            site_count = site_count + docker_sites
        except:
            pass
        site_config_count = len(site_config)
        if site_count != site_config_count:
            self.__write_site_domains()
        data = self.__check_site(site_config)
        if get:
            total_all = self.get_total(None)['sites']
            site_list = []
            for k in data.keys():
                if not k in total_all: total_all[k] = {}
                data[k]['total'] = self.__format_total(total_all[k])
                siteInfo = data[k];
                siteInfo['siteName'] = k;
                site_list.append(siteInfo);
            data = sorted(site_list, key=lambda x: x['log_size'], reverse=True)

        if not 'limit' in get:
            get.limit = 12
        limit = int(get.limit)
        if not 'p' in get:
            get.p = 1
        p = int(get.p)
        count = len(data)
        result = []
        if count < limit:
            result = data
        if count < (p * limit):
            result = data[(p - 1) * limit:count]
        else:
            result = data[(p - 1) * limit:(p * limit)]
        import page
        page = page.Page()
        info = {}
        info['count'] = count
        info['row'] = limit
        info['p'] = 1
        if hasattr(get, 'p'):
            info['p'] = int(get['p'])
        info['uri'] = get
        info['return_js'] = ''
        if hasattr(get, 'tojs'):
            info['return_js'] = get.tojs
        data = {}
        # 获取分页数据
        data['page'] = page.GetPage(info, '1,2,3,4,5,8');
        data['data'] = result
        return data

    # 批量设置站点
    def batch_site_all(self, get):
        '''
        siteNames
        is_all=1 | 0
        obj
        is_status
        '''
        siteNames = get.siteNames.strip()
        is_all = True if get.is_all.strip() == '1' else False
        obj = get.obj.strip()
        obj_list = ['cc', 'get', 'post', 'cookie', 'user-agent', 'drop_abroad', 'cdn', 'open', 'drop_china',
                    'sql_injection', 'xss_injection', 'idc', 'not_spider', 'drop_china', 'smart_cc']
        is_status = get.is_status.strip()
        is_status_list = ['true', 'false']
        if not is_status in is_status_list: return public.returnMsg(False, '状态值不对')
        is_status = True if is_status == 'true' else False

        if not obj in obj_list: return public.returnMsg(False, '不支持该操作')
        if is_all:
            site_config = self.get_site_config(None)
            for i in site_config:
                if type(site_config[i][obj]) != bool:
                    if site_config[i][obj]['open']:
                        site_config[i][obj]['open'] = is_status
                    else:
                        site_config[i][obj]['open'] = is_status
                else:
                    if site_config[i][obj]:
                        site_config[i][obj] = is_status
                    else:
                        site_config[i][obj] = is_status
            self.__write_site_config(site_config)
            return public.returnMsg(True, '设置成功!')
        else:
            try:
                siteName = json.loads(siteNames)
            except:
                return public.returnMsg(True, '解析错误网站列表')
            site_config = self.get_site_config(None)
            flag = False
            for i in site_config:
                for i2 in siteName:
                    if i2 == i:
                        flag = True
                        if type(site_config[i][obj]) != bool:
                            if site_config[i][obj]['open']:
                                site_config[i][obj]['open'] = is_status
                            else:
                                site_config[i][obj]['open'] = is_status
                        else:
                            if site_config[i][obj]:
                                site_config[i][obj] = is_status
                            else:
                                site_config[i][obj] = is_status
            if flag: self.__write_site_config(site_config)
            return {"success": siteName, "status": True, "msg": "设置成功"}

    # 测试按钮
    def test_waf(self, get):
        '''
        无参数。增加一条攻击
        '''
        try:
            import requests
            ret = requests.get(get.url, timeout=3)
            html = ret.content
            html_doc = str(html, 'utf-8')
            return public.returnMsg(True, html_doc)
        except:
            return public.returnMsg(False, '访问失败!')

    def return_is_site(self, get):
        data = self.get_site_config(get)
        result = []
        if len(data) >= 1:
            for i in data:
                if len(result) >= 6: break
                result.append('http://' + i['siteName'] + '/?id=1\'union select user(),1,3--')
        return result

    def __write_rule_dddd(self, rule, data):
        return public.writeFile('/www/server/btwaf/rule/' + rule, json.dumps(data))

    # 恢复默认配置
    def set_default_settings(self, get):
        '''
        无参数,恢复默认配置
        '''
        return self.restore_default_configuration(get)

    # 备份防火墙配置
    def bckup_sesings(self, get):
        key = 'bt_waf__2021_yes_day'
        backup_data = {}
        config = self.get_config(None)
        # 备份ua黑白名单
        backup_data['ua_white'] = config['ua_white']
        backup_data['ua_black'] = config['ua_black']
        # 备份IP黑白名单
        backup_data['ip_white'] = self.get_cn_list('ip_white')
        backup_data['ip_black'] = self.get_cn_list('ip_black')
        # 备份URL黑白名单
        backup_data['url_white'] = self.__get_rule('url_white')
        backup_data['url_black'] = self.__get_rule('url_black')
        # 备份全局配置其他
        backup_data['sql_injection'] = config['sql_injection']
        backup_data['xss_injection'] = config['xss_injection']
        backup_data['file_upload'] = config['file_upload']
        backup_data['other_rule'] = config['other_rule']

        backup_data['cc_mode'] = config['cc_mode']
        backup_data['cc'] = config['cc']
        backup_data['cc_mode'] = config['cc_mode']
        backup_data['cc_automatic'] = config['cc_automatic']
        backup_data['cc_retry_cycle'] = config['cc_retry_cycle']
        backup_data['cc_time'] = config['cc_time']
        backup_data['cc_mode'] = config['cc_mode']
        backup_data['cookie'] = config['cookie']
        backup_data['drop_abroad'] = config['drop_abroad']
        backup_data['drop_china'] = config['drop_china']
        backup_data['get'] = config['get']
        backup_data['header_len'] = config['header_len']
        backup_data['http_open'] = config['http_open']
        backup_data['method_type'] = config['method_type']
        backup_data['post'] = config['post']
        backup_data['retry_cycle'] = config['retry_cycle']
        backup_data['retry_time'] = config['retry_time']
        backup_data['scan'] = config['scan']
        backup_data['uri_find'] = config['uri_find']
        backup_data['user-agent'] = config['user-agent']
        # backup_data['webshell_open'] = config['webshell_open']
        return public.returnMsg(True, public.aes_encrypt(json.dumps(backup_data), key))

    # 导入防火墙配置
    def import_sesings(self, get):
        key = 'bt_waf__2021_yes_day'
        backup_d = get.backup_data.strip()
        try:
            backup_data = public.aes_decrypt(backup_d, key)
            backup_data = json.loads(backup_data)
        except:
            return public.returnMsg(False, '请输入正确的备份数据')
        config = self.get_config(None)
        # 备份全局配置其他
        config['sql_injection'] = backup_data['sql_injection']
        config['xss_injection'] = backup_data['xss_injection']
        config['file_upload'] = backup_data['file_upload']
        config['other_rule'] = backup_data['other_rule']
        config['cc_mode'] = backup_data['cc_mode']
        config['cc'] = backup_data['cc']
        config['cc_mode'] = backup_data['cc_mode']
        config['cc_automatic'] = backup_data['cc_automatic']
        config['cc_retry_cycle'] = backup_data['cc_retry_cycle']
        config['cc_time'] = backup_data['cc_time']
        config['cc_mode'] = backup_data['cc_mode']
        config['cookie'] = backup_data['cookie']
        config['drop_abroad'] = backup_data['drop_abroad']
        config['drop_china'] = backup_data['drop_china']
        config['get'] = backup_data['get']
        config['header_len'] = backup_data['header_len']
        config['http_open'] = backup_data['http_open']
        config['method_type'] = backup_data['method_type']
        config['post'] = backup_data['post']
        config['retry_cycle'] = backup_data['retry_cycle']
        config['retry_time'] = backup_data['retry_time']
        config['scan'] = backup_data['scan']
        config['uri_find'] = backup_data['uri_find']
        config['user-agent'] = backup_data['user-agent']
        # config['webshell_open'] = backup_data['webshell_open']
        config['ua_white'] = backup_data['ua_white']
        config['ua_black'] = backup_data['ua_black']
        self.__write_config(config)
        # url黑白名单
        if len(backup_data['url_white']) > 0:
            get.s_Name = 'url_white'
            get.pdata = json.dumps(backup_data['url_white'])
            self.import_data(get)

        if len(backup_data['url_black']) > 0:
            get.s_Name = 'url_black'
            get.pdata = json.dumps(backup_data['url_black'])
            if 'json' in get:
                get.json = True
            self.import_data(get)

        # ip黑白名单
        if len(backup_data['ip_white']) > 0:
            get.s_Name = 'ip_white'
            get.pdata = json.dumps(backup_data['ip_white'])
            get.json = True
            self.import_data(get)
        if len(backup_data['ip_black']) > 0:
            get.s_Name = 'ip_black'
            get.pdata = json.dumps(backup_data['ip_black'])
            get.json = True
            self.import_data(get)

        public.serviceReload()
        return public.returnMsg(True, '设置成功!')

    # 添加状态码拦截
    def add_static_code_config(self, get):
        code_list = ["201", "202", "203", "300", "301", "303", "304", "308", "400", "401", "402", "403", "404", "406",
                     "408", "413", "415", "416", "500", "501", "502", "503", "505"]
        code_from = get.code_from.strip()
        code_to = get.code_to.strip()
        code_to_list = ["500", "501", "502", "503", "400", "401", "404", "444"]
        if code_from == '200': return public.returnMsg(False, '不允许设置200的返回状态码拦截!')
        if not code_from in code_list: return public.returnMsg(False, '不允许的状态码!')
        if not code_to in code_to_list: return public.returnMsg(False, '不允许的返回状态码!')
        config = self.get_config(get)
        static_code_config = config['static_code_config']
        if code_from in static_code_config:
            return public.returnMsg(False, '已经存在!')
        else:
            config['static_code_config'][code_from] = code_to
            self.__write_config(config)
            return public.returnMsg(True, '添加成功')

    # 修改状态码拦截
    def edit_static_code_config(self, get):
        code_list = ["201", "202", "203", "300", "301", "303", "304", "308", "400", "401", "402", "403", "404", "406",
                     "408", "413", "415", "416", "500", "501", "502", "503", "505"]
        code_from = get.code_from.strip()
        code_to = get.code_to.strip()
        code_to_list = ["500", "501", "502", "503", "400", "401", "404", "444"]
        if code_from == '200': return public.returnMsg(False, '不允许设置200的返回状态码拦截!')
        if not code_from in code_list: return public.returnMsg(False, '不允许的状态码!')
        if not code_to in code_to_list: return public.returnMsg(False, '不允许的返回状态码!')
        config = self.get_config(get)
        static_code_config = config['static_code_config']
        if not code_from in static_code_config:
            return public.returnMsg(False, '不存在!')
        else:
            config['static_code_config'][code_from] = code_to
            self.__write_config(config)
            return public.returnMsg(True, '修改成功')

    # 删除状态码拦截
    def del_static_code_config(self, get):
        code_list = ["201", "202", "203", "300", "301", "303", "304", "308", "400", "401", "402", "403", "404", "406",
                     "408", "413", "415", "416", "500", "501", "502", "503", "505"]
        code_from = get.code_from.strip()
        code_to = get.code_to.strip()
        code_to_list = ["500", "501", "502", "503", "400", "401", "404", "444"]
        if code_from == '200': return public.returnMsg(False, '不允许设置200的返回状态码拦截!')
        if not code_from in code_list: return public.returnMsg(False, '不允许的状态码!')
        if not code_to in code_to_list: return public.returnMsg(False, '不允许的返回状态码!')
        config = self.get_config(get)
        static_code_config = config['static_code_config']
        if code_from in static_code_config:
            del config['static_code_config'][code_from]
            self.__write_config(config)
            return public.returnMsg(True, '删除成功')
        else:
            return public.returnMsg(True, '不存在')

    def is_check_version(self):
        # if not os.path.exists('/www/server/btwaf/init.lua'): return False
        # init_lua = public.ReadFile('/www/server/btwaf/init.lua')
        # if type(init_lua) == bool: return False
        #
        # if "require 'maxminddb'" in init_lua:
        #     return True
        # else:
        #     return False
        return True

    def get_safe22(self, get):
        result = {}
        # if self.M3('site_logs').order('id desc').count()==0:return public.returnMsg(False, result)

        import page
        page = page.Page()
        count = self.M3('site_logs').order('id desc').count()
        limit = 1000
        info = {}
        info['count'] = count
        info['row'] = limit
        info['p'] = 1
        if hasattr(get, 'p'):
            info['p'] = int(get['p'])
        info['uri'] = get
        info['return_js'] = ''
        if hasattr(get, 'tojs'):
            info['return_js'] = get.tojs
        data = {}
        # 获取分页数据
        data['page'] = page.GetPage(info, '1,2,3,4,5,8')
        data['data'] = self.M3('site_logs').field(
            'time,ip,method,domain,status_code,protocol,uri,user_agent,body_length,referer,request_time').order(
            'id desc').limit(
            str(page.SHIFT) + ',' + str(page.ROW)).select()
        return public.returnMsg(True, data)

    def get_logs(self, get):
        import cgi
        pythonV = sys.version_info[0]
        path = get.path.strip()
        if not os.path.exists(path): return ''
        # 判断文件超过3M 就不读取
        if os.path.getsize(path) > 1024 * 1024 * 3: return '文件过大,请下载查看 文件路径\n:%s' % path

        try:
            import html
            pythonV = sys.version_info[0]
            if 'drop_ip' in get:
                path = path
                num = 12
            else:
                path = path
                num = 10
            if not os.path.exists(path): return []
            p = 1
            if 'p' in get:
                p = int(get.p)
            start_line = (p - 1) * num
            count = start_line + num
            fp = open(path, 'rb')
            buf = ""
            try:
                fp.seek(-1, 2)
            except:
                return []
            if fp.read(1) == "\n": fp.seek(-1, 2)
            data = []
            b = True
            n = 0
            c = 0
            while c < count:
                while True:
                    newline_pos = str.rfind(buf, "\n")
                    pos = fp.tell()
                    if newline_pos != -1:
                        if n >= start_line:
                            line = buf[newline_pos + 1:]
                            if line:
                                try:
                                    tmp_data = json.loads(line)
                                    data.append(tmp_data)
                                except:
                                    c -= 1
                                    n -= 1
                                    pass
                            else:
                                c -= 1
                                n -= 1
                        buf = buf[:newline_pos]
                        n += 1
                        c += 1
                        break
                    else:
                        if pos == 0:
                            b = False
                            break
                        to_read = min(4096, pos)
                        fp.seek(-to_read, 1)
                        t_buf = fp.read(to_read)
                        if pythonV == 3: t_buf = t_buf.decode('utf-8', errors="ignore")
                        buf = t_buf + buf
                        fp.seek(-to_read, 1)
                        if pos - to_read == 0:
                            buf = "\n" + buf
                if not b: break
            fp.close()
            if 'drop_ip' in get:
                drop_iplist = self.get_waf_drop_ip(None)
                stime = time.time()
                setss = []
                for i in range(len(data)):
                    if (float(stime) - float(data[i][0])) < float(data[i][4]) and not data[i][1] in setss:
                        setss.append(data[i][1])
                        data[i].append(data[i][1] in drop_iplist)
                    else:
                        data[i].append(False)
        except:
            data = []
            return public.get_error_info()
        if len(data) >= 1:
            if (len(data[0]) >= 1):
                return data[0][0].replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>').replace("&quot;",
                                                                                                          "\"")
        return data

    def get_timestamp(self, str):
        timeArray = time.strptime('2021-06-06', "%Y-%m-%d")
        timeStamp = int(time.mktime(timeArray))
        return (timeStamp, timeStamp + 86400)

    def bytpes_to_string(self, data):
        for i in data:
            for key in i.keys():
                i[key] = self.to_str(i[key])

        return data

    def get_safe_logs_sql2(self, get):
        '''
        siteName:网站名称
        start_time:2021-05-06
        end_time:2021-05-07
        p:1  页数
        limit:10
        '''
        if not 'siteName' in get:
            return public.returnMsg(True, "请传递网站名称")
        if not 'limit' in get:
            limit = 10
        else:
            limit = int(get.limit.strip())
        if not 'p' in get:
            p = 10
        else:
            p = int(get.p.strip())
        if not 'start_time' in get:
            start_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
        else:
            start_time = get.start_time.strip()
        if not 'end_time' in get:
            # end_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
            end_time = start_time
        else:
            end_time = get.end_time.strip()
        start_time = start_time + ' 00:00:00'
        end_time2 = end_time + ' 23:59:59'
        start_timeStamp = int(time.mktime(time.strptime(start_time, '%Y-%m-%d %H:%M:%S')))
        end_timeStamp = int(time.mktime(time.strptime(end_time2, '%Y-%m-%d %H:%M:%S')))

        if os.path.exists("/www/server/btwaf/totla_db/totla_db.db"):
            import page
            page = page.Page()
            count = self.M2('totla_log').field('time').where("time>? and time<? and server_name=?", (
                start_timeStamp, end_timeStamp, get.siteName.strip())).order('id desc').count()
            info = {}
            info['count'] = count
            info['row'] = limit
            info['p'] = 1
            if hasattr(get, 'p'):
                info['p'] = int(get['p'])
            info['uri'] = get
            info['return_js'] = ''
            if hasattr(get, 'tojs'):
                info['return_js'] = get.tojs
            data = {}
            # 获取分页数据
            data['page'] = page.GetPage(info, '1,2,3,4,5,8')
            data['data'] = []
            data22 = self.M3('totla_log').field(
                'time,time_localtime,server_name,ip,ip_city,ip_country,ip_subdivisions,ip_longitude,ip_latitude,type,uri,user_agent,filter_rule,incoming_value,value_risk,http_log,http_log_path').order(
                'id desc').where("time>? and time<? and server_name=?",
                                 (start_timeStamp, end_timeStamp, get.siteName.strip())).limit(
                str(page.SHIFT) + ',' + str(page.ROW)).select()
            if type(data22) == str: public.returnMsg(True, data)
            try:
                data['data'] = self.bytpes_to_string(data22)
            except:
                pass
            return public.returnMsg(True, data)
        else:
            data = {}
            data['page'] = "<div><span class='Pcurrent'>1</span><span class='Pcount'>共0条</span></div>"
            data['data'] = []
            return public.returnMsg(False, data)

    # 设置经纬度
    def set_server_longitude(self, get):
        latitude = get.latitude.strip()
        longitude = get.longitude.strip()
        is_check_longitude = [latitude, longitude]
        if len(re.findall(r'-?[0-9]*\.*[0-9]+$', longitude)) == 0: return public.returnMsg(False, '经纬度错误')
        if len(re.findall(r'-?[0-9]*\.*[0-9]+$', latitude)) == 0: return public.returnMsg(False, '经纬度错误')
        if os.path.exists('/www/server/panel/data/get_geo2ip.json'):
            data = json.loads(public.ReadFile('/www/server/panel/data/get_geo2ip.json'))
            data['latitude'] = latitude
            data['longitude'] = longitude
            public.WriteFile('/www/server/panel/data/get_geo2ip.json', json.dumps(data))
            return public.returnMsg(True, '设置成功')
        else:
            return public.returnMsg(False, '设置失败')

    # 从外部刷新经纬度
    def get_wai_longitude(self, get):
        import requests
        result = {}
        jsonda = requests.get("http://www.bt.cn/api/panel/get_geo2ip", timeout=3).json()
        result['ip_address'] = jsonda['traits']['ip_address']
        result['latitude'] = jsonda['location']['latitude']
        result['longitude'] = jsonda['location']['longitude']
        public.WriteFile('/www/server/panel/data/get_geo2ip.json', json.dumps(result))
        return public.returnMsg(True, result)

    def get_server_longitude(self, get):

        try:
            if os.path.exists('/www/server/panel/data/get_geo2ip.json'):
                data = json.loads(public.ReadFile('/www/server/panel/data/get_geo2ip.json'))
                return public.returnMsg(True, data)
            else:
                #
                import requests
                result = {}
                user_info = public.get_user_info()
                data = {}
                data['ip'] = user_info['address']
                data['uid'] = user_info['uid']
                data["serverid"] = user_info["serverid"]
                jsonda = requests.get("https://www.bt.cn/api/panel/get_ip_info", timeout=3).json()
                result['ip_address'] = data['ip']
                result['latitude'] = jsonda[data['ip']]['latitude']
                result['longitude'] = jsonda[data['ip']]['longitude']
                public.WriteFile('/www/server/panel/data/get_geo2ip.json', json.dumps(result))
                return public.returnMsg(True, result)
        except:
            result = {}
            result['ip_address'] = "localhost"
            result['latitude'] = 39.929986
            result['longitude'] = 116.395645
            return public.returnMsg(True, result)

    def gongji_map(self, get):
        '''
        返回攻击地图
        '''
        if os.path.exists("/www/server/btwaf/totla_db/totla_db.db"):
            map_24_data = self.M2('totla_log').field(
                'ip,ip_country,ip_subdivisions,ip_longitude,ip_latitude').where("time>=?",
                                                                                int(time.time()) - 86400 * 7).order(
                'id desc').limit("500").select()
            if type(map_24_data) == str: return public.returnMsg(True, [])
            ret = []
            for i in map_24_data:
                if i['ip_country'] == '内网地址': continue
                if not i["ip_latitude"]: continue
                if not i["ip_longitude"]: continue
                ret.append(i)

            return public.returnMsg(True, ret)
        return public.returnMsg(True, [])

    '''攻击搜索'''
    '''
        所有网站[前10W条数据分析]
            根据IP搜索
            根据URI进行搜索
            根据UA搜索
            根据时间搜索攻击
        单个网站[5W条数据分析]
            根据IP搜索
            根据URI进行搜索
            根据UA搜索
            根据时间搜索攻击
    '''

    def get_search(self, get):
        '''
        :param get:
            参数is_all 是否查询所有
            参数server_name 当查询所有的时候不需要传递
            参数type  查询的类型 1->ip  2->uri  3->url 4->时间搜索
            参数start_time  end_time --> 类型为4 的时候才传递的时间参数  默认不传递是今天的
            参数serach 类型为1-2-3 的时候需要传递的查询语句
        '''
        if not 'is_all' in get:
            is_all = 0
        else:
            is_all = get.is_all.strip()
        if not os.path.exists("/www/server/btwaf/totla_db/totla_db.db"): return public.returnMsg(False, "无数据库文件")
        if int(is_all) == 1:
            if not 'type' in get: return public.returnMsg(False, "必须传递type参数")
            type = get.type.strip()
            if int(type) == 4:
                if not 'start_time' in get:
                    start_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
                else:
                    start_time = get.start_time.strip()
                if not 'end_time' in get:
                    end_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
                else:
                    end_time = get.end_time.strip()
                start_time = start_time + ' 00:00:00'
                end_time2 = end_time + ' 23:59:59'
                start_timeStamp = int(time.mktime(time.strptime(start_time, '%Y-%m-%d %H:%M:%S')))
                end_timeStamp = int(time.mktime(time.strptime(end_time2, '%Y-%m-%d %H:%M:%S')))
                import page
                page = page.Page()
                count = self.M2('totla_log').field('time').where("time>? and time<?", (
                    start_timeStamp, end_timeStamp)).order('id desc').count()
                info = {}
                info['count'] = count
                info['row'] = 10
                info['p'] = 1
                if hasattr(get, 'p'):
                    info['p'] = int(get['p'])
                info['uri'] = get
                info['return_js'] = ''
                if hasattr(get, 'tojs'):
                    info['return_js'] = get.tojs
                data = {}
                # 获取分页数据
                data['page'] = page.GetPage(info, '1,2,3,4,5,8')
                data22 = self.M3('totla_log').field(
                    'id,time,time_localtime,server_name,ip,uri,filter_rule').order('id desc').where("time>? and time<?",
                                                                                                    (start_timeStamp,
                                                                                                     end_timeStamp)).limit(
                    str(page.SHIFT) + ',' + str(page.ROW)).select()
                data['data'] = self.bytpes_to_string(data22)
                return public.returnMsg(True, data)
            else:
                if not 'serach' in get: return public.returnMsg(False, "必须传递serach参数")
                serach = get.serach.strip()
                if int(type) == 1:
                    import page
                    page = page.Page()
                    count = self.M2('totla_log').field('time').where("ip=?", serach).order('id desc').count()
                    info = {}
                    info['count'] = count
                    info['row'] = 10
                    info['p'] = 1
                    if hasattr(get, 'p'):
                        info['p'] = int(get['p'])
                    info['uri'] = get
                    info['return_js'] = ''
                    if hasattr(get, 'tojs'):
                        info['return_js'] = get.tojs
                    data = {}
                    # 获取分页数据
                    data['page'] = page.GetPage(info, '1,2,3,4,5,8')
                    data22 = self.M3('totla_log').field(
                        'id,time,time_localtime,server_name,ip,uri,filter_rule').order('id desc').where("ip=?",
                                                                                                        serach).limit(
                        str(page.SHIFT) + ',' + str(page.ROW)).select()
                    data['data'] = self.bytpes_to_string(data22)
                    return public.returnMsg(True, data)
                if int(type) == 2:
                    try:
                        result = []
                        '''uri==> /?id=/etc/passwd  代表的是/  为uri'''

                        data_count = self.M2('totla_log').query(
                            "select COUNT(*) from totla_log WHERE uri like '{}%';".format(serach))
                        if data_count[0]:
                            if data_count[0][0]:
                                count = data_count[0][0]
                            else:
                                count = 0
                        else:
                            count = 0
                        import page
                        page = page.Page()
                        count = count
                        info = {}
                        info['count'] = count
                        info['row'] = 12
                        info['p'] = 1
                        if hasattr(get, 'p'):
                            info['p'] = int(get['p'])
                        info['uri'] = get
                        info['return_js'] = ''
                        if hasattr(get, 'tojs'):
                            info['return_js'] = get.tojs
                        data = {}
                        # 获取分页数据
                        data['page'] = page.GetPage(info, '1,2,3,4,5,8')
                        data222 = self.M2('totla_log').query(
                            "select id,time,time_localtime,server_name,ip,uri,filter_rule from totla_log WHERE uri like '{0}%' limit {1},{2}".format(
                                serach, str(page.SHIFT), str(page.ROW)))
                        if len(data222) > 0:
                            ret = []
                            for i in data222:
                                ret.append(
                                    {"id": i[0], "time": i[1], "time_localtime": i[2], "server_name": i[3], "ip": i[4],
                                     "uri": i[5], "filter_rule": i[6]})
                            data['data'] = ret
                        else:
                            data['data'] = []
                        return public.returnMsg(True, data)
                    except:
                        return {"status": True, "msg": {
                            "page": "<div><span class='Pcurrent'>1</span><span class='Pcount'>共0条</span></div>",
                            "data": []}}
                if int(type) == 3:
                    '''url ==> /?id=/etc/passwd 代表为 /?id=/etc/passwd'''
                    import page
                    page = page.Page()
                    count = self.M2('totla_log').field('time').where("uri=?", serach).order('id desc').count()
                    info = {}
                    info['count'] = count
                    info['row'] = 10
                    info['p'] = 1
                    if hasattr(get, 'p'):
                        info['p'] = int(get['p'])
                    info['uri'] = get
                    info['return_js'] = ''
                    if hasattr(get, 'tojs'):
                        info['return_js'] = get.tojs
                    data = {}
                    # 获取分页数据
                    data['page'] = page.GetPage(info, '1,2,3,4,5,8')
                    data22 = self.M3('totla_log').field(
                        'id,time,time_localtime,server_name,ip,uri,filter_rule').order('id desc').where("uri=?",
                                                                                                        serach).limit(
                        str(page.SHIFT) + ',' + str(page.ROW)).select()
                    data['data'] = self.bytpes_to_string(data22)
                    return public.returnMsg(True, data)
                else:
                    return public.returnMsg(False, "参数传递错误")
        else:
            if not 'server_name' in get:
                return public.returnMsg(False, "请选择需要查询的网站名称")
            else:
                server_name = get.server_name.strip()
                if not 'type' in get: return public.returnMsg(False, "必须传递type参数")
                type = get.type.strip()
                if int(type) == 4:
                    if not 'start_time' in get:
                        start_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
                    else:
                        start_time = get.start_time.strip()
                    if not 'end_time' in get:
                        end_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
                    else:
                        end_time = get.end_time.strip()
                    start_time = start_time + ' 00:00:00'
                    end_time2 = end_time + ' 23:59:59'
                    start_timeStamp = int(time.mktime(time.strptime(start_time, '%Y-%m-%d %H:%M:%S')))
                    end_timeStamp = int(time.mktime(time.strptime(end_time2, '%Y-%m-%d %H:%M:%S')))
                    import page
                    page = page.Page()
                    count = self.M2('totla_log').field('time').where("time>? and time<? and server_name=?", (
                        start_timeStamp, end_timeStamp, server_name)).order('id desc').count()
                    info = {}
                    info['count'] = count
                    info['row'] = 10
                    info['p'] = 1
                    if hasattr(get, 'p'):
                        info['p'] = int(get['p'])
                    info['uri'] = get
                    info['return_js'] = ''
                    if hasattr(get, 'tojs'):
                        info['return_js'] = get.tojs
                    data = {}
                    # 获取分页数据
                    data['page'] = page.GetPage(info, '1,2,3,4,5,8')
                    data22 = self.M2('totla_log').field(
                        'id,time,time_localtime,server_name,ip,uri,filter_rule').order('id desc').where(
                        "time>? and time<? and server_name=?",
                        (start_timeStamp, end_timeStamp, server_name)).limit(
                        str(page.SHIFT) + ',' + str(page.ROW)).select()
                    data['data'] = data22
                    return public.returnMsg(True, data)
                else:
                    if not 'serach' in get: return public.returnMsg(False, "必须传递serach参数")
                    serach = get.serach.strip()
                    if int(type) == 1:
                        import page
                        page = page.Page()
                        count = self.M2('totla_log').field('time').where("ip=? and server_name=?",
                                                                         (serach, server_name)).order('id desc').count()
                        info = {}
                        info['count'] = count
                        info['row'] = 10
                        info['p'] = 1
                        if hasattr(get, 'p'):
                            info['p'] = int(get['p'])
                        info['uri'] = get
                        info['return_js'] = ''
                        if hasattr(get, 'tojs'):
                            info['return_js'] = get.tojs
                        data = {}
                        # 获取分页数据
                        data['page'] = page.GetPage(info, '1,2,3,4,5,8')
                        data22 = self.M3('totla_log').field(
                            'id,time,time_localtime,server_name,ip,uri,filter_rule').order('id desc').where(
                            "ip=? and server_name=?", (serach, server_name)).limit(
                            str(page.SHIFT) + ',' + str(page.ROW)).select()
                        data['data'] = self.bytpes_to_string(data22)
                        return public.returnMsg(True, data)
                    if int(type) == 2:
                        try:
                            data_count = self.M2('totla_log').query(
                                "select COUNT(*) from totla_log WHERE server_name='{0}' and uri like '{1}?%';".format(
                                    server_name, serach))
                            if data_count[0]:
                                if data_count[0][0]:
                                    count = data_count[0][0]
                                else:
                                    count = 0
                            else:
                                count = 0
                            import page
                            page = page.Page()
                            count = count
                            info = {}
                            info['count'] = count
                            info['row'] = 10
                            info['p'] = 1
                            if hasattr(get, 'p'):
                                info['p'] = int(get['p'])
                            info['uri'] = get
                            info['return_js'] = ''
                            if hasattr(get, 'tojs'):
                                info['return_js'] = get.tojs
                            data = {}
                            # 获取分页数据
                            data['page'] = page.GetPage(info, '1,2,3,4,5,8')
                            data222 = self.M2('totla_log').query(
                                "select id,time,time_localtime,server_name,ip,uri,filter_rule from totla_log WHERE server_name='{3}' and  uri like '{0}?%' limit {1},{2}".format(
                                    serach, str(page.SHIFT), str(page.ROW), server_name))
                            if len(data222) > 0:
                                ret = []
                                for i in data222:
                                    ret.append(
                                        {"id": i[0], "time": i[1], "time_localtime": i[2], "server_name": i[3],
                                         "ip": i[4],
                                         "uri": i[5], "filter_rule": i[6]})
                                data['data'] = ret
                            else:
                                data['data'] = []
                            return public.returnMsg(True, data)
                        except:
                            return {"status": True, "msg": {
                                "page": "<div><span class='Pcurrent'>1</span><span class='Pcount'>共0条</span></div>",
                                "data": []}}
                    if int(type) == 3:
                        '''url ==> /?id=/etc/passwd 代表为 /?id=/etc/passwd'''
                        import page
                        page = page.Page()
                        count = self.M2('totla_log').field('time').where("uri=? and server_name=?",
                                                                         (serach, server_name)).order('id desc').count()
                        info = {}
                        info['count'] = count
                        info['row'] = 10
                        info['p'] = 1
                        if hasattr(get, 'p'):
                            info['p'] = int(get['p'])
                        info['uri'] = get
                        info['return_js'] = ''
                        if hasattr(get, 'tojs'):
                            info['return_js'] = get.tojs
                        data = {}
                        # 获取分页数据
                        data['page'] = page.GetPage(info, '1,2,3,4,5,8')
                        data22 = self.M3('totla_log').field(
                            'id,time,time_localtime,server_name,ip,uri,filter_rule').order('id desc').where(
                            "uri=? and server_name=?", (serach, server_name)).limit(
                            str(page.SHIFT) + ',' + str(page.ROW)).select()
                        data['data'] = self.bytpes_to_string(data22)
                        return public.returnMsg(True, data)
                    else:
                        return public.returnMsg(False, "参数传递错误")

    def get_id_log(self, get):
        '''
        返回当前ID的数据
        '''
        id = get.id.strip()
        if self.M2('totla_log').where("id=?", id).count() == 0: return public.returnMsg(False, "当前ID不存在")
        data22 = self.M3('totla_log').field(
            'id,time,time_localtime,server_name,ip,ip_city,ip_country,ip_subdivisions,ip_longitude,ip_latitude,type,uri,user_agent,filter_rule,incoming_value,value_risk,http_log,http_log_path').order(
            'id desc').where("id=?", id).select()
        data = self.bytpes_to_string(data22)
        return public.returnMsg(True, data)

    def takeSecond(self, elem):
        return elem[1]

    def report_data(self, data):
        '''
        返回报表数据
        '''
        result = {}
        result["type"] = {}
        result["ip"] = {}
        result["uri"] = {}
        result["ip_list"] = {}
        result['uri_list'] = {}
        tmp = {}
        for i in data:
            if i['ip'] in result["ip"]:
                result["ip"][i['ip']] = result["ip"][i['ip']] + 1
            else:
                result["ip_list"][i['ip']] = {"uri": {}, "list": [], "type": {}, "ip_country": ""}
                result["ip"][i['ip']] = 1
            tmp[i['ip']] = i['ip_country']
            if not result["ip_list"][i['ip']]["ip_country"]:
                result["ip_list"][i['ip']]["ip_country"] = i["ip_country"]
            tmp[i['ip'] + "ip_subdivisions"] = i['ip_subdivisions']
            if not "ip_subdivisions" in result["ip_list"][i['ip']]:
                result["ip_list"][i['ip']]["ip_subdivisions"] = i["ip_subdivisions"]
            tmp[i['ip'] + "ip_city"] = i['ip_city']
            if not "ip_city" in result["ip_list"][i['ip']]:
                result["ip_list"][i['ip']]["ip_city"] = i["ip_city"]
            #
            # if not result["ip_list"][i['ip']]["ip_subdivisions"]:
            #    result["ip_list"][i['ip']]["ip_subdivisions"]=i["ip_subdivisions"]

            # if not result["ip_list"][i['ip']]["ip_city"]:
            #    result["ip_list"][i['ip']]["ip_city"]=i["ip_city"]

            url = i['uri'].split("?")[0]
            if url in result["ip_list"][i['ip']]["uri"]:
                result["ip_list"][i['ip']]["uri"][url] += 1
            else:
                result["ip_list"][i['ip']]["uri"][url] = 1
            if url in result["uri"]:
                result["uri"][url] = result["uri"][url] + 1
            else:
                result["uri"][url] = 1
            if i['filter_rule'] in result["ip_list"][i['ip']]["type"]:
                result["ip_list"][i['ip']]["type"][i['filter_rule']] += 1
            else:
                result["ip_list"][i['ip']]["type"][i['filter_rule']] = 1
            if i['filter_rule'] in result["type"]:
                if i['filter_rule']:
                    result["type"][i['filter_rule']] += 1
            else:
                if i['filter_rule']:
                    result["type"][i['filter_rule']] = 1
            if not url in result['uri_list']:
                result['uri_list'][url] = {"ip_list": []}
            if len(result['uri_list'][url]['ip_list']) < 100:
                result['uri_list'][url]['ip_list'].append(
                    {"id": i["id"], "uri": i['uri'], "ip": i["ip"], "filter_rule": i["filter_rule"],
                     "server_name": i['server_name'], "time_localtime": i["time_localtime"],
                     "ip_country": i["ip_country"], "ip_subdivisions": i["ip_subdivisions"], "ip_city": i["ip_city"]})
            if len(result["ip_list"][i['ip']]["list"]) < 100:
                result["ip_list"][i['ip']]["list"].append(
                    {"id": i["id"], "uri": i['uri'], "filter_rule": i["filter_rule"], "server_name": i['server_name'],
                     "time_localtime": i["time_localtime"], "ip_country": i["ip_country"],
                     "ip_subdivisions": i["ip_subdivisions"], "ip_city": i["ip_city"]})

        result["ip"] = (sorted(result["ip"].items(), key=lambda kv: (kv[1], kv[0]), reverse=True))
        if len(result["ip"]) > 100:
            result["ip"] = result["ip"][0:100]
        ip_country = []
        for i in result["ip"]:
            # 查看ip归属地
            ret = []
            ret.append(i[0])
            ret.append(i[1])
            ip_c = tmp[i[0]]
            ip_p = tmp[i[0] + "ip_subdivisions"]
            ip_d = tmp[i[0] + "ip_city"]
            ret.append(ip_c)
            ret.append(ip_p)
            ret.append(ip_d)
            ip_country.append(ret)
        result["ip"] = ip_country

        top_uri = (sorted(result["uri"].items(), key=lambda kv: ((kv[1]), kv[0]), reverse=True))
        result["uri"] = top_uri
        top_type = (sorted(result["type"].items(), key=lambda kv: (kv[1], kv[0]), reverse=True))
        result["type"] = top_type
        ip_list = {}
        for i in result["ip"]:
            if i[0] in result['ip_list']:
                result['ip_list'][i[0]]['uri'] = (
                    sorted(result['ip_list'][i[0]]['uri'].items(), key=lambda kv: (kv[1], kv[0]), reverse=True))
                ip_list[i[0]] = result['ip_list'][i[0]]
        result["ip_list"] = ip_list
        return result

    def get_report(self, get):
        # 默认是获取当天的数据
        if not 'start_time' in get:
            start_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
        else:
            start_time = get.start_time.strip()
        if not 'end_time' in get:
            end_time = start_time
        else:
            end_time = get.end_time.strip()
        start_time = start_time + ' 00:00:00'
        end_time2 = end_time + ' 23:59:59'
        start_timeStamp = int(time.mktime(time.strptime(start_time, '%Y-%m-%d %H:%M:%S')))
        end_timeStamp = int(time.mktime(time.strptime(end_time2, '%Y-%m-%d %H:%M:%S')))
        key = "get_report" + str(start_timeStamp) + str(end_timeStamp)

        if public.cache_get(key):
            public.run_thread(self.get_report_info, get)
            inf = public.cache_get(key)
            return public.returnMsg(True, inf)
        else:
            return self.get_report_info(get)

    '''
    所有网站[前30W条数据分析]
        漏洞攻击类型分布图
        攻击IP流量分析（top200）
        攻击页面分析(top 200)

    单个网站[前10W条数据分析]
        漏洞攻击类型分布图
        攻击IP流量分析（top200）
        攻击页面分析(top 200)
    '''

    def get_report_info(self, get):
        tmp = {"type": [], "ip": [], "uri": [], "ip_list": {}, "uri_list": {}}
        # 默认是获取当天的数据
        if not 'start_time' in get:
            start_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
        else:
            start_time = get.start_time.strip()
        if not 'end_time' in get:
            end_time = start_time
        else:
            end_time = get.end_time.strip()
        start_time = start_time + ' 00:00:00'
        end_time2 = end_time + ' 23:59:59'
        start_timeStamp = int(time.mktime(time.strptime(start_time, '%Y-%m-%d %H:%M:%S')))
        end_timeStamp = int(time.mktime(time.strptime(end_time2, '%Y-%m-%d %H:%M:%S')))
        key = "get_report" + str(start_timeStamp) + str(end_timeStamp)

        if 'server_name' in get:
            if os.path.exists("/www/server/btwaf/totla_db/totla_db.db"):
                map_24_data = self.M3('totla_log').field(
                    'id,time_localtime,ip,uri,server_name,type,filter_rule,ip_city,ip_country,ip_subdivisions').where(
                    "time>? and time<? and server_name=?",
                    (start_timeStamp, end_timeStamp, get.server_name.strip())).limit("10000").order('id desc').select()
                if type(map_24_data) == str: return public.returnMsg(True, tmp)
                map_24_data = self.bytpes_to_string(map_24_data)
                public.cache_set(key, self.report_data(map_24_data), 30)
                return public.returnMsg(True, self.report_data(map_24_data))
            return public.returnMsg(True, tmp)
        else:
            if os.path.exists("/www/server/btwaf/totla_db/totla_db.db"):
                map_24_data = self.M3('totla_log').field(
                    'id,time_localtime,ip,uri,server_name,type,filter_rule,ip_city,ip_country,ip_subdivisions').where(
                    "time>? and time<?", (start_timeStamp, end_timeStamp), ).limit("10000").order('id desc').select()
                if type(map_24_data) == str: return public.returnMsg(True, tmp)
                map_24_data = self.bytpes_to_string(map_24_data)
                public.cache_set(key, self.report_data(map_24_data), 30)
                return public.returnMsg(True, self.report_data(map_24_data))
            return public.returnMsg(True, tmp)

    def get_server_name(self, get):
        try:
            site_config = public.readFile(self.__path + 'site.json')
            resutl = []
            data = json.loads(site_config)
            for i in data.items():
                resutl.append(i[0])
            return resutl
        except:
            return []
        return []

    def test222(self, get):
        return self.M2('totla_log').field('id,time_localtime,ip,uri,server_name,type,filter_rule').limit(
            "100000").order(
            'id desc').count()

    def get_cc_uri_frequency(self, get):
        get_config = self.get_config(None)
        return get_config['cc_uri_frequency']

    def add_cc_uri_frequency(self, get):
        if 'url' not in get: return public.ReturnMsg(False, '参数url不能为空')
        if 'frequency' not in get: return public.ReturnMsg(False, '参数frequency不能为空')
        if 'cycle' not in get: return public.ReturnMsg(False, '参数cycle不能为空')

        get_config = self.get_config(None)
        cc_uri_frequency = get_config['cc_uri_frequency']
        if get.url.strip() in cc_uri_frequency:
            return public.ReturnMsg(False, '已经存在')

        cc_uri_frequency[get.url.strip()] = {'frequency': get.frequency.strip(), 'cycle': get.cycle.strip()}
        get_config['cc_uri_frequency'] = cc_uri_frequency
        self.__write_config(get_config)
        return public.ReturnMsg(True, '添加成功')

    def del_cc_uri_frequency(self, get):
        if 'url' not in get: return public.ReturnMsg(False, '参数url不能为空')
        get_config = self.get_config(None)
        cc_uri_frequency = get_config['cc_uri_frequency']
        if get.url.strip() in cc_uri_frequency:
            del cc_uri_frequency[get.url.strip()]
            get_config['cc_uri_frequency'] = cc_uri_frequency
            self.__write_config(get_config)
            return public.ReturnMsg(True, '删除成功')
        return public.ReturnMsg(False, '不存在')

    def edit_cc_uri_frequency(self, get):
        if 'url' not in get: return public.ReturnMsg(False, '参数url不能为空')
        if 'frequency' not in get: return public.ReturnMsg(False, '参数frequency不能为空')
        if 'cycle' not in get: return public.ReturnMsg(False, '参数cycle不能为空')
        get_config = self.get_config(None)
        cc_uri_frequency = get_config['cc_uri_frequency']
        if get.url.strip() in cc_uri_frequency:
            cc_uri_frequency[get.url.strip()] = {'frequency': get.frequency.strip(), 'cycle': get.cycle.strip()}
            get_config['cc_uri_frequency'] = cc_uri_frequency
            self.__write_config(get_config)
            return public.ReturnMsg(True, '修改成功')
        return public.ReturnMsg(False, '不存在')

    # 验证是否存在人机验证
    def check_renji(self, get):
        # if os.path.exists('/www/server/btwaf/init.lua'):
        #     lua_data = public.ReadFile('/www/server/btwaf/init.lua')
        #     if 'a20be899_96a6_40b2_88ba_32f1f75f1552_yanzheng_huadong' in lua_data:
        #         return True
        #     else:
        #         return False
        return True

    # 添加url_cc_param 参数
    def add_url_cc_param(self, get):
        '''
        @name 添加url_cc_param 参数
        @param get.uri 请求的uri
        @param get.param 参数列表
        @param get.type 参数值
        @param get.stype  类型值  一个是url  一个是regular
        '''
        # {"index.php":{"param":[],"type":1,"stype":"url"}}
        if not 'uri' in get: return public.returnMsg(False, "必须传递uri参数")
        if not 'param' in get: return public.returnMsg(False, "必须传递param参数")
        if not 'type' in get: return public.returnMsg(False, "必须传递type参数")
        if not 'stype' in get: return public.returnMsg(False, "必须传递stype参数")
        config = self.get_config(None)
        if get.uri.strip() in config['url_cc_param']: return public.returnMsg(False, "当前URI已经存在")
        try:
            param = json.loads(get.param)
            type = (int(get.type))
        except:
            return public.returnMsg(False, "param类型不对,需要json格式")

        if 'url_cc_param' not in config:
            config['url_cc_param'] = {}
        config['url_cc_param'][get.uri.strip()] = {"param": param, 'type': type, 'stype': get.stype.strip()}
        self.__write_config(config)
        return public.returnMsg(True, "添加成功")

    # 删除url_cc_param 参数
    def del_url_cc_param(self, get):
        if not 'uri' in get: return public.returnMsg(False, "必须传递uri参数")
        config = self.get_config(None)
        if 'url_cc_param' not in config:
            config['url_cc_param'] = {}
        if not get.uri.strip() in config['url_cc_param']: return public.returnMsg(False, "当前URI不存在")
        del config['url_cc_param'][get.uri.strip()]
        self.__write_config(config)
        return public.returnMsg(True, "删除成功")

    def wubao_webshell(self, get):
        if 'path' not in get:
            return public.returnMsg(False, '必须传递path参数')
        path = self.Recycle_bin + get.path
        if not os.path.exists(path):
            return public.returnMsg(False, '文件不存在')
        dFile = get.path.replace('_bt_', '/').split('_t_')[0]
        file_md5 = public.Md5(dFile)
        # 删除webshell那个内容以及文件
        webshell_path = "/www/server/panel/data/btwaf_wubao/"
        if not os.path.exists(webshell_path):
            os.makedirs(webshell_path)
        wubao_file = webshell_path + file_md5 + ".txt"
        public.WriteFile(wubao_file, '')
        # 恢复文件
        return self.Re_Recycle_bin(get)

    def del_yangben(self, get):

        if not 'path' in get:
            return public.returnMsg(False, '必须传递path参数')
        if not 'is_path' in get:
            is_path = 1
        webshell_path = "/www/server/panel/data/btwaf_webshell/"

        if os.path.exists(webshell_path + get.is_path):
            try:
                os.remove(webshell_path + get.is_path)
            except:
                pass
        if 'delete' in get:
            if os.path.exists(get.path):
                try:
                    os.remove(get.path)
                except:
                    pass
        try:
            webshell_info = json.loads(public.ReadFile("/www/server/btwaf/webshell.json"))
            if get.path in webshell_info:
                webshell_path = "/www/server/panel/data/btwaf_webshell/"
                if os.path.exists(webshell_path + webshell_info[get.path]):
                    os.remove(webshell_path + webshell_info[get.path])
                del webshell_info[get.path]
                public.writeFile('/www/server/btwaf/webshell.json', json.dumps(webshell_info))
        except:
            pass

        return public.returnMsg(True, '删除成功')

    def restore_default_configuration(self, get):
        config_path = '/www/server/btwaf/config.json'
        config = '''{
	"scan": {
		"status": 444,
		"ps": "过滤常见扫描测试工具的渗透测试",
		"open": true,
		"reqfile": ""
	},
	"cc": {
		"status": 444,
		"ps": "过虑CC攻击",
		"increase": false,
		"limit": 120,
		"endtime": 300,
		"open": true,
		"reqfile": "",
		"cycle": 60
	},
	"logs_path": "/www/wwwlogs/btwaf",
	"open": true,
	"reqfile_path": "/www/server/btwaf/html",
	"retry": 10,
	"log": true,
	"cc_automatic": false,
	"user-agent": {
		"status": 403,
		"ps": "通常用于过滤浏览器、蜘蛛及一些自动扫描器",
		"open": true,
		"reqfile": "user_agent.html"
	},
	"other": {
		"status": 403,
		"ps": "其它非通用过滤",
		"reqfile": "other.html"
	},
	"uri_find": [],
	"cc_retry_cycle": "600",
	"cc_time": "60",
	"ua_black": [],
	"drop_abroad": {
		"status": 444,
		"ps": "禁止中国大陆以外的地区访问站点",
		"open": true,
		"reqfile": ""
	},
	"retry_cycle": 120,
	"get": {
		"status": 403,
		"ps": "过滤uri、uri参数中常见sql注入、xss等攻击",
		"open": true,
		"reqfile": "get.html"
	},
	"body_character_string": [],
	"start_time": 0,
	"cookie": {
		"status": 403,
		"ps": "过滤利用Cookie发起的渗透攻击",
		"open": true,
		"reqfile": "cookie.html"
	},
	"retry_time": 1800,
	"post": {
		"status": 403,
		"ps": "过滤POST参数中常见sql注入、xss等攻击",
		"open": true,
		"reqfile": "post.html"
	},
	"scan_conf":{"open": true, "limit": 240, "cycle": 60},
	"ua_white": [],
	"body_regular": [],
	"log_save": 30
}'''

        public.WriteFile(config_path, config)

        # 读取网站配置文件
        try:
            site_config = json.loads(public.readFile(self.__path + 'site.json'))
        except:
            site_config = {}
        for i in site_config:
            public.cache_remove("btwaf_site_config" + i)

        site_config_path = '/www/server/btwaf/site.json'
        public.WriteFile(site_config_path, '{}')

        # ip白名单
        ip_white_path = '/www/server/btwaf/rule/ip_white.json'
        public.WriteFile(ip_white_path, '[[2130706433, 2130706687]]')

        # ip黑名单
        ip_black_path = '/www/server/btwaf/rule/ip_black.json'
        public.WriteFile(ip_black_path, '[]')

        # url白名单
        url_white_path = '/www/server/btwaf/rule/url_white.json'
        public.WriteFile(url_white_path, '[]')

        # url黑名单
        url_black_path = '/www/server/btwaf/rule/url_black.json'
        public.WriteFile(url_black_path, '[]')

        # 统计文件
        statistics_path = '/www/server/btwaf/total.json'
        public.WriteFile(statistics_path,
                         '{"rules":{"user_agent":0,"cookie":0,"post":0,"args":0,"url":0,"cc":0},"sites":{},"total":0}')

        # domains.json
        domains_path = '/www/server/btwaf/domains.json'

        public.WriteFile(domains_path, '[]')

        # 地区限制
        area_limit_path = '/www/server/btwaf/rule/reg_tions.json'

        public.WriteFile(area_limit_path, '[]')

        public.WriteFile("/www/server/btwaf/rule/cc_uri_white.json", '[]')
        public.WriteFile("/www/server/btwaf/rule/customize.json", '{}')
        public.WriteFile("/www/server/btwaf/rule/customize_count.json", '{}')
        public.WriteFile("/www/server/btwaf/rule/get_spider.json", '{}')
        public.WriteFile("/www/server/btwaf/rule/head_white.json", '[]')
        public.WriteFile("/www/server/btwaf/rule/ip_black_v6.json", '[]')
        public.WriteFile("/www/server/btwaf/rule/ip_white_v6.json", '[]')
        public.WriteFile("/www/server/btwaf/rule/not_spider.json", '{}')
        public.WriteFile("/www/server/btwaf/rule/reg_city.json", '[]')
        public.WriteFile("/www/server/btwaf/rule/reg_tions.json", '[]')
        public.WriteFile("/www/server/btwaf/rule/url_request_mode.json", '[]')
        public.WriteFile("/www/server/btwaf/rule/url_white_senior.json", '[]')

        # 初始化默认配置

        self.get_config(get)
        self.get_site_config(get)
        public.ExecShell("/etc/init.d/nginx restar")
        return public.returnMsg(True, '恢复成功')

    def get_site_logs_sql(self, tables, conditions):
        start_date = conditions["start_time"]
        end_date = conditions["end_time"]
        reverse_mode = ""
        if "reverse_mode" in conditions:
            reverse_mode = conditions["reverse_mode"]

        time_reverse = False
        if 'server_name' in conditions:
            where_sql = " where server_name=\"{}\" ".format(conditions['server_name'])
            if "time_reverse" in conditions:
                time_reverse = conditions["time_reverse"]
            if not time_reverse:
                where_sql += " and time >= {} and time <= {}".format(start_date, end_date)
            else:
                where_sql += " and time < {} or time > {}".format(start_date, end_date)
        else:
            if "time_reverse" in conditions:
                time_reverse = conditions["time_reverse"]
            if not time_reverse:
                where_sql = " where time >= {} and time <= {}".format(start_date, end_date)
            else:
                where_sql = " where time < {} or time > {}".format(start_date, end_date)

        conditions_keys = conditions.keys()
        if "status_code" in conditions_keys:
            status_code = conditions["status_code"]
            status_code_50x = [500, 501, 502, 503, 504, 505, 506, 507, 509]
            status_code_40x = [400, 401, 402, 403, 404, 405, 406, 407, 408, 409]
            status_code_5xx = [500, 501, 502, 503, 504, 505, 506, 507, 509, 510]
            status_code_4xx = [400, 401, 402, 403, 404, 405, 406, 407, 408, 409,
                               410, 411, 412, 413, 414, 415, 416, 417, 418, 421,
                               422, 423, 424, 425, 426, 449, 451, 499]
            if status_code in ["5xx", "5**", "5XX"]:
                status_code = ",".join([str(s) for s in status_code_5xx])
            elif status_code in ["50x", "50X", "50*"]:
                status_code = ",".join([str(s) for s in status_code_50x])
            elif status_code in ["4xx", "4**", "4XX"]:
                status_code = ",".join([str(s) for s in status_code_4xx])
            elif status_code in ["40x", "40X", "40*"]:
                status_code = ",".join([str(s) for s in status_code_40x])
            else:
                status_code = status_code
            if status_code != "all":
                if not reverse_mode:
                    where_sql += " and status_code in ({})".format(status_code)
                else:
                    where_sql += " and status_code not in ({})".format(status_code)
        if "method" in conditions_keys:
            method = conditions["method"]
            if method != "all":
                if not reverse_mode:
                    where_sql += " and method='{}'".format(method)
                else:
                    where_sql += " and method<>'{}'".format(method)
        search_url = ""
        if "serach_url" in conditions_keys:
            search_url = conditions["serach_url"]
        if "uri" in conditions_keys:
            search_url = conditions["uri"]
        search_mode = "fuzzy"
        if "search_mode" in conditions_keys:
            search_mode = conditions["search_mode"]
        if search_url:
            if search_url.find(",") < 0:
                if search_mode == "fuzzy":
                    if not reverse_mode:
                        where_sql += " and uri like '%{}%'".format(search_url)
                    else:
                        where_sql += " and uri not like '%{}%'".format(search_url)
                else:
                    if not reverse_mode:
                        where_sql += " and uri='{}'".format(search_url)
                    else:
                        where_sql += " and uri<>'{}'".format(search_url)
            else:
                _sql = ""
                for url in search_url.split(","):
                    url = url.strip()
                    if _sql:
                        _sql += " or "
                    if search_mode == "fuzzy":
                        if not reverse_mode:
                            _sql += "uri like '%{}%'".format(url)
                        else:
                            _sql += "uri not like '%{}%'".format(url)
                    else:
                        if not reverse_mode:
                            _sql += "uri='{}'".format(url)
                        else:
                            _sql += "uri<>'{}'".format(url)
                where_sql += " and " + _sql
        # ip
        if "ip" in conditions_keys:
            ip = conditions["ip"].strip()
            if ip:
                ip = ip.replace("，", ",")
                if ip.find(",") > 0:
                    ip = ",".join(["'" + ip.strip() + "'" for ip in ip.split(",")])
                    if not reverse_mode:
                        where_sql += " and ip in (" + ip + ")"
                    else:
                        where_sql += " and ip not in (" + ip + ")"
                elif ip.find("*") >= 0:
                    ip = ip.replace("*", "%")
                    if not reverse_mode:
                        where_sql += " and (ip like \"" + ip + "\" or ip like \"" + ip + "\")"
                    else:
                        where_sql += " and ip not like \"" + ip + "\" and ip not like \"" + ip + "\""
                else:
                    if not reverse_mode:
                        where_sql += " and (ip=\"" + ip + "\" or ip like \"%" + ip + "%\")"
                    else:
                        where_sql += " and ip<>\"" + ip + "\" and ip not like \"%" + ip + "%\""
        # 域名过滤
        if "domain" in conditions_keys:
            domain = conditions["domain"].strip()
            if domain:
                if search_mode == "fuzzy":
                    if not reverse_mode:
                        where_sql += " and server_name like '%" + domain + "%'"
                    else:
                        where_sql += " and server_name not like '%" + domain + "%'"
                else:
                    if not reverse_mode:
                        where_sql += " and server_name='" + domain + "'"
                    else:
                        where_sql += " and server_name<>'" + domain + "'"
        # ua过滤
        if "user_agent" in conditions_keys:
            user_agent = conditions["user_agent"].strip()
            if user_agent:
                if search_mode == "fuzzy":
                    if not reverse_mode:
                        where_sql += " and user_agent like '%" + user_agent + "%'"
                    else:
                        where_sql += " and user_agent not like '%" + user_agent + "%'"
                else:
                    if not reverse_mode:
                        where_sql += " and user_agent='" + user_agent + "'"
                    else:
                        where_sql += " and user_agent<>'" + user_agent + "'"

        select_sql = "select {} from %s" % (tables) + where_sql
        return select_sql

    def __format_field(self, field):
        import re
        fields = []
        for key in field:
            s_as = re.search(r'\s+as\s+', key, flags=re.IGNORECASE)
            if s_as:
                as_tip = s_as.group()
                key = key.split(as_tip)[1]
            fields.append(key)
        return fields

    '''
        @搜索拦截日志
        @param {"ip":"192.168.10.1,192.168.10.1,192.168.10.*"}   ip搜索 
        @param {"url":"/ali.php"}     url搜索
        @param {"site":"www.bt.cn"}   按照网站搜索 
        @param {"start_time":"time"}  开始时间  
        @param {"end_time":"time"}    结束时间
        @param {"ua":"Mozilla/5.0"}   按照ua搜索 
    '''

    def get_search_logs(self, get):
        if 'data' in get:
            try:
                data = json.loads(get.data)
                if 'ip' in data and data['ip']:
                    get.ip = data['ip']
                if 'domain' in data and data['domain']:
                    get.domain = data['domain']
                if 'serach_url' in data and data['serach_url']:
                    get.serach_url = data['serach_url']
                if 'user_agent' in data and data['user_agent']:
                    get.user_agent = data['user_agent']
                if 'start_time' in data and data['start_time']:
                    get.start_time = data['start_time']
                if 'end_time' in data and data['end_time']:
                    get.end_time = data['end_time']
                if 'limit' in data and data['limit']:
                    get.limit = data['limit']
                if 'p' in data and data['p']:
                    get.p = data['p']
            except:
                pass
        result = {}
        if 'limit' in get:
            limit = int(get.limit)
        else:
            limit = 12

        if os.path.exists("/www/server/btwaf/totla_db/totla_db.db"):
            try:
                if self.M2('totla_log').order('id desc').count() == 0: return {"status": True, "msg": {
                    "page": "<div><span class='Pcurrent'>1</span><span class='Pcount'>\u51710\u6761</span></div>",
                    "data": []}}
            except:
                return {"status": True, "msg": {
                    "page": "<div><span class='Pcurrent'>1</span><span class='Pcount'>\u51710\u6761</span></div>",
                    "data": []}}
        try:
            if not 'start_time' in get:
                start_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
            else:
                start_time = get.start_time.strip()
            if not 'end_time' in get:
                # end_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
                end_time = start_time
            else:
                end_time = get.end_time.strip()
            start_time = start_time + ' 00:00:00'
            end_time2 = end_time + ' 23:59:59'
            start_timeStamp = int(time.mktime(time.strptime(start_time, '%Y-%m-%d %H:%M:%S')))
            end_timeStamp = int(time.mktime(time.strptime(end_time2, '%Y-%m-%d %H:%M:%S')))

            conditions = {}
            if "ip" in get:
                conditions["ip"] = get.ip
            if "domain" in get:
                conditions["domain"] = get.domain
            if "serach_url" in get:
                conditions["serach_url"] = get.serach_url
            if "user_agent" in get:
                conditions["user_agent"] = get.user_agent

            if 'time_reverse' in get:
                conditions["time_reverse"] = get.time_reverse

            # if 'start_time' in get:
            #     conditions["start_time"] =start_timeStamp
            # else:
            #     conditions["start_time"] = 0
            #
            # if 'end_time' in get:
            #     conditions["end_time"] = end_timeStamp
            # else:
            #     conditions["end_time"] = int(time.time())
            #

            conditions["start_time"] = start_timeStamp
            conditions["end_time"] = end_timeStamp

            orderby = "time"
            if "orderby" in get:
                orderby = get.orderby

            desc = True
            if "desc" in get:
                desc = True if get.desc.lower() == "true" else False

            page_size = 10
            get.page_size = page_size

            if "exact_match" in get:
                conditions["search_mode"] = "exact" if get.exact_match.lower() == "true" else "fuzzy"
            else:
                conditions["search_mode"] = "fuzzy"
            if "reverse_match" in get:
                conditions["reverse_mode"] = True if get.reverse_match.lower() == "true" else False
            if "time_reverse" in get:
                conditions["time_reverse"] = True if get.time_reverse.lower() == "true" else False
            if "response_time" in get:
                conditions["response_time"] = float(get.response_time)
                if "response_time_comparator" in get:
                    conditions["response_time_comparator"] = get.response_time_comparator

            offset = 0
            if "offset" in get:
                offset = int(get.offset)

            select_sql = self.get_site_logs_sql('totla_log', conditions)
            self.__OPT_FIELD = 'time,time_localtime,server_name,ip,ip_city,ip_country,ip_subdivisions,ip_longitude,ip_latitude,type,uri,user_agent,filter_rule,incoming_value,value_risk,http_log,http_log_path'
            count = "count(*)"
            select_data_sql = select_sql.format(count)
            # return select_data_sql
            result = self.M2('totla_log').query(select_data_sql)
            import page
            page = page.Page()
            count = result[0][0]
            info = {}
            info['count'] = count
            info['row'] = limit
            info['p'] = 1
            if hasattr(get, 'p'):
                info['p'] = int(get['p'])
            info['uri'] = get
            info['return_js'] = ''
            if hasattr(get, 'tojs'):
                info['return_js'] = get.tojs
            data = {}
            # 获取分页数据
            data['page'] = page.GetPage(info, '1,2,3,4,5,8')

            select_data_sql = select_sql.format(self.__OPT_FIELD)

            if orderby:
                select_data_sql += " order by " + orderby
            if desc:
                select_data_sql += " desc"
            sub_select_data_sql = select_data_sql + " limit " + (str(page.SHIFT) + ',' + str(page.ROW))
            # sub_select_data_sql += " offset " + str(sub_offset)
            sub_select_data_sql += ";"
            # return sub_select_data_sql
            result = self.M2('totla_log').query(sub_select_data_sql)
            if self.__OPT_FIELD != "*":
                fields = self.__format_field(self.__OPT_FIELD.split(','))
                tmp = []
                for row in result:
                    i = 0
                    tmp1 = {}
                    for key in fields:
                        try:
                            tmp1[key.strip('`')] = row[i]
                            i += 1
                        except:
                            continue

                    tmp.append(tmp1)
                    del (tmp1)
                result = tmp
                del (tmp)
            data['data'] = self.bytpes_to_string(result)
            # self.is_feng(data)
            return public.returnMsg(True, data)

        except:
            return {"status": True, "msg": {
                "page": "<div><span class='Pcurrent'>1</span><span class='Pcount'>\u51710\u6761</span></div>",
                "data": []}}

    # 导出所有的封锁日志
    def export_info(self, get):
        from BTPanel import send_file
        cvs_path = "/www/server/panel/data/1.csv"
        try:
            data222 = self.M3('blocking_ip').field(
                'time,time_localtime,server_name,ip,uri,user_agent').order(
                'id desc').select()
            data = self.bytpes_to_string(data222)
            import csv
            with open(cvs_path, 'w') as file:
                writer = csv.writer(file)
                writer.writerow(['time', 'server_name', 'ip', 'uri', 'user_agent'])
                for row in data222:
                    writer.writerow(
                        [row['time_localtime'], row['server_name'], row['ip'], row['uri'], row['user_agent']])
            return send_file(cvs_path, conditional=True, etag=True)
        except:
            public.writeFile(cvs_path, '')
            return send_file(cvs_path, conditional=True, etag=True)

    # 搜索网站
    def get_search_sites(self, get):
        # 所有所有的网站信息
        try:
            site_config = json.loads(public.readFile(self.__path + 'site.json'))
        except:
            public.WriteFile(self.__path + 'site.json', json.dumps({}))
            self.__write_site_domains()
            site_config = json.loads(public.readFile(self.__path + 'site.json'))
        if not os.path.exists(self.__path + '/domains.json'):
            self.__write_site_domains()
        else:
            site_count = public.M('sites').count()
            if site_count != len(site_config):
                self.__write_site_domains()
        data_site = self.__check_site(site_config)
        if get:
            total_all = self.get_total(None)['sites']
            site_list = []
            for k in data_site.keys():
                if not k in total_all: total_all[k] = {}
                data_site[k]['total'] = self.__format_total(total_all[k])
                siteInfo = data_site[k]
                siteInfo['siteName'] = k
                site_list.append(siteInfo)
            data_site = sorted(site_list, key=lambda x: x['log_size'], reverse=True)
        # return data_site
        import data as data2
        data2 = data2.data()
        get2 = public.dict_obj()
        get2.search = get.search
        get2.table = 'sites'
        get2.limit = 200
        if 'p' not in get:
            get2.p = 1
        get2.type = '-1'
        datas = data2.getData(get2)

        ret = []
        if datas['data']:
            for site in datas['data']:
                for i in data_site:
                    if i['siteName'] == site['name']:
                        ret.append(i)
        data_site = ret
        if not 'limit' in get:
            get.limit = 12
        limit = int(get.limit)
        if not 'p' in get:
            get.p = 1
        p = int(get.p)
        count = len(data_site)
        result = []
        if count < limit:
            result = data_site
        if count < (p * limit):
            result = data_site[(p - 1) * limit:count]
        else:
            result = data_site[(p - 1) * limit:(p * limit)]
        import page
        page = page.Page()
        info = {}
        info['count'] = count
        info['row'] = limit
        info['p'] = 1
        if hasattr(get, 'p'):
            info['p'] = int(get['p'])
        info['uri'] = get
        info['return_js'] = ''
        if hasattr(get, 'tojs'):
            info['return_js'] = get.tojs
        data = {}
        # 获取分页数据
        data['page'] = page.GetPage(info, '1,2,3,4,5,8')
        data['data'] = result
        return data

    def get_site_safe_logs(self, get):
        '''
        siteName:按照网站进行高级搜索
        start_time:2022--06
        end_time:2021-05-07
        p:1  页数
        limit:10
        @param {"ip":"192.168.10.1,192.168.10.1,192.168.10.*"}   ip搜索
        @param {"url":"/ali.php"}     url搜索
        @param {"site":"www.bt.cn"}   按照网站搜索
        @param {"start_time":"time"}  开始时间
        @param {"end_time":"time"}    结束时间
        @param {"ua":"Mozilla/5.0"}   按照ua搜索

        '''
        if not 'siteName' in get:
            return public.returnMsg(False, "请传递网站名称")
        if not 'limit' in get:
            limit = 10
        else:
            limit = int(get.limit.strip())
        if not 'p' in get:
            p = 10
        else:
            p = int(get.p.strip())
        if not 'start_time' in get:
            start_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
        else:
            start_time = get.start_time.strip()
        if not 'end_time' in get:
            # end_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
            end_time = start_time
        else:
            end_time = get.end_time.strip()
        start_time = start_time + ' 00:00:00'
        end_time2 = end_time + ' 23:59:59'
        start_timeStamp = int(time.mktime(time.strptime(start_time, '%Y-%m-%d %H:%M:%S')))
        end_timeStamp = int(time.mktime(time.strptime(end_time2, '%Y-%m-%d %H:%M:%S')))

        conditions = {}
        if "ip" in get:
            conditions["ip"] = get.ip
        conditions["server_name"] = get.siteName
        if "serach_url" in get:
            conditions["serach_url"] = get.serach_url
        if "user_agent" in get:
            conditions["user_agent"] = get.user_agent

        # conditions["time_reverse"] = 1

        conditions["start_time"] = start_timeStamp

        conditions["end_time"] = end_timeStamp

        orderby = "time"
        if "orderby" in get:
            orderby = get.orderby

        desc = True
        if "desc" in get:
            desc = True if get.desc.lower() == "true" else False

        page_size = 10
        get.page_size = page_size

        if "exact_match" in get:
            conditions["search_mode"] = "exact" if get.exact_match.lower() == "true" else "fuzzy"
        else:
            conditions["search_mode"] = "fuzzy"
        if "reverse_match" in get:
            conditions["reverse_mode"] = True if get.reverse_match.lower() == "true" else False
        if "time_reverse" in get:
            conditions["time_reverse"] = True if get.time_reverse.lower() == "true" else False
        if "response_time" in get:
            conditions["response_time"] = float(get.response_time)
            if "response_time_comparator" in get:
                conditions["response_time_comparator"] = get.response_time_comparator
        offset = 0
        if "offset" in get:
            offset = int(get.offset)
        select_sql = self.get_site_logs_sql('totla_log', conditions)
        # 获取所有的网站信息
        if os.path.exists("/www/server/btwaf/totla_db/totla_db.db"):
            import page
            page = page.Page()
            self.__OPT_FIELD = 'time,time_localtime,server_name,ip,ip_city,ip_country,ip_subdivisions,ip_longitude,ip_latitude,type,uri,user_agent,filter_rule,incoming_value,value_risk,http_log,http_log_path'
            count = "count(*)"
            select_data_sql = select_sql.format(count)
            result = self.M2('totla_log').query(select_data_sql)
            info = {}
            info['count'] = result[0][0]
            info['row'] = limit
            info['p'] = 1
            if hasattr(get, 'p'):
                info['p'] = int(get['p'])
            info['uri'] = get
            info['return_js'] = ''
            if hasattr(get, 'tojs'):
                info['return_js'] = get.tojs
            data = {}
            # 获取分页数据
            data['page'] = page.GetPage(info, '1,2,3,4,5,8')
            data['data'] = []
            select_data_sql = select_sql.format(self.__OPT_FIELD)

            if orderby:
                select_data_sql += " order by " + orderby
            if desc:
                select_data_sql += " desc"

            sub_select_data_sql = select_data_sql + " limit " + (str(page.SHIFT) + ',' + str(page.ROW))
            sub_select_data_sql += ";"
            result = self.M2('totla_log').query(sub_select_data_sql)
            if self.__OPT_FIELD != "*":
                fields = self.__format_field(self.__OPT_FIELD.split(','))
                tmp = []
                for row in result:
                    i = 0
                    tmp1 = {}
                    if type(row) != list: continue
                    for key in fields:
                        tmp1[key.strip('`')] = row[i]
                        i += 1
                    tmp.append(tmp1)
                    del (tmp1)
                result = tmp
                del (tmp)
            try:
                data['data'] = self.bytpes_to_string(result)
            except:
                data = {}
                data['page'] = "<div><span class='Pcurrent'>1</span><span class='Pcount'>共0条</span></div>"
                data['data'] = []
                return public.returnMsg(False, data)
            return public.returnMsg(True, data)
        else:
            data = {}
            data['page'] = "<div><span class='Pcurrent'>1</span><span class='Pcount'>共0条</span></div>"
            data['data'] = []
            return public.returnMsg(False, data)

    # 获取回收站信息
    def Get_Recycle_bin(self, get):
        data = []
        rPath = self.__PATH + 'Recycle'
        if not os.path.exists(rPath): return data
        for file in os.listdir(rPath):
            try:
                tmp = {}
                fname = os.path.join(rPath, file)
                # return fname
                if sys.version_info[0] == 2:
                    fname = fname.encode('utf-8')
                else:
                    fname.encode('utf-8')
                tmp1 = file.split('_bt_')
                tmp2 = tmp1[len(tmp1) - 1].split('_t_')
                file = self.xssencode(file)
                tmp['rname'] = file
                tmp['dname'] = file.replace('_bt_', '/').split('_t_')[0]
                if tmp['dname'].find('@') != -1:
                    tmp['dname'] = "BTDB_" + tmp['dname'][5:].replace('@', "\\u").encode().decode("unicode_escape")
                tmp['name'] = tmp2[0]
                tmp['time'] = int(float(tmp2[1]))
                if os.path.islink(fname):
                    filePath = os.readlink(fname)
                    if os.path.exists(filePath):
                        tmp['size'] = os.path.getsize(filePath)
                    else:
                        tmp['size'] = 0
                else:
                    tmp['size'] = os.path.getsize(fname)
                if os.path.isdir(fname):
                    if file[:5] == 'BTDB_':
                        tmp['size'] = public.get_path_size(fname)
                    # data['dirs'].append(tmp)
                else:
                    data.append(tmp)
            except:
                continue
        data = sorted(data, key=lambda x: x['time'], reverse=True)
        return data

    def html_decode(self, text):
        '''
            @name HTML解码
            @author hwliang
            @param text 要解码的HTML
            @return string 返回解码后的HTML
        '''
        try:
            from cgi import html
            text2 = html.unescape(text)
            return text2
        except:
            return text

    # 从回收站恢复
    def Re_Recycle_bin(self, get):
        if sys.version_info[0] == 2:
            get.path = get.path.encode('utf-8')
        get.path = self.html_decode(get.path).replace(';', '')
        dFile = get.path.replace('_bt_', '/').split('_t_')[0]
        if not os.path.exists(self.Recycle_bin + '/' + get.path):
            return public.returnMsg(False, 'FILE_RE_RECYCLE_BIN_ERR')
        try:
            import shutil
            shutil.move(self.Recycle_bin + '/' + get.path, dFile)
            return public.returnMsg(True, 'FILE_RE_RECYCLE_BIN')
        except:
            return public.returnMsg(False, 'FILE_RE_RECYCLE_BIN_ERR')

    def Del_Recycle_bin(self, get):
        if sys.version_info[0] == 2:
            get.path = get.path.encode('utf-8')
        tfile = self.html_decode(get.path).replace(';', '')
        filename = self.Recycle_bin + '/' + get.path
        public.ExecShell('chattr  -i ' + filename)
        try:
            os.remove(filename)
        except:
            public.ExecShell("rm -f " + filename)
        return public.returnMsg(True, '已经从木马隔离箱中永久删除当前文件' + tfile)

    # 移动到回收站
    def Mv_Recycle_bin(self, path):
        rPath = self.Recycle_bin
        if not os.path.exists(self.Recycle_bin):
            os.makedirs(self.Recycle_bin)
        rFile = os.path.join(rPath, path.replace('/', '_bt_') + '_t_' + str(time.time()))
        try:
            import shutil
            shutil.move(path, rFile)
            return True
        except:
            return False

    # 设置告警
    def Set_Alarm(self, get):
        '''
            @name 设置告警
            @param get
            @param CC攻击告警   120秒内有30个IP触发CC拦截。就告警
            @param 封锁IP总数   如果120秒内有60 IP触发封锁。就告警
            @param 版本更新     如果有新版本。就告警
            @param 发现木马     如果有木马。就告警
            @param 安全漏洞通知   如果有新的安全漏洞。就告警
        '''
        pdata = {}
        if 'cc' not in get:
            pdata['cc'] = {"cycle": 120, "limit": 30, "status": False}
        else:
            pdata['cc'] = json.loads(get.cc)
        if 'file' not in get:
            pdata['file'] = {"cycle": 120, "limit": 60, "status": False}
        else:
            pdata['file'] = json.loads(get.file)
        # 新版本
        if 'version' not in get:
            pdata['version'] = {"status": False}
        else:
            pdata['version'] = json.loads(get.version)

        if 'webshell' not in get:
            pdata['webshell'] = {"status": False}
        else:
            pdata['webshell'] = json.loads(get.vul)

        if 'vul' not in get:
            pdata['vul'] = {"status": False}
        else:
            pdata['vul'] = json.loads(get.vul)

        if 'send' not in get:
            pdata['send'] = {"status": False, "send_type": "error"}
        else:
            pdata['send'] = json.loads(get.send)
        # 设置告警
        send_type = pdata['send']['send_type']
        if not public.M('send_settings').where('name=?', ('btwaf',)).count():
            self.insert_settings('btwaf', 'python_script', '/www/server/panel/plugin/btwaf/send.py', send_type, 60)
            self.__write_log('开启告警成功')
            # self.get_Alarm_info()
        public.WriteFile("data/btwaf_alarm.json", json.dumps(pdata))
        return public.returnMsg(True, '设置成功')

    def Get_Alarm(self, get):
        '''
            @name 获取告警设置
        '''
        # self.get_Alarm_info()
        try:
            if not os.path.exists("data/btwaf_alarm.json"):
                self.Set_Alarm(get)
            info = json.loads(public.readFile("data/btwaf_alarm.json"))
            if info['send']['status'] and info['send']['send_type'] != "error":
                if not public.M('send_settings').where('name=?', ('btwaf',)).count():
                    self.insert_settings('btwaf', 'python_script', '/www/server/panel/plugin/btwaf/send.py',
                                         info['send']['send_type'], 60)
            return info
        except:
            self.Set_Alarm(get)
            return json.loads(public.readFile("data/btwaf_alarm.json"))

    def start_main(self, path):
        if not os.path.exists(path): return False
        module = os.path.basename(path).split('.')[0]
        module_dir = os.path.dirname(path)
        sys.path.insert(0, "{}".format(module_dir))
        send_to_user_info = __import__('{}'.format(module))
        try:
            public.mod_reload(send_to_user_info)
        except:
            pass
        return eval('send_to_user_info.{}()'.format(module))

    def get_Alarm_info(self):
        obj = self.start_main("/www/server/panel/class/send_to_user.py")
        if obj:
            # 判断是否存在send_mail_data这个方法名
            if hasattr(obj, 'send_mail_data'):
                return True
        return False

    def get_drop_abroad_count(self, get):
        inf = public.cache_get("get_drop_abroad_count")
        if inf:
            return public.returnMsg(True, inf)
        count = 0
        try:
            site_config = json.loads(public.readFile(self.__path + 'site.json'))
        except:
            return public.returnMsg(True, count)

        for i in site_config:
            if site_config[i]['drop_abroad']:
                count += 1
        public.cache_set("get_drop_abroad_count", count, 360)
        return public.returnMsg(True, count)

    # 攻击报表导出
    def attack_export(self, get):
        from BTPanel import send_file
        cvs_path = "/www/server/panel/data/2.csv"
        try:
            # data222 = self.M3('blocking_ip').field(
            #     'time,time_localtime,server_name,ip,uri,user_agent').order(
            #     'id desc').select()
            # data = self.bytpes_to_string(data222)
            import csv
            info = self.get_report(get)

            with open(cvs_path, 'w') as file:
                writer = csv.writer(file)
                writer.writerow(['IP报表', '时间', '网站域名', '攻击IP', '攻击的URL', '攻击的User-Agent'])
                if info['ip_list']:
                    for i in info['ip_list']:
                        writer.writerow([info['ip_list'][i], i['server_name'], i['ip'], i['uri'], i['user_agent']])

            return send_file(cvs_path, conditional=True, etag=True)
        except:
            public.writeFile(cvs_path, '')
            return send_file(cvs_path, conditional=True, etag=True)

    def nday_get(self, get):
        pass

    def add_ipv6_white(self, get):
        ip = get.ip
        if not 'ps' in get:
            ps = ""
        else:
            ps = get.ps
        # 利用/分割取第一个为IP
        ip_addr = ip.split("/")[0]
        if not self.ipv6_check(ip_addr):
            return public.returnMsg(False, '请输入正确的IP地址!')
        # 读取ipv6白名单文件
        ipv6_white = self.__get_rule('ip_white_v6')
        if not ipv6_white: ipv6_white = []
        for i in ipv6_white:
            if ip in i:
                return public.returnMsg(False, '已存在!')

        ipv6_white.insert(0, [ip, ps])
        self.__write_rule('ip_white_v6', ipv6_white)
        return public.returnMsg(True, '添加成功!')

    def del_ipv6_white(self, get):
        ip = get.ip
        # 利用/分割取第一个为IP
        ipv6_white = self.__get_rule('ip_white_v6')
        if not ipv6_white: ipv6_white = []

        for i in ipv6_white:
            if ip == i[0]:
                ipv6_white.remove(i)
                self.__write_rule('ip_white_v6', ipv6_white)
                return public.returnMsg(True, '删除成功!')
        return public.returnMsg(False, '不存在!')

    def edit_ipv6_white(self, get):
        # 只允许修改ps
        ip = get.ip
        ps = get.ps
        # 利用/分割取第一个为IP
        ip_addr = ip.split("/")[0]
        if not self.ipv6_check(ip_addr):
            return public.returnMsg(False, '请输入正确的IP地址!')
        ipv6_white = self.__get_rule('ip_white_v6')
        if not ipv6_white: ipv6_white = []
        for i in ipv6_white:
            if ip in i:
                i[1] = ps
                self.__write_rule('ip_white_v6', ipv6_white)
                return public.returnMsg(True, '修改成功!')
        return public.returnMsg(False, '不存在!')

    def import_ipv6_white(self, get):
        # 导入一行一个
        ip = get.ip
        # \n进行分割
        ipv6_white = self.__get_rule('ip_white_v6')
        if not ipv6_white: ipv6_white = []
        ip_list = ip.strip().split()
        for i in ip_list:
            # /进行分割取第一个为IP
            ip_addr = i.split("/")[0]
            if self.ipv6_check(ip_addr):
                # 判断i是否存在于ipv6_white 中
                flag = True
                for i2 in ipv6_white:
                    if i == i2[0]:
                        flag = False
                if flag:
                    ipv6_white.insert(0, [i, ""])
        self.__write_rule('ip_white_v6', ipv6_white)
        return public.returnMsg(True, '导入成功!')

    def clear_ipv6_white(self, get):
        self.__write_rule('ip_white_v6', [])
        return public.returnMsg(True, '清空完成!')

    def add_ipv6_black(self, get):
        ip = get.ip
        if not 'ps' in get:
            ps = ""
        else:
            ps = get.ps
        # 利用/分割取第一个为IP
        ip_addr = ip.split("/")[0]
        if not self.ipv6_check(ip_addr):
            return public.returnMsg(False, '请输入正确的IP地址!')
        # 读取ipv6白名单文件
        ipv6_black = self.__get_rule('ip_black_v6')
        if not ipv6_black: ipv6_black = []
        for i in ipv6_black:
            if ip in i:
                return public.returnMsg(False, '已存在!')

        ipv6_black.insert(0, [ip, ps])
        self.__write_rule('ip_black_v6', ipv6_black)
        return public.returnMsg(True, '添加成功!')

    def del_ipv6_black(self, get):
        ip = get.ip
        # 利用/分割取第一个为IP
        ipv6_black = self.__get_rule('ip_black_v6')
        if not ipv6_black: ipv6_black = []

        for i in ipv6_black:
            if ip == i[0]:
                ipv6_black.remove(i)
                self.__write_rule('ip_black_v6', ipv6_black)
                return public.returnMsg(True, '删除成功!')
        return public.returnMsg(False, '不存在!')

    def edit_ipv6_black(self, get):
        # 只允许修改ps
        ip = get.ip
        ps = get.ps
        # 利用/分割取第一个为IP
        ip_addr = ip.split("/")[0]
        if not self.ipv6_check(ip_addr):
            return public.returnMsg(False, '请输入正确的IP地址!')
        ipv6_black = self.__get_rule('ip_black_v6')
        if not ipv6_black: ipv6_black = []
        for i in ipv6_black:
            if ip in i:
                i[1] = ps
                self.__write_rule('ip_black_v6', ipv6_black)
                return public.returnMsg(True, '修改成功!')
        return public.returnMsg(False, '不存在!')

    def import_ipv6_black(self, get):
        # 导入一行一个
        ip = get.ip
        # \n进行分割
        ipv6_black = self.__get_rule('ip_black_v6')
        if not ipv6_black: ipv6_black = []
        ip_list = ip.strip().split()
        for i in ip_list:
            # /进行分割取第一个为IP
            ip_addr = i.split("/")[0]
            if self.ipv6_check(ip_addr):
                # 判断i是否存在于ipv6_white 中
                flag = True
                for i2 in ipv6_black:
                    if i == i2[0]:
                        flag = False
                if flag:
                    ipv6_black.insert(0, [i, ""])
        self.__write_rule('ip_black_v6', ipv6_black)
        return public.returnMsg(True, '导入成功!')

    def clear_ipv6_black(self, get):
        self.__write_rule('ip_black_v6', [])
        return public.returnMsg(True, '清空完成!')

    def export_logs(self, get):
        if 'siteName' not in get:
            return public.returnMsg(False, '请选择站点')
        siteName = get.siteName
        from BTPanel import send_file
        cvs_path = "/www/server/panel/data/1.csv"
        try:
            data = []
            if siteName == "all":
                data222 = self.M3('totla_log').field(
                    'time,time_localtime,server_name,ip,uri,user_agent,ip_country,filter_rule').order(
                    'id desc').select()
                data = self.bytpes_to_string(data222)

            else:
                # 使用,分割域名
                siteName_list = siteName.split(",")
                for i in siteName_list:
                    data222 = self.M3('totla_log').field(
                        'time,time_localtime,server_name,ip,uri,user_agent,ip_country,filter_rule').where(
                        "server_name=?", (i,)).order(
                        'id desc').select()
                    data.extend(self.bytpes_to_string(data222))
            import csv
            with open(cvs_path, 'w') as file:
                writer = csv.writer(file)
                writer.writerow(['time', 'server_name', 'ip', 'uri', 'user_agent', 'ip_country', 'filter_rule'])
                for row in data:
                    writer.writerow(
                        [row['time_localtime'], row['server_name'], row['ip'], row['uri'], row['user_agent'],
                         row['ip_country'], row['filter_rule']])

            return send_file(cvs_path, conditional=True, etag=True)
        except:
            public.writeFile(cvs_path, '')
            return send_file(cvs_path, conditional=True, etag=True)

    def share_ip(self, get):
        '''
        共享IP计划、一小时更新一次
        :return:
        '''
        # 获取当前时间搓
        # 获取上一次的时间搓
        path = "/www/server/panel/data/share_ip.json"
        if not os.path.exists(path):
            public.writeFile(path, json.dumps({"time": int(time.time())}))
            share_ip_info = {"time": 0}
        else:
            share_ip_info = json.loads(public.readFile(path))
        if (int(time.time()) - share_ip_info["time"]) < 3600:
            return public.returnMsg(False, "未达到时间")
        end_time = int(time.time())
        start_time = end_time - 3600
        import requests
        count = self.M2('totla_log').field('time').where("time>? and time<? and value_risk!=?",
                                                         (start_time, end_time, "cc")).order('id desc').count()
        if type(count) == "str":
            return public.returnMsg(False, "更新失败")
        # 如果大于100 则只取100
        map_info = self.M2('totla_log').field(
            'time,server_name,ip,ip_country,type,uri,user_agent,value_risk,http_log,http_log_path,filter_rule').where(
            "time>? and time<? and value_risk!=?", (start_time, end_time, "cc")).order('id desc').limit("100").select()
        data = []
        for i in map_info:
            i2 = {}
            if i["http_log_path"]:
                tmp = i['http_log']
                get = public.dict_obj()
                get.path = tmp
                i['http_log'] = self.get_logs(get)
            if not i["value_risk"]:
                i["value_risk"] = i["filter_rule"]
            i2["latest_block_time"] = i["time"]
            i2["host"] = i["server_name"]
            i2["attack_ip"] = i["ip"]
            i2["uri"] = i["uri"]
            i2["attack_type"] = i["value_risk"]
            i2["request_method"] = i["type"]
            i2["ua"] = i["user_agent"]
            i2["request_body"] = i["http_log"]
            i2["block_count"] = 1
            data.append(i2)
        request_data = {
            "x_bt_token": "ODIwMjNlZmQ3OTg4MDUxMzdjN2ZhNzAy",
            "uid": "",
            "data": data
        }
        # 获取用户的UID
        user_info = public.get_user_info()
        if 'uid' in user_info:
            request_data["uid"] = user_info["uid"]
        url = "https://api.bt.cn/bt_waf/submit_waf_block_logs"
        requests.post(url, json=request_data, timeout=5)
        # 设置时间搓
        share_ip_info["time"] = int(time.time())
        public.writeFile(path, json.dumps(share_ip_info))
        return public.returnMsg(True, "更新成功")

    # 解密数据
    def _encode(self, data):
        """
        @name 解密数据
        @author cjxin
        @data string 解密数据
        """
        import urllib
        if sys.version_info[0] == 2:
            result = urllib.unquote(binascii.unhexlify(data))
        else:
            if type(data) == str: data = data.encode('utf-8')
            tmp = binascii.unhexlify(data)
            if type(tmp) != str: tmp = tmp.decode('utf-8')
            result = urllib.parse.unquote(tmp)

        if type(result) != str: result = result.decode('utf-8')

        return json.loads(result)

    def get_ip(self, get):
        '''
        获取共享的恶意IP库 每天更新一次
        :return:
        '''
        try:
            path = "/www/server/panel/data/share_ip_info.json"
            if not os.path.exists(path):
                public.writeFile(path, json.dumps({"time": int(time.time())}))
                share_ip_info = {"time": 0}
            else:
                share_ip_info = json.loads(public.readFile(path))
            if (int(time.time()) - share_ip_info["time"]) < 3600:
                return public.returnMsg(False, "未到时间")
            import requests
            request_data = {"x_bt_token": "MzI3YjAzOGQ3Yjk3NjUxYjVlMDkyMGFm"}
            user_info = public.get_user_info()
            if 'uid' in user_info:
                request_data["uid"] = user_info["uid"]
            url = "https://api.bt.cn/bt_waf/get_malicious_ip"
            info = requests.post(url, json=request_data, timeout=5).json()
            ip_info = self._encode(info["data"])
            if type(ip_info) != list:
                return public.returnMsg(False, "更新失败")
            data = {}
            for i in ip_info:
                data[i['ip']] = i['release_time']
            public.WriteFile("/www/server/btwaf/rule/malicious_ip.json", json.dumps(data))
            # 设置时间搓
        except:
            pass
        return public.returnMsg(True, "更新成功")

    def paginate_data(self, data, page_number, page_size):
        if not isinstance(data, list):
            raise TypeError(f"unsupported pagination type {type(data).__name__}")
        page_number = int(page_number)
        page_size = int(page_size)
        start_index = (page_number - 1) * page_size
        if start_index >= len(data):
            return {"list": [], "total": len(data)}

        end_index = start_index + page_size
        if end_index > len(data):
            end_index = len(data)

        return {"list": data[start_index:end_index], "total": len(data)}

    def GetNumLines(self, path, num, p=1):
        if not os.path.exists(path): return ""
        if isinstance(num, str) and not re.match("\d+", num):
            return ""

        pyVersion = sys.version_info[0]
        max_len = 1024 * 1024 * 10
        try:

            start_line = (p - 1) * num
            count = start_line + num
            fp = open(path, 'rb')
            buf = ""
            fp.seek(-1, 2)
            if fp.read(1) == "\n": fp.seek(-1, 2)
            data = []
            total_len = 0
            b = True
            n = 0
            for i in range(count):
                while True:
                    newline_pos = str.rfind(str(buf), "\n")
                    pos = fp.tell()
                    if newline_pos != -1:
                        if n >= start_line:
                            line = buf[newline_pos + 1:]
                            line_len = len(line)
                            total_len += line_len
                            sp_len = total_len - max_len
                            if sp_len > 0:
                                line = line[sp_len:]
                            try:
                                data.insert(0, line)
                            except:
                                pass
                        buf = buf[:newline_pos]
                        n += 1
                        break
                    else:
                        if pos == 0:
                            b = False
                            break
                        to_read = min(4096, pos)
                        fp.seek(-to_read, 1)
                        t_buf = fp.read(to_read)
                        if pyVersion == 3:
                            t_buf = t_buf.decode('utf-8', errors='ignore')

                        buf = t_buf + buf
                        fp.seek(-to_read, 1)
                        if pos - to_read == 0:
                            buf = "\n" + buf
                    if total_len >= max_len: break
                if not b: break
            fp.close()
            result = "\n".join(data)
        except:
            if re.match("[`\$\&\;]+", path): return ""
            result = public.ExecShell("tail -n {} {}".format(num, path))[0]
            if len(result) > max_len:
                result = result[-max_len:]

        try:
            try:
                result = json.dumps(result)
                return json.loads(result).strip()
            except:
                if pyVersion == 2:
                    result = result.decode('utf8', errors='ignore')
                else:
                    result = result.encode('utf-8', errors='ignore').decode("utf-8", errors="ignore")
            return result.strip()
        except:
            return ""

    def get_rule_hit_list(self, get):
        '''
            filter :默认全部  accept  refuse
            p: 叶码
            p_size：每页显示的数量
        :param get:
        :return:
        '''
        if 'filter' not in get:
            get.filter = "all"
        if 'p' not in get:
            get.p = 1
        if 'limit' not in get:
            get.limit = 10
        if 'keyword' not in get:
            get.keyword = ""
        filter = get.filter
        if filter == "accept":
            filter = "accept"
        elif filter == "refuse":
            filter = "refuse"
        else:
            filter = "all"
        path = "/www/server/btwaf/btwaf_rule_hit.json"
        # 读取后2000行
        if not os.path.exists(path):
            return public.returnMsg(True, {"list": [], "total": 0})
        # 读取文件
        data = self.GetNumLines(path, 2001)
        tmp = []
        for i in data.split("\n"):
            if i:
                info = i.split("|")
                if len(info) != 12:
                    continue
                tmp2 = {}
                if filter == "accept":
                    if info[0] != "放行":
                        continue
                if filter == "refuse":
                    if info[0] != "拦截":
                        continue
                if not get.keyword == "":
                    if not get.keyword in i:
                        continue
                tmp2['status'] = info[0]
                tmp2['key'] = info[1]
                tmp2['timestimp'] = info[2]
                tmp2['server_name'] = info[3]
                tmp2['uri'] = info[4]
                tmp2['rule_name'] = info[5]
                tmp2['rule_type'] = info[6]
                tmp2['rule_ps'] = info[7]
                tmp2['ip'] = info[8]
                tmp2['ip_country'] = info[9]
                tmp2['ip_province'] = info[10]
                tmp2['ip_city'] = info[11]
                tmp.append(tmp2)
        # 排序tmp
        tmp.sort(key=lambda x: x['timestimp'], reverse=True)
        tmp_info = self.paginate_data(tmp, get.p, get.limit)
        return public.returnMsg(True, tmp_info)

    def get_rule_hit_type_list(self, get):
        "pass"

        info = {"IP白名单": True, "IP黑名单": True, "URI白名单": True, "URI黑名单": True, "UA白名单": True,
                "UA黑名单": True, "地区限制": True, "云端恶意IP库": True, "人机验证": False, "内容替换": False}
        path = "/www/server/btwaf/rule/rule_hit_list.json"
        if not os.path.exists(path):
            public.writeFile(path, json.dumps(info))
            return public.returnMsg(True, info)
        info = json.loads(public.readFile(path))
        return public.returnMsg(True, info)

    def set_hit_type(self, get):
        '''
        设置命中规则的类型
        :param get:
        :return:
        '''
        path = "/www/server/btwaf/rule/rule_hit_list.json"
        if 'data' not in get:
            return public.returnMsg(False, "参数错误")
        try:
            info = json.loads(get.data)
            public.WriteFile(path, json.dumps(info))
            return public.returnMsg(True, "设置成功")
        except:
            pass

    def delete_rule_hit_list(self, get):
        '''清空日志'''
        path = "/www/server/btwaf/btwaf_rule_hit.json"
        public.writeFile(path, "")
        return public.returnMsg(True, "清空成功")

    def get_update_malicious_ip(self, get):
        import requests
        request_data = {"x_bt_token": "MzI3YjAzOGQ3Yjk3NjUxYjVlMDkyMGFm"}
        user_info = public.get_user_info()
        if 'uid' in user_info:
            request_data["uid"] = user_info["uid"]
        url = "https://api.bt.cn/bt_waf/get_malicious_ip"
        info = requests.post(url, json=request_data, timeout=5).json()
        ip_info = self._encode(info["data"])
        if type(ip_info) != list:
            return public.returnMsg(False, "更新失败")
        data = {}
        count = 0
        for i in ip_info:
            count += 1
            data[i['ip']] = i['release_time']
        public.WriteFile("/www/server/btwaf/rule/malicious_ip.json", json.dumps(data))
        # 重载一下
        public.serviceReload()
        return public.returnMsg(True, "更新成功,共更新{}条".format(count))

    def get_charge_malicious_ip(self, get):
        url = "https://www.bt.cn/api/bt_waf/get_malicious"
        reulst_list = {}
        total = 0
        user = {}
        try:
            user = json.loads(public.ReadFile('/www/server/panel/data/userInfo.json'))
        except:
            pass
        if not user:
            return public.returnMsg(False, "请先登录")

        if not 'uid' in user:
            return public.returnMsg(False, "请先登录")
        if not 'access_key' in user:
            return public.returnMsg(False, "请先登录")
        if not 'serverid' in user:
            return public.returnMsg(False, "请先登录")

        # 如果uid 为123456 并且 手机号码为 18888888888
        if user['uid'] == '123456' and user['username'] == '18888888888':
            return public.returnMsg(False, "请登录官网账号")

        data = {"x_bt_token": "SksBSpWhJE7oVRixKCAZVEsN3QDnfQBU", "page": 1, "uid": user["uid"],
                "access_key": user["access_key"], "serverid": user["serverid"]}
        import requests
        path = "/www/server/btwaf/rule/btmalibrary_malicious.json"
        reulst_list = {}
        total = 0
        for i in range(1, 50):
            try:
                data["page"] = i
                result = requests.post(url, json=data, timeout=60).json()
                if result["success"]:
                    total += len(result["res"]['list'])
                    reulst_list.update(result["res"]['list'])
                else:
                    return public.returnMsg(False, result["res"])
                if total >= result["res"]['total']:
                    break
            except:
                break
        if len(reulst_list) >= 1000:
            public.WriteFile(path, json.dumps(reulst_list))
            public.ServiceReload()
        return public.returnMsg(True, "更新成功,共更新{}条".format(total))

    def download_charge_malicious_ip(self, get):
        # 导出堡塔恶意情报IP库
        path = "/www/server/btwaf/rule/btmalibrary_malicious.json"
        if not os.path.exists(path):
            return public.returnMsg(False, "文件不存在")
        cvs_path = "/www/server/panel/data/charge_malicious_ip.txt"
        infos = {}
        try:
            infos = json.loads(public.readFile(path))
        except:
            return public.returnMsg(False, "文件读取失败")
        if len(infos) == 0:
            return public.returnMsg(False, "文件为空")
        # 打开文件
        with open(cvs_path, 'w') as file:
            for i in infos:
                file.write(i + '\n')
        return public.returnMsg(True, "导出成功")

    def get_customize_list(self, get):
        '''
        获取自定义规则列表
        :param get:
        :return:
        '''
        path = "/www/server/btwaf/rule/customize.json"
        if not os.path.exists(path):
            public.writeFile(path, "{}")

        cu_count = "/www/server/btwaf/rule/customize_count.json"
        if not os.path.exists(cu_count):
            public.writeFile(cu_count, "{}")
        else:
            try:
                cu_count = json.loads(public.readFile(cu_count))
            except:
                cu_count = {}
        try:
            data = json.loads(public.readFile(path))
            if 'rules' in data:
                for i in data['rules']:
                    if i in cu_count:
                        data['rules'][i]['hit'] = cu_count[i]
                    else:
                        data['rules'][i]['hit'] = 0
        except:
            data = {}
        return public.returnMsg(True, data)

    def parse_cidr(self, cidr):
        # 获取/ 的分割。如果判断为长度不为2则返回False
        parts = cidr.split('/')
        if len(parts) != 2:
            return False
        try:
            import ipaddress
            # 使用 ipaddress 模块来直接解析 CIDR 字符串。
            network = ipaddress.ip_interface(cidr)
        except:
            # 处理 ValueError 异常，这可能是由于无效的 CIDR 地址格式。
            return False
        return True

    def walk(self, node):
        if node['type'] == "option":
            if not 'type' in node['option']: return public.returnMsg(False, "规则不能为空")
            if not 'operator' in node['option']: return public.returnMsg(False, "规则不能为空")
            if node['option']['type'] == "" or node['option']['operator'] == "": return public.returnMsg(False,
                                                                                                         "规则不能为空")
            # 客户端IP
            if node['option']['type'] == "ip":
                if not 'right_factor' in node['option']: return public.returnMsg(False, "规则不能为空")
                if node['option']['right_factor'] == "":
                    return public.returnMsg(False, "客户端IP不能为空")
                # 集合运算
                if node['option']['operator'] == "in" or node['option']['operator'] == "not_in":
                    ips = node['option']['right_factor'].split(",")
                    for v in ips:
                        if not public.check_ip(v):
                            return public.returnMsg(False, "客户端IP {} 格式错误".format(v))
                else:
                    if not public.check_ip(node['option']['right_factor']):
                        return public.returnMsg(False, "客户端IP {} 格式错误".format(node['option']['right_factor']))
            # CIDR表达式
            if node['option']['type'] == "ip_range":
                if not 'right_factor' in node['option']: return public.returnMsg(False, "规则不能为空")
                if node['option']['right_factor'] == "":
                    return public.returnMsg(False, "IP段不能为空")
                # 集合运算
                if node['option']['operator'] == "in" or node['option']['operator'] == "not_in":
                    ips = node['option']['right_factor'].split(",")
                    for v in ips:
                        if not self.parse_cidr(v):
                            return public.returnMsg(False, "IP段 {} 格式错误，必须为CIDR表达式".format(v))
                else:
                    if not self.parse_cidr(node['option']['right_factor']):
                        return public.returnMsg(False, "IP段 {} 格式错误，必须为CIDR表达式".format(
                            node['option']['right_factor']))
            if node['option']['type'] == "referer":
                if not 'right_factor' in node['option']: return public.returnMsg(False, "规则不能为空")
                if node['option']['operator'] == "null":
                    node['option']['right_factor'] = "空"
                if node['option']['right_factor'] == "":
                    return public.returnMsg(False, "来源URL不能为空")
            if node['option']['type'] == "method":
                if not 'right_factor' in node['option']: return public.returnMsg(False, "规则不能为空")
                if node['option']['right_factor'] == "":
                    return public.returnMsg(False, "请传递匹配的内容")

            if node['option']['type'] == "uri":
                if not 'right_factor' in node['option']: return public.returnMsg(False, "规则不能为空")
                if node['option']['right_factor'] == "":
                    return public.returnMsg(False, "请传递你需要设置的URL内容")
            if node['option']['type'] == "uri_with_param":
                if not 'right_factor' in node['option']: return public.returnMsg(False, "规则不能为空")
                if node['option']['right_factor'] == "":
                    return public.returnMsg(False, "请传递你需要设置的URL内容")

            if node['option']['type'] == "param":
                if not 'right_factor' in node['option']: return public.returnMsg(False, "规则不能为空")
                if node['option']['right_factor'] == "":
                    return public.returnMsg(False, "请传递匹配的内容")

            if node['option']['type'] == "param_name":
                if not 'right_factor' in node['option']: return public.returnMsg(False, "规则不能为空")
                if node['option']['right_factor'] == "":
                    return public.returnMsg(False, "请传递匹配的内容")
            if node['option']['type'] == "user-agent":
                if not 'right_factor' in node['option']: return public.returnMsg(False, "规则不能为空")
                if node['option']['operator'] == "null":
                    node['option']['right_factor'] = "空"
                if node['option']['right_factor'] == "":
                    return public.returnMsg(False, "请输入你需要设置的User-Agent")
                #如果设置的长度elt_len
                if node['option']['operator'] == "elt_len":
                    #判断right_factor 这个是否为数字
                    try:
                        node['option']['right_factor']=int(node['option']['right_factor'])
                    except:
                        return public.returnMsg(False, "User-Agent长度判断必须为数字")
            if node['option']['type'] == "request_header_name":
                if not 'right_factor' in node['option']: return public.returnMsg(False, "规则不能为空")
                if node['option']['right_factor'] == "":
                    return public.returnMsg(False, "请输入你需要设置的请求头名称")

        return public.returnMsg(True, "校验通过")

    def create_customize_rule(self, get):
        '''
        创建自定义规则
        :param get:
        :return:

        '''
        import random
        if 'infos' in get:
            infos = json.loads(get.infos)
        else:
            return public.returnMsg(False, "参数错误")
        if not 'id' in infos:
            infos['id'] = str(int(random.randint(1000, 9999) + random.randint(1000, int(time.time()))))
        if not 'name' in infos:
            return public.returnMsg(False, "规则名称不能为空")
        if not 'servers' in infos:
            return public.returnMsg(False, "关联的网站不能为空")
        if not 'priority' in infos:
            return public.returnMsg(False, "优先级不能为空")
        if not 'status' in infos:
            return public.returnMsg(False, "启用状态不能为空")
        if not 'is_global' in infos:
            return public.returnMsg(False, "是否全局规则不能为空")
        if not 'src' in infos:
            infos['src'] = 0
        if not 'execute_phase' in infos:
            infos['execute_phase'] = "access"
        if not 'action' in infos:
            return public.returnMsg(False, "匹配成功后的动作不能为空")
        if not 'root' in infos:
            return public.returnMsg(False, "匹配入口不能为空")

        if not 'create_time' in infos:
            infos['create_time'] = int(time.time())
        # 检查action中的数据
        if not 'cc' in infos['action']:
            infos['action']['cc'] = None
            infos['action']['block_time'] = 0

        # 规则校验
        if not 'children' in infos['root']:
            return public.returnMsg(False, "规则不能为空5")
        if not infos['root']['children']:
            return public.returnMsg(False, "规则不能为空4")
        # 判断是否有空规则
        if len(infos['root']['children']) == 0: return public.returnMsg(False, "规则不能为空3")
        # 遍历规则树
        for i in infos['root']['children']:
            if 'children' in i:
                children = i['children']
                for i2 in children:
                    status_infos = self.walk(i2)
                    if 'status' in status_infos:
                        if status_infos["status"] == False:
                            return status_infos

        # 写入配置文件
        path = "/www/server/btwaf/rule/customize.json"
        if not os.path.exists(path):
            public.writeFile(path, "{}")
        try:
            data = json.loads(public.readFile(path))
        except:
            data = {}
        # 判断allsite 是否存在
        if not 'allsite' in data:
            data['allsite'] = []
        # 判断rules 是否存在
        if not 'rules' in data:
            data['rules'] = {}
        if infos['id'] in data['rules']:
            return public.returnMsg(False, "规则ID已存在")

        # 判断规则名是否存在
        # for i in data['rules']:
        #     if data['rules'][i]['name']==infos['name']:
        #         return public.returnMsg(False,"规则名已存在")

        # 把这个ID添加到rules中
        data['rules'][infos['id']] = infos
        # 设置这个ID到server中即可
        for i in infos['servers']:
            #
            if not i in data:
                data[i] = [infos['id']]
            else:
                # 判断这个ID是否在这个列表中
                if not infos['id'] in data[i]:
                    data[i].append(infos['id'])

        # 写入配置文件
        public.WriteFile(path, json.dumps(data))
        public.serviceReload()
        return public.returnMsg(True, "添加成功")

    def remove_customize_rule(self, get):
        '''
            @name 删除自定义规则
        '''
        if 'id' not in get:
            return public.returnMsg(False, "参数错误")

        path = "/www/server/btwaf/rule/customize.json"
        if not os.path.exists(path):
            public.writeFile(path, "{}")
        try:
            data = json.loads(public.readFile(path))
        except:
            data = {}

        if 'rules' in data:
            if get.id in data['rules']:
                del data['rules'][get.id]
        # 遍历每个key 判断是否有这个id
        for i in data:
            if i == "allsite": continue
            if i == "rules": continue
            # 如果v为list
            if isinstance(data[i], list):
                if get.id in data[i]:
                    data[i].remove(get.id)
        public.WriteFile(path, json.dumps(data))
        public.serviceReload()
        return public.returnMsg(True, "删除成功")

    def get_customize_rule_id(self, get):
        if 'id' not in get:
            return public.returnMsg(False, "参数错误")

        path = "/www/server/btwaf/rule/customize.json"
        if not os.path.exists(path):
            public.writeFile(path, "{}")
            return public.returnMsg(False, "规则不存在")
        try:
            data = json.loads(public.readFile(path))
        except:
            data = {}
            return public.returnMsg(False, "规则不存在")
        if 'rules' in data:
            if get.id in data['rules']:
                return public.returnMsg(True, data['rules'][get.id])
            else:
                return public.returnMsg(False, "规则不存在")
        else:
            return public.returnMsg(False, "规则不存在")

    def update_customize_rule(self, get):
        if 'id' not in get:
            return public.returnMsg(False, "参数错误")
        path = "/www/server/btwaf/rule/customize.json"
        if not os.path.exists(path):
            public.writeFile(path, "{}")
            return public.returnMsg(False, "规则不存在")
        try:
            data = json.loads(public.readFile(path))
        except:
            data = {}
            return public.returnMsg(False, "规则不存在")
        if not 'rules' in data: public.returnMsg(False, "规则不存在")
        if not get.id in data['rules']: public.returnMsg(False, "规则不存在")

        if 'infos' in get:
            infos = json.loads(get.infos)
        else:
            return public.returnMsg(False, "参数错误")

        # pass
        if not 'name' in infos:
            return public.returnMsg(False, "规则名称不能为空")
        if not 'servers' in infos:
            return public.returnMsg(False, "关联的网站不能为空")
        if not 'priority' in infos:
            return public.returnMsg(False, "优先级不能为空")
        if not 'status' in infos:
            return public.returnMsg(False, "启用状态不能为空")
        if not 'is_global' in infos:
            return public.returnMsg(False, "是否全局规则不能为空")
        if not 'src' in infos:
            infos['src'] = 0
        if not 'execute_phase' in infos:
            infos['execute_phase'] = "access"
        if not 'action' in infos:
            return public.returnMsg(False, "匹配成功后的动作不能为空")
        if not 'root' in infos:
            return public.returnMsg(False, "匹配入口不能为空")

        if not 'create_time' in infos:
            infos['create_time'] = int(time.time())
        # 检查action中的数据
        if not 'cc' in infos['action']:
            infos['action']['cc'] = None
            infos['action']['block_time'] = 0

        # 规则校验
        if not 'children' in infos['root']:
            return public.returnMsg(False, "规则不能为空5")
        if not infos['root']['children']:
            return public.returnMsg(False, "规则不能为空4")
        # 判断是否有空规则
        if len(infos['root']['children']) == 0: return public.returnMsg(False, "规则不能为空3")
        # 遍历规则树
        for i in infos['root']['children']:
            if 'children' in i:
                children = i['children']
                for i2 in children:
                    status_infos = self.walk(i2)
                    if 'status' in status_infos:
                        if status_infos["status"] == False:
                            return status_infos

        # 如果域名发生了变化
        if infos['servers'] == data['rules'][get.id]['servers']:
            # 如果域名没发生任何变化的情况那么就直接保存这个配置
            data['rules'][get.id] = infos
        else:
            # 如果域名发生了变化
            # 遍历每个key 判断是否有这个id
            for i in data:
                if i == "allsite": continue
                if i == "rules": continue
                # 如果v为list
                if isinstance(data[i], list):
                    if get.id in data[i]:
                        # 判断这个id 是否在infos['servers'] 列表中、如果不在则直接删除
                        if not i in infos['servers']:
                            data[i].remove(get.id)
            data['rules'][get.id] = infos

        # 保存这个配置
        public.WriteFile(path, json.dumps(data))
        public.serviceReload()
        return public.returnMsg(True, "修改成功")

    def set_status_customize_rule(self, get):
        if 'id' not in get:
            return public.returnMsg(False, "参数错误")
        if 'status' not in get:
            return public.returnMsg(False, "需要传递状态")
        path = "/www/server/btwaf/rule/customize.json"
        if not os.path.exists(path):
            public.writeFile(path, "{}")
            return public.returnMsg(False, "规则不存在")
        try:
            data = json.loads(public.readFile(path))
        except:
            data = {}
            return public.returnMsg(False, "规则不存在")
        if not 'rules' in data: public.returnMsg(False, "规则不存在")
        if not get.id in data['rules']: public.returnMsg(False, "规则不存在")

        if get.status == "1" or get.status == 1 or get.status == "true" or get.status == True:
            data['rules'][get.id]['status'] = 1
        else:
            data['rules'][get.id]['status'] = 0
        public.WriteFile(path, json.dumps(data))
        public.serviceReload()
        return public.returnMsg(True, "修改成功")

    def get_customize_config_help(self, get):

        # 获取网站的列表
        path = "/www/server/btwaf/domains.json"
        if not os.path.exists(path):
            public.writeFile(path, "{}")
        try:
            data = json.loads(public.readFile(path))
        except:
            data = {}

        list_map = {}
        for i in data:
            name = i['name']
            list_map[name] = name

        return {
            "action": [
                {
                    "has_response": False,
                    "response": [],
                    "text": "放行",
                    "type": "allow"
                },
                {
                    "has_response": True,
                    "response": [
                        {
                            "text": "默认拦截页",
                            "type": "black_page"
                        },
                        {
                            "text": "444响应",
                            "type": "no_response"
                        }
                    ],
                    "text": "拦截",
                    "type": "deny"
                }, {
                    "has_response": True,
                    "response": [
                        {
                            "text": "无感验证（推荐使用）",
                            "type": "validate_silence"
                        },
                        {
                            "text": "滑动验证",
                            "type": "validate_slide"
                        }
                    ],
                    "text": "人机验证",
                    "type": "validate"
                },
            ],
            "operators": {
                "egt": {
                    "data_type": "number",
                    "text": "大于或等于"
                },
                "elt": {
                    "data_type": "number",
                    "text": "小于或等于"
                },
                "eq": {
                    "data_type": "string",
                    "text": "等于/完全匹配"
                },
                "gt": {
                    "data_type": "number",
                    "text": "大于"
                },
                "elt_len":{
                    "data_type": "number",
                    "text": "UA长度小于或等于"
                },
                "eq_len": {
                    "data_type": "eq_len",
                    "text": "等于这个长度"
                },
                "gt_len": {
                    "data_type": "eq_len",
                    "text": "大于这个长度"
                },
                "in": {
                    "data_type": "set",
                    "text": "包含以下各项"
                },
                "like": {
                    "data_type": "string",
                    "text": "模糊匹配"
                },
                "lt": {
                    "data_type": "number",
                    "text": "小于"
                },
                "neq": {
                    "data_type": "string",
                    "text": "不等于"
                },
                "not_in": {
                    "data_type": "set",
                    "text": "不包含以下各项"
                },
                "prefix": {
                    "data_type": "string",
                    "text": "匹配开头"
                },
                "regexp": {
                    "data_type": "string",
                    "text": "正则表达式"
                },
                "suffix": {
                    "data_type": "string",
                    "text": "匹配结尾"
                },
                "null": {
                    "data_type": "null",
                    "text": "匹配空"
                }
            },
            "options": [
                {
                    "left_factor_enabled": False,
                    "left_widget": {},
                    "operators": [
                        "eq",
                        "neq"
                    ],
                    "right_factor_enabled": True,
                    "right_widget": {
                        "hint": "示例：192.168.1.1",
                        "placeholder": "请输入客户端IP",
                        "type": "text",
                        "value": ""
                    },
                    "text": "客户端IP",
                    "type": "ip"
                },
                {
                    "left_factor_enabled": False,
                    "left_widget": {},
                    "operators": [
                        "eq",
                        "neq"
                    ],
                    "right_factor_enabled": True,
                    "right_widget": {
                        "hint": "示例:美国,德国",
                        "placeholder": "美国,德国",
                        "type": "mult",
                        "value": ['中国以外地区', '中国',
                                  '美国', '日本', '英国', '德国', '韩国', '法国', '巴西', '加拿大', '意大利',
                                  '澳大利亚', '荷兰', '俄罗斯', '印度', '瑞典', '西班牙', '墨西哥',
                                  '比利时', '南非', '波兰', '瑞士', '阿根廷', '印度尼西亚', '埃及', '哥伦比亚',
                                  '土耳其', '越南', '挪威', '芬兰', '丹麦', '乌克兰', '奥地利',
                                  '伊朗', '智利', '罗马尼亚', '捷克', '泰国', '沙特阿拉伯', '以色列', '新西兰',
                                  '委内瑞拉', '摩洛哥', '马来西亚', '葡萄牙', '爱尔兰', '新加坡',
                                  '欧洲联盟', '匈牙利', '希腊', '菲律宾', '巴基斯坦', '保加利亚', '肯尼亚',
                                  '阿拉伯联合酋长国', '阿尔及利亚', '塞舌尔', '突尼斯', '秘鲁', '哈萨克斯坦',
                                  '斯洛伐克', '斯洛文尼亚', '厄瓜多尔', '哥斯达黎加', '乌拉圭', '立陶宛', '塞尔维亚',
                                  '尼日利亚', '克罗地亚', '科威特', '巴拿马', '毛里求斯', '白俄罗斯',
                                  '拉脱维亚', '多米尼加', '卢森堡', '爱沙尼亚', '苏丹', '格鲁吉亚', '安哥拉',
                                  '玻利维亚', '赞比亚', '孟加拉国', '巴拉圭', '波多黎各', '坦桑尼亚',
                                  '塞浦路斯', '摩尔多瓦', '阿曼', '冰岛', '叙利亚', '卡塔尔', '波黑', '加纳',
                                  '阿塞拜疆', '马其顿', '约旦', '萨尔瓦多', '伊拉克', '亚美尼亚', '马耳他',
                                  '危地马拉', '巴勒斯坦', '斯里兰卡', '特立尼达和多巴哥', '黎巴嫩', '尼泊尔',
                                  '纳米比亚', '巴林', '洪都拉斯', '莫桑比克', '尼加拉瓜', '卢旺达', '加蓬',
                                  '阿尔巴尼亚', '利比亚', '吉尔吉斯坦', '柬埔寨', '古巴', '喀麦隆', '乌干达',
                                  '塞内加尔', '乌兹别克斯坦', '黑山', '关岛', '牙买加', '蒙古', '文莱',
                                  '英属维尔京群岛', '留尼旺', '库拉索岛', '科特迪瓦', '开曼群岛', '巴巴多斯',
                                  '马达加斯加', '伯利兹', '新喀里多尼亚', '海地', '马拉维', '斐济', '巴哈马',
                                  '博茨瓦纳', '扎伊尔', '阿富汗', '莱索托', '百慕大', '埃塞俄比亚', '美属维尔京群岛',
                                  '列支敦士登', '津巴布韦', '直布罗陀', '苏里南', '马里', '也门',
                                  '老挝', '塔吉克斯坦', '安提瓜和巴布达', '贝宁', '法属玻利尼西亚', '圣基茨和尼维斯',
                                  '圭亚那', '布基纳法索', '马尔代夫', '泽西岛', '摩纳哥', '巴布亚新几内亚',
                                  '刚果', '塞拉利昂', '吉布提', '斯威士兰', '缅甸', '毛里塔尼亚', '法罗群岛', '尼日尔',
                                  '安道尔', '阿鲁巴', '布隆迪', '圣马力诺', '利比里亚',
                                  '冈比亚', '不丹', '几内亚', '圣文森特岛', '荷兰加勒比区', '圣马丁', '多哥', '格陵兰',
                                  '佛得角', '马恩岛', '索马里', '法属圭亚那', '西萨摩亚',
                                  '土库曼斯坦', '瓜德罗普', '马里亚那群岛', '瓦努阿图', '马提尼克', '赤道几内亚',
                                  '南苏丹', '梵蒂冈', '格林纳达', '所罗门群岛', '特克斯和凯科斯群岛', '多米尼克',
                                  '乍得', '汤加', '瑙鲁', '圣多美和普林西比', '安圭拉岛', '法属圣马丁', '图瓦卢',
                                  '库克群岛', '密克罗尼西亚联邦', '根西岛', '东帝汶', '中非',
                                  '几内亚比绍', '帕劳', '美属萨摩亚', '厄立特里亚', '科摩罗', '圣皮埃尔和密克隆',
                                  '瓦利斯和富图纳', '英属印度洋领地', '托克劳', '马绍尔群岛', '基里巴斯',
                                  '纽埃', '诺福克岛', '蒙特塞拉特岛', '朝鲜', '马约特', '圣卢西亚', '圣巴泰勒米岛']
                    },
                    "text": "国家/地区",
                    "type": "ip_belongs"
                },
                {
                    "left_factor_enabled": False,
                    "left_widget": {},
                    "operators": [
                        "in",
                        "not_in"
                    ],
                    "right_factor_enabled": True,
                    "right_widget": {
                        "hint": "示例：192.168.1.0/24",
                        "placeholder": "请输入CIDR表达式",
                        "type": "text",
                        "value": ""
                    },
                    "text": "IP段",
                    "type": "ip_range"
                },
                {
                    "left_factor_enabled": False,
                    "left_widget": {},
                    "operators": [
                        "eq",
                        "neq",
                        "in",
                        "not_in"
                    ],
                    "right_factor_enabled": True,
                    "right_widget": {
                        "hint": "",
                        "placeholder": "请选择请求方式",
                        "type": "select",
                        "value": [
                            {
                                "key": "GET",
                                "label": "GET"
                            },
                            {
                                "key": "POST",
                                "label": "POST"
                            },
                            {
                                "key": "PUT",
                                "label": "PUT"
                            },
                            {
                                "key": "DELETE",
                                "label": "DELETE"
                            },
                            {
                                "key": "PATCH",
                                "label": "PATCH"
                            },
                            {
                                "key": "TRACE",
                                "label": "TRACE"
                            },
                            {
                                "key": "HEAD",
                                "label": "HEAD"
                            },
                            {
                                "key": "OPTIONS",
                                "label": "OPTIONS"
                            },
                            {
                                "key": "CONNECT",
                                "label": "CONNECT"
                            }
                        ]
                    },
                    "text": "请求方式",
                    "type": "method"
                },
                {
                    "left_factor_enabled": False,
                    "left_widget": {},
                    "operators": [
                        "eq",
                        "neq",
                        "prefix",
                        "suffix",
                        "like",
                        "regexp",
                        "in",
                        "not_in"
                    ],
                    "right_factor_enabled": True,
                    "right_widget": {
                        "hint": "示例：/index.php",
                        "placeholder": "请输入URI",
                        "type": "text",
                        "value": ""
                    },
                    "text": "URI(不带参数)",
                    "type": "uri"
                },
                {
                    "left_factor_enabled": False,
                    "left_widget": {},
                    "operators": [
                        "eq",
                        "neq",
                        "prefix",
                        "suffix",
                        "like",
                        "regexp",
                        "in",
                        "not_in"
                    ],
                    "right_factor_enabled": True,
                    "right_widget": {
                        "hint": "示例：/index.php?username=xiaoming",
                        "placeholder": "请输入URI",
                        "type": "text",
                        "value": ""
                    },
                    "text": "URI(带参数)",
                    "type": "uri_with_param"
                },
                {
                    "left_factor_enabled": False,
                    "left_widget": {},
                    "operators": [
                        "in",
                        "not_in"
                    ],
                    "right_factor_enabled": True,
                    "right_widget": {
                        "hint": "示例：username",
                        "placeholder": "请输入参数名称",
                        "type": "text",
                        "value": ""
                    },
                    "text": "URI参数名称",
                    "type": "param_name"
                },
                {
                    "left_factor_enabled": True,
                    "left_widget": {
                        "hint": "示例：username",
                        "placeholder": "请输入参数名称",
                        "type": "text",
                        "value": ""
                    },
                    "operators": [
                        "eq",
                        "neq",
                        "prefix",
                        "suffix",
                        "like",
                        "regexp"
                    ],
                    "right_factor_enabled": True,
                    "right_widget": {
                        "hint": "示例：xiaoming",
                        "placeholder": "请输入参数值",
                        "type": "text",
                        "value": ""
                    },
                    "text": "URI请求参数",
                    "type": "param"
                },

                {
                    "left_factor_enabled": True,
                    "left_widget": {
                        "hint": "示例：Host",
                        "placeholder": "请输入请求头名称",
                        "type": "text",
                        "value": ""
                    },
                    "operators": [
                        "eq",
                        "neq",
                        "prefix",
                        "suffix",
                        "like",
                        "regexp"
                    ],
                    "right_factor_enabled": True,
                    "right_widget": {
                        "hint": "示例：www.bt.cn",
                        "placeholder": "请输入匹配值",
                        "type": "text",
                        "value": ""
                    },
                    "text": "请求头",
                    "type": "request_header"
                },
                {
                    "left_factor_enabled": True,
                    "left_widget": {
                        "hint": "示例：username",
                        "placeholder": "请输入参数名称",
                        "type": "text",
                        "value": ""
                    },
                    "operators": [
                        "eq",
                        "neq",
                        "prefix",
                        "suffix",
                        "like",
                        "regexp"
                    ],
                    "right_factor_enabled": True,
                    "right_widget": {
                        "hint": "示例：xiaoming",
                        "placeholder": "请输入参数值",
                        "type": "text",
                        "value": ""
                    },
                    "text": "POST请求参数",
                    "type": "post_param"
                },
                {
                    "left_factor_enabled": False,
                    "left_widget": {},
                    "operators": [
                        "regexp",
                        "eq",
                        "neq",
                        "prefix",
                        "suffix",
                        "like",
                        "in",
                        "not_in"
                    ],
                    "right_factor_enabled": True,
                    "right_widget": {
                        "hint": "示例：username=ddd\u0026aaa=ccc",
                        "placeholder": "输入需要匹配的内容",
                        "type": "text",
                        "value": ""
                    },
                    "text": "Post Body内容匹配",
                    "type": "body_param"
                },
                {
                    "left_factor_enabled": False,
                    "left_widget": {},
                    "operators": [
                        "eq",
                        "neq",
                        "like",
                        "null",
                        "elt_len"
                    ],
                    "right_factor_enabled": True,
                    "right_widget": {
                        "hint": "示例：Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6)...",
                        "placeholder": "请输入匹配值",
                        "type": "text",
                        "value": ""
                    },
                    "text": "User Agent",
                    "type": "user-agent"
                },
                {
                    "left_factor_enabled": False,
                    "left_widget": {},
                    "operators": [
                        "eq",
                        "neq",
                        "in",
                        "not_in",
                        "prefix",
                        "suffix",
                        "regexp",
                        "null"
                    ],
                    "right_factor_enabled": True,
                    "right_widget": {
                        "hint": "示例：https://www.bt.cn/",
                        "placeholder": "请输入匹配值",
                        "type": "text",
                        "value": ""
                    },
                    "text": "引用方/referer",
                    "type": "referer"
                },
                {
                    "left_factor_enabled": False,
                    "left_widget": {},
                    "operators": [
                        "in",
                        "not_in"
                    ],
                    "right_factor_enabled": True,
                    "right_widget": {
                        "hint": "示例：Host",
                        "placeholder": "请输入请求头名称",
                        "type": "text",
                        "value": ""
                    },
                    "text": "请求头名称",
                    "type": "request_header_name"
                }
            ],
            "sitemap": list_map
        }

    def HttpGetHttp(self, url, timeout=3):
        """
            @name 发送GET请求
            @author hwliang<hwl@bt.cn>
            @url 被请求的URL地址(必需)
            @timeout 超时时间默认60秒
            @return string
        """
        import requests
        config = self.get_config(None)
        toekn = config["access_token"]
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36",
            "btwaf-access-token": toekn
        }
        try:
            res = public.HttpGet(url, timeout=1, headers=headers)
            try:
                res = json.loads(res)
                return res
            except:
                count = totle_db2.Sql().dbfile("total_report").table("request_total").field("SUM(request)").where(
                    "server_name='global' and date=?", ((time.strftime('%Y-%m-%d', time.localtime())))).getField(
                    "SUM(request)")
                if type(count) == int:
                    count = int(count)
                elif type(count) == str:
                    count = int(count)
                else:
                    count = 0
                return {"qps": 0, "today_request": count}
        except:
            return {}

    def new_overview(self, get):

        if 'new_overview' in get:
            return self.overview(get)
        else:
            result = {}
            result["count"] = {
                "today_request": 0,
                "malicious_request": 0,
                "webshell": 0,
                "unprotected_site": 0,
                "maybe_err_cc": 0,
                "unprotected_site_list": [],
                "maybe_err_cc_list": []
            }
            result["time"] = int(time.time())
            result["autoEvent"] = ["自动化事件1", "自动化事件2"]
            result["traffic_filter"] = []

            result["qps"] = 0

            result['map'] = []
            result['type'] = []

            result2 = {}
            result2['map'] = {}
            result2['map']['info'] = {}
            result2['map']['24_day_count'] = 0
            result2['map']['1_day_count'] = 0
            result2['map']['top10_ip'] = {}
            result2['map']['24_day_count'] = 0

            result["attack_details"] = []
            # 隔离木马文件
            result["count"]["webshell"] = self.get_webshell_size()
            config = self.get_config(None)
            result['open'] = config['open']
            # 网站配置
            site_config = self.get_site_config(None)
            # 获取网站关闭的数量
            for i in site_config:
                if 'open' in site_config[i] and not site_config[i]['open']:
                    result["count"]["unprotected_site"] += 1
                    result["count"]["unprotected_site_list"].append(i)

            # 判断CC的设置是否有问题
            for i in site_config:
                # 如果这个网站没有开启防护直接跳过
                if 'open' in site_config[i] and not site_config[i]['open']: continue
                # 同时开启了禁国外和禁止国内就提醒
                if 'drop_abroad' in site_config[i] and site_config[i]['drop_abroad'] and site_config[i]['drop_china']:
                    result["count"]["maybe_err_cc"] += 1
                    result["count"]["maybe_err_cc_list"].append(
                        "CC设置存在问题提醒:网站:" + i + " 同时开启了禁国外和禁止国内, 可能会导致所有用户访问不了网站")
                # 判断是否开了CC
                if 'cc' in site_config[i] and 'open' in site_config[i]['cc'] and site_config[i]['cc']['open']:
                    # 判断数字是否太小了
                    if not 'cycle' in site_config[i]['cc']: continue
                    if not 'limit' in site_config[i]['cc']: continue
                    if site_config[i]['cc']['cycle'] < 60:
                        result["count"]["maybe_err_cc"] += 1
                        result["count"]["maybe_err_cc_list"].append(
                            "CC设置存在问题提醒:网站:" + i + " CC设置的访问时间过小、建议设置为60秒以上,可能会影响正常用户访问")
                    if site_config[i]['cc']['limit'] < 30:
                        result["count"]["maybe_err_cc"] += 1
                        result["count"]["maybe_err_cc_list"].append(
                            "CC设置存在问题提醒:网站:" + i + " CC设置的访问次数过小、建议设置为30次以上、可能会影响正常用户访问")
                # 拦截次数
                if 'retry_cycle' in site_config[i] and site_config[i]['retry_cycle'] < 50:
                    result["count"]["maybe_err_cc"] += 1
                    result["count"]["maybe_err_cc_list"].append(
                        "CC设置存在问题提醒:网站:" + i + " 攻击次数拦截时间设置的时间过小、建议设置为60秒以上、设置过小可能拦截效果不太好")
                if 'retry' in site_config[i] and site_config[i]['retry'] < 10:
                    result["count"]["maybe_err_cc"] += 1
                    result["count"]["maybe_err_cc_list"].append(
                        "CC设置存在问题提醒:网站:" + i + " 攻击次数拦截设置拦截次数过小、建议设置为10次以上、可能会导致误拦截")

            last_timeStamp = int(time.mktime(
                time.strptime(time.strftime("%Y-%m-%d", time.localtime(time.time())) + ' 00:00:00',
                              '%Y-%m-%d %H:%M:%S')))
            last_end_timeStamp = int(time.mktime(
                time.strptime(time.strftime("%Y-%m-%d", time.localtime(time.time())) + ' 23:59:59',
                              '%Y-%m-%d %H:%M:%S')))
            # 恶意请求数量
            last_count = self.M2('totla_log').field('time,ip,ip_country,ip_city,ip_subdivisions').where(
                "time>=? and time<=?", (last_timeStamp, last_end_timeStamp)).order(
                'id desc').count()
            if type(last_count) == int:
                result["count"]['malicious_request'] = last_count
            infos = self.HttpGetHttp('http://127.0.0.1/get_global_status')
            if len(infos) > 0:
                result["count"]['today_request'] = infos['today_request']
                result['qps'] = infos['qps']
            return result

    def get_config_overview(self):
        try:
            config = json.loads(public.readFile(self.__path + 'config.json'))
            site_config = json.loads(public.readFile(self.__path + 'site.json'))
            return config, site_config
        except:
            return {}, {}

    def overview(self, get):
        result = {}
        result["count"] = {
            "today_request": 0,
            "malicious_request": 0,
            "webshell": 0,
            "unprotected_site": 0,
            "maybe_err_cc": 0,
            "unprotected_site_list": [],
            "maybe_err_cc_list": []
        }
        result["time"] = int(time.time())

        result["autoEvent"] = ["自动化事件1", "自动化事件2"]
        result["traffic_filter"] = []

        result["qps"] = 0
        result["type"] = []
        result['map'] = []

        result2 = {}
        result2['map'] = {}
        result2['map']['info'] = {}
        result2['map']['24_day_count'] = 0
        result2['map']['1_day_count'] = 0
        result2['map']['top10_ip'] = {}
        result2['map']['24_day_count'] = 0

        result["attack_details"] = []
        # 隔离木马文件
        result["count"]["webshell"] = self.get_webshell_size()
        config, site_config = self.get_config_overview()
        if '3D' not in config:
            config['3D'] = True
            # 写入配置文件
            public.writeFile(self.__path + 'config.json', json.dumps(config))
        result['3D'] = config['3D']
        result['open'] = config['open']
        # 获取网站关闭的数量
        for i in site_config:
            if 'open' in site_config[i] and not site_config[i]['open']:
                result["count"]["unprotected_site"] += 1
                result["count"]["unprotected_site_list"].append(i)

        # 判断CC的设置是否有问题
        for i in site_config:
            # 如果这个网站没有开启防护直接跳过
            if 'open' in site_config[i] and not site_config[i]['open']: continue
            # 同时开启了禁国外和禁止国内就提醒
            if 'drop_abroad' in site_config[i] and site_config[i]['drop_abroad'] and site_config[i]['drop_china']:
                result["count"]["maybe_err_cc"] += 1
                result["count"]["maybe_err_cc_list"].append(
                    "CC设置存在问题提醒:网站:" + i + " 同时开启了禁国外和禁止国内, 可能会导致所有用户访问不了网站")
            # 判断是否开了CC
            if 'cc' in site_config[i] and 'open' in site_config[i]['cc'] and site_config[i]['cc']['open']:
                # 判断数字是否太小了
                if not 'cycle' in site_config[i]['cc']: continue
                if not 'limit' in site_config[i]['cc']: continue
                if site_config[i]['cc']['cycle'] < 60:
                    result["count"]["maybe_err_cc"] += 1
                    result["count"]["maybe_err_cc_list"].append(
                        "CC设置存在问题提醒:网站:" + i + " CC设置的访问时间过小、建议设置为60秒以上,可能会影响正常用户访问")
                if site_config[i]['cc']['limit'] < 30:
                    result["count"]["maybe_err_cc"] += 1
                    result["count"]["maybe_err_cc_list"].append(
                        "CC设置存在问题提醒:网站:" + i + " CC设置的访问次数过小、建议设置为30次以上、可能会影响正常用户访问")
            # 拦截次数
            if 'retry_cycle' in site_config[i] and site_config[i]['retry_cycle'] < 50:
                result["count"]["maybe_err_cc"] += 1
                result["count"]["maybe_err_cc_list"].append(
                    "CC设置存在问题提醒:网站:" + i + " 攻击次数拦截时间设置的时间过小、建议设置为60秒以上、设置过小可能拦截效果不太好")
            if 'retry' in site_config[i] and site_config[i]['retry'] < 10:
                result["count"]["maybe_err_cc"] += 1
                result["count"]["maybe_err_cc_list"].append(
                    "CC设置存在问题提醒:网站:" + i + " 攻击次数拦截设置拦截次数过小、建议设置为10次以上、可能会导致误拦截")
            if 'spider_status' in site_config[i] and not site_config[i]['spider_status']:
                result["count"]["maybe_err_cc"] += 1
                result["count"]["maybe_err_cc_list"].append(
                    "CC设置存在问题提醒:网站:" + i + " 未开启蜘蛛爬取功能、会导致百度、谷歌等蜘蛛爬取失败、影响录入")

        #
        if not 'start_time' in get:
            start_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
        else:
            # 判断时间格式
            if not re.match(r'^\d{4}-\d{2}-\d{2}$', get.start_time):
                start_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
            else:
                start_time = get.start_time.strip()
        if not 'end_time' in get:
            end_time = start_time
        else:
            end_time = get.end_time.strip()

        s_time = start_time + ' 00:00:00'
        e_time = end_time + ' 23:59:59'
        start_timeStamp = int(time.mktime(time.strptime(s_time, '%Y-%m-%d %H:%M:%S')))
        end_timeStamp = int(time.mktime(time.strptime(e_time, '%Y-%m-%d %H:%M:%S')))
        last_timeStamp = int(time.mktime(
            time.strptime(time.strftime("%Y-%m-%d", time.localtime(time.time())) + ' 00:00:00', '%Y-%m-%d %H:%M:%S')))
        last_end_timeStamp = int(time.mktime(
            time.strptime(time.strftime("%Y-%m-%d", time.localtime(time.time())) + ' 23:59:59', '%Y-%m-%d %H:%M:%S')))

        # 恶意请求数量
        last_count = self.M2('totla_log').field('time,ip,ip_country,ip_city,ip_subdivisions').where(
            "time>=? and time<=?", (last_timeStamp, last_end_timeStamp)).order(
            'id desc').count()
        if type(last_count) == int:
            result["count"]['malicious_request'] = last_count
        infos = self.HttpGetHttp('http://127.0.0.1/get_global_status')
        if len(infos) > 0:
            result["count"]['today_request'] = infos['today_request']
            result['qps'] = infos['qps']
        # 流量过滤

        if os.path.exists('/www/server/btwaf/totla_db/total_report.db'):
            result["traffic_filter"] = totle_db3.Sql().dbfile("total_report").table("request_total").field(
                "hour,minute,request,err_499,err_502,proxy_count").where("date=? and server_name='global'",
                                                                         start_time).select()
        else:
            result["traffic_filter"] = []
        map_24_data = self.M2('totla_log').field(
            'time,server_name,filter_rule,ip,ip_country,ip_city,ip_subdivisions').order(
            'id desc').where("time>=? and time<=?", (last_timeStamp, last_end_timeStamp)).limit("10000").select()
        if type(map_24_data) == str:
            if map_24_data == "error: file is encrypted or is not a database" or map_24_data == "error: database disk image is malformed":
                try:
                    os.remove("/www/server/btwaf/totla_db/totla_db.db")
                except:
                    pass
            return result
        is_time = time.time()
        ip_map = {}
        tmp_rule = {}
        for i in map_24_data:
            if i['filter_rule'] in tmp_rule:
                tmp_rule[i['filter_rule']] += 1
            else:
                tmp_rule[i['filter_rule']] = 1
            if not ip_map.get(i['ip'] + "country"):
                ip_map[i['ip'] + "country"] = i['ip_country']
            if not ip_map.get(i['ip'] + "city"):
                ip_map[i['ip'] + "city"] = i['ip_city']
            if not ip_map.get(i['ip'] + "subdivisions"):
                ip_map[i['ip'] + "subdivisions"] = i['ip_subdivisions']
            if i['ip'] in result2['map']['top10_ip']:
                result2['map']['top10_ip'][i['ip']] = result2['map']['top10_ip'][i['ip']] + 1
            else:
                result2['map']['top10_ip'][i['ip']] = 1
            if i['ip_country'] == None: continue
            if i['ip_country'] in result2['map']['info']:
                result2['map']['info'][i['ip_country']] = result2['map']['info'][i['ip_country']] + 1
            else:
                result2['map']['info'][i['ip_country']] = 1

        top_type = (sorted(tmp_rule.items(), key=lambda kv: (kv[1], kv[0]), reverse=True))
        result["type"] = top_type

        if len(result2['map']['info']):
            try:
                result2['map']['info'] = (sorted(result2['map']['info'].items(), key=lambda kv: (kv[1], kv[0])))[::-1]
            except:
                pass
        top10_ip = (sorted(result2['map']['top10_ip'].items(), key=lambda kv: (kv[1], kv[0])))
        #
        if len(top10_ip) > 40:
            result2['map']['top10_ip'] = top10_ip[::-1][:40]
        else:
            result2['map']['top10_ip'] = top10_ip[::-1]
        result_top_10 = []
        for i in result2['map']['top10_ip']:
            i2 = list(i)
            if ip_map.get(i[0] + "country"):
                ret = ip_map[i[0] + "country"]
                i2.append(ret)
            if ip_map.get(i[0] + "subdivisions"):
                ret = ip_map[i[0] + "subdivisions"]
                i2.append(ret)
            if ip_map.get(i[0] + "city"):
                ret = ip_map[i[0] + "city"]
                i2.append(ret)
            result_top_10.append(i2)
        result2['map']['top10_ip'] = result_top_10
        for i in result2['map']['info']:
            if i[0] == "未知位置": continue
            result['map'].append({"name": i[0], "value": i[1]})
        for i in result2['map']['top10_ip']:
            if len(i) == 3:
                result['attack_details'].append({"ip": i[0], "count": i[1], "address": i[2]})
            elif len(i) == 4:
                if i[2] == i[3]:
                    address = i[2]
                else:
                    address = i[2] + "-" + i[3]
                result['attack_details'].append({"ip": i[0], "count": i[1], "address": address})
            elif len(i) == 5:
                if i[3] == i[4]:
                    address = i[3]
                else:
                    address = i[3] + "-" + i[4]
                result['attack_details'].append({"ip": i[0], "count": i[1], "address": address})
            else:
                result['attack_details'].append({"ip": i[0], "count": i[1], "address": " ".join(i[2:])})
        return result

    def attack_report_log(self, get):
        '''
        start_time:2021-05-06
        end_time:2021-05-07
        p:1  页数
        limit:10
        '''
        if not 'limit' in get:
            limit = 10
        else:
            limit = int(get.limit.strip())
        if not 'p' in get:
            p = 10
        else:
            p = int(get.p.strip())
        flag = False
        keyword_flag = False
        if not 'keyword' in get:
            keyword = ''
        else:
            if get.keyword.strip() == "":
                keyword_flag = False
                keyword = ''
            else:
                keyword_flag = True
                keyword = get.keyword.strip() + "%"

        if not 'start_time' in get:
            start_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
        else:
            flag = True
            # 判断日期格式
            if not re.match(r'^\d{4}-\d{2}-\d{2}$', get.start_time):
                start_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
            else:
                start_time = get.start_time.strip()
        if not 'end_time' in get:
            end_time = start_time
        else:
            end_time = get.end_time.strip()

        start_time = start_time + ' 00:00:00'
        end_time2 = end_time + ' 23:59:59'
        start_timeStamp = int(time.mktime(time.strptime(start_time, '%Y-%m-%d %H:%M:%S')))
        end_timeStamp = int(time.mktime(time.strptime(end_time2, '%Y-%m-%d %H:%M:%S')))
        count = 0
        if os.path.exists("/www/server/btwaf/totla_db/totla_db.db"):
            import page
            page = page.Page()
            if flag:

                if keyword_flag and len(keyword) > 0 and keyword != "":
                    count = self.M2('totla_log').field('time').where(
                        "time>? and time<? and server_name like ? or ip like ?  or ip_city like ? or ip_country like ? or  uri like ?  or user_agent like ? or filter_rule like ? or ip_subdivisions like ?",
                        (start_timeStamp, end_timeStamp, keyword, keyword, keyword, keyword, keyword, keyword, keyword,
                         keyword)).order('id desc').count()
                else:
                    count = self.M2('totla_log').field('time').where("time>? and time<?", (
                        start_timeStamp, end_timeStamp)).order('id desc').count()
            else:
                if keyword_flag and len(keyword) > 0:
                    count = self.M2('totla_log').field('time').where(
                        "server_name like ? or ip like ?  or ip_city like ? or ip_country like ? or  uri like ?  or user_agent like ? or filter_rule like ? or ip_subdivisions like ?",
                        (keyword, keyword, keyword, keyword, keyword, keyword, keyword, keyword)).order(
                        'id desc').count()
                else:
                    count = self.M2('totla_log').field('time').order('id desc').count()
            info = {}
            info['count'] = count
            info['row'] = limit
            info['p'] = 1
            if hasattr(get, 'p'):
                info['p'] = int(get['p'])
            info['uri'] = get
            info['return_js'] = ''
            if hasattr(get, 'tojs'):
                info['return_js'] = get.tojs
            data = {}
            # 获取分页数据
            data['page'] = page.GetPage(info, '1,2,3,4,5,8')
            data['data'] = []
            data['total'] = count
            if flag:
                if keyword_flag and len(keyword) > 0:
                    data22 = self.M3('totla_log').field(
                        'time,time_localtime,server_name,ip,ip_city,ip_country,ip_subdivisions,ip_longitude,ip_latitude,type,uri,user_agent,filter_rule,incoming_value,value_risk,http_log,http_log_path').order(
                        'id desc').where(
                        "time>? and time<? and server_name like ? or ip like ?  or ip_city like ? or ip_country like ? or  uri like ?  or user_agent like ? or filter_rule like ? or ip_subdivisions like ?",
                        (start_timeStamp, end_timeStamp, keyword, keyword, keyword, keyword, keyword, keyword, keyword,
                         keyword)).limit(
                        str(page.SHIFT) + ',' + str(page.ROW)).select()

                else:
                    data22 = self.M3('totla_log').field(
                        'time,time_localtime,server_name,ip,ip_city,ip_country,ip_subdivisions,ip_longitude,ip_latitude,type,uri,user_agent,filter_rule,incoming_value,value_risk,http_log,http_log_path').order(
                        'id desc').where("time>? and time<?",
                                         (start_timeStamp, end_timeStamp)).limit(
                        str(page.SHIFT) + ',' + str(page.ROW)).select()

            else:
                if keyword and len(keyword) > 0:
                    data22 = self.M3('totla_log').field(
                        'time,time_localtime,server_name,ip,ip_city,ip_country,ip_subdivisions,ip_longitude,ip_latitude,type,uri,user_agent,filter_rule,incoming_value,value_risk,http_log,http_log_path').order(
                        'id desc').where(
                        "server_name like ? or ip like ? or ip_city like ? or ip_country like ? or uri like ? or user_agent like ? or filter_rule like ? or ip_subdivisions like ?",
                        (keyword, keyword, keyword, keyword, keyword, keyword, keyword, keyword)).limit(
                        str(page.SHIFT) + ',' + str(page.ROW)).select()
                else:
                    data22 = self.M3('totla_log').field(
                        'time,time_localtime,server_name,ip,ip_city,ip_country,ip_subdivisions,ip_longitude,ip_latitude,type,uri,user_agent,filter_rule,incoming_value,value_risk,http_log,http_log_path').order(
                        'id desc').limit(
                        str(page.SHIFT) + ',' + str(page.ROW)).select()
            if type(data22) == str: public.returnMsg(True, data)
            data['total'] = count
            try:

                data['data'] = self.bytpes_to_string(data22)
            except:
                pass
            return public.returnMsg(True, data)
        else:
            data = {}
            data['page'] = "<div><span class='Pcurrent'>1</span><span class='Pcount'>共0条</span></div>"
            data['total'] = count
            data['data'] = []
            return public.returnMsg(False, data)

    def get_ip_infos(self, type):
        if type == 'ip_white' or type == 'ip_black' or type == 'cn':
            try:
                rule = self.__get_rule(type)
                for i in rule:
                    for i2 in range(len(i)):
                        if i2 >= 2: continue
                        i[i2] = self.long2ip(i[i2])
                return rule
            except:
                return []
        else:
            rule = self.__get_rule(type)
            for i in rule:
                for i2 in range(len(i)):
                    i[i2] = self.long2ip(i[i2])
            return rule

    def get_rule_ip(self, get):
        '''
        @name 获取IP规则
        :param rule ip_black IP黑名单    ip_white  IP白名单
        :return:
        '''
        if not 'rule' in get:
            return public.returnMsg(False, '参数错误')
        rule_list = ['ip_black', 'ip_white', 'url_white', 'url_black', 'ua_black', 'ua_white']
        if get.rule not in rule_list:
            return public.returnMsg(False, '参数错误')
        if 'p' not in get:
            get.p = 1
        if 'limit' not in get:
            get.limit = 10
        if 'keyword' not in get:
            keyword = ''
        else:
            keyword = get.keyword.strip()
        if get.rule == 'ip_black':
            data = self.get_ip_infos("ip_black")
            ipv6 = self.__get_rule('ip_black_v6')
            for i in ipv6:
                # 插入到第一个位置
                data.insert(0, i)
            if len(keyword) > 0:
                tmp_data = []
                for i in data:
                    # 遍历i 的长度
                    for i2 in range(len(i)):
                        if keyword in i[i2]:
                            tmp_data.append(i)
                            break
                data = tmp_data
            tmp_info = self.paginate_data(data, get.p, get.limit)
            return public.returnMsg(True, tmp_info)
        elif get.rule == 'ip_white':
            data = self.get_ip_infos("ip_white")
            ipv6 = self.__get_rule('ip_white_v6')
            for i in ipv6:
                # 插入到第一个位置
                data.insert(0, i)
            if len(keyword) > 0:
                tmp_data = []
                for i in data:
                    for i2 in range(len(i)):
                        if keyword in i[i2]:
                            tmp_data.append(i)
                            break
                data = tmp_data
            tmp_info = self.paginate_data(data, get.p, get.limit)
            return public.returnMsg(True, tmp_info)
        elif get.rule == 'url_white':
            data = self.__get_rule("url_white")
            if len(keyword) > 0:
                tmp_data = []
                for i in data:
                    if keyword in i:
                        tmp_data.append(i)
                        break
                data = tmp_data
            tmp_info = self.paginate_data(data, get.p, get.limit)
            return public.returnMsg(True, tmp_info)
        elif get.rule == 'url_black':
            data = self.__get_rule("url_black")
            if len(keyword) > 0:
                tmp_data = []
                for i in data:
                    if keyword in i:
                        tmp_data.append(i)
                        break
                data = tmp_data
            tmp_info = self.paginate_data(data, get.p, get.limit)
            return public.returnMsg(True, tmp_info)
        elif get.rule == 'ua_black':
            config = self.get_config(None)
            data = config['ua_black']
            if len(keyword) > 0:
                tmp_data = []
                for i in data:
                    if keyword in i:
                        tmp_data.append(i)
                        break
                data = tmp_data
            tmp_info = self.paginate_data(data, get.p, get.limit)
            return public.returnMsg(True, tmp_info)
        elif get.rule == 'ua_white':
            config = self.get_config(None)
            data = config['ua_white']
            if len(keyword) > 0:
                tmp_data = []
                for i in data:
                    if keyword in i:
                        tmp_data.append(i)
                        break
                data = tmp_data
            tmp_info = self.paginate_data(data, get.p, get.limit)
            return public.returnMsg(True, tmp_info)
        else:
            return public.returnMsg(False, '参数错误')

    def remove_rule_check(self, get):
        if not 'rule' in get:
            return public.returnMsg(False, '参数错误')
        rule_list = ['ip_black', 'ip_white', 'url_white', 'url_black', 'ua_black', 'ua_white']
        if get.rule not in rule_list:
            return public.returnMsg(False, '参数错误')
        type_list = ['ipv4', 'ipv6']
        if get.rule == 'ip_black' or get.rule == 'ip_white':
            if not 'type' in get:
                return public.returnMsg(False, '缺少参数type')
            if get.type not in type_list:
                return public.returnMsg(False, 'type参数错误')
            if get.type == 'ipv4':
                if not 'start_ip' in get or not 'end_ip' in get:
                    return public.returnMsg(False, '缺少参数')
                start_ip = self.ip2long(get.start_ip)
                end_ip = self.ip2long(get.end_ip)
                flag = False
                tmp = []
                data = self.__get_rule(get.rule)
                for i in data:
                    if i[0] == start_ip and i[1] == end_ip:
                        flag = True
                        tmp = i
                        break
                if flag:
                    if get.rule == 'ip_black':
                        public.ExecShell('echo "-,%s-%s" >/dev/shm/.bt_ip_filter' % (get.start_ip, get.end_ip))
                    data.remove(tmp)
                    self.__write_rule(get.rule, data)
                    return public.returnMsg(True, '删除成功')
                else:
                    return public.returnMsg(False, '删除失败、数据不存在')
            else:
                if not 'start_ip' in get:
                    return public.returnMsg(False, '缺少参数')
                data = self.__get_rule(get.rule + "_v6")
                flag = False
                tmp = []
                for i in data:
                    if i[0] == get.start_ip.strip():
                        flag = True
                        tmp = i
                        break
                if flag:
                    data.remove(tmp)
                    self.__write_rule(get.rule + "_v6", data)
                    return public.returnMsg(True, '删除成功')
                else:
                    return public.returnMsg(False, '删除失败、数据不存在')

        if get.rule == 'url_white' or get.rule == 'url_black':
            if not 'url' in get:
                return public.returnMsg(False, '缺少参数')
            data = self.__get_rule(get.rule)
            flag = False
            tmp = []
            if not get.url.strip() in data:
                return public.returnMsg(False, '删除失败、数据不存在')
            data.remove(get.url.strip())
            self.__write_rule(get.rule, data)
            return public.returnMsg(True, '删除成功')

        if get.rule == 'ua_black' or get.rule == 'ua_white':
            if not 'ua' in get:
                return public.returnMsg(False, '缺少ua参数')

            config = self.get_config(None)
            data = config[get.rule]
            if not get.ua in data:
                return public.returnMsg(False, '删除失败、数据不存在')
            data.remove(get.ua)
            config[get.rule] = data
            self.__write_config(config)
            return public.returnMsg(True, '删除成功')

    def edit_rule_check(self, get):
        if not 'rule' in get:
            return public.returnMsg(False, '参数错误')
        rule_list = ['ip_black', 'ip_white', 'url_white', 'url_black', 'ua_black', 'ua_white']
        if get.rule not in rule_list:
            return public.returnMsg(False, '参数错误')
        type_list = ['ipv4', 'ipv6']
        if get.rule == 'ip_black' or get.rule == 'ip_white':
            if not 'type' in get:
                return public.returnMsg(False, '缺少参数type')
            if get.type not in type_list:
                return public.returnMsg(False, 'type参数错误')
            if get.type == 'ipv4':
                if not 'start_ip' in get or not 'end_ip' in get or not 'ps' in get:
                    return public.returnMsg(False, '缺少参数')
                start_ip = self.ip2long(get.start_ip)
                end_ip = self.ip2long(get.end_ip)
                flag = False
                tmp = []
                data = self.__get_rule(get.rule)
                for i in data:
                    if len(i) < 3: i.append("")
                    if i[0] == start_ip and i[1] == end_ip:
                        flag = True
                        i[2] = get.ps
                        tmp = i
                        break
                if flag:

                    self.__write_rule(get.rule, data)
                    return public.returnMsg(True, '修改成功')
                else:
                    return public.returnMsg(False, '修改失败、数据不存在')
            else:
                if not 'start_ip' in get or not 'ps' in get:
                    return public.returnMsg(False, '缺少参数')
                data = self.__get_rule(get.rule + "_v6")
                flag = False
                tmp = []
                for i in data:
                    if i[0] == get.start_ip.strip():
                        flag = True
                        i[1] = get.ps
                        tmp = i
                        break
                if flag:
                    self.__write_rule(get.rule + "_v6", data)
                    return public.returnMsg(True, '修改成功')
                else:
                    return public.returnMsg(False, '修改失败、数据不存在')

    def import_rule_check(self, get):
        if not 'rule' in get:
            return public.returnMsg(False, '参数错误')
        rule_list = ['ip_black', 'ip_white', 'url_white', 'url_black', 'ua_black', 'ua_white']
        if get.rule not in rule_list:
            return public.returnMsg(False, '参数错误')
        type_list = ['ipv4', 'ipv6']
        if not 'pdata' in get:
            return public.returnMsg(False, '缺少参数pdata')

        bt_ip_filter = ""
        if get.rule == 'ip_black' or get.rule == 'ip_white':
            padata = get.pdata.strip().split()
            if not padata: return public.returnMsg(False, '数据格式不正确')
            iplist = self.get_cn_list(get.rule)
            ipv6_tmp = []
            for i in padata:
                ip_addr = i.split("/")[0]
                if self.ipv6_check(ip_addr):
                    ipv6_tmp.append(i)
                    continue
                elif re.search("\d+.\d+.\d+.\d+-\d+.\d+.\d+.\d+$", i):
                    ip = i.split('-')
                    ips = self.is_ip_zhuanhuang(ip[0], ip[1])
                    if not ips: continue
                    if ips in iplist: continue
                    iplist.insert(0, ips)

                elif re.search("\d+.\d+.\d+.\d+/\d+$", i):
                    ips = self.is_ip_zhuanhuang(i, ip_duan=True)
                    if not ips: continue
                    if ips in iplist: continue
                    iplist.insert(0, ips)

                elif re.search("\d+.\d+.\d+.\d+$", i):
                    ips = self.is_ip_zhuanhuang(i)
                    if not ips: continue
                    if ips in iplist: continue
                    iplist.insert(0, ips)
                if get.rule == 'ip_black':
                    ips = self.is_ip_zhuanhuang(i)
                    if not ips: continue
                    # 如果他在白名单中则不添加
                    ipn = [ips[0], ips[1]]
                    ip_white_rule = self.get_cn_list('ip_white')
                    if ipn in ip_white_rule: continue
                    # self.bt_ip_filter("+,%s-%s,86400" % (ips[0], ips[1]))
                    bt_ip_filter += "+,%s-%s,86400\n" % (ips[0], ips[1])
                if get.rule == "ip_white":
                    ips = self.is_ip_zhuanhuang(i)
                    # self.bt_ip_filter("-,%s-%s" % (ips[0], ips[1]))
                    bt_ip_filter += "-,%s-%s\n" % (ips[0], ips[1])
            if len(ipv6_tmp) > 0:
                ipv6 = self.__get_rule(get.rule + "_v6")
                # 添加没有的数据
                ipv6_flag = False
                for i in ipv6_tmp:
                    if i not in ipv6:
                        ipv6.insert(0, [i, ""])
                        ipv6_flag = True
                if ipv6_flag:
                    self.__write_rule(get.rule + "_v6", ipv6)
            self.__write_rule(get.rule, self.cn_to_ip(iplist))

            # 如果是IP黑名单
            if get.rule == 'ip_black':
                self.bt_ip_filter(bt_ip_filter)
            if get.rule == 'ip_white':
                self.bt_ip_filter(bt_ip_filter)
            return public.returnMsg(True, 'IP导入成功!')

        if get.rule == 'url_white' or get.rule == 'url_black':
            pdata = get.pdata.strip().split()
            iplist = self.__get_rule(get.rule)
            for ips in pdata:
                if ips in iplist: continue;
                iplist.insert(0, ips)
            self.__write_rule(get.rule, iplist)
            return public.returnMsg(True, 'URL导入成功!')
        if get.rule == 'ua_white' or get.rule == 'ua_black':
            pdata = get.pdata.strip().split("\n")
            config = self.get_config(None)
            iplist = config[get.rule]
            for ips in pdata:
                if len(ips) < 1: continue
                # 去掉首位空格
                ips = ips.strip()
                if not ips: continue
                if ips in iplist: continue;
                iplist.insert(0, ips)
            config[get.rule] = iplist
            self.__write_config(config)
            return public.returnMsg(True, 'UA导入成功!')

    def empty_rule_check(self, get):
        if not 'rule' in get:
            return public.returnMsg(False, '参数错误')
        rule_list = ['ip_black', 'ip_white', 'url_white', 'url_black', 'ua_black', 'ua_white']
        if get.rule not in rule_list:
            return public.returnMsg(False, '参数错误')
        if get.rule == 'ip_black' or get.rule == 'ip_white':
            if get.rule == 'ip_black':
                self.bt_ip_filter("-,0.0.0.0")
            self.__write_rule(get.rule, [])
            self.__write_rule(get.rule + "_v6", [])
            return public.returnMsg(True, '清空成功!')
        if get.rule == 'url_white' or get.rule == 'url_black':
            self.__write_rule(get.rule, [])
            return public.returnMsg(True, '清空成功!')
        if get.rule == 'ua_white' or get.rule == 'ua_black':
            config = self.get_config(None)
            config[get.rule] = []
            self.__write_config(config)
            return public.returnMsg(True, '清空成功!')

    def export_rule_check(self, get):
        if not 'rule' in get:
            return public.returnMsg(False, '参数错误')
        rule_list = ['ip_black', 'ip_white', 'url_white', 'url_black', 'ua_black', 'ua_white']
        if get.rule not in rule_list:
            return public.returnMsg(False, '参数错误')
        cvs_path = "/www/server/panel/data/" + get.rule + ".txt"

        tmp_info = ""
        if get.rule == 'ip_black' or get.rule == 'ip_white':
            data = self.get_ip_infos(get.rule)
            ipv6 = self.__get_rule(get.rule + '_v6')
            for i in ipv6:
                # 插入到第一个位置
                tmp_info += i[0] + "\n"
            for i in data:
                tmp_info += i[0] + "-" + i[1] + "\n"
            public.WriteFile(cvs_path, tmp_info)
            return public.returnMsg(True, '导出成功!')
        if get.rule == 'url_white' or get.rule == 'url_black':
            data = self.__get_rule(get.rule)
            for i in data:
                tmp_info += i + "\n"
            public.WriteFile(cvs_path, tmp_info)
            return public.returnMsg(True, '导出成功!')
        if get.rule == 'ua_white' or get.rule == 'ua_black':
            config = self.get_config(None)
            data = config[get.rule]
            for i in data:
                tmp_info += i + "\n"
            public.WriteFile(cvs_path, tmp_info)
            return public.returnMsg(True, '导出成功!')

    def open_rule_check(self, get):
        site_config = self.get_site_config(None)
        # 获取网站关闭的数量
        for i in site_config:
            if 'open' in site_config[i] and not site_config[i]['open']:
                site_config[i]['open'] = True
        self.__write_site_config(site_config)
        return public.returnMsg(True, '开启成功!')

    def get_autoevent(self, get):

        return public.returnMsg(True, {"list": [{"timestimp": 1722583029, "info": "自动化事件"}], "total": 1})

    def get_cms_rule_list(self, get):
        cms_path = "/www/server/btwaf/inc/cms/"
        # 遍历目录
        result = []
        cms_rule_open = False

        try:
            config = json.loads(public.readFile(self.__path + 'config.json'))
            if 'cms_rule_open' in config:
                cms_rule_open = config['cms_rule_open']
        except:
            pass

        if 'p' not in get:
            get.p = 1
        if 'limit' not in get:
            get.limit = 15
        if 'keyword' not in get:
            get.keyword = ""
        for i in os.listdir(cms_path):
            # 判断lua结尾的文件
            if not i.endswith(".json"): continue
            # 读取文件内容
            data = public.readFile(cms_path + i)
            if not data: continue
            try:
                data = json.loads(data)
            except:
                continue
            data["file"] = i
            result.append(data)
        # 通过id 排序
        result = sorted(result, key=lambda x: x["ruleid"])
        tmp_info = self.paginate_data(result, get.p, get.limit)
        tmp_info["cms_rule_open"] = cms_rule_open
        return public.returnMsg(True, tmp_info)

    def set_cms_rule_status(self, get):
        cms_path = "/www/server/btwaf/inc/cms/"
        if not "file" in get: return public.returnMsg(False, "参数错误")
        if not "status" in get: return public.returnMsg(False, "参数错误")
        file = cms_path + get.file
        if not os.path.exists(file): return public.returnMsg(False, "文件不存在")
        data = public.readFile(file)
        if not data: return public.returnMsg(False, "文件内容为空")
        try:
            data = json.loads(data)
        except:
            return public.returnMsg(False, "文件内容不是json格式")
        if get.status == "1" or get.status == 1:
            data["status"] = True
        else:
            data["status"] = False
        # data["status"]=get.status
        public.writeFile(file, json.dumps(data))

        # 重载nginx
        public.serviceReload()
        time.sleep(0.23)
        return public.returnMsg(True, "设置成功")

    def start_crawler(self, get):
        '''
            @name 开启爬虫防护
        :param get:
        :return:
        '''
        if not 'html' in get: return public.returnMsg(False, "参数错误、缺少html参数")
        if not 'site' in get: return public.returnMsg(False, "参数错误、缺少site参数")
        if not 'html_fast' in get: return public.returnMsg(False, "参数错误、缺少html_fast参数")
        if not 'js' in get: return public.returnMsg(False, "参数错误、缺少js参数")
        if not 'picture' in get: return public.returnMsg(False, "参数错误、缺少picture参数")
        if not 'picturenew' in get: return public.returnMsg(False, "参数错误、缺少picturenew参数")
        if not 'htmlnew' in get: return public.returnMsg(False, "参数错误、缺少htmlnew参数")
        if get.html == '1' or get.html == 1 or get.html == 'true' or get.html == True:
            get.html = True
        else:
            get.html = False

        if get.picture == '1' or get.picture == 1 or get.picture == 'true' or get.picture == True:
            get.picture = True
        else:
            get.picture = False
        if get.html_fast == '1' or get.html_fast == 1 or get.html_fast == 'true' or get.html_fast == True:
            get.html_fast = True
        else:
            get.html_fast = False

        if get.js == '1' or get.js == 1 or get.js == 'true' or get.js == True:
            get.js = True
        else:
            get.js = False

        # 处理json.loads picturenew
        try:
            picturenew = json.loads(get.picturenew)
        except:
            return public.returnMsg(False, "参数错误、picturenew参数不是json格式")

        try:
            htmlnew = json.loads(get.htmlnew)
        except:
            return public.returnMsg(False, "参数错误、htmlnew参数不是json格式")

        if 'type' not in htmlnew:
            return public.returnMsg(False, "参数错误、htmlnew参数中缺少type参数")
        if 'text' not in htmlnew:
            return public.returnMsg(False, "参数错误、htmlnew参数中缺少text参数")
        # type 只允许text 和default
        if htmlnew['type'] not in ['text', 'default']:
            return public.returnMsg(False, "参数错误、htmlnew参数中type参数只允许text和default")
        # 检查长度
        if len(htmlnew['text']) > 100:
            return public.returnMsg(False, "参数错误、htmlnew参数中text参数长度不能超过100")
        # 不允许出现XSS字符串
        if "<" in htmlnew['text'] or ">" in htmlnew['text'] or '"' in htmlnew['text']:
            return public.returnMsg(False, "网页自定义内容不能包含特殊字符 <  > \"")

        if 'type' not in picturenew:
            return public.returnMsg(False, "参数错误、picturenew参数中缺少type参数")
        if 'text' not in picturenew:
            return public.returnMsg(False, "参数错误、picturenew参数中缺少text参数")
        # type 只允许text 和default
        if picturenew['type'] not in ['text', 'default']:
            return public.returnMsg(False, "参数错误、picturenew参数中type参数只允许text和default")
        # 检查长度
        if len(picturenew['text']) > 100:
            return public.returnMsg(False, "参数错误、picturenew参数中text参数长度不能超过100")
            # 不允许出现XSS字符串
        if "<" in picturenew['text'] or ">" in picturenew['text'] or '"' in picturenew['text']:
            return public.returnMsg(False, "水印字符不能包含特殊字符 <  > \"")
        # 暂时不支持中文
        if re.search(u'[\u4e00-\u9fa5]', picturenew['text']):
            return public.returnMsg(False, "水印字符暂时不能包含中文、下版本将会支持")

        # 检查是否安装站点加速
        conf = public.readFile("/www/server/panel/vhost/nginx/btwaf.conf")
        if not conf:
            return public.returnMsg(False, '未找到配置文件!')
        if conf.find("#body_filter_by_lua_file") != -1:
            if not os.path.exists("/www/server/panel/vhost/nginx/speed.conf"):
                conf = conf.replace("#body_filter_by_lua_file", "body_filter_by_lua_file")
                public.writeFile("/www/server/panel/vhost/nginx/btwaf.conf", conf)
                public.serviceReload()
            else:
                return public.returnMsg(False, '清先卸载堡塔网站加速插件才能使用此功能!')
        # 检查伪静态是否包含!-e $request_filename
        if os.path.exists("/www/server/panel/vhost/rewrite/" + get.site.strip() + ".conf"):
            conf = public.readFile("/www/server/panel/vhost/rewrite/" + get.site.strip() + ".conf")
            if '!-e $request_filename' in conf:
                return public.returnMsg(False, '伪静态中包含!-e $request_filename 指令、需要删除后才能使用此功能!')

        # 读取网站配置
        site_config = self.get_site_config(None)
        if get.site.strip() not in site_config:
            return public.returnMsg(False, "网站不存在")
        if 'crawler' not in site_config[get.site.strip()]:
            site_config[get.site.strip()]['crawler'] = {
                'html': False,
                'html_fast': False,
                'js': False,
                'picture': False,
            }
            site_config[get.site.strip()]['crawler']['html'] = get.html
            site_config[get.site.strip()]['crawler']['html_fast'] = get.html_fast
            site_config[get.site.strip()]['crawler']['js'] = get.js
            site_config[get.site.strip()]['crawler']['picture'] = get.picture

            site_config[get.site.strip()]['crawler']['picturenew'] = picturenew
            site_config[get.site.strip()]['crawler']['htmlnew'] = htmlnew
        else:
            if 'html' not in site_config[get.site.strip()]['crawler']:
                site_config[get.site.strip()]['crawler']['html'] = get.html
            else:
                site_config[get.site.strip()]['crawler']['html'] = get.html
            if 'html_fast' not in site_config[get.site.strip()]['crawler']:
                site_config[get.site.strip()]['crawler']['html_fast'] = get.html_fast
            else:
                site_config[get.site.strip()]['crawler']['html_fast'] = get.html_fast
            if 'js' not in site_config[get.site.strip()]['crawler']:
                site_config[get.site.strip()]['crawler']['js'] = get.js
            else:
                site_config[get.site.strip()]['crawler']['js'] = get.js
            if 'picture' not in site_config[get.site.strip()]['crawler']:
                site_config[get.site.strip()]['crawler']['picture'] = get.picture
            else:
                site_config[get.site.strip()]['crawler']['picture'] = get.picture
            site_config[get.site.strip()]['crawler']['picturenew'] = picturenew
            site_config[get.site.strip()]['crawler']['htmlnew'] = htmlnew

        self.__write_site_config(site_config)
        return public.returnMsg(True, "设置成功")

    def add_temporary_ip(self, get):
        '''
        :param ip 临时IP
        timeout 临时时间
        :return:
        '''
        if not 'ip' in get: return public.returnMsg(False, '参数错误')
        if not 'timeout' in get: return public.returnMsg(False, '参数错误')
        # 判断IP是否合法
        ip = get.ip.strip()
        if not public.check_ip(ip): return public.returnMsg(False, 'IP地址不合法')
        # 时间
        timeout = int(get.timeout)
        if timeout < 1: return public.returnMsg(False, '时间不能小于1')

        try:
            data = json.loads(self.HttpGet('http://127.0.0.1/add_temporary_ip?ip=' + ip + '&timeout=' + str(timeout)))
            if data["status"]:
                self.bt_ip_filter("+,%s,%s" % (ip, timeout))
            return data
        except:
            return public.returnMsg(False, '添加失败')

    def del_temporary_ip(self, get):
        '''
                :param ip 临时IP
        '''
        if not 'ip' in get: return public.returnMsg(False, '参数错误')
        # 判断IP是否合法
        ip = get.ip.strip()
        if not public.check_ip(ip): return public.returnMsg(False, 'IP地址不合法')
        try:
            data = json.loads(self.HttpGet('http://127.0.0.1/remove_btwaf_drop_ip?ip=' + ip))
            self.bt_ip_filter("-,%s" % ip)
            return data
        except:
            return public.returnMsg(False, '删除失败')

    def start_limiting_timeout(self, get):
        '''
            @name 等待室功能
            open 代表开启
            qps  代表最低触发要求
            time  代表分钟   默认10分钟
            user  代表50个用户数
            type  代表默认使用带宝塔标识的页面   default 代表是默认。自定义使用text
            text   代表选择自定义的时候的文字。例如：网站在线人数过多，需排队
        '''

        site_config = self.get_site_config(None)
        if not 'site' in get: return public.returnMsg(False, '参数错误')
        if not 'limiting' in get: return public.returnMsg(False, '参数错误')

        try:
            limiting = json.loads(get.limiting)
        except:
            return public.returnMsg(False, '参数错误')
        if not 'open' in limiting:
            return public.returnMsg(False, '参数错误、缺少open参数')
        if 'open' in limiting:
            if not 'qps' in limiting: return public.returnMsg(False, '参数错误、缺少qps参数')
            if not 'time' in limiting: return public.returnMsg(False, '参数错误、缺少time参数')
            if not 'user' in limiting: return public.returnMsg(False, '参数错误、缺少user参数')
            if not 'identity' in limiting: return public.returnMsg(False, '参数错误、缺少identity参数')
            if not 'type' in limiting['identity']: return public.returnMsg(False, '参数错误、缺少type参数')
            if not 'text' in limiting['identity']: return public.returnMsg(False, '参数错误、缺少text参数')
            if limiting['qps'] == "null" or limiting['qps'] == "" or limiting['qps'] == None:
                limiting['qps'] = 1
            if limiting['time'] == "null" or limiting['time'] == "" or limiting['time'] == None:
                limiting['time'] = 10
            if limiting['user'] == "null" or limiting['user'] == "" or limiting['user'] == None:
                limiting['user'] = 50
            open = limiting['open']
            qps = int(limiting['qps'])
            time = int(limiting['time'])
            user = int(limiting['user'])
            type = limiting['identity']['type']
            text = limiting['identity']['text']
            if type not in ['default', 'text']: return public.returnMsg(False, '参数错误、type参数只允许default和text')
            if qps < 0: return public.returnMsg(False, 'qps不能小于0')
            if qps > 10000: return public.returnMsg(False, 'qps不能大于10000')
            if time < 1: return public.returnMsg(False, 'time不能小于1')
            if time > 60: return public.returnMsg(False, 'time不能大于60')
            if user < 1: return public.returnMsg(False, 'user不能小于1')
            if user > 10000: return public.returnMsg(False, 'user不能大于10000')
            if len(text) > 200: return public.returnMsg(False, 'text长度不能大于200')
            site = get.site.strip()
            # 伪静态是否包含!-e $request_filename
            if os.path.exists("/www/server/panel/vhost/rewrite/" + get.site.strip() + ".conf"):
                conf = public.readFile("/www/server/panel/vhost/rewrite/" + get.site.strip() + ".conf")
                if '!-e $request_filename' in conf:
                    return public.returnMsg(False, '伪静态中包含!-e $request_filename 指令、需要删除后才能使用此功能!')

            # 判断site_config 中是否存在
            if get.site.strip() not in site_config:
                return public.returnMsg(False, '网站不存在')
            if 'limiting' not in site_config[get.site.strip()]:
                site_config[site]['limiting'] = {}
                site_config[site]['limiting']['timeout'] = {"open": False, "time": 10, "user": 50, "qps": 1,
                                                            "type": "default", "text": ""}
            if open == '1' or open == 1 or open == 'true' or open == True:
                site_config[site]['limiting']['timeout']['open'] = True
            else:
                site_config[site]['limiting']['timeout']['open'] = False
            # 判断
            site_config[site]['limiting']['timeout']['qps'] = qps
            site_config[site]['limiting']['timeout']['time'] = time
            site_config[site]['limiting']['timeout']['user'] = user
            site_config[site]['limiting']['timeout']['identity'] = limiting['identity']

        self.__write_site_config(site_config)
        return public.returnMsg(True, '设置成功')

    def get_user_limit(self, get):
        '''
            @name 获取限流配置文件
        :return:
        '''

        path = "/www/server/btwaf/rule/limit.json"
        if not os.path.exists(path):
            return public.returnMsg(True, [])
        data = public.readFile(path)
        if not data:
            return public.returnMsg(True, [])
        try:
            data = json.loads(data)

            return public.returnMsg(True, data)
        except:
            return public.returnMsg(True, [])

    def add_user_limit(self, get):
        '''
            @name 添加自定义限流
        :param get:
        :return:
        '''
        if not 'data' in get: return public.returnMsg(False, '参数错误,缺少data参数')
        try:
            data = json.loads(get.data)
        except:
            return public.returnMsg(False, '参数错误,data参数不是json格式')
        if 'name' not in data: return public.returnMsg(False, '参数错误,缺少name参数')
        if 'site' not in data: return public.returnMsg(False, '参数错误,缺少site参数')
        if 'types' not in data: return public.returnMsg(False, '参数错误,缺少types参数')
        if 'url' not in data: return public.returnMsg(False, '参数错误,缺少url参数')
        if 'region' not in data: return public.returnMsg(False, '参数错误,缺少region参数')
        if 'condition' not in data: return public.returnMsg(False, '参数错误,缺少condition参数')
        if 'action' not in data: return public.returnMsg(False, '参数错误,缺少action参数')
        if data["action"] == "status_404" or data["action"] == "status_403" or data["action"] == "status_502" or data[
            "action"] == "status_503" or data["action"] == "drop":
            data["return"] = "html"
        if 'return' not in data: return public.returnMsg(False, '参数错误,缺少return参数')
        if len(data['region']) == 0: return public.returnMsg(False, '参数错误,触发条件不能为空,最少选择一个触发条件')
        # name 不允许存在XSS字符串
        if "<" in data['name'] or ">" in data['name'] or '"' in data['name']:
            return public.returnMsg(False, "名称不能包含特殊字符 <  > \"")
        types_list = ["all", "url"]
        if data['types'] not in types_list: return public.returnMsg(False, '参数错误,types参数只允许all和url')
        if data['types'] == 'all':
            data['url'] = '/'
        if data['types'] == 'url':
            if len(data['url']) == 0: return public.returnMsg(False, '参数错误,url不能为空')
            if data['url'] == ' ': return public.returnMsg(False, '参数错误,url不能为空')
            if data['url'] == '/': return public.returnMsg(False, '指定URL不能为 /  不然会全站都会限流')
            # 要以/开头
            if data['url'][0] != '/': return public.returnMsg(False, '参数错误,url必须以/开头')
        # data["region"]["req"] 不能小于1
        if 'req' in data['region']:
            # 判断是否为数字
            if data['region']['req'] < 1: return public.returnMsg(False, '每秒访问限制不能小于1')

        if 'count' in data['region']:
            if 'count' in data['region']['count']:
                if data['region']['count']['count'] < 20: return public.returnMsg(False, '时间访问限制次数不能小于20次')
                if data['region']['count']['time'] < 30: return public.returnMsg(False, '时间访问限制-时间不能小于30秒')

        # condition 只能是1 2 3
        if data['condition'] not in [1, 2, 3]: return public.returnMsg(False, '参数错误,condition参数错误')
        data["status"] = 403
        # action 只允许status  content  drop
        if data['action'] not in ['status', 'content', 'drop', "status_404", "status_403", "status_502",
                                  "status_503"]: return public.returnMsg(False, '参数错误,action参数错误')
        # return 只允许html  json 444
        if data['return'] not in ['html', 'json', '444']: return public.returnMsg(False, '参数错误,return参数错误')
        data["id"] = public.GetRandomString(12)

        # 读取文件
        path = "/www/server/btwaf/rule/limit.json"
        if not os.path.exists(path):
            data_list = []
        else:
            data_list = public.readFile(path)
            if not data_list:
                data_list = []
            else:
                try:
                    data_list = json.loads(data_list)
                except:
                    data_list = []

        site_list = data["site"].split(",")
        # 判断是否存在
        for i in data_list:
            if i['name'] == data['name']:
                return public.returnMsg(False, '名称已经存在')
            # 如果添加的网站为allsite 那么如果里面存在allsite 则判断是否为一样的URL
            if i['site'] == 'allsite' and 'allsite' in data['site']:
                # 如果URL一致的话。就不允许添加了
                if i["types"] == data["types"] and i["url"] == data["url"]:
                    return public.returnMsg(False, 'URL已经存在')
            # 如果是单个网站的话
            tmp = 0
            if len(site_list) == len(i['site']):
                # 判断site_list 是否在i['site']中
                for i2 in site_list:
                    if i2 in i['site']:
                        tmp += 1
                if tmp == len(site_list):
                    if i["types"] == data["types"] and i["url"] == data["url"]:
                        return public.returnMsg(False, 'URL已经存在')
        # 如果都不存在的话。那么就开始添加
        tmp_site = {}
        for i in site_list:
            tmp_site[i] = 1

        data["site"] = tmp_site
        data["open"] = True
        data_list.append(data)
        public.writeFile(path, json.dumps(data_list))
        public.serviceReload()
        return public.returnMsg(True, '添加成功')

    def edit_user_limit(self, get):
        if not 'data' in get: return public.returnMsg(False, '参数错误,缺少data参数')
        try:
            data = json.loads(get.data)
        except:
            return public.returnMsg(False, '参数错误,data参数不是json格式')

        if 'id' not in data: return public.returnMsg(False, '参数错误,缺少id参数')
        # 读取文件
        path = "/www/server/btwaf/rule/limit.json"
        if not os.path.exists(path):
            data_list = []
        else:
            data_list = public.readFile(path)
            if not data_list:
                data_list = []
            else:
                try:
                    data_list = json.loads(data_list)
                except:
                    data_list = []
        # 判断ID是否在data_list中
        flag = False
        for i in data_list:
            if i['id'] == data['id']:
                flag = True
                break
        if not flag: return public.returnMsg(False, 'ID不存在')
        if 'name' not in data: return public.returnMsg(False, '参数错误,缺少name参数')
        site_flag = False
        if 'site' not in data:
            site_flag = True
        if 'types' not in data: return public.returnMsg(False, '参数错误,缺少types参数')
        if 'url' not in data: return public.returnMsg(False, '参数错误,缺少url参数')
        if 'region' not in data: return public.returnMsg(False, '参数错误,缺少region参数')
        if 'condition' not in data: return public.returnMsg(False, '参数错误,缺少condition参数')
        if 'action' not in data: return public.returnMsg(False, '参数错误,缺少action参数')
        if data["action"] == "status_404" or data["action"] == "status_403" or data["action"] == "status_502" or data[
            "action"] == "status_503" or data["action"] == "drop":
            data["return"] = "html"
        if 'return' not in data: return public.returnMsg(False, '参数错误,缺少return参数')
        if len(data['region']) == 0: return public.returnMsg(False, '参数错误,触发条件不能为空,最少选择一个触发条件')
        # name 不允许存在XSS字符串
        if "<" in data['name'] or ">" in data['name'] or '"' in data['name']:
            return public.returnMsg(False, "名称不能包含特殊字符 <  > \"")
        types_list = ["all", "url"]
        if data['types'] not in types_list: return public.returnMsg(False, '参数错误,types参数只允许all和url')
        if data['types'] == 'all':
            data['url'] = '/'
        if data['types'] == 'url':
            if len(data['url']) == 0: return public.returnMsg(False, '参数错误,url不能为空')
            if data['url'] == ' ': return public.returnMsg(False, '参数错误,url不能为空')
            if data['url'] == '/': return public.returnMsg(False, '指定URL不能为 /  不然会全站都会限流')
            # 要以/开头
            if data['url'][0] != '/': return public.returnMsg(False, '参数错误,url必须以/开头')
        # data["region"]["req"] 不能小于1
        if 'req' in data['region']:
            # 判断是否为数字
            if data['region']['req'] < 1: return public.returnMsg(False, '每秒访问限制不能小于1')

        if 'count' in data['region']:
            if 'count' in data['region']['count']:
                if data['region']['count']['count'] < 20: return public.returnMsg(False, '时间访问限制次数不能小于20次')
                if data['region']['count']['time'] < 30: return public.returnMsg(False, '时间访问限制-时间不能小于30秒')

        # condition 只能是1 2 3
        if data['condition'] not in [1, 2, 3]: return public.returnMsg(False, '参数错误,condition参数错误')
        data["status"] = 403
        # action 只允许status  content  drop
        if data['action'] not in ['status', 'content', 'drop', "status_404", "status_403", "status_502",
                                  "status_503"]: return public.returnMsg(False, '参数错误,action参数错误')
        # return 只允许html  json 444
        if data['return'] not in ['html', 'json', '444']: return public.returnMsg(False, '参数错误,return参数错误')
        if not site_flag:
            site_list = data["site"].split(",")
        else:
            site_list = []
        # #判断是否存在
        for i in data_list:
            if site_flag: continue
            if i['id'] == data['id']: continue
            # 如果添加的网站为allsite 那么如果里面存在allsite 则判断是否为一样的URL
            if i['site'] == 'allsite' and 'allsite' in data['site']:
                # 如果URL一致的话。就不允许添加了
                if i["types"] == data["types"] and i["url"] == data["url"]:
                    return public.returnMsg(False, '此条规则已经存在')
            # 如果是单个网站的话
            tmp = 0
            if len(site_list) == len(i['site']):
                # 判断site_list 是否在i['site']中
                for i2 in site_list:
                    if i2 in i['site']:
                        tmp += 1
                if tmp == len(site_list):
                    if i["types"] == data["types"] and i["url"] == data["url"]:
                        return public.returnMsg(False, '此条规则已经存在')

        # 如果都不存在的话。修改
        tmp_site = {}
        if not site_flag:
            for i in site_list:
                tmp_site[i] = 1
            data["site"] = tmp_site

        for i in data_list:
            if i['id'] == data['id']:
                i['name'] = data['name']

                i['types'] = data['types']
                i['url'] = data['url']
                i['region'] = data['region']
                i['condition'] = data['condition']
                i['action'] = data['action']
                i['return'] = data['return']
                if not site_flag:
                    i['site'] = data['site']

        public.writeFile(path, json.dumps(data_list))
        public.serviceReload()
        return public.returnMsg(True, '修改成功')

    def del_user_limit(self, get):
        if not 'id' in get: return public.returnMsg(False, '参数错误,缺少id参数')
        # 读取文件
        path = "/www/server/btwaf/rule/limit.json"
        if not os.path.exists(path):
            data_list = []
        else:
            data_list = public.readFile(path)
            if not data_list:
                data_list = []
            else:
                try:
                    data_list = json.loads(data_list)
                except:
                    data_list = []
        # 判断ID是否在data_list中
        flag = False
        for v in data_list:
            if v['id'] == get.id:
                flag = True
                del data_list[data_list.index(v)]
                break
        if not flag: return public.returnMsg(False, 'ID不存在')
        # 保存文件
        public.writeFile(path, json.dumps(data_list))
        public.serviceReload()
        return public.returnMsg(True, '删除成功')

    def set_user_limit(self, get):
        if not 'id' in get: return public.returnMsg(False, '参数错误,缺少id参数')
        # 读取文件
        path = "/www/server/btwaf/rule/limit.json"
        if not os.path.exists(path):
            data_list = []
        else:
            data_list = public.readFile(path)
            if not data_list:
                data_list = []
            else:
                try:
                    data_list = json.loads(data_list)
                except:
                    data_list = []

        # 判断ID是否在data_list中
        flag = False
        for i in data_list:
            if i['id'] == get.id:
                flag = True
                if i['open'] or i['open'] == True:
                    i['open'] = False
                else:
                    i["open"] = True
                break
        if not flag: return public.returnMsg(False, 'ID不存在')
        # 保存文件
        public.writeFile(path, json.dumps(data_list))
        public.serviceReload()
        return public.returnMsg(True, '设置成功')

    # 启动告警
    def start_btwaf_send(self, get):
        if 'open' not in get: return public.returnMsg(False, '参数错误,缺少open参数')
        if 'attack' not in get: return public.returnMsg(False, '参数错误,缺少attack参数')
        if 'cc' not in get: return public.returnMsg(False, '参数错误,缺少cc参数')
        if 'send_type' not in get: return public.returnMsg(False, '参数错误,请传递告警方式')
        # if 'malicious_ip' not in get:return public.returnMsg(False,'参数错误,缺少malicious_ip参数')
        if 'customize' not in get: return public.returnMsg(False, '参数错误,缺少customize参数')
        if 'uablack' not in get: return public.returnMsg(False, '参数错误,缺少uablack参数')
        if 'upload' not in get: return public.returnMsg(False, '参数错误,缺少upload参数')
        if 'abroad' not in get: return public.returnMsg(False, '参数错误,缺少abroad参数')
        if get.send_type not in ['feishu', "dingding", "weixin"]:
            return public.returnMsg(False, '参数错误,告警方式只允许飞书 钉钉 企业微信')
        try:
            config = json.loads(public.readFile(self.__path + 'config.json'))
        except:
            return public.returnMsg(False, '读取配置文件失败')
        if 'msg_send' not in config:
            config['msg_send'] = {
                "open": False,
                "attack": True,
                "timeout": 120,
                "cc": True,
                "malicious_ip": False,
                "customize": False,
                "uablack": False,
                "upload": True,
                "abroad": False,
                "send_type": "",
                "reserve": ""
            }

        if get.open == 1 or get.open == '1' or get.open == True or get.open == 'true':
            open = True
        else:
            open = False

        if get.attack == 1 or get.attack == '1' or get.attack == True or get.attack == 'true':
            attack = True
        else:
            attack = False

        if get.cc == 1 or get.cc == '1' or get.cc == True or get.cc == 'true':
            cc = True
        else:
            cc = False

        # if get.malicious_ip==1 or get.malicious_ip=='1' or get.malicious_ip==True or get.malicious_ip=='true':
        #     malicious_ip=True
        # else:
        #     malicious_ip=False

        if get.customize == 1 or get.customize == '1' or get.customize == True or get.customize == 'true':
            customize = True
        else:
            customize = False

        if get.uablack == 1 or get.uablack == '1' or get.uablack == True or get.uablack == 'true':
            uablack = True
        else:
            uablack = False

        if get.upload == 1 or get.upload == '1' or get.upload == True or get.upload == 'true':
            upload = True
        else:
            upload = False

        if get.abroad == 1 or get.abroad == '1' or get.abroad == True or get.abroad == 'true':
            abroad = True
        else:
            abroad = False

        config['msg_send']['open'] = open
        config['msg_send']['attack'] = attack
        config['msg_send']['cc'] = cc
        config['msg_send']['send_type'] = get.send_type
        # config['msg_send']['malicious_ip']=malicious_ip
        config['msg_send']['customize'] = customize
        config['msg_send']['uablack'] = uablack
        config['msg_send']['upload'] = upload
        config['msg_send']['abroad'] = abroad

        public.writeFile(self.__path + 'config.json', json.dumps(config))
        return public.returnMsg(True, '设置成功')

    def get_msg_obj(self, msg):
        '''
            @name 获取消息对象
            @param msg str 消息内容
            @return dict
        '''
        # 判断/www/server/panel/class/msg 目录是否存在
        if not os.path.exists('/www/server/panel/class/msg'):
            return False, None
        obj = public.init_msg(msg)
        if obj:
            return True, obj
        return False, None

    def start_btwaf_send_test(self, get):
        if 'send_type' not in get: return public.returnMsg(False, '参数错误,请传递告警方式')
        if get.send_type not in ['feishu', "dingding", "weixin"]:
            return public.returnMsg(False, '参数错误,告警方式只允许飞书 钉钉 企业微信')
        msg = '''防火墙拦截记录告警模拟测试: 
拦截恶意攻击次数：20
攻击IP Top10：
  排名第1位:192.168.1.19 20次

告警时间：''' + "\n告警时间：" + time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())) + "\n（最多十分钟告警一次）"

        status, obj = self.get_msg_obj(get.send_type)
        if not status:
            return public.returnMsg(False, '实例化消息通道失败、请检查消息通道是否设置正确')

        return obj.send_msg(msg)

    def backiplist(self, get):
        '''

        :param get:   data=["192.168.10.1","192.168.100.1“]
        :return:
        '''
        if not 'data' in get: return public.returnMsg(False, '参数错误')
        try:
            data = json.loads(get.data)
        except:
            return public.returnMsg(False, '参数错误')
        # 去重
        data = list(set(data))
        data_v4 = self.get_ip_infos("ip_black")
        data_v6 = self.get_ip_infos("ip_black_v6")
        result = {}
        v4_flag = False
        v6_flag = False
        for i in data:
            if public.is_ipv4(i):
                ipn = [i, i]
                ipn2 = [i, i, "批量拉黑IP"]
                if ipn not in data_v4 and ipn2 not in data_v4:
                    ipn.append("批量拉黑IP")
                    data_v4.append(ipn)
                    v4_flag = True
                    result[i] = True
                else:
                    result[i] = False
            if public.is_ipv6(i):
                if i not in data_v6:
                    data_v6.append(i)
                    result[i] = True
                    v6_flag = False
                else:
                    result[i] = False
        if v4_flag:
            self.__write_rule("ip_black", self.cn_to_ip(data_v4))
        if v6_flag:
            self.__write_rule("ip_black_v6", data_v6)
        return result

    def get_malicious_ip_database(self, get):
        '''
            获取恶意IP库情报库
        :return:
        '''
        try:
            config = json.loads(public.readFile('/www/server/btwaf/config.json'))
        except:
            return False
        if not config["btmalibrary"]: return False
        try:
            self.__user = json.loads(public.ReadFile('/www/server/panel/data/userInfo.json'))
        except:
            self.__user = []
            pass
        if len(self.__user) == 0: return False
        path = "/www/server/btwaf/rule/btmalibrary_malicious.json"
        # 获取情报库
        url = "https://www.bt.cn/api/bt_waf/get_malicious"
        reulst_list = {}
        total = 0
        data = {"x_bt_token": "SksBSpWhJE7oVRixKCAZVEsN3QDnfQBU", "page": 1, "uid": self.__user["uid"],
                "access_key": self.__user["access_key"], "serverid": self.__user["serverid"]}
        import requests
        for i in range(1, 50):
            try:
                data["page"] = i
                result = requests.post(url, json=data, timeout=60).json()
                if result["success"]:
                    print("获取恶意IP库情报库成功")
                    total += len(result["res"]['list'])
                    # 并集合
                    reulst_list.update(result["res"]['list'])
                if total >= result["res"]['total']:
                    break
            except:
                break
        if len(reulst_list) >= 1:
            public.WriteFile(path, json.dumps(reulst_list))
            public.ServiceReload()

    def get_index_map(self, get):
        '''
        返回攻击地图
        '''
        infos = {"ip_address": "0.0.0.0", "latitude": 23.048884, "longitude": 113.760234}
        local_ip = self.get_server_longitude(get)
        if local_ip["status"]:
            infos["ip_address"] = local_ip["msg"]["ip_address"]
            # 如果是空的经纬度
            infos["latitude"] = local_ip["msg"]["latitude"]
            infos["longitude"] = local_ip["msg"]["longitude"]
            if infos["latitude"] == "":
                infos["latitude"] = 23.048884
            if infos["longitude"] == "":
                infos["longitude"] = 113.760234
            # 有字符串的情况下
            try:
                infos["latitude"] = float(infos["latitude"])
                infos["longitude"] = float(infos["longitude"])
            except:
                pass

        result = {"load_ip": infos, "attack_ip": []}
        ret = []
        tmp_list = {}
        if os.path.exists("/www/server/btwaf/totla_db/totla_db.db"):
            map_24_data = self.M2('totla_log').field(
                'ip,ip_country,ip_longitude,ip_latitude').where("time>=?", int(time.time()) - 86400 * 1).order(
                'id desc').limit("1000").select()
            if type(map_24_data) == str: return result
            # 过滤掉重复的
            for i in map_24_data:
                if i['ip_country'] == '内网地址': continue
                if not i["ip_latitude"]: continue
                if not i["ip_longitude"]: continue
                tmp = i["ip_latitude"] + i["ip_longitude"]
                if tmp in tmp_list: continue
                tmp_list[tmp] = 1
                if len(tmp_list) > 200: break
                try:
                    i["ip_latitude"] = float(i["ip_latitude"])
                    i["ip_longitude"] = float(i["ip_longitude"])
                    ret.append(i)
                except:
                    continue
        # 只取100个
        if len(ret) > 100:
            ret = ret[:100]
        result["attack_ip"] = ret
        return result

    def get_3d_status(self, get):
        config, site_config = self.get_config_overview()
        result = {}
        if '3D' not in config:
            config['3D'] = True
            # 写入配置文件
            public.writeFile(self.__path + 'config.json', json.dumps(config))
        result['3D'] = config['3D']
        return result
    
        
    def waf_large_screen_qps(self,get):
        '''
        WAF 大屏
        :param get:
        :return:
        '''
        result={}
        result["total"]=0
        result["malicious_total"]=0
        result["qps"] = 0
        result["waf_large_screen_text"]="宝塔WAF大屏"
        infos = self.HttpGetHttp('http://127.0.0.1/get_global_status')
        if len(infos) > 0:
            result['total'] = infos['today_request']
            result['qps'] = infos['qps']

        start_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
        s_time = start_time + ' 00:00:00'
        e_time = start_time + ' 23:59:59'
        start_timeStamp = int(time.mktime(time.strptime(s_time, '%Y-%m-%d %H:%M:%S')))
        end_timeStamp = int(time.mktime(time.strptime(e_time, '%Y-%m-%d %H:%M:%S')))
        last_count = self.M2('totla_log').field('time,ip,ip_country,ip_city,ip_subdivisions').where(
            "time>=? and time<=?", (start_timeStamp, end_timeStamp)).order(
            'id desc').count()
        if type(last_count) == int:
            result["malicious_total"] = last_count
        path='/www/server/panel/data/waf_large_screen_text.json'
        if os.path.exists(path):
            result["waf_large_screen_text"]=public.ReadFile(path)
        return result


    def get_server_longitude_country(self):
        try:
            if os.path.exists('/www/server/panel/data/get_geo2ip_map.json'):
                data = json.loads(public.ReadFile('/www/server/panel/data/get_geo2ip_map.json'))
                return data
            else:
                #
                import requests
                result = {}
                user_info = public.get_user_info()
                data = {}
                data['ip'] = user_info['address']
                data['uid'] = user_info['uid']
                data["serverid"] = user_info["serverid"]
                jsonda = requests.get("https://www.bt.cn/api/panel/get_ip_info", timeout=3).json()
                result['ip_address'] = data['ip']
                result['latitude'] = jsonda[data['ip']]['latitude']
                result['longitude'] = jsonda[data['ip']]['longitude']
                result['country'] = jsonda[data['ip']]['country']
                public.WriteFile('/www/server/panel/data/get_geo2ip_map.json', json.dumps(result))
                return result
        except:
            result = {}
            result['ip_address'] = "localhost"
            result['latitude'] = 39.929986
            result['longitude'] = 116.395645
            result["country"]="中国"
            public.WriteFile('/www/server/panel/data/get_geo2ip_map.json', json.dumps(result))
            return result


    def waf_large_screen_map(self,get):
        result = {}
        result["list"] = []   #攻击类型 饼图
        result["map"] = {}  # 攻击类型 饼图
        country=self.get_server_longitude_country()
        result["map"]["server"]=country
        result["map"]["list"]=[]
        result['attack_details']=[]
        start_time = time.strftime("%Y-%m-%d", time.localtime(time.time()))
        s_time = start_time + ' 00:00:00'
        e_time = start_time + ' 23:59:59'
        start_timeStamp = int(time.mktime(time.strptime(s_time, '%Y-%m-%d %H:%M:%S')))
        end_timeStamp = int(time.mktime(time.strptime(e_time, '%Y-%m-%d %H:%M:%S')))
        map_24_data = self.M2('totla_log').field(
            'time,server_name,filter_rule,ip,ip_country,ip_city,ip_subdivisions').order(
            'id desc').where("time>=? and time<=?", (start_timeStamp, end_timeStamp)).limit("10000").select()
        ip_map = {}
        tmp_rule = {}
        result2={}
        result2['map']={}
        result2['map']['info']={}
        result2['map']['top10_ip']={}
        result2['map']['country_ip_count']={}
        for i in map_24_data:
            if i['filter_rule'] in tmp_rule:
                tmp_rule[i['filter_rule']] += 1
            else:
                tmp_rule[i['filter_rule']] = 1
            if not ip_map.get(i['ip'] + "country"):
                ip_map[i['ip'] + "country"] = i['ip_country']
            if i['ip_country'] not in  result2['map']['country_ip_count']:
                result2['map']['country_ip_count'][i['ip_country']]={}
            if i['ip'] not in result2['map']['country_ip_count'][i['ip_country']]:
                result2['map']['country_ip_count'][i['ip_country']][i['ip']]=1

            if not ip_map.get(i['ip'] + "city"):
                ip_map[i['ip'] + "city"] = i['ip_city']
            if not ip_map.get(i['ip'] + "subdivisions"):
                ip_map[i['ip'] + "subdivisions"] = i['ip_subdivisions']
            if i['ip'] in result2['map']['top10_ip']:
                result2['map']['top10_ip'][i['ip']] = result2['map']['top10_ip'][i['ip']] + 1
            else:
                result2['map']['top10_ip'][i['ip']] = 1
            if i['ip_country'] == None: continue
            if i['ip_country'] in result2['map']['info']:
                result2['map']['info'][i['ip_country']] = result2['map']['info'][i['ip_country']] + 1
            else:
                result2['map']['info'][i['ip_country']] = 1
        for i in tmp_rule:
            result["list"].append({"name":i,"value":tmp_rule[i]})

        if len(result2['map']['info']):
            try:
                result2['map']['info'] = (sorted(result2['map']['info'].items(), key=lambda kv: (kv[1], kv[0])))[::-1]
            except:
                pass
        top10_ip = (sorted(result2['map']['top10_ip'].items(), key=lambda kv: (kv[1], kv[0])))
        #
        if len(top10_ip) > 40:
            result2['map']['top10_ip'] = top10_ip[::-1][:40]
        else:
            result2['map']['top10_ip'] = top10_ip[::-1]
        result_top_10 = []
        for i in result2['map']['top10_ip']:
            i2 = list(i)
            if ip_map.get(i[0] + "country"):
                ret = ip_map[i[0] + "country"]
                i2.append(ret)
            if ip_map.get(i[0] + "subdivisions"):
                ret = ip_map[i[0] + "subdivisions"]
                i2.append(ret)
            if ip_map.get(i[0] + "city"):
                ret = ip_map[i[0] + "city"]
                i2.append(ret)
            result_top_10.append(i2)
        result2['map']['top10_ip'] = result_top_10
        for i in result2['map']['info']:
            if i[0] == "未知位置": continue
            if i[0]=="内网地址":continue
            ip_count=0
            if i[0] in result2['map']['country_ip_count']:
                ip_count=len(result2['map']['country_ip_count'][i[0]])
            result["map"]["list"].append({"country": i[0], "attack_count": i[1],"ip_count":ip_count})
        for i in result2['map']['top10_ip']:
            if len(i) == 3:
                result['attack_details'].append({"ip": i[0], "count": i[1], "address": i[2]})
            elif len(i) == 4:
                if i[2] == i[3]:
                    address = i[2]
                else:
                    address = i[2] + "-" + i[3]
                result['attack_details'].append({"ip": i[0], "count": i[1], "address": address})
            elif len(i) == 5:
                if i[3] == i[4]:
                    address = i[3]
                else:
                    address = i[3] + "-" + i[4]
                result['attack_details'].append({"ip": i[0], "count": i[1], "address": address})
            else:
                result['attack_details'].append({"ip": i[0], "count": i[1], "address": " ".join(i[2:])})
        return result



    def update_large_screen_text(self,get):
        if 'text' not in get:
            return public.returnMsg(False, "缺少参数")
        text=get.text.strip()
        public.WriteFile('/www/server/panel/data/waf_large_screen_text.json', text)
        return public.returnMsg(True,"修改成功")