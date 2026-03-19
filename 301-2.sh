#!/bin/bash
#第二版，清空所有301重定向，重新全部设置301
BT_URL="面板地址:端口"
BT_KEY="apikey"
SLEEP_BETWEEN=1

gen_token() {
    local now; now=$(date +%s)
    local key_md5; key_md5=$(echo -n "$BT_KEY" | md5sum | awk '{print $1}')
    local token; token=$(echo -n "${now}${key_md5}" | md5sum | awk '{print $1}')
    echo "request_time=${now}&request_token=${token}"
}

bt_post() {
    local token; token=$(gen_token)
    curl -s -k -X POST "${BT_URL}$1" \
        -d "${token}&$2" \
        --connect-timeout 15 --max-time 90
}

get_sites() {
    bt_post "/data?action=getData" "table=sites&limit=200&tojs=1" \
    | python3 -c "
import sys, json
try:
    obj = json.loads(sys.stdin.read())
    for s in obj.get('data', []):
        sid, name = str(s.get('id','')), s.get('name','').strip()
        if sid and name: print(sid + '|' + name)
except: pass
"
}

get_site_domains() {
    bt_post "/data?action=getData" "table=domain&limit=100&tojs=1&search=$1" \
    | python3 -c "
import sys, json, re
try:
    obj = json.loads(sys.stdin.read())
    for item in obj.get('data', []):
        name = item.get('name','').strip().split(':')[0]
        if name and not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', name):
            print(name)
except: pass
"
}

create_redirect() {
    local site="$1"
    local bare="$2"
    local www="$3"
    
    python3 - "$site" "$bare" "$www" "$BT_URL" "$BT_KEY" <<'PYEOF'
import sys, json, ssl, urllib.request, urllib.parse, time, hashlib

site   = sys.argv[1]
bare   = sys.argv[2]
www    = sys.argv[3]
bt_url = sys.argv[4]
bt_key = sys.argv[5]

now     = str(int(time.time()))
key_md5 = hashlib.md5(bt_key.encode()).hexdigest()
token   = hashlib.md5((now + key_md5).encode()).hexdigest()

short_name = 'r_' + hashlib.md5(bare.encode()).hexdigest()[:8]

data = urllib.parse.urlencode({
    'request_time':   now,
    'request_token':  token,
    'sitename':       site,
    'redirectname':   short_name,
    'tourl':          'https://' + www,
    'redirectdomain': json.dumps([bare]),
    'redirectpath':   '/',
    'redirecttype':   '301',
    'type':           '1',
    'domainorpath':   'domain',
    'holdpath':       '1'
}).encode()

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

req = urllib.request.Request(
    bt_url + '/site?action=CreateRedirect',
    data=data,
    headers={'Content-Type': 'application/x-www-form-urlencoded'},
)
try:
    with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
        print(r.read().decode())
except Exception as e:
    print(json.dumps({'status': False, 'msg': str(e)}))
PYEOF
}

for cmd in curl python3 md5sum; do
    command -v "$cmd" &>/dev/null || { echo "缺少依赖：$cmd"; exit 1; }
done

echo "======================================"
echo "  宝塔面板批量设置"
echo "======================================"

echo "正在清理"
python3 -c "
import os, json

db_path = '/www/server/panel/data/redirect.conf'
if os.path.exists(db_path):
    try:
        with open(db_path, 'r') as f:
            data = json.loads(f.read())
        new_data = []
        for r in data:
            name = r.get('redirectname', '')
            domains = r.get('redirectdomain', [])
            
           
            if name.startswith('r_') or name.startswith('to_www_') or not domains:
                continue
            new_data.append(r)
            
        with open(db_path, 'w') as f:
            json.dump(new_data, f)
    except:
        pass

os.system('rm -f /www/server/panel/vhost/apache/extension/*/r_*.conf')
os.system('rm -f /www/server/panel/vhost/apache/extension/*/to_www*.conf')
"
bt reload &>/dev/null
apachectl graceful &>/dev/null
echo "等待10秒"
sleep 10
echo "清理完成"
echo "--------------------------------------"

mapfile -t SITES < <(get_sites)
[ ${#SITES[@]} -eq 0 ] && { echo "未获取到站点，请检查 BT_KEY / BT_URL"; exit 1; }

SUCCESS=0; SKIP=0; FAIL=0; IDX=0
FAIL_DETAILS=()

for SITE_INFO in "${SITES[@]}"; do
    [ -z "$SITE_INFO" ] && continue
    ((IDX++))
    SITE_ID="${SITE_INFO%%|*}"
    SITE="${SITE_INFO##*|}"

    echo "[${IDX}/${#SITES[@]}] 处理站点: ${SITE}"

    mapfile -t ALL_DOMAINS < <(get_site_domains "$SITE_ID")
    
    BARE_DOMAINS=()
    WWW_DOMAINS=()

    for DOMAIN in "${ALL_DOMAINS[@]}"; do
        [ -z "$DOMAIN" ] && continue
        if echo "$DOMAIN" | grep -qE "^www\."; then
            WWW_DOMAINS+=("$DOMAIN")
        elif ! echo "$DOMAIN" | grep -qE "^www\." && ! echo "$DOMAIN" | grep -qE "^[a-f0-9]{8}\."; then
            BARE_DOMAINS+=("$DOMAIN")
        fi
    done

    if [ ${#BARE_DOMAINS[@]} -eq 0 ]; then
        echo "状态: 跳过 (未找到裸域)"
        echo ""
        ((SKIP++))
        continue
    fi

    if [ ${#WWW_DOMAINS[@]} -eq 0 ]; then
        echo "状态: 失败 (未找到 www 域名)"
        echo ""
        FAIL_DETAILS+=("${SITE}|未找到 www 域名，无法确定跳转目标")
        ((FAIL++))
        continue
    fi

    for i in "${!BARE_DOMAINS[@]}"; do
        BARE="${BARE_DOMAINS[$i]}"
        
        WWW="www.${BARE}"
        FOUND=0
        for WD in "${WWW_DOMAINS[@]}"; do
            [ "$WD" = "$WWW" ] && FOUND=1 && break
        done
        [ "$FOUND" -eq 0 ] && WWW="${WWW_DOMAINS[0]}"

        echo "裸域: ${BARE}"
        echo "目标: https://${WWW}"

     
        RESULT=$(create_redirect "$SITE" "$BARE" "$WWW")
        STATUS=$(echo "$RESULT" | python3 -c "
import sys, json
try:
    obj = json.loads(sys.stdin.read())
    print('ok' if obj.get('status') else 'fail:' + str(obj.get('msg','')))
except: print('fail:parse error')
")

        if [[ "$STATUS" == "ok" ]]; then
            echo "状态: 设置成功"
            echo ""
            ((SUCCESS++))
        else
            echo "状态: 失败 (${STATUS#fail:})"
            echo ""
            FAIL_DETAILS+=("${SITE}|设置失败 (${STATUS#fail:})")
            ((FAIL++))
        fi
        
        sleep "$SLEEP_BETWEEN"
    done
done

echo "--------------------------------------"
echo ""
echo "======================================"
echo "               执行总结"
echo "======================================"
echo "✅ 成功: ${SUCCESS}    ⏭️ 跳过: ${SKIP}    ❌ 失败: ${FAIL}"

if [ "$FAIL" -gt 0 ] || [ "$SKIP" -gt 0 ]; then
    echo ""
    echo "【失败/跳过详情清单】"
    err_idx=1
    for detail in "${FAIL_DETAILS[@]}"; do
        fail_site="${detail%%|*}"
        fail_reason="${detail##*|}"
        echo "${err_idx}. ${fail_site}"
        echo "   原因: ${fail_reason}"
        ((err_idx++))
    done
fi
echo "======================================"

[ "$FAIL" -gt 0 ] && exit 1 || exit 0
