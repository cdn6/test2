#!/bin/bash
#自动批量申请let证书并部署脚本
BT_URL="你的面板地址:端口"
BT_KEY="你的面板apikey白名单添加本机ip和127.0.0.1"
AUTH_TYPE="http"
SLEEP_BETWEEN=5

TMP_CERT=$(mktemp)
TMP_KEY=$(mktemp)
trap 'rm -f "$TMP_CERT" "$TMP_KEY"' EXIT

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
    bt_post "/data?action=getData" "table=sites&limit=1000&tojs=1" \
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

check_cert_deployed() {
    local site="$1"
    local token_data; token_data=$(gen_token)

    curl -s -k -X POST "${BT_URL}/site?action=GetSSL" \
        -d "${token_data}&siteName=${site}" \
        --connect-timeout 15 | python3 -c "
import sys, json
try:
    obj = json.loads(sys.stdin.read())
    if obj.get('status') is True:
        print('deployed')
    else:
        print('none')
except:
    print('error')
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

apply_cert() {
    local site_id="$1"; shift
    local domains_json; domains_json=$(python3 -c "
import json, sys
print(json.dumps(sys.argv[1:]))" "$@")
    local encoded; encoded=$(python3 -c "
import urllib.parse, sys
print(urllib.parse.quote(sys.argv[1], safe=''))" "$domains_json")
    bt_post "/acme" \
        "action=apply_cert_api&domains=${encoded}&auth_type=${AUTH_TYPE}&auth_to=${site_id}&auto_wildcard=0&id=${site_id}"
}

deploy_cert() {
    local site="$1"
    python3 - "$site" "$TMP_CERT" "$TMP_KEY" "$BT_URL" "$BT_KEY" <<'PYEOF'
import sys, json, ssl, urllib.request, urllib.parse, time, hashlib

site     = sys.argv[1]
cert_file = sys.argv[2]
key_file  = sys.argv[3]
bt_url   = sys.argv[4]
bt_key   = sys.argv[5]

cert = open(cert_file).read().strip()
key  = open(key_file).read().strip()

now      = str(int(time.time()))
key_md5  = hashlib.md5(bt_key.encode()).hexdigest()
token    = hashlib.md5((now + key_md5).encode()).hexdigest()

data = urllib.parse.urlencode({
    'request_time':  now,
    'request_token': token,
    'siteName':      site,
    'csr':           cert,
    'key':           key,
}).encode()

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

req = urllib.request.Request(
    bt_url + '/site?action=SetSSL',
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

mapfile -t SITES < <(get_sites)
[ ${#SITES[@]} -eq 0 ] && { echo "未获取到站点，请检查 BT_KEY / BT_URL"; exit 1; }

echo "======================================"
echo "  宝塔面板批量申请与部署"
echo "======================================"
echo "共找到 ${#SITES[@]} 个站点，开始执行..."
echo ""
echo "--------------------------------------"

SUCCESS=0; SKIP=0; FAIL=0; IDX=0
FAIL_DETAILS=()

for SITE_INFO in "${SITES[@]}"; do
    [ -z "$SITE_INFO" ] && continue
    ((IDX++))
    SITE_ID="${SITE_INFO%%|*}"
    SITE="${SITE_INFO##*|}"

    echo "[${IDX}/${#SITES[@]}] 处理站点: ${SITE}"

    DEPLOY_STATUS=$(check_cert_deployed "$SITE")
    if [ "$DEPLOY_STATUS" == "deployed" ]; then
        echo "状态: 检测到已部署证书，直接跳过。"
        echo ""
        ((SKIP++))
        continue
    fi

    mapfile -t DOMAINS < <(get_site_domains "$SITE_ID")
    if [ ${#DOMAINS[@]} -eq 0 ]; then
        echo "状态: 失败 (无可用域名)"
        echo ""
        FAIL_DETAILS+=("${SITE}|状态: 失败 (无可用域名)")
        ((FAIL++))
        continue
    fi
    
    DOMAIN_STR=$(IFS=', '; echo "${DOMAINS[*]}")
    echo "域名: ${DOMAIN_STR}"

    for RETRY in 1 2 3; do
        RESULT=$(apply_cert "$SITE_ID" "${DOMAINS[@]}")
        STATUS=$(echo "$RESULT" | python3 -c "
import sys, json
try:
    obj = json.loads(sys.stdin.read())
    print('ok' if obj.get('status') else 'fail:' + str(obj.get('msg','')))
except: print('fail:parse error')
")
        [[ "$STATUS" == "ok" ]] && break
        if echo "$STATUS" | grep -q "orderNotReady\|order"; then
            sleep 10
        else
            break
        fi
    done

    if [[ "$STATUS" != "ok" ]]; then
        echo "申请: 申请失败 (${STATUS#fail:})"
        echo "部署: 未执行"
        echo ""
        FAIL_DETAILS+=("${SITE}|申请失败 (${STATUS#fail:})")
        ((FAIL++))
        sleep "$SLEEP_BETWEEN"
        continue
    fi

    echo "$RESULT" | python3 -c "
import sys, json
obj = json.loads(sys.stdin.read())
open('$TMP_CERT', 'w').write((obj.get('cert','') + obj.get('root','')).strip())
open('$TMP_KEY',  'w').write(obj.get('private_key','').strip())
"
    EXPIRE=$(echo "$RESULT" | python3 -c "
import sys, json, datetime
try:
    t = json.loads(sys.stdin.read()).get('cert_timeout', 0)
    print(datetime.datetime.fromtimestamp(t).strftime('%Y-%m-%d') if t else '')
except: print('')
")

    if [ ! -s "$TMP_CERT" ] || [ ! -s "$TMP_KEY" ]; then
        echo "申请: 申请成功 (证书内容为空)"
        echo "部署: 未执行"
        echo ""
        FAIL_DETAILS+=("${SITE}|申请成功，但证书内容提取失败")
        ((FAIL++))
        sleep "$SLEEP_BETWEEN"
        continue
    fi

    echo "申请: 申请成功 (到期: ${EXPIRE})"

    DEPLOY_RESULT=$(deploy_cert "$SITE")
    DEPLOY_STATUS=$(echo "$DEPLOY_RESULT" | python3 -c "
import sys, json
try:
    obj = json.loads(sys.stdin.read())
    print('ok' if obj.get('status') else 'fail:' + str(obj.get('msg','')))
except: print('fail:parse error')
")

    if [[ "$DEPLOY_STATUS" == "ok" ]]; then
        echo "部署: 部署成功"
        echo ""
        ((SUCCESS++))
    else
        echo "部署: 部署失败 (${DEPLOY_STATUS#fail:})"
        echo ""
        FAIL_DETAILS+=("${SITE}|部署失败 (${DEPLOY_STATUS#fail:})")
        ((FAIL++))
    fi

    sleep "$SLEEP_BETWEEN"
done

echo "--------------------------------------"
echo ""
echo "======================================"
echo "               执行总结"
echo "======================================"
echo "✅ 成功: ${SUCCESS}    ⏭️ 跳过: ${SKIP}    ❌ 失败: ${FAIL}"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "【失败详情清单】"
    err_idx=1
    for detail in "${FAIL_DETAILS[@]}"; do
        fail_site="${detail%%|*}"
        fail_reason="${detail##*|}"
        echo "${err_idx}. ${fail_site}"
        echo "   原因: ${fail_reason}"
        ((err_idx++))
    done
fi
echo ""
echo "======================================"

[ "$FAIL" -gt 0 ] && exit 1 || exit 0
