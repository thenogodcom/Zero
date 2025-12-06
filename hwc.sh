#!/usr/bin/env bash
#
# Description: Ultimate All-in-One Manager for Caddy, Sing-box (as WARP), Hysteria & AdGuard Home.
# Author: Your Name (Inspired by P-TERX, Refactored for Sing-box)
# Version: 7.5.0 (Sing-box Auto-Remediation Edition)

# --- 第1節：全域設定與定義 ---

# 顏色定義，用於日誌輸出
FontColor_Red="\033[31m"; FontColor_Green="\033[32m"; FontColor_Yellow="\033[33m"
FontColor_Purple="\033[35m"; FontColor_Suffix="\033[0m"

# 標準化日誌函數
log() {
    local LEVEL="$1"; local MSG="$2"
    case "${LEVEL}" in
        INFO)  local LEVEL="[${FontColor_Green}資訊${FontColor_Suffix}]";;
        WARN)  local LEVEL="[${FontColor_Yellow}警告${FontColor_Suffix}]";;
        ERROR) local LEVEL="[${FontColor_Red}錯誤${FontColor_Suffix}]";;
    esac
    echo -e "${LEVEL} ${MSG}"
}

# 固定的應用程式基礎目錄
APP_BASE_DIR="/root/hwc"

# 組件定義
CADDY_CONTAINER_NAME="caddy-manager"; CADDY_IMAGE_NAME="caddy:latest"; CADDY_CONFIG_DIR="${APP_BASE_DIR}/caddy"; CADDY_CONFIG_FILE="${CADDY_CONFIG_DIR}/Caddyfile"; CADDY_DATA_VOLUME="hwc_caddy_data"
# --- WARP 組件已替換為 Sing-box ---
SB_WARP_CONTAINER_NAME="warp-gateway"; SB_WARP_IMAGE_NAME="ghcr.io/sagernet/sing-box:latest"; SB_WARP_CONFIG_DIR="${APP_BASE_DIR}/singbox-warp"; SB_WARP_CONFIG_FILE="${SB_WARP_CONFIG_DIR}/config.json"
# -----------------------------------
HYSTERIA_CONTAINER_NAME="hysteria-server"; HYSTERIA_IMAGE_NAME="tobyxdd/hysteria"; HYSTERIA_CONFIG_DIR="${APP_BASE_DIR}/hysteria"; HYSTERIA_CONFIG_FILE="${HYSTERIA_CONFIG_DIR}/config.yaml"
ADGUARD_CONTAINER_NAME="adguard-home"; ADGUARD_IMAGE_NAME="adguard/adguardhome:edge"; ADGUARD_CONFIG_DIR="${APP_BASE_DIR}/adguard/conf"; ADGUARD_WORK_DIR="${APP_BASE_DIR}/adguard/work"

SHARED_NETWORK_NAME="hwc-proxy-net"
SCRIPT_URL="https://raw.githubusercontent.com/thenogodcom/warp/main/hwc.sh"; SHORTCUT_PATH="/usr/local/bin/hwc"
declare -A CONTAINER_STATUSES

# --- 第2節：所有函數定義 ---

# 檢查並安裝必要工具 (curl, jq)
check_dependencies() {
    for cmd in curl jq; do
        if ! command -v $cmd &>/dev/null; then
            log WARN "'$cmd' 未安裝，正在嘗試自動安裝..."
            if command -v apt-get &>/dev/null; then apt-get update && apt-get install -y --no-install-recommends $cmd;
            elif command -v yum &>/dev/null; then yum install -y $cmd;
            elif command -v dnf &>/dev/null; then dnf install -y $cmd;
            else log ERROR "無法自動安裝 '$cmd'。請手動安裝後重試。"; exit 1; fi
        fi
    done
}

# 自我安裝快捷命令
self_install() {
    local running_script_path
    if [[ -f "$0" ]]; then running_script_path=$(readlink -f "$0"); fi
    if [ "$running_script_path" = "$SHORTCUT_PATH" ]; then return 0; fi

    log INFO "首次運行設定：正在安裝 'hwc' 快捷命令以便日後存取..."
    check_dependencies
    
    if cp "$0" "${SHORTCUT_PATH}"; then
        chmod +x "${SHORTCUT_PATH}"
        log INFO "快捷命令 'hwc' 安裝成功。正在從新位置重新啟動..."
        exec "${SHORTCUT_PATH}" "$@"
    else
        log ERROR "無法安裝 'hwc' 快捷命令至 ${SHORTCUT_PATH}。"; sleep 3
    fi
}

# 驗證函數
validate_domain() { [[ ! "$1" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]] && { log ERROR "域名格式無效: $1"; return 1; }; return 0; }
validate_email() { [[ ! "$1" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] && { log ERROR "郵箱格式無效: $1"; return 1; }; return 0; }
validate_backend_service() { [[ ! "$1" =~ ^[a-zA-Z0-9\._-]+:[0-9]+$ ]] && { log ERROR "後端服務地址格式無效 (應為 hostname:port): $1"; return 1; }; return 0; }

# 檢測證書路徑
detect_cert_path() {
    local domain="$1"; local base_path="/data/caddy/certificates"
    if container_exists "$CADDY_CONTAINER_NAME"; then
        for ca_dir in "acme-v02.api.letsencrypt.org-directory" "acme.zerossl.com-v2-DV90"; do
            if docker exec "$CADDY_CONTAINER_NAME" [ -f "$base_path/$ca_dir/$domain/$domain.crt" ] 2>/dev/null; then
                echo "$base_path/$ca_dir/$domain/$domain.crt|$base_path/$ca_dir/$domain/$domain.key"; return 0
            fi
        done
    fi
    echo "$base_path/acme-v02.api.letsencrypt.org-directory/$domain/$domain.crt|$base_path/acme-v02.api.letsencrypt.org-directory/$domain/$domain.key"
}

# 生成隨機密碼
generate_random_password() {
    tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 16
}

# Docker 環境檢查與安裝
install_docker() {
    log INFO "偵測到 Docker 未安裝，正在使用官方通用腳本安裝..."
    if ! curl -fsSL https://get.docker.com | sh; then
        log ERROR "Docker 安裝失敗。"; exit 1
    fi
    systemctl enable --now docker
    log INFO "Docker 安裝成功並已啟動。"
}
check_docker() {
    if ! command -v docker &>/dev/null; then install_docker; fi
    if ! docker info >/dev/null 2>&1; then
        log WARN "Docker 服務未運行，正在嘗試啟動..."; systemctl start docker; sleep 3
        if ! docker info >/dev/null 2>&1; then log ERROR "無法啟動 Docker 服務。"; exit 1; fi
        log INFO "Docker 服務已成功啟動。"
    fi
}

# 常用函數
check_root() { if [ "$EUID" -ne 0 ]; then log ERROR "此腳本必須以 root 身份運行。"; exit 1; fi; }
check_editor() { for e in nano vi vim; do if command -v $e &>/dev/null; then EDITOR=$e; return 0; fi; done; return 1; }
container_exists() { docker ps -a --format '{{.Names}}' | grep -q "^${1}$"; }
press_any_key() { echo ""; read -p "按 Enter 鍵返回..." < /dev/tty; }

# --- 各組件配置生成函數 ---
generate_caddy_config() {
    local primary_domain="$1"; local email="$2"; local log_mode="$3"; local proxy_domain="$4"; local backend_service="$5"
    mkdir -p "${CADDY_CONFIG_DIR}"
    local log_block=""
    if [[ ! "$log_mode" =~ ^[yY]$ ]]; then log_block="    log {\n        output stderr\n        level  ERROR\n    }"; fi
    cat > "${CADDY_CONFIG_FILE}" <<EOF
{
    email ${email}
${log_block}
    servers { protocols h1 h2 }
}
${primary_domain} {
    reverse_proxy ${backend_service} {
        header_up Host {host}
        header_up X-Real-IP {remote}
        header_up X-Forwarded-For {remote}
        header_up X-Forwarded-Proto {scheme}
    }
}
EOF
    if [ -n "$proxy_domain" ]; then
        cat >> "${CADDY_CONFIG_FILE}" <<EOF
${proxy_domain} {
    reverse_proxy https://${primary_domain} {
        header_up Host {upstream_hostport}
    }
}
EOF
    fi
    log INFO "Caddyfile 已為域名 ${primary_domain} 建立。"
}
generate_singbox_config() {
    local private_key="$1"; local ipv6_address="$2"
    mkdir -p "${SB_WARP_CONFIG_DIR}"
    cat > "${SB_WARP_CONFIG_FILE}" <<EOF
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [{
      "type": "socks", "tag": "socks-in", "listen": "::", "listen_port": 8008,
      "sniff": true, "sniff_override_destination": true
  }],
  "outbounds": [{
      "type": "wireguard", "tag": "warp-out", "server": "162.159.192.1", "server_port": 2408,
      "local_address": [ "172.16.0.2/32", "${ipv6_address}" ],
      "private_key": "${private_key}",
      "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "mtu": 1280
  }],
  "route": { "rules": [{ "inbound": "socks-in", "outbound": "warp-out" }], "auto_detect_interface": true }
}
EOF
    log INFO "Sing-box (WARP) 設定檔已生成。"
}
generate_hysteria_config() {
    local domain="$1"; local password="$2"; local log_mode="$3"
    mkdir -p "${HYSTERIA_CONFIG_DIR}"
    local log_level="error"; if [[ "$log_mode" =~ ^[yY]$ ]]; then log_level="info"; fi
    local cert_path_info=$(detect_cert_path "$domain"); local cert_path="${cert_path_info%%|*}"; local key_path="${cert_path_info##*|}"
    
    cat > "${HYSTERIA_CONFIG_FILE}" <<EOF
listen: :443
logLevel: ${log_level}
resolvePreference: IPv4
dns:
  server: udp://${ADGUARD_CONTAINER_NAME}:53
  timeout: 4s
auth:
  type: password
  password: ${password}
tls:
  cert: ${cert_path}
  key: ${key_path}
outbounds:
  - name: direct
    type: direct
  - name: warp
    type: socks5
    socks5:
      addr: ${SB_WARP_CONTAINER_NAME}:8008
acl:
  inline:
    - direct(geosite:private)
    - direct(geosite:cn)
    - direct(suffix:youtube.com)
    - direct(suffix:youtu.be)
    - direct(suffix:ytimg.com)
    - direct(suffix:googlevideo.com)
    - direct(suffix:github.com)
    - direct(suffix:github.io)
    - direct(suffix:githubassets.com)
    - direct(suffix:githubusercontent.com)
    - warp(all)
EOF
    log INFO "Hysteria 設定檔已建立，日誌級別 '${log_level}'。"
}

# --- Sing-box (WARP) 核心輔助函數 ---
generate_warp_account_data() {
    log INFO "正在使用 wgcf 註冊新的 WARP 帳戶..."
    local arch; case $(uname -m) in x86_64) arch="amd64";; aarch64) arch="arm64";; *) log ERROR "不支援的CPU架構: $(uname -m)"; return 1;; esac
    mkdir -p "${SB_WARP_CONFIG_DIR}"; rm -f "${SB_WARP_CONFIG_DIR}/wgcf"*
    local cmd="apk add --no-cache curl jq && url=\$(curl -s https://api.github.com/repos/ViRb3/wgcf/releases/latest | jq -r \".assets[]|select(.name|contains(\\\"linux_${arch}\\\"))|.browser_download_url\") && curl -L -o wgcf \$url && chmod +x wgcf && ./wgcf register --accept-tos && ./wgcf generate"
    if docker run --rm -v "${SB_WARP_CONFIG_DIR}:/data" -w /data alpine:latest sh -c "$cmd" >/dev/null 2>&1; then
        log INFO "WARP 帳戶註冊成功。"; return 0
    else
        log ERROR "WARP 註冊失敗 (可能是 Cloudflare API 限制)。"; return 1
    fi
}
update_warp_keys_interactive() {
    if [ ! -f "$SB_WARP_CONFIG_FILE" ]; then log ERROR "設定檔不存在。"; return 1; fi
    echo -e "\n${FontColor_Yellow}--- 手動更換 WARP 金鑰 ---${FontColor_Suffix}"
    read -p "請輸入 PrivateKey: " pk < /dev/tty
    read -p "請輸入 Address (IPv6 地址, e.g., 2606:4700...): " ip6_addr < /dev/tty
    if [ -z "$pk" ] || [ -z "$ip6_addr" ]; then log ERROR "輸入格式錯誤。"; return 1; fi
    
    jq --arg pk "$pk" --arg ip6 "${ip6_addr}/128" '.outbounds[0].private_key = $pk | .outbounds[0].local_address[1] = $ip6' "$SB_WARP_CONFIG_FILE" > "${SB_WARP_CONFIG_FILE}.tmp" && mv "${SB_WARP_CONFIG_FILE}.tmp" "$SB_WARP_CONFIG_FILE"
    if [ $? -eq 0 ]; then log INFO "金鑰更新成功，正在重啟 Sing-box..."; docker restart "$SB_WARP_CONTAINER_NAME"; else log ERROR "金鑰更新失敗。"; fi
}

# --- 各組件管理函數 ---
manage_caddy() {
    if ! container_exists "$CADDY_CONTAINER_NAME"; then
        while true; do
            clear; log INFO "--- 管理 Caddy (未安裝) ---"; echo " 1. 安裝 Caddy (SSL證書)"; echo " 0. 返回主選單"
            read -p "請輸入選項: " choice < /dev/tty
            case "$choice" in
                1)
                    log INFO "--- 正在安裝 Caddy ---"
                    while true; do read -p "請輸入主域名: " PRIMARY_DOMAIN < /dev/tty; if validate_domain "$PRIMARY_DOMAIN"; then break; fi; done
                    while true; do read -p "請輸入郵箱: " EMAIL < /dev/tty; if validate_email "$EMAIL"; then break; fi; done
                    read -p "請輸入後端服務地址（格式: hostname:port）[預設: app:80]: " BACKEND_SERVICE < /dev/tty; BACKEND_SERVICE=${BACKEND_SERVICE:-app:80}
                    if ! validate_backend_service "$BACKEND_SERVICE"; then press_any_key; continue; fi
                    read -p "請輸入代理偽裝域名 (可選): " PROXY_DOMAIN < /dev/tty
                    if [ -n "$PROXY_DOMAIN" ]; then while true; do if validate_domain "$PROXY_DOMAIN"; then break; fi; read -p "請重新輸入代理偽裝域名: " PROXY_DOMAIN < /dev/tty; done; fi
                    read -p "是否為 Caddy 啟用詳細日誌? (y/N): " LOG_MODE < /dev/tty
                    generate_caddy_config "$PRIMARY_DOMAIN" "$EMAIL" "$LOG_MODE" "$PROXY_DOMAIN" "$BACKEND_SERVICE"
                    log INFO "正在拉取 Caddy 鏡像..."; docker pull "$CADDY_IMAGE_NAME"
                    docker network create "${SHARED_NETWORK_NAME}" &>/dev/null; docker network create "web-services" &>/dev/null
                    if docker run -d --name "${CADDY_CONTAINER_NAME}" --restart always --network "${SHARED_NETWORK_NAME}" -p 80:80/tcp -p 443:443/tcp -v "${CADDY_CONFIG_FILE}:/etc/caddy/Caddyfile:ro" -v "${CADDY_DATA_VOLUME}:/data" "$CADDY_IMAGE_NAME"; then
                        if docker network connect "web-services" "${CADDY_CONTAINER_NAME}" 2>/dev/null; then log INFO "Caddy 部署成功，已連接到 ${SHARED_NETWORK_NAME} 和 web-services 網絡。"; else log WARN "Caddy 已啟動，但連接 web-services 網絡失敗。"; fi
                    else log ERROR "Caddy 部署失敗。"; fi
                    press_any_key; break;;
                0) break;; *) log ERROR "無效輸入!"; sleep 1;;
            esac
        done
    else
        while true; do
            clear; log INFO "--- 管理 Caddy (已安裝) ---"; echo " 1. 查看日誌"; echo " 2. 編輯 Caddyfile"; echo " 3. 重啟"; echo " 4. 卸載"; echo " 0. 返回"
            read -p "請輸入選項: " choice < /dev/tty
            case "$choice" in
                1) docker logs -f "$CADDY_CONTAINER_NAME"; press_any_key;;
                2) if check_editor; then "$EDITOR" "${CADDY_CONFIG_FILE}"; log INFO "設定已儲存，請手動重啟以生效。"; fi; press_any_key;;
                3) docker restart "$CADDY_CONTAINER_NAME"; log INFO "Caddy 已重啟。"; press_any_key;;
                4)
                    read -p "確定要卸載 Caddy 嗎? (y/N): " u_choice < /dev/tty
                    if [[ "$u_choice" =~ ^[yY]$ ]]; then
                        docker stop "${CADDY_CONTAINER_NAME}" &>/dev/null && docker rm "${CADDY_CONTAINER_NAME}" &>/dev/null
                        read -p "是否刪除設定檔和證書? (y/N): " d_choice < /dev/tty
                        if [[ "$d_choice" =~ ^[yY]$ ]]; then rm -rf "${CADDY_CONFIG_DIR}"; docker volume rm "${CADDY_DATA_VOLUME}" &>/dev/null; fi
                        log INFO "Caddy 已卸載。";
                    fi; press_any_key; break;;
                0) break;; *) log ERROR "無效輸入!"; sleep 1;;
            esac
        done
    fi
}
manage_singbox_warp() {
    if ! container_exists "$SB_WARP_CONTAINER_NAME"; then
        while true; do
            clear; log INFO "--- 管理 Sing-box (WARP Gateway) (未安裝) ---"
            echo " 1. 自動註冊免費 WARP 帳號並安裝"; echo " 2. 手動輸入 WARP 金鑰並安裝"; echo " 0. 返回"
            read -p "請輸入選項: " choice < /dev/tty
            local pk="" ip6=""
            case "$choice" in
                1)
                    if ! generate_warp_account_data; then press_any_key; continue; fi
                    local conf="${SB_WARP_CONFIG_DIR}/wgcf-profile.conf"
                    pk=$(grep -oP 'PrivateKey = \K.*' "$conf"); ip6=$(grep -oP 'Address = \K.*' "$conf" | awk -F, '{print $2}'|awk -F/ '{print $1}'|xargs)
                    if [ -z "$pk" ] || [ -z "$ip6" ]; then log ERROR "提取金鑰失敗。"; press_any_key; continue; fi;;
                2)
                    read -p "請輸入 PrivateKey: " pk < /dev/tty
                    read -p "請輸入 Address (僅 IPv6 地址): " ip6 < /dev/tty
                    if [ -z "$pk" ] || [ -z "$ip6" ]; then log ERROR "輸入資料不完整。"; press_any_key; continue; fi;;
                0) break;; *) log ERROR "無效輸入!"; sleep 1; continue;;
            esac
            log INFO "正在拉取 Sing-box 鏡像..."; docker pull "$SB_WARP_IMAGE_NAME"
            generate_singbox_config "$pk" "${ip6}/128"
            docker network create "${SHARED_NETWORK_NAME}" &>/dev/null
            docker run -d --name "$SB_WARP_CONTAINER_NAME" --restart always --network "${SHARED_NETWORK_NAME}" --cap-add NET_ADMIN --sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv4.conf.all.src_valid_mark=1 -v "${SB_WARP_CONFIG_FILE}:/etc/sing-box/config.json:ro" "$SB_WARP_IMAGE_NAME" run -c /etc/sing-box/config.json
            log INFO "Sing-box (WARP) 部署成功。"; press_any_key; break
        done
    else
        while true; do
            clear; log INFO "--- 管理 Sing-box (WARP Gateway) (已安裝) ---"
            echo " 1. 查看日誌"; echo " 2. 手動更換 WARP 金鑰"; echo " 3. 重啟"; echo " 4. 卸載"; echo " 0. 返回"
            read -p "請輸入選項: " choice < /dev/tty
            case "$choice" in
                1) docker logs -f "$SB_WARP_CONTAINER_NAME"; press_any_key;;
                2) update_warp_keys_interactive; press_any_key;;
                3) docker restart "$SB_WARP_CONTAINER_NAME"; log INFO "Sing-box 已重啟。"; press_any_key;;
                4) docker stop "$SB_WARP_CONTAINER_NAME" &>/dev/null && docker rm "$SB_WARP_CONTAINER_NAME" &>/dev/null && rm -rf "$SB_WARP_CONFIG_DIR"; log INFO "已卸載。"; press_any_key; break;;
                0) break;; *) log ERROR "無效輸入!"; sleep 1;;
            esac
        done
    fi
}
manage_hysteria() {
    if ! container_exists "$HYSTERIA_CONTAINER_NAME"; then
        while true; do
            clear; log INFO "--- 管理 Hysteria (未安裝) ---"; echo " 1. 安裝 Hysteria"; echo " 0. 返回"
            read -p "請輸入選項: " choice < /dev/tty
            case "$choice" in
                1)
                    if ! container_exists "$CADDY_CONTAINER_NAME" || ! container_exists "$SB_WARP_CONTAINER_NAME"; then log ERROR "依賴項缺失！請先安裝 Caddy 和 Sing-box (WARP)。"; press_any_key; continue; fi
                    local domains=$(awk 'NR>1 && NF>=2 && $2=="{" {print $1}' "${CADDY_CONFIG_FILE}" 2>/dev/null | tr '\n' ' ')
                    log INFO "檢測到 Caddy 中的域名: $domains"
                    read -p "請確認 Hysteria 使用的域名 [${domains%% *}]: " domain < /dev/tty; domain=${domain:-${domains%% *}}
                    if ! validate_domain "$domain"; then press_any_key; continue; fi
                    read -p "請設定連接密碼 (留空自動生成): " password < /dev/tty
                    if [ -z "$password" ]; then password=$(generate_random_password); log INFO "已自動生成密碼: ${FontColor_Yellow}${password}${FontColor_Suffix}"; fi
                    read -p "是否為 Hysteria 啟用詳細日誌？(y/N): " LOG_MODE < /dev/tty
                    generate_hysteria_config "$domain" "$password" "$LOG_MODE"
                    log INFO "正在拉取 Hysteria 鏡像..."; docker pull "$HYSTERIA_IMAGE_NAME"

                    local DNS_ARG=""
                    if container_exists "$ADGUARD_CONTAINER_NAME" && [ "$(docker inspect -f '{{.State.Running}}' "$ADGUARD_CONTAINER_NAME" 2>/dev/null)" = "true" ]; then
                        local AG_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$ADGUARD_CONTAINER_NAME" 2>/dev/null | awk '{print $1}')
                        if [ -n "$AG_IP" ]; then DNS_ARG="--dns=${AG_IP}"; log INFO "檢測到 AdGuard (IP: ${AG_IP})，將強制 Hysteria 使用此 DNS。"; else log WARN "無法獲取 AdGuard IP。"; fi
                    else log WARN "未安裝或未運行 AdGuard，Hysteria 將使用預設 DNS。"; fi
                    
                    if docker run -d --name "$HYSTERIA_CONTAINER_NAME" --restart always --network "${SHARED_NETWORK_NAME}" ${DNS_ARG} -v "${HYSTERIA_CONFIG_FILE}:/config.yaml:ro" -v "${CADDY_DATA_VOLUME}:/data:ro" -p 443:443/udp "$HYSTERIA_IMAGE_NAME" server -c /config.yaml; then
                        log INFO "Hysteria 部署成功。";
                    else
                        log ERROR "Hysteria 部署失敗。";
                    fi
                    press_any_key; break;;
                0) break;; *) log ERROR "無效輸入!"; sleep 1;;
            esac
        done
    else
        while true; do
            clear; log INFO "--- 管理 Hysteria (已安裝) ---"; echo " 1. 查看日誌"; echo " 2. 編輯設定檔"; echo " 3. 重啟"; echo " 4. 卸載"; echo " 0. 返回"
            read -p "請輸入選項: " choice < /dev/tty
            case "$choice" in
                1) docker logs -f "$HYSTERIA_CONTAINER_NAME"; press_any_key;;
                2) if check_editor; then "$EDITOR" "$HYSTERIA_CONFIG_FILE"; log INFO "設定已儲存，請手動重啟以生效。"; fi; press_any_key;;
                3) docker restart "$HYSTERIA_CONTAINER_NAME"; log INFO "Hysteria 已重啟。"; press_any_key;;
                4) docker stop "$HYSTERIA_CONTAINER_NAME" &>/dev/null && docker rm "$HYSTERIA_CONTAINER_NAME" &>/dev/null && rm -rf "$HYSTERIA_CONFIG_DIR"; log INFO "已卸載。"; press_any_key; break;;
                0) break;; *) log ERROR "無效輸入!"; sleep 1;;
            esac
        done
    fi
}
manage_adguard() {
    if ! container_exists "$ADGUARD_CONTAINER_NAME"; then
        while true; do
            clear; log INFO "--- 管理 AdGuard Home (未安裝) ---"
            echo " 1. 安裝 AdGuard Home (用於廣告過濾)"; echo " 0. 返回主選單"
            read -p "請輸入選項: " choice < /dev/tty
            case "$choice" in
                1)
                    log INFO "--- 正在安裝 AdGuard Home ---"
                    log INFO "正在拉取最新的 AdGuard Home 鏡像..."
                    if ! docker pull "${ADGUARD_IMAGE_NAME}"; then log ERROR "AdGuard 鏡像拉取失敗。"; press_any_key; continue; fi
                    mkdir -p "${ADGUARD_CONFIG_DIR}" "${ADGUARD_WORK_DIR}"
                    docker network create "${SHARED_NETWORK_NAME}" &>/dev/null
                    ADGUARD_CMD=(docker run -d --name "${ADGUARD_CONTAINER_NAME}" --restart always --network "${SHARED_NETWORK_NAME}" -v "${ADGUARD_WORK_DIR}:/opt/adguardhome/work" -v "${ADGUARD_CONFIG_DIR}:/opt/adguardhome/conf" -p 3000:3000/tcp "${ADGUARD_IMAGE_NAME}")
                    if "${ADGUARD_CMD[@]}"; then
                        log INFO "AdGuard Home 部署成功。首次設定請訪問: http://<您的IP>:3000"
                        log INFO "請務必在 Hysteria 安裝/重裝前完成 AdGuard Home 的初始化設定。"
                    else
                        log ERROR "AdGuard Home 部署失敗。"
                    fi
                    press_any_key; break;;
                0) break;;
                *) log ERROR "無效輸入!"; sleep 1;;
            esac
        done
    else
        while true; do
            clear; log INFO "--- 管理 AdGuard Home (已安裝) ---"
            echo " 1. 查看日誌"; echo " 2. 重啟 AdGuard 容器"; echo " 3. 卸載 AdGuard Home"; echo " 0. 返回主選單"
            read -p "請輸入選項: " choice < /dev/tty
            case "$choice" in
                1) docker logs -f "$ADGUARD_CONTAINER_NAME"; press_any_key;;
                2) log INFO "正在重啟 AdGuard..."; docker restart "$ADGUARD_CONTAINER_NAME"; sleep 2;;
                3)
                    read -p "確定要卸載 AdGuard Home 嗎? (y/N): " uninstall_choice < /dev/tty
                    if [[ "$uninstall_choice" =~ ^[yY]$ ]]; then
                        docker stop "${ADGUARD_CONTAINER_NAME}" &>/dev/null && docker rm "${ADGUARD_CONTAINER_NAME}" &>/dev/null
                        rm -rf "${ADGUARD_CONFIG_DIR}" "${ADGUARD_WORK_DIR}"
                        log INFO "AdGuard Home 已卸載。";
                    fi
                    press_any_key; break;;
                0) break;;
                *) log ERROR "無效輸入!"; sleep 1;;
            esac
        done
    fi
}

# --- 系統級管理函數 (含自動修復) ---
wait_for_container_ready() {
    local container="$1"; local service_name="$2"; max_wait="${3:-30}"
    log INFO "等待 ${service_name} 就緒..."
    for i in $(seq 1 $max_wait); do
        if [ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)" != "true" ]; then sleep 1; continue; fi
        case "$container" in
            "$ADGUARD_CONTAINER_NAME") if docker exec "$container" sh -c "timeout 1 nslookup google.com 127.0.0.1 >/dev/null 2>&1" 2>/dev/null; then echo; log INFO "✓ ${service_name} DNS 測試通過"; return 0; fi;;
            "$SB_WARP_CONTAINER_NAME") if docker exec "$container" sh -c "timeout 2 wget -qO- --header 'Accept: application/dns-json' 'https://1.1.1.1/dns-query?name=google.com'" >/dev/null 2>&1; then echo; log INFO "✓ ${service_name} 連通性測試通過"; return 0; fi;;
            "$HYSTERIA_CONTAINER_NAME"|"$CADDY_CONTAINER_NAME") if docker logs "$container" 2>&1 | tail -n 20 | grep -qiE "serving|running|listening|server up"; then echo; log INFO "✓ ${service_name} 已就緒"; return 0; fi;;
        esac
        echo -ne "."; sleep 1
    done
    echo ""; return 1
}
restart_all_services() {
    log INFO "正在按依賴順序重啟所有正在運行的容器..."
    local restart_order=("$ADGUARD_CONTAINER_NAME:AdGuard" "$CADDY_CONTAINER_NAME:Caddy" "$SB_WARP_CONTAINER_NAME:Sing-box (WARP)" "$HYSTERIA_CONTAINER_NAME:Hysteria")
    local restarted=0
    
    for item in "${restart_order[@]}"; do
        local container="${item%%:*}"; local service_name="${item#*:}"
        
        # 檢查容器是否存在且正在運行
        if container_exists "$container" && [ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)" = "true" ]; then
            log INFO "正在重啟 ${service_name}..."
            
            if docker restart "$container" &>/dev/null; then
                # 對所有重啟的容器進行健康檢查
                if wait_for_container_ready "$container" "$service_name" 30; then
                    restarted=$((restarted + 1))
                else
                    # 健康檢查失敗，不再觸發自動修復，僅發出警告
                    log WARN "✗ ${service_name} 重啟後未能在 30 秒內通過功能測試，已跳過。請稍後手動檢查其日誌。"
                fi
                sleep 2 # 保持服務間的啟動間隔
            else
                log ERROR "✗ ${service_name} 重啟失敗，請檢查 Docker 服務狀態。"
            fi
        fi
    done
    
    if [ "$restarted" -eq 0 ]; then 
        log WARN "沒有正在運行的容器可供重啟。"
    else 
        log INFO "所有服務已按順序重啟完成。${restarted} 個容器已處理。"
    fi
}
clear_all_logs() {
    log INFO "正在清除所有已安裝服務容器的內部日誌..."
    for container in "$CADDY_CONTAINER_NAME" "$SB_WARP_CONTAINER_NAME" "$HYSTERIA_CONTAINER_NAME" "$ADGUARD_CONTAINER_NAME"; do
        if container_exists "$container"; then
            local log_path=$(docker inspect --format='{{.LogPath}}' "$container")
            if [ -f "$log_path" ]; then truncate -s 0 "$log_path"; fi
        fi
    done
    log INFO "所有服務日誌已清空。"
}
clear_logs_and_restart_all() {
    clear_all_logs
    log INFO "3秒後將自動重啟所有正在運行的服務..."
    sleep 3
    restart_all_services
}
uninstall_all_services() {
    log WARN "此操作將不可逆地刪除所有容器、設定檔和數據！"
    read -p "您確定要徹底清理所有服務嗎? (y/N): " choice < /dev/tty
    if [[ ! "$choice" =~ ^[yY]$ ]]; then log INFO "操作已取消。"; return; fi
    docker stop "$CADDY_CONTAINER_NAME" "$SB_WARP_CONTAINER_NAME" "$HYSTERIA_CONTAINER_NAME" "$ADGUARD_CONTAINER_NAME" &>/dev/null
    docker rm "$CADDY_CONTAINER_NAME" "$SB_WARP_CONTAINER_NAME" "$HYSTERIA_CONTAINER_NAME" "$ADGUARD_CONTAINER_NAME" &>/dev/null
    rm -rf "${APP_BASE_DIR}"; docker volume rm "${CADDY_DATA_VOLUME}" &>/dev/null; docker network rm "${SHARED_NETWORK_NAME}" &>/dev/null
    log INFO "所有服務已徹底清理完畢。"
}

# 主菜單
check_all_status() {
    local containers=("$CADDY_CONTAINER_NAME" "$SB_WARP_CONTAINER_NAME" "$HYSTERIA_CONTAINER_NAME" "$ADGUARD_CONTAINER_NAME")
    for container in "${containers[@]}"; do
        if ! container_exists "$container"; then CONTAINER_STATUSES["$container"]="${FontColor_Red}未安裝${FontColor_Suffix}"; else
            local status=$(docker inspect --format '{{.State.Status}}' "$container" 2>/dev/null)
            if [ "$status" = "running" ]; then CONTAINER_STATUSES["$container"]="${FontColor_Green}運行中${FontColor_Suffix}"; else CONTAINER_STATUSES["$container"]="${FontColor_Red}異常(${status})${FontColor_Suffix}"; fi
        fi
    done
}
start_menu() {
    while true; do
        check_all_status; clear
        echo -e "\n${FontColor_Purple}Caddy + Sing-box(WARP) + Hysteria + AdGuard 管理腳本${FontColor_Suffix} (v7.5.0)"
        echo -e "  快捷命令: ${FontColor_Yellow}hwc${FontColor_Suffix}  |  設定目錄: ${FontColor_Yellow}${APP_BASE_DIR}${FontColor_Suffix}"
        echo -e " --------------------------------------------------"
        echo -e "  Caddy 服務 (SSL)        : ${CONTAINER_STATUSES[$CADDY_CONTAINER_NAME]}"
        echo -e "  Sing-box (WARP Gateway) : ${CONTAINER_STATUSES[$SB_WARP_CONTAINER_NAME]}"
        echo -e "  Hysteria 服務           : ${CONTAINER_STATUSES[$HYSTERIA_CONTAINER_NAME]}"
        echo -e "  AdGuard Home 服務 (DNS) : ${CONTAINER_STATUSES[$ADGUARD_CONTAINER_NAME]}"
        echo -e " --------------------------------------------------\n"
        echo -e " ${FontColor_Green}1.${FontColor_Suffix} 管理 Caddy..."
        echo -e " ${FontColor_Green}2.${FontColor_Suffix} 管理 Sing-box (WARP)..."
        echo -e " ${FontColor_Green}3.${FontColor_Suffix} 管理 Hysteria..."
        echo -e " ${FontColor_Green}4.${FontColor_Suffix} 管理 AdGuard Home...\n"
        echo -e " ${FontColor_Yellow}5.${FontColor_Suffix} 清理日誌並重啟所有服務"
        echo -e " ${FontColor_Red}6.${FontColor_Suffix} 徹底清理所有服務\n"
        echo -e " ${FontColor_Yellow}0.${FontColor_Suffix} 退出腳本\n"
        read -p " 請輸入選項 [0-6]: " num < /dev/tty
        case "$num" in
            1) manage_caddy;; 2) manage_singbox_warp;; 3) manage_hysteria;; 4) manage_adguard;;
            5) clear_logs_and_restart_all; press_any_key;;
            6) uninstall_all_services; press_any_key;;
            0) exit 0;;
            *) log ERROR "無效輸入!"; sleep 2;;
        esac
    done
}

# --- 第3節：腳本入口 (主邏輯) ---
clear
cat <<-'EOM'
  ____      _        __          __      _   _             _             _
 / ___|__ _| |_ __ _ \ \        / /     | | | |           | |           (_)
| |   / _` | __/ _` | \ \  /\  / /  __ _| |_| |_ ___ _ __ | |_ __ _ _ __ _  ___
| |__| (_| | || (_| |  \ \/  \/ /  / _` | __| __/ _ \ '_ \| __/ _` | '__| |/ __|
 \____\__,_|\__\__,_|   \  /\  /  | (_| | |_| ||  __/ | | | || (_| | |  | | (__
                        \/  \/    \__,_|\__|\__\___|_| |_|\__\__,_|_|  |_|\___|
EOM
echo -e "${FontColor_Purple}Caddy + Sing-box(WARP) + Hysteria + AdGuard 終極一鍵管理腳本${FontColor_Suffix} (v7.5.0)"
echo "----------------------------------------------------------------"

check_root
self_install "$@"
check_docker
mkdir -p "${APP_BASE_DIR}"
start_menu
