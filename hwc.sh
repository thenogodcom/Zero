#!/usr/bin/env bash
#
# Description: Ultimate All-in-One Manager for Caddy & Mihomo (Clash.Meta)
# Author: Your Name (Refactored for Mihomo/Clash.Meta)
# Version: 7.0.0 (Mihomo Edition)

# --- 第1節:全域設定與定義 ---
set -eo pipefail

# 顏色定義,用於日誌輸出
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
CADDY_CONTAINER_NAME="caddy-manager"; CADDY_IMAGE_NAME="caddy:latest"; CADDY_CONFIG_DIR="${APP_BASE_DIR}/caddy"; CADDY_CONFIG_FILE="${CADDY_CONFIG_DIR}/Caddyfile"; CADDY_DATA_VOLUME="hwc_caddy_data"
MIHOMO_CONTAINER_NAME="mihomo"; MIHOMO_IMAGE_NAME="metacubex/mihomo:latest"; MIHOMO_CONFIG_DIR="${APP_BASE_DIR}/mihomo"; MIHOMO_CONFIG_FILE="${MIHOMO_CONFIG_DIR}/config.yaml"
SHARED_NETWORK_NAME="hwc-proxy-net"
SCRIPT_URL="https://raw.githubusercontent.com/thenogodcom/warp/main/hwc.sh"; SHORTCUT_PATH="/usr/local/bin/hwc"
declare -A CONTAINER_STATUSES

# --- 第2節:所有函數定義 ---

# 自我安裝快捷命令
self_install() {
    local args_string
    printf -v args_string '%q ' "$@"
    local running_script_path
    if [[ -f "$0" ]]; then running_script_path=$(readlink -f "$0"); fi
    if [ "$running_script_path" = "$SHORTCUT_PATH" ]; then return 0; fi

    log INFO "首次運行設定:正在安裝 'hwc' 快捷命令..."
    if ! command -v curl &>/dev/null; then
        if command -v apt-get &>/dev/null; then apt-get update && apt-get install -y curl; fi
        if command -v yum &>/dev/null; then yum install -y curl; fi
    fi
    # 這裡假設您會更新 URL，或者您可以移除下面的下載檢查直接使用 cp
    if cp "$0" "${SHORTCUT_PATH}"; then
        chmod +x "${SHORTCUT_PATH}"
        log INFO "快捷命令 'hwc' 安裝成功。正在從新位置重新啟動..."
        exec "${SHORTCUT_PATH}" $args_string
    else
        log ERROR "無法安裝 'hwc' 快捷命令。"
        sleep 2
    fi
}

# 驗證域名格式
validate_domain() {
    local domain="$1"
    if [[ ! "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
        log ERROR "域名格式無效: $domain"; return 1
    fi; return 0
}

# 驗證郵箱格式
validate_email() {
    local email="$1"
    if [[ ! "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log ERROR "郵箱格式無效: $email"; return 1
    fi; return 0
}

# 驗證後端服務地址
validate_backend_service() {
    local service="$1"
    if [[ ! "$service" =~ ^[a-zA-Z0-9\._-]+:[0-9]+$ ]]; then
        log ERROR "後端服務地址格式無效(應為 hostname:port): $service"; return 1
    fi; return 0
}

# 檢測證書路徑(支持多個 CA)
detect_cert_path() {
    local domain="$1"; local base_path="/data/caddy/certificates"
    if container_exists "$CADDY_CONTAINER_NAME"; then
        for ca_dir in "acme-v02.api.letsencrypt.org-directory" "acme.zerossl.com-v2-DV90"; do
            local cert_check
            cert_check=$(docker exec "$CADDY_CONTAINER_NAME" sh -c "[ -f $base_path/$ca_dir/$domain/$domain.crt ] && echo 'exists'" 2>/dev/null)
            if [ "$cert_check" = "exists" ]; then
                echo "$base_path/$ca_dir/$domain/$domain.crt|$base_path/$ca_dir/$domain/$domain.key"; return 0
            fi
        done
    fi
    echo "$base_path/acme-v02.api.letsencrypt.org-directory/$domain/$domain.crt|$base_path/acme-v02.api.letsencrypt.org-directory/$domain/$domain.key"; return 1
}

# 生成隨機密碼
generate_random_password() {
    local part1=$(tr -dc 'a-z0-9' < /dev/urandom | head -c 8)
    local part2=$(tr -dc 'a-z0-9' < /dev/urandom | head -c 4)
    local part3=$(tr -dc 'a-z0-9' < /dev/urandom | head -c 12)
    echo "${part1}-${part2}-${part3}"
}

# 安裝 Docker
install_docker() {
    log INFO "偵測到 Docker 未安裝,正在使用官方通用腳本進行安裝..."
    if ! curl -fsSL https://get.docker.com | sh; then
        log ERROR "Docker 安裝失敗。"; exit 1
    fi
    systemctl start docker && systemctl enable docker
    log INFO "Docker 安裝成功並已啟動。"
}

check_root() { if [ "$EUID" -ne 0 ]; then log ERROR "此腳本必須以 root 身份運行。"; exit 1; fi; }

check_docker() {
    if ! command -v docker &>/dev/null; then install_docker; fi
    if ! docker info > /dev/null 2>&1; then systemctl start docker; sleep 3; fi
}

check_editor() {
    for editor in nano vi vim; do
        if command -v $editor &>/dev/null; then EDITOR=$editor; return 0; fi
    done
    log ERROR "未找到合適的文字編輯器。"; return 1
}

container_exists() { docker ps -a --format '{{.Names}}' | grep -q "^${1}$"; }
press_any_key() { echo ""; read -p "按 Enter 鍵返回..." < /dev/tty; }

# 生成 Caddyfile
generate_caddy_config() {
    local primary_domain="$1" email="$2" log_mode="$3" proxy_domain="$4" backend_service="$5"
    mkdir -p "${CADDY_CONFIG_DIR}"
    local global_log_block=""
    if [[ ! "$log_mode" =~ ^[yY]$ ]]; then
        global_log_block="    log {\n        output stderr\n        level ERROR\n    }"
    fi
    cat > "${CADDY_CONFIG_FILE}" <<EOF
{
    email ${email}
${global_log_block}
    servers { protocols h1 h2 }
}
(security_headers) {
    header -Via
    header -Server
    header Server "nginx"
}
(proxy_to_backend) {
    reverse_proxy ${backend_service} {
        header_up Host {args.0}
        header_up X-Real-IP {remote}
        header_up X-Forwarded-For {remote}
        header_up X-Forwarded-Proto {scheme}
    }
}
${primary_domain} {
    import security_headers
    import proxy_to_backend {host}
}
EOF
    if [ -n "$proxy_domain" ]; then
        echo "${proxy_domain} { import security_headers; import proxy_to_backend ${primary_domain} }" >> "${CADDY_CONFIG_FILE}"
    fi
    log INFO "Caddyfile 已生成。"
}

# 使用 wgcf 生成 WARP 帳戶
generate_warp_conf() {
    log INFO "正在使用 wgcf 註冊 WARP 帳戶..."
    local arch; case $(uname -m) in x86_64) arch="amd64";; aarch64) arch="arm64";; *) return 1;; esac
    
    local CMD="apk add --no-cache curl jq && \
    WGCF_URL=\$(curl -s https://api.github.com/repos/ViRb3/wgcf/releases/latest | jq -r \".assets[] | select(.name | contains(\\\"linux_${arch}\\\")) | .browser_download_url\") && \
    curl -fL -o wgcf \"\$WGCF_URL\" && chmod +x wgcf && ./wgcf"

    rm -f "${MIHOMO_CONFIG_DIR}/wgcf-account.toml"
    mkdir -p "${MIHOMO_CONFIG_DIR}"

    if ! docker run --rm -v "${MIHOMO_CONFIG_DIR}:/data" -w /data alpine:latest sh -c "$CMD register --accept-tos" > /dev/null 2>&1; then
        log ERROR "WARP 註冊失敗。請檢查網絡。"; return 1
    fi
    if ! docker run --rm -v "${MIHOMO_CONFIG_DIR}:/data" -w /data alpine:latest sh -c "$CMD generate" > /dev/null 2>&1; then
        log ERROR "WARP 配置生成失敗。"; return 1
    fi
    log INFO "WARP 帳戶已生成。"
}

# 生成 Mihomo (Clash.Meta) 設定檔 (YAML)
generate_mihomo_config() {
    local domain="$1" password="$2" private_key="$3" ipv4_address="$4" ipv6_address="$5" public_key="$6" log_level="${7:-info}"
    
    mkdir -p "${MIHOMO_CONFIG_DIR}"
    
    local cert_path_info; cert_path_info=$(detect_cert_path "$domain")
    local cert_path="${cert_path_info%%|*}"; local key_path="${cert_path_info##*|}"
    local cert_path_in_container="${cert_path/\/data/\/caddy_certs}"
    local key_path_in_container="${key_path/\/data/\/caddy_certs}"

    # Mihomo 配置
    cat > "${MIHOMO_CONFIG_FILE}" <<EOF
log-level: ${log_level}
ipv6: true
allow-lan: true
mode: rule
external-controller: 0.0.0.0:9090
unified-delay: true

dns:
  enable: true
  listen: 0.0.0.0:1053
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - https://1.1.1.1/dns-query
    - https://8.8.8.8/dns-query

listeners:
  - name: hysteria2-in
    type: hysteria2
    port: 443
    listen: "::"
    password: "${password}"
    tls:
      enabled: true
      certificate: "${cert_path_in_container}"
      private-key: "${key_path_in_container}"
      alpn:
        - h3

proxies:
  - name: WARP
    type: wireguard
    server: 162.159.192.1
    port: 2408
    ip: "${ipv4_address}"
    ipv6: "${ipv6_address}"
    private-key: "${private_key}"
    public-key: "${public_key}"
    mtu: 1280
    udp: true

proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - WARP

rules:
  - MATCH,Proxy
EOF
    log INFO "Mihomo (YAML) 設定檔生成完畢。"
}

manage_caddy() {
    if ! container_exists "$CADDY_CONTAINER_NAME"; then
        while true; do
            clear; log INFO "--- 管理 Caddy (未安裝) ---"
            echo " 1. 安裝 Caddy"; echo " 0. 返回"
            read -p "請輸入選項: " choice < /dev/tty
            case "$choice" in
                1)
                    while true; do read -p "請輸入主域名: " PRIMARY_DOMAIN < /dev/tty; if [ -n "$PRIMARY_DOMAIN" ] && validate_domain "$PRIMARY_DOMAIN"; then break; fi; done
                    while true; do read -p "請輸入您的郵箱: " EMAIL < /dev/tty; if [ -n "$EMAIL" ] && validate_email "$EMAIL"; then break; fi; done
                    read -p "請輸入後端服務地址 [預設: app:80]: " BACKEND_SERVICE < /dev/tty; BACKEND_SERVICE=${BACKEND_SERVICE:-app:80}
                    if ! validate_backend_service "$BACKEND_SERVICE"; then press_any_key; continue; fi
                    read -p "請輸入代理域名 (可選): " PROXY_DOMAIN < /dev/tty
                    if [ -n "$PROXY_DOMAIN" ] && ! validate_domain "$PROXY_DOMAIN"; then press_any_key; continue; fi
                    
                    generate_caddy_config "$PRIMARY_DOMAIN" "$EMAIL" "N" "$PROXY_DOMAIN" "$BACKEND_SERVICE"
                    log INFO "正在拉取 Caddy 鏡像..."
                    docker pull "${CADDY_IMAGE_NAME}"
                    docker network create "${SHARED_NETWORK_NAME}" &>/dev/null
                    
                    if docker run -d --name "${CADDY_CONTAINER_NAME}" --restart always --network "${SHARED_NETWORK_NAME}" -p 80:80/tcp -p 443:443/tcp -v "${CADDY_CONFIG_FILE}:/etc/caddy/Caddyfile:ro" -v "${CADDY_DATA_VOLUME}:/data" "${CADDY_IMAGE_NAME}"; then
                        log INFO "Caddy 部署成功。"
                    else 
                        log ERROR "Caddy 部署失敗。"; docker rm -f "${CADDY_CONTAINER_NAME}" 2>/dev/null
                    fi
                    press_any_key; break;;
                0) break;; *) log ERROR "無效輸入!"; sleep 1;;
            esac
        done
    else
        while true; do
            clear; log INFO "--- 管理 Caddy (已安裝) ---"
            echo " 1. 查看日誌"; echo " 2. 編輯 Caddyfile"; echo " 3. 重啟 Caddy"; echo " 4. 卸載 Caddy"; echo " 0. 返回"
            read -p "請輸入選項: " choice < /dev/tty
            case "$choice" in
                1) docker logs -f "$CADDY_CONTAINER_NAME"; press_any_key;;
                2) if check_editor; then "$EDITOR" "${CADDY_CONFIG_FILE}"; log INFO "請重啟以應用。"; fi; press_any_key;;
                3) docker restart "$CADDY_CONTAINER_NAME"; log INFO "已重啟。"; sleep 1;;
                4)
                    read -p "確定卸載? (y/N): " u < /dev/tty
                    if [[ "$u" =~ ^[yY]$ ]]; then
                        docker rm -f "${CADDY_CONTAINER_NAME}" &>/dev/null
                        rm -rf "${CADDY_CONFIG_DIR}"
                        docker volume rm "${CADDY_DATA_VOLUME}" &>/dev/null
                        log INFO "已卸載。";
                    fi; press_any_key; break;;
                0) break;;
            esac
        done
    fi
}

# 更新 Mihomo WARP 金鑰 (重寫 Config)
update_mihomo_warp_keys() {
    if [ ! -f "$MIHOMO_CONFIG_FILE" ]; then log ERROR "設定檔不存在。"; return 1; fi
    
    # 讀取現有配置中的域名和密碼 (簡單 grep 提取)
    local domain=$(grep 'certificate:' "$MIHOMO_CONFIG_FILE" | awk -F/ '{print $(NF-1)}')
    local password=$(grep 'password:' "$MIHOMO_CONFIG_FILE" | head -n1 | awk '{print $2}' | tr -d '"')

    if [ -z "$domain" ] || [ -z "$password" ]; then
        log ERROR "無法從現有配置中讀取域名或密碼，請重新安裝或手動編輯。"
        return 1
    fi

    log INFO "--- 更新 WARP 金鑰 ---"
    local private_key warp_address ipv4_address ipv6_address
    read -p "PrivateKey: " private_key < /dev/tty
    read -p "Address (帶逗號的完整行): " warp_address < /dev/tty
    
    ipv4_address=$(echo "$warp_address" | awk -F, '{print $1}' | awk -F/ '{print $1}' | xargs)
    ipv6_address=$(echo "$warp_address" | awk -F, '{print $2}' | awk -F/ '{print $1}' | xargs)
    local public_key="bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

    if [ -z "$ipv4_address" ] || [ -z "$private_key" ]; then log ERROR "輸入無效。"; return 1; fi
    
    generate_mihomo_config "$domain" "$password" "$private_key" "$ipv4_address" "$ipv6_address" "$public_key" "info"
    log INFO "配置已更新，請重啟 Mihomo。"
}

manage_mihomo() {
    if ! container_exists "$MIHOMO_CONTAINER_NAME"; then
        while true; do
            clear; log INFO "--- 管理 Mihomo (未安裝) ---"
            echo " 1. 安裝 Mihomo (Hysteria2 + WARP)"; echo " 0. 返回"
            read -p "請輸入選項: " choice < /dev/tty
            case "$choice" in
                1)
                    if ! container_exists "$CADDY_CONTAINER_NAME"; then log ERROR "請先安裝 Caddy。"; press_any_key; break; fi
                    
                    local available_domains=$(awk 'NR>1 && NF>=2 && $2=="{" {print $1}' "${CADDY_CONFIG_FILE}" 2>/dev/null | tr '\n' ' ')
                    local HY_DOMAIN=""
                    if [ -n "$available_domains" ]; then
                        read -p "請選擇域名 [${available_domains%% *}]: " HY_DOMAIN < /dev/tty
                        HY_DOMAIN=${HY_DOMAIN:-${available_domains%% *}}
                    else
                        read -p "請輸入域名: " HY_DOMAIN < /dev/tty
                    fi
                    
                    local PASSWORD=$(generate_random_password)
                    log INFO "已生成密碼: ${FontColor_Yellow}${PASSWORD}${FontColor_Suffix}"
                    
                    local private_key ipv4_address ipv6_address public_key
                    read -p "自動生成 WARP 帳戶? (Y/n): " AUTO_WARP < /dev/tty
                    if [[ ! "$AUTO_WARP" =~ ^[nN]$ ]]; then
                        if ! generate_warp_conf; then press_any_key; break; fi
                        private_key=$(grep -oP 'PrivateKey = \K.*' "${MIHOMO_CONFIG_DIR}/wgcf-profile.conf")
                        public_key=$(grep -oP 'PublicKey = \K.*' "${MIHOMO_CONFIG_DIR}/wgcf-profile.conf")
                        warp_addresses=$(grep -oP 'Address = \K.*' "${MIHOMO_CONFIG_DIR}/wgcf-profile.conf")
                        ipv4_address=$(echo "$warp_addresses" | awk -F, '{print $1}' | awk -F/ '{print $1}' | xargs)
                        ipv6_address=$(echo "$warp_addresses" | awk -F, '{print $2}' | awk -F/ '{print $1}' | xargs)
                    else
                        read -p "PrivateKey: " private_key < /dev/tty
                        read -p "Address: " warp_address < /dev/tty
                        ipv4_address=$(echo "$warp_address" | awk -F, '{print $1}' | awk -F/ '{print $1}' | xargs)
                        ipv6_address=$(echo "$warp_address" | awk -F, '{print $2}' | awk -F/ '{print $1}' | xargs)
                        public_key="bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
                    fi
                    
                    log INFO "正在拉取 Mihomo 鏡像..."
                    docker pull "${MIHOMO_IMAGE_NAME}"
                    generate_mihomo_config "$HY_DOMAIN" "$PASSWORD" "$private_key" "$ipv4_address" "$ipv6_address" "$public_key"
                    
                    log INFO "正在部署 Mihomo..."
                    # Mihomo 容器運行參數：映射 Config 和 Caddy 證書，開啟 NET_ADMIN 以支持 TUN/WireGuard
                    if docker run -d --name "${MIHOMO_CONTAINER_NAME}" --restart always --network "${SHARED_NETWORK_NAME}" \
                        --cap-add NET_ADMIN --device /dev/net/tun \
                        -p 443:443/udp -p 1080:1080/tcp \
                        -v "${MIHOMO_CONFIG_FILE}:/root/.config/mihomo/config.yaml:ro" \
                        -v "${CADDY_DATA_VOLUME}:/caddy_certs:ro" \
                        "${MIHOMO_IMAGE_NAME}"; then
                        log INFO "Mihomo 部署成功。"
                    else 
                        log ERROR "部署失敗。"; docker rm -f "${MIHOMO_CONTAINER_NAME}" 2>/dev/null; rm -rf "${MIHOMO_CONFIG_DIR}"
                    fi
                    press_any_key; break;;
                0) break;; *) log ERROR "無效輸入!"; sleep 1;;
            esac
        done
    else
        while true; do
            clear; log INFO "--- 管理 Mihomo (已安裝) ---"
            echo " 1. 查看日誌"; echo " 2. 編輯配置 (YAML)"; echo " 3. 重啟 Mihomo"
            echo " 4. 手動更換 WARP 金鑰"; echo " 5. 卸載 Mihomo"; echo " 0. 返回"
            read -p "請輸入選項: " choice < /dev/tty
            case "$choice" in
                1) docker logs -f "$MIHOMO_CONTAINER_NAME"; press_any_key;;
                2) if check_editor; then "$EDITOR" "${MIHOMO_CONFIG_FILE}"; log INFO "請重啟以應用。"; fi; press_any_key;;
                3) docker restart "$MIHOMO_CONTAINER_NAME"; log INFO "已重啟。"; sleep 1;;
                4) update_mihomo_warp_keys; press_any_key;;
                5)
                    read -p "確定卸載? (y/N): " u < /dev/tty
                    if [[ "$u" =~ ^[yY]$ ]]; then
                        docker rm -f "${MIHOMO_CONTAINER_NAME}" &>/dev/null
                        rm -rf "${MIHOMO_CONFIG_DIR}"
                        docker rmi "${MIHOMO_IMAGE_NAME}" &>/dev/null
                        log INFO "已卸載。";
                    fi; press_any_key; break;;
                0) break;;
            esac
        done
    fi
}

clear_all_logs() {
    log INFO "正在清除日誌..."
    for c in "$CADDY_CONTAINER_NAME" "$MIHOMO_CONTAINER_NAME"; do
        if container_exists "$c"; then
            local p=$(docker inspect --format='{{.LogPath}}' "$c")
            [ -f "$p" ] && truncate -s 0 "$p"
        fi
    done
    log INFO "日誌已清空。"
}

restart_all_services() {
    log INFO "重啟所有服務..."
    [ "$(docker inspect -f '{{.State.Running}}' "$CADDY_CONTAINER_NAME" 2>/dev/null)" = "true" ] && docker restart "$CADDY_CONTAINER_NAME"
    [ "$(docker inspect -f '{{.State.Running}}' "$MIHOMO_CONTAINER_NAME" 2>/dev/null)" = "true" ] && docker restart "$MIHOMO_CONTAINER_NAME"
    log INFO "完成。"
}

uninstall_all_services() {
    read -p "確定要徹底清理所有服務嗎? (y/N): " choice < /dev/tty
    if [[ ! "$choice" =~ ^[yY]$ ]]; then return; fi
    log INFO "清理中..."
    docker rm -f "$CADDY_CONTAINER_NAME" "$MIHOMO_CONTAINER_NAME" &>/dev/null
    rm -rf "${APP_BASE_DIR}"
    docker volume rm "${CADDY_DATA_VOLUME}" &>/dev/null
    docker network rm "${SHARED_NETWORK_NAME}" &>/dev/null
    docker rmi -f "${CADDY_IMAGE_NAME}" "${MIHOMO_IMAGE_NAME}" &>/dev/null
    log INFO "清理完畢。"
}

check_all_status() {
    for c in "$CADDY_CONTAINER_NAME" "$MIHOMO_CONTAINER_NAME"; do
        if ! container_exists "$c"; then
            CONTAINER_STATUSES["$c"]="${FontColor_Red}未安裝${FontColor_Suffix}"
        else
            local s=$(docker inspect --format '{{.State.Status}}' "$c" 2>/dev/null)
            if [ "$s" = "running" ]; then CONTAINER_STATUSES["$c"]="${FontColor_Green}運行中${FontColor_Suffix}"; else CONTAINER_STATUSES["$c"]="${FontColor_Red}異常${FontColor_Suffix}"; fi
        fi
    done
}

start_menu() {
    while true; do
        check_all_status; clear
        echo -e "\n${FontColor_Purple}Caddy + Mihomo 一鍵管理腳本${FontColor_Suffix} (v7.0.0)"
        echo -e " --------------------------------------------------"
        echo -e "  Caddy  服務 : ${CONTAINER_STATUSES[$CADDY_CONTAINER_NAME]}"
        echo -e "  Mihomo 服務 : ${CONTAINER_STATUSES[$MIHOMO_CONTAINER_NAME]}"
        echo -e " --------------------------------------------------\n"
        echo -e " 1. 管理 Caddy"
        echo -e " 2. 管理 Mihomo (Clash.Meta)\n"
        echo -e " 3. 清理日誌並重啟"
        echo -e " 4. 徹底卸載\n"
        echo -e " 0. 退出\n"
        read -p " 請輸入: " num < /dev/tty
        case "$num" in
            1) manage_caddy;; 2) manage_mihomo;;
            3) clear_all_logs; restart_all_services; press_any_key;;
            4) uninstall_all_services; press_any_key;;
            0) exit 0;;
            *) log ERROR "無效!"; sleep 1;;
        esac
    done
}

# --- 第3節:腳本入口 ---
clear
echo -e "${FontColor_Purple}Caddy + Mihomo Manager${FontColor_Suffix}"
check_root
self_install "$@"
check_docker
mkdir -p "${APP_BASE_DIR}"
start_menu
