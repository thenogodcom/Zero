#!/usr/bin/env bash
#
# Description: Ultimate All-in-One Manager for Caddy & Mihomo (Clash.Meta)
# Author: Your Name (Refactored for Mihomo/Clash.Meta)
# Version: 7.4.0 (Fix: Startup Exit Issue)

# --- 第1節:全域設定與定義 ---
# 移除 set -eo pipefail 以防止腳本在環境檢查時意外退出
# set -eo pipefail 

# 顏色定義
FontColor_Red="\033[31m"; FontColor_Green="\033[32m"; FontColor_Yellow="\033[33m"
FontColor_Purple="\033[35m"; FontColor_Suffix="\033[0m"

log() {
    local LEVEL="$1"; local MSG="$2"
    case "${LEVEL}" in
        INFO)  local LEVEL="[${FontColor_Green}資訊${FontColor_Suffix}]";;
        WARN)  local LEVEL="[${FontColor_Yellow}警告${FontColor_Suffix}]";;
        ERROR) local LEVEL="[${FontColor_Red}錯誤${FontColor_Suffix}]";;
    esac
    echo -e "${LEVEL} ${MSG}"
}

# 基礎目錄與變數
APP_BASE_DIR="/root/hwc"
CADDY_CONTAINER_NAME="caddy-manager"; CADDY_IMAGE_NAME="caddy:latest"; CADDY_CONFIG_DIR="${APP_BASE_DIR}/caddy"; CADDY_CONFIG_FILE="${CADDY_CONFIG_DIR}/Caddyfile"; CADDY_DATA_VOLUME="hwc_caddy_data"
MIHOMO_CONTAINER_NAME="mihomo"; MIHOMO_IMAGE_NAME="metacubex/mihomo:latest"; MIHOMO_CONFIG_DIR="${APP_BASE_DIR}/mihomo"; MIHOMO_CONFIG_FILE="${MIHOMO_CONFIG_DIR}/config.yaml"
SHARED_NETWORK_NAME="hwc-proxy-net"
SCRIPT_URL="https://raw.githubusercontent.com/thenogodcom/warp/main/hwc.sh"; SHORTCUT_PATH="/usr/local/bin/hwc"
declare -A CONTAINER_STATUSES

# --- 第2節:所有函數定義 ---

self_install() {
    local running_script_path
    if [[ -f "$0" ]]; then running_script_path=$(readlink -f "$0"); fi
    
    # 如果已經是快捷路徑，直接返回
    if [ "$running_script_path" = "$SHORTCUT_PATH" ]; then return 0; fi

    # 確保快捷目錄存在
    mkdir -p /usr/local/bin

    log INFO "首次運行: 正在安裝 'hwc' 快捷命令..."
    if cp "$0" "${SHORTCUT_PATH}"; then
        chmod +x "${SHORTCUT_PATH}"
        log INFO "安裝成功！您以後可以直接輸入 'hwc' 來管理。"
        log INFO "正在切換到新路徑運行..."
        exec "${SHORTCUT_PATH}" "$@"
    else
        log ERROR "快捷命令安裝失敗，將繼續以當前方式運行。"
        sleep 1
    fi
}

validate_domain() {
    [[ "$1" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]] || { log ERROR "域名格式無效: $1"; return 1; }
}

validate_email() {
    [[ "$1" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || { log ERROR "郵箱格式無效: $1"; return 1; }
}

validate_backend_service() {
    [[ "$1" =~ ^[a-zA-Z0-9\._-]+:[0-9]+$ ]] || { log ERROR "後端服務地址格式無效: $1"; return 1; }
}

# 等待並檢測證書路徑
wait_and_detect_cert() {
    local domain="$1"
    local base_path_caddy="/data/caddy/certificates"
    local found_cert=""
    local found_key=""
    local max_retries=60
    local count=0

    log INFO "正在檢查域名 ${domain} 的 SSL 證書..."
    
    while [ $count -lt $max_retries ]; do
        if ! container_exists "$CADDY_CONTAINER_NAME"; then
            log ERROR "Caddy 容器未運行，無法獲取證書。"
            return 1
        fi

        for ca_dir in "acme-v02.api.letsencrypt.org-directory" "acme.zerossl.com-v2-DV90"; do
            local cert_file="$base_path_caddy/$ca_dir/$domain/$domain.crt"
            local key_file="$base_path_caddy/$ca_dir/$domain/$domain.key"
            
            if docker exec "$CADDY_CONTAINER_NAME" test -f "$cert_file" && docker exec "$CADDY_CONTAINER_NAME" test -f "$key_file"; then
                found_cert="$cert_file"
                found_key="$key_file"
                break 2
            fi
        done

        log WARN "證書尚未生成 (嘗試 $(($count + 1))/$max_retries)...等待 3 秒..."
        sleep 3
        count=$((count + 1))
    done

    if [ -z "$found_cert" ]; then
        log ERROR "超時：Caddy 未能在預定時間內簽發證書。"
        return 1
    fi

    log INFO "已找到證書：$found_cert"
    echo "$found_cert|$found_key"
    return 0
}

generate_random_password() {
    local p1=$(tr -dc 'a-z0-9' < /dev/urandom | head -c 8)
    local p2=$(tr -dc 'a-z0-9' < /dev/urandom | head -c 4)
    local p3=$(tr -dc 'a-z0-9' < /dev/urandom | head -c 12)
    echo "${p1}-${p2}-${p3}"
}

install_docker() {
    log INFO "正在安裝 Docker..."
    if ! curl -fsSL https://get.docker.com | sh; then
        log ERROR "Docker 安裝腳本執行失敗，請手動安裝 Docker。"
        exit 1
    fi
    systemctl start docker 2>/dev/null
    systemctl enable docker 2>/dev/null
}

check_root() { [ "$EUID" -ne 0 ] && { log ERROR "必須以 root 身份運行"; exit 1; }; }

check_docker() {
    if ! command -v docker &>/dev/null; then
        install_docker
    fi
    if ! docker info >/dev/null 2>&1; then
        log WARN "Docker 服務似乎未運行，正在嘗試啟動..."
        systemctl start docker 2>/dev/null || service docker start 2>/dev/null
        sleep 3
        if ! docker info >/dev/null 2>&1; then
            log ERROR "無法啟動 Docker，請手動檢查 Docker 服務狀態。"
            # 不強制退出，嘗試繼續顯示選單
        fi
    fi
}

check_editor() {
    for e in nano vi vim; do command -v $e &>/dev/null && { EDITOR=$e; return 0; }; done
    log ERROR "未找到編輯器"; return 1
}

container_exists() { docker ps -a --format '{{.Names}}' | grep -q "^${1}$"; }
press_any_key() { echo ""; read -p "按 Enter 鍵返回..." < /dev/tty; }

generate_caddy_config() {
    local p_dom="$1" mail="$2" log_m="$3" prox_dom="$4" backend="$5"
    mkdir -p "${CADDY_CONFIG_DIR}"
    local log_blk=""
    [[ ! "$log_m" =~ ^[yY]$ ]] && log_blk="    log {\n        output stderr\n        level ERROR\n    }"
    
    cat > "${CADDY_CONFIG_FILE}" <<EOF
{
    email ${mail}
${log_blk}
    servers { protocols h1 h2 }
}
(security_headers) {
    header -Via
    header -Server
    header Server "nginx"
}
(proxy_to_backend) {
    reverse_proxy ${backend} {
        header_up Host {args.0}
        header_up X-Real-IP {remote}
        header_up X-Forwarded-For {remote}
        header_up X-Forwarded-Proto {scheme}
    }
}
${p_dom} {
    import security_headers
    import proxy_to_backend {host}
}
EOF
    [ -n "$prox_dom" ] && echo "${prox_dom} { import security_headers; import proxy_to_backend ${p_dom} }" >> "${CADDY_CONFIG_FILE}"
    log INFO "Caddyfile 已生成。"
}

generate_warp_conf() {
    log INFO "正在註冊 WARP 帳戶..."
    local arch; case $(uname -m) in x86_64) arch="amd64";; aarch64) arch="arm64";; *) return 1;; esac
    
    local CMD="apk add --no-cache curl jq && \
    WGCF_URL=\$(curl -s https://api.github.com/repos/ViRb3/wgcf/releases/latest | jq -r \".assets[] | select(.name | contains(\\\"linux_${arch}\\\")) | .browser_download_url\") && \
    curl -fL -o wgcf \"\$WGCF_URL\" && chmod +x wgcf && ./wgcf"

    rm -f "${MIHOMO_CONFIG_DIR}/wgcf-account.toml"
    mkdir -p "${MIHOMO_CONFIG_DIR}"

    if ! docker run --rm -v "${MIHOMO_CONFIG_DIR}:/data" -w /data alpine:latest sh -c "$CMD register --accept-tos" > /dev/null 2>&1; then
        log ERROR "WARP 註冊失敗。"; return 1
    fi
    if ! docker run --rm -v "${MIHOMO_CONFIG_DIR}:/data" -w /data alpine:latest sh -c "$CMD generate" > /dev/null 2>&1; then
        log ERROR "WARP 配置生成失敗。"; return 1
    fi
    log INFO "WARP 帳戶已生成。"
}

generate_mihomo_config() {
    local domain="$1" password="$2" p_key="$3" ipv4="$4" ipv6="$5" pub_key="$6" cert_path="$7" key_path="$8"
    
    mkdir -p "${MIHOMO_CONFIG_DIR}"
    
    local cert_path_in_container="${cert_path/\/data/\/caddy_certs}"
    local key_path_in_container="${key_path/\/data/\/caddy_certs}"

    log INFO "Mihomo 證書路徑: $cert_path_in_container"

    cat > "${MIHOMO_CONFIG_FILE}" <<EOF
log-level: info
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
      cert: "${cert_path_in_container}"
      key: "${key_path_in_container}"
      alpn:
        - h3

proxies:
  - name: WARP
    type: wireguard
    server: 162.159.192.1
    port: 2408
    ip: "${ipv4}"
    ipv6: "${ipv6}"
    private-key: "${p_key}"
    public-key: "${pub_key}"
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
    log INFO "Mihomo 設定檔生成完畢。"
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
                    [ -z "$BACKEND_SERVICE" ] || validate_backend_service "$BACKEND_SERVICE" || { press_any_key; continue; }
                    read -p "請輸入代理域名 (可選): " PROXY_DOMAIN < /dev/tty
                    [ -n "$PROXY_DOMAIN" ] && ! validate_domain "$PROXY_DOMAIN" && { press_any_key; continue; }
                    
                    generate_caddy_config "$PRIMARY_DOMAIN" "$EMAIL" "N" "$PROXY_DOMAIN" "$BACKEND_SERVICE"
                    log INFO "正在部署 Caddy..."
                    docker pull "${CADDY_IMAGE_NAME}"
                    docker network create "${SHARED_NETWORK_NAME}" &>/dev/null
                    
                    if docker run -d --name "${CADDY_CONTAINER_NAME}" --restart always --network "${SHARED_NETWORK_NAME}" -p 80:80/tcp -p 443:443/tcp -v "${CADDY_CONFIG_FILE}:/etc/caddy/Caddyfile:ro" -v "${CADDY_DATA_VOLUME}:/data" "${CADDY_IMAGE_NAME}"; then
                        log INFO "Caddy 部署成功。請等待幾分鐘讓 Caddy 申請證書。"
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

update_mihomo_warp_keys() {
    [ ! -f "$MIHOMO_CONFIG_FILE" ] && { log ERROR "設定檔不存在。"; return 1; }
    local domain; domain=$(grep 'cert:' "$MIHOMO_CONFIG_FILE" | head -n1 | sed -E 's/.*\/([a-zA-Z0-9.-]+)\/[a-zA-Z0-9.-]+\.crt.*/\1/')
    local password; password=$(grep 'password:' "$MIHOMO_CONFIG_FILE" | head -n1 | awk '{print $2}' | tr -d '"')
    
    local cert_path_info; cert_path_info=$(wait_and_detect_cert "$domain")
    if [ $? -ne 0 ]; then log ERROR "無法驗證證書路徑，請檢查 Caddy。"; return 1; fi
    local cert_path="${cert_path_info%%|*}"
    local key_path="${cert_path_info##*|}"

    log INFO "--- 更新 WARP 金鑰 ---"
    local private_key warp_address ipv4 ipv6
    read -p "PrivateKey: " private_key < /dev/tty
    read -p "Address (帶逗號的完整行): " warp_address < /dev/tty
    
    ipv4=$(echo "$warp_address" | awk -F, '{print $1}' | awk -F/ '{print $1}' | xargs)
    ipv6=$(echo "$warp_address" | awk -F, '{print $2}' | awk -F/ '{print $1}' | xargs)
    
    [[ -z "$ipv4" || -z "$private_key" ]] && { log ERROR "輸入無效。"; return 1; }
    
    generate_mihomo_config "$domain" "$password" "$private_key" "$ipv4" "$ipv6" "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=" "$cert_path" "$key_path"
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
                    
                    log INFO "正在驗證證書是否存在（請耐心等待，Caddy 申請證書需要時間）..."
                    local cert_path_info
                    if ! cert_path_info=$(wait_and_detect_cert "$HY_DOMAIN"); then
                        log ERROR "證書獲取失敗，Mihomo 安裝中止。"; press_any_key; break
                    fi
                    local cert_path="${cert_path_info%%|*}"
                    local key_path="${cert_path_info##*|}"

                    local PASSWORD=$(generate_random_password)
                    log INFO "已生成密碼: ${FontColor_Yellow}${PASSWORD}${FontColor_Suffix}"
                    
                    local p_key ipv4 ipv6 pub_key
                    read -p "自動生成 WARP 帳戶? (Y/n): " AUTO_WARP < /dev/tty
                    if [[ ! "$AUTO_WARP" =~ ^[nN]$ ]]; then
                        if ! generate_warp_conf; then press_any_key; break; fi
                        p_key=$(grep -oP 'PrivateKey = \K.*' "${MIHOMO_CONFIG_DIR}/wgcf-profile.conf")
                        pub_key=$(grep -oP 'PublicKey = \K.*' "${MIHOMO_CONFIG_DIR}/wgcf-profile.conf")
                        w_addrs=$(grep -oP 'Address = \K.*' "${MIHOMO_CONFIG_DIR}/wgcf-profile.conf")
                        ipv4=$(echo "$w_addrs" | awk -F, '{print $1}' | awk -F/ '{print $1}' | xargs)
                        ipv6=$(echo "$w_addrs" | awk -F, '{print $2}' | awk -F/ '{print $1}' | xargs)
                    else
                        read -p "PrivateKey: " p_key < /dev/tty
                        read -p "Address: " w_addr < /dev/tty
                        ipv4=$(echo "$w_addr" | awk -F, '{print $1}' | awk -F/ '{print $1}' | xargs)
                        ipv6=$(echo "$w_addr" | awk -F, '{print $2}' | awk -F/ '{print $1}' | xargs)
                        pub_key="bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
                    fi
                    
                    log INFO "正在拉取 Mihomo 鏡像..."
                    docker pull "${MIHOMO_IMAGE_NAME}"
                    generate_mihomo_config "$HY_DOMAIN" "$PASSWORD" "$p_key" "$ipv4" "$ipv6" "$pub_key" "$cert_path" "$key_path"
                    
                    log INFO "正在部署 Mihomo..."
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
        echo -e "\n${FontColor_Purple}Caddy + Mihomo 一鍵管理腳本${FontColor_Suffix} (v7.4.0)"
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
