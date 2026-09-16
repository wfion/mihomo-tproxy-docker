#!/bin/sh
# 使用 iptables 版 TProxy 规则

MIHOMO_PORT=7893
MIHOMO_DNS_PORT=1053
TPROXY_MARK=1
ROUTE_TABLE=100

CN_IP_FILE="/mihomo/config/cn_cidr.txt"
LOCAL_CONFIG_FILE="/mihomo/config/config.yaml"
OVERRIDE_CONFIG_FILE="/mihomo/config/override.yaml"
RUNTIME_CONFIG_DIR="/tmp/mihomo-runtime"
RUNTIME_CONFIG_FILE="$RUNTIME_CONFIG_DIR/config.yaml"

RESERVED_IPS="0.0.0.0/8 10.0.0.0/8 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4"

fail() {
    echo "Error: $*" >&2
    exit 1
}

prepare_config() {
    umask 077
    base_config="$LOCAL_CONFIG_FILE"
    effective_config="$LOCAL_CONFIG_FILE"
    generated_config="false"

    if [ -n "${CONFIG_URL:-}" ] && [ -f "$LOCAL_CONFIG_FILE" ]; then
        echo "*** Using local Mihomo configuration while remote configuration updates in background ***"
        return
    elif [ -n "${CONFIG_URL:-}" ]; then
        mkdir -p "$RUNTIME_CONFIG_DIR"
        download_file="$RUNTIME_CONFIG_DIR/config.download"
        echo "*** Downloading Mihomo configuration ***"
        if ! curl --noproxy "*" --fail --location --silent --show-error \
            --connect-timeout 15 --max-time 60 --retry 2 \
            --user-agent "${CONFIG_USER_AGENT:-clash.meta}" \
            --output "$download_file" "$CONFIG_URL"; then
            fail "Failed to download the Mihomo configuration."
        fi
        if [ ! -s "$download_file" ]; then
            fail "Downloaded Mihomo configuration is empty."
        fi
        base_config="$download_file"
        effective_config="$download_file"
        generated_config="true"
    elif [ ! -f "$LOCAL_CONFIG_FILE" ]; then
        fail "Mihomo configuration not found: $LOCAL_CONFIG_FILE"
    fi

    if [ -e "$OVERRIDE_CONFIG_FILE" ] && [ ! -f "$OVERRIDE_CONFIG_FILE" ]; then
        fail "Override configuration is not a regular file: $OVERRIDE_CONFIG_FILE"
    fi

    if [ -f "$OVERRIDE_CONFIG_FILE" ]; then
        if ! yq eval --exit-status 'tag == "!!map"' "$OVERRIDE_CONFIG_FILE" >/dev/null; then
            fail "Override configuration must be a YAML mapping."
        fi
        if ! yq eval --exit-status '(keys | length == 1) and (keys | .[0] == "rules")' "$OVERRIDE_CONFIG_FILE" >/dev/null; then
            fail "Override configuration may only contain the top-level 'rules' field."
        fi
        if ! yq eval --exit-status '.rules | tag == "!!seq"' "$OVERRIDE_CONFIG_FILE" >/dev/null; then
            fail "Override configuration 'rules' must be a YAML array."
        fi
        if ! yq eval --exit-status '.rules == null or (.rules | tag == "!!seq")' "$base_config" >/dev/null; then
            fail "Base configuration 'rules' must be a YAML array when present."
        fi

        mkdir -p "$RUNTIME_CONFIG_DIR"
        merged_file="$RUNTIME_CONFIG_DIR/config.merged"
        if ! OVERRIDE_CONFIG_FILE="$OVERRIDE_CONFIG_FILE" yq eval \
            '.rules = (load(strenv(OVERRIDE_CONFIG_FILE)).rules + (.rules // []))' \
            "$base_config" > "$merged_file"; then
            fail "Failed to merge the override rules."
        fi
        mv "$merged_file" "$RUNTIME_CONFIG_FILE"
        effective_config="$RUNTIME_CONFIG_FILE"
        generated_config="true"
    fi

    if [ "$generated_config" = "true" ]; then
        echo "*** Checking generated Mihomo configuration ***"
        if ! /mihomo/mihomo -t -d /mihomo/config -f "$effective_config"; then
            fail "Generated Mihomo configuration is invalid."
        fi
        MIHOMO_CONFIG_FILE="$effective_config"
    else
        MIHOMO_CONFIG_FILE=""
    fi
}

update_config_in_background() {
    [ -n "${CONFIG_URL:-}" ] || return 0
    [ -f "$LOCAL_CONFIG_FILE" ] || return 0
    (
        sleep "${CONFIG_UPDATE_DELAY:-30}"
        update_file="$RUNTIME_CONFIG_DIR/config.update"
        mkdir -p "$RUNTIME_CONFIG_DIR"
        echo "*** Updating Mihomo configuration in background ***"
        if curl --fail --location --silent --show-error \
            --connect-timeout 15 --max-time 60 --retry 2 \
            --user-agent "${CONFIG_USER_AGENT:-clash.meta}" \
            --output "$update_file" "$CONFIG_URL" && [ -s "$update_file" ] && \
            /mihomo/mihomo -t -d /mihomo/config -f "$update_file" >/dev/null 2>&1; then
            cp "$update_file" "${LOCAL_CONFIG_FILE}.new" &&
            mv "${LOCAL_CONFIG_FILE}.new" "$LOCAL_CONFIG_FILE"
            echo "*** Mihomo configuration updated; reloading ***"
            kill -HUP "$mihomo_pid" 2>/dev/null || true
        else
            echo "Warning: background Mihomo configuration update failed." >&2
            rm -f "$update_file"
        fi
    ) &
}

# 校验环境变量
if [ "$BYPASS_CN" != "true" ] && [ "$BYPASS_CN" != "false" ]; then
    echo "Error: '\$BYPASS_CN' Must be 'true' or 'false'."
    exit 1
fi

if [ "$QUIC" != "true" ] && [ "$QUIC" != "false" ]; then
    echo "Error: '\$QUIC' Must be 'true' or 'false'."
    exit 1
fi

if [ "$CONTAINER_PROXY" != "true" ] && [ "$CONTAINER_PROXY" != "false" ]; then
    echo "Error: '\$CONTAINER_PROXY' Must be 'true' or 'false'."
    exit 1
fi

# 在修改网络规则前下载、合并并校验配置。
prepare_config

# 路由标记
ip rule add fwmark $TPROXY_MARK table $ROUTE_TABLE 2>/dev/null
ip route add local 0.0.0.0/0 dev lo table $ROUTE_TABLE 2>/dev/null

# 清理已有规则
iptables -t mangle -F
iptables -t mangle -X clash 2>/dev/null
iptables -t mangle -N clash

# 保留地址不代理
for ip in $RESERVED_IPS; do
    iptables -t mangle -A clash -d $ip -j RETURN
done

# 中国大陆 IP 分流
if [ "$BYPASS_CN" = "true" ] && [ -f "$CN_IP_FILE" ]; then
    while read -r ip; do
        case "$ip" in
            \#*|"") continue ;;
        esac
        iptables -t mangle -A clash -d "$ip" -j RETURN
    done < "$CN_IP_FILE"
fi

# 禁用 QUIC
if [ "$QUIC" = "false" ]; then
    iptables -t mangle -A clash -p udp --dport 443 -j DROP
fi

# TProxy 转发
iptables -t mangle -A clash -p udp -j TPROXY --on-port $MIHOMO_PORT --tproxy-mark $TPROXY_MARK
iptables -t mangle -A clash -p tcp -j TPROXY --on-port $MIHOMO_PORT --tproxy-mark $TPROXY_MARK

# DNS 劫持
#iptables -t mangle -A PREROUTING -p udp --dport 53 -j TPROXY --on-port $MIHOMO_DNS_PORT --tproxy-mark $TPROXY_MARK

# 应用 chain
iptables -t mangle -A PREROUTING -j clash

echo "*** Starting Mihomo ***"
if [ -n "$MIHOMO_CONFIG_FILE" ] && [ "${1:-}" = "/mihomo/mihomo" ]; then
    set -- "$@" -f "$MIHOMO_CONFIG_FILE"
fi
if [ -n "${CONFIG_URL:-}" ] && [ -f "$LOCAL_CONFIG_FILE" ]; then
    "$@" &
    mihomo_pid=$!
    update_config_in_background
    wait "$mihomo_pid"
else
    exec "$@"
fi
