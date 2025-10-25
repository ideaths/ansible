#!/usr/bin/env bash

# Preflight kiểm tra hệ thống cho RKE2 + Cilium (không dùng kube-proxy)
# Hỗ trợ Ubuntu/Debian, CentOS/RHEL. Xuất báo cáo dễ đọc, phù hợp CI/CD.
# Thoát với mã khác 0 nếu có kiểm tra FAILED.

set -euo pipefail

# Tùy chọn
NO_COLOR="false"
QUIET="false"
FORMAT="text" # text|json

# Màu sắc
if [[ -t 1 ]]; then
  RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[0;33m"; BLUE="\033[0;34m"; NC="\033[0m"
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; NC=""
fi

print_usage() {
  cat <<EOF
Preflight kiểm tra hệ thống cho RKE2+Cilium (không kube-proxy)

Sử dụng:
  $(basename "$0") [--no-color] [--quiet] [--format text|json]

Tuỳ chọn:
  --no-color       Tắt màu trong output
  --quiet          Chỉ in tóm tắt, giảm log chi tiết
  --format         Định dạng output: text (mặc định) hoặc json
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-color) NO_COLOR="true"; shift ;;
    --quiet) QUIET="true"; shift ;;
    --format) FORMAT="${2:-text}"; shift 2 ;;
    -h|--help) print_usage; exit 0 ;;
    *) echo "Unknown option: $1"; print_usage; exit 2 ;;
  esac
done

if [[ "${NO_COLOR}" == "true" ]]; then
  RED=""; GREEN=""; YELLOW=""; BLUE=""; NC="";
fi

# Thu thập kết quả
declare -a REPORT
declare -i FAIL_COUNT=0

pass() {
  local name="$1"; local msg="${2:-}";
  REPORT+=("PASS|$name|$msg")
  [[ "$QUIET" == "true" ]] || echo -e "[${GREEN}PASS${NC}] $name${msg:+ - $msg}"
}

fail() {
  local name="$1"; local msg="${2:-}"; local fix="${3:-}";
  REPORT+=("FAIL|$name|$msg|$fix")
  FAIL_COUNT+=1
  echo -e "[${RED}FAIL${NC}] $name${msg:+ - $msg}"
  [[ -n "$fix" ]] && echo -e "        Gợi ý: $fix"
}

warn() {
  local name="$1"; local msg="${2:-}"; local tip="${3:-}";
  REPORT+=("WARN|$name|$msg|$tip")
  if [[ "$QUIET" != "true" ]]; then
    echo -e "[${YELLOW}WARN${NC}] $name${msg:+ - $msg}"
    if [[ -n "$tip" ]]; then echo -e "        Mẹo: $tip"; fi
  fi
}

info() {
  [[ "$QUIET" == "true" ]] || echo -e "[INFO] $*"
}

# Tiện ích so sánh phiên bản (>=)
version_ge() {
  # return 0 if $1 >= $2
  local a="$1" b="$2"
  [[ "$(printf '%s\n' "$b" "$a" | sort -V | head -n1)" == "$b" ]]
}

# Lấy thông tin distro
get_distro() {
  local id="" ver="" like=""
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    id="$ID"; ver="$VERSION_ID"; like="${ID_LIKE:-}"
  fi
  echo "$id|$ver|$like"
}

# 1. Kiểm tra phiên bản kernel và module
check_kernel_version_and_modules() {
  local raw_kv kv min="4.9.17"
  raw_kv="$(uname -r)"
  kv="${raw_kv%%-*}" # chỉ lấy X.Y.Z
  if version_ge "$kv" "$min"; then
    pass "Kernel version" "$(uname -s) $raw_kv ≥ $min"
  else
    fail "Kernel version" "Đang là $raw_kv, yêu cầu ≥ $min" "Nâng cấp kernel lên ≥ $min (khuyến nghị 5.4+)."
  fi

  # Kiểm tra module bpfilter (có thể builtin hoặc không có)
  if grep -q '^bpfilter' /proc/modules 2>/dev/null; then
    pass "Kernel module: bpfilter" "Đã nạp"
  else
    # Có thể builtin, thử kiểm tra config
    if [[ -f "/boot/config-$(uname -r)" ]] && grep -qE '^CONFIG_BPFILTER=' "/boot/config-$(uname -r)"; then
      pass "Kernel module: bpfilter" "Builtin trong kernel"
    else
      warn "Kernel module: bpfilter" "Không thấy trong /proc/modules" "Nếu thiếu, cân nhắc bật CONFIG_BPFILTER hoặc nâng kernel."
    fi
  fi

  # BPF & cgroups: xác minh tính năng thay vì module
  if grep -q bpf /proc/filesystems; then
    pass "Kernel feature: BPF filesystem" "/proc/filesystems có bpf"
  else
    fail "Kernel feature: BPF filesystem" "Thiếu hỗ trợ bpf fs" "Bật CONFIG_BPF và CONFIG_BPF_SYSCALL; nâng cấp kernel."
  fi

  if mount | grep -q " on /sys/fs/cgroup"; then
    pass "Kernel feature: cgroups" "Đã mount cgroups"
  else
    fail "Kernel feature: cgroups" "Chưa mount /sys/fs/cgroup" "Bật cgroups (systemd, cgconfig) hoặc kiểm tra kernel params."
  fi
}

# 2. Kiểm tra cấu hình mạng: eBPF, sysctl, xung đột
check_network_and_sysctl() {
  # eBPF unprivileged
  local unpriv_bpf="/proc/sys/kernel/unprivileged_bpf_disabled"
  if [[ -f "$unpriv_bpf" ]]; then
    local v; v="$(cat "$unpriv_bpf" 2>/dev/null || echo 1)"
    if [[ "$v" == "0" ]]; then
      pass "eBPF unprivileged" "kernel.unprivileged_bpf_disabled=0"
    else
      warn "eBPF unprivileged" "kernel.unprivileged_bpf_disabled=$v" "Thiết lập về 0 để cho phép eBPF không đặc quyền (Ubuntu)."
    fi
  else
    warn "eBPF unprivileged" "Không có tham số trên distro này" "Bỏ qua nếu kernel đã hỗ trợ eBPF."
  fi

  # BPF JIT
  local bpf_jit="/proc/sys/net/core/bpf_jit_enable"
  if [[ -f "$bpf_jit" ]]; then
    local v; v="$(cat "$bpf_jit" 2>/dev/null || echo 0)"
    if [[ "$v" == "1" ]]; then
      pass "BPF JIT" "net.core.bpf_jit_enable=1"
    else
      fail "BPF JIT" "net.core.bpf_jit_enable=$v" "sysctl -w net.core.bpf_jit_enable=1 && lưu vào /etc/sysctl.d/*.conf"
    fi
  else
    warn "BPF JIT" "Không tìm thấy /proc/sys/net/core/bpf_jit_enable" "Kiểm tra kernel hỗ trợ BPF JIT."
  fi

  # IP forwarding (IPv4)
  local ipf="/proc/sys/net/ipv4/ip_forward"
  if [[ -f "$ipf" ]]; then
    local v; v="$(cat "$ipf")"
    if [[ "$v" == "1" ]]; then
      pass "IP forwarding (IPv4)" "net.ipv4.ip_forward=1"
    else
      fail "IP forwarding (IPv4)" "net.ipv4.ip_forward=$v" "sysctl -w net.ipv4.ip_forward=1"
    fi
  else
    warn "IP forwarding (IPv4)" "Không tìm thấy tham số" "Kiểm tra kernel IPv4."
  fi

  # rp_filter phải tắt cho Cilium
  local rp_all="/proc/sys/net/ipv4/conf/all/rp_filter"
  local rp_def="/proc/sys/net/ipv4/conf/default/rp_filter"
  local rp_ok=true
  for f in "$rp_all" "$rp_def"; do
    if [[ -f "$f" ]]; then
      local v; v="$(cat "$f")"
      if [[ "$v" != "0" ]]; then rp_ok=false; fi
    else
      rp_ok=false
    fi
  done
  if $rp_ok; then
    pass "Reverse path filter" "all/default rp_filter=0"
  else
    fail "Reverse path filter" "rp_filter != 0 hoặc thiếu" "sysctl -w net.ipv4.conf.all.rp_filter=0; net.ipv4.conf.default.rp_filter=0"
  fi

  # Redirects
  local r_all="/proc/sys/net/ipv4/conf/all/accept_redirects"
  local s_all="/proc/sys/net/ipv4/conf/all/send_redirects"
  local r_def="/proc/sys/net/ipv4/conf/default/accept_redirects"
  local s_def="/proc/sys/net/ipv4/conf/default/send_redirects"
  local ok_redir=true
  for f in "$r_all" "$s_all" "$r_def" "$s_def"; do
    if [[ -f "$f" ]]; then
      local v; v="$(cat "$f")"
      # Cilium khuyến cáo disable accepts; send_redirects=0
      if [[ "$f" == *accept_redirects && "$v" != "0" ]]; then ok_redir=false; fi
      if [[ "$f" == *send_redirects && "$v" != "0" ]]; then ok_redir=false; fi
    fi
  done
  if $ok_redir; then
    pass "ICMP redirects" "accept/send_redirects=0"
  else
    warn "ICMP redirects" "Một số cờ != 0" "sysctl -w net.ipv4.conf.{all,default}.accept_redirects=0; send_redirects=0"
  fi

  # Xung đột network manager/kube-proxy
  local conflicts=()
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet kube-proxy 2>/dev/null; then conflicts+=("kube-proxy.service đang chạy"); fi
    if systemctl is-active --quiet flannel 2>/dev/null; then conflicts+=("flannel.service đang chạy"); fi
    if systemctl is-active --quiet calico 2>/dev/null; then conflicts+=("calico.service đang chạy"); fi
    if systemctl is-active --quiet weave 2>/dev/null; then conflicts+=("weave.service đang chạy"); fi
  else
    if pgrep -f kube-proxy >/dev/null 2>&1; then conflicts+=("Tiến trình kube-proxy chạy"); fi
  fi
  if [[ ${#conflicts[@]} -eq 0 ]]; then
    pass "Xung đột network" "Không phát hiện xung đột với network manager khác"
  else
    fail "Xung đột network" "${conflicts[*]}" "Dừng các dịch vụ/tiến trình CNI khác khi dùng Cilium"
  fi
}

# 3. Yêu cầu phần cứng
check_hardware() {
  # CPU kiến trúc
  local arch; arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64|aarch64|arm64|ppc64le|s390x)
      pass "CPU kiến trúc" "$arch hỗ trợ eBPF"
      ;;
    *)
      warn "CPU kiến trúc" "$arch chưa được kiểm chứng" "Khuyến nghị x86_64 hoặc arm64 cho production."
      ;;
  esac

  # RAM >= 2GB
  local mem_kb; mem_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
  local mem_gb_str; mem_gb_str=$(awk -v kb="$mem_kb" 'BEGIN { printf "%.2f", kb/1024/1024 }')
  if (( mem_kb >= 2*1024*1024 )); then
    pass "RAM" "${mem_gb_str} GB"
  else
    fail "RAM" "${mem_gb_str} GB (<2GB)" "Nâng RAM tối thiểu 2GB."
  fi

  # Storage >= 10GB free tại /var
  local fs_path="/var"
  local free_mb; free_mb=$(df -Pm "$fs_path" | awk 'NR==2{print $4}')
  if (( free_mb >= 10240 )); then
    pass "Storage" "$fs_path còn trống ${free_mb} MB (≥ 10240 MB)"
  else
    fail "Storage" "$fs_path chỉ còn ${free_mb} MB" "Giải phóng dung lượng hoặc tăng partition (khuyến nghị ≥ 10GB)."
  fi
}

# 4. Bảo mật: SELinux/AppArmor, Firewall
check_security() {
  # SELinux
  if command -v getenforce >/dev/null 2>&1; then
    local se; se=$(getenforce || echo Permissive)
    case "$se" in
      Enforcing|Permissive)
        pass "SELinux" "Trạng thái: $se"
        ;;
      Disabled)
        warn "SELinux" "Đang Disabled" "Cilium có thể chạy, nhưng xem xét chính sách SELinux phù hợp."
        ;;
      *)
        warn "SELinux" "Trạng thái không rõ: $se" "Kiểm tra lại cấu hình SELinux."
        ;;
    esac
  else
    info "SELinux" "Không phát hiện getenforce, có thể hệ thống dùng AppArmor"
  fi

  # AppArmor
  if command -v aa-status >/dev/null 2>&1; then
    local aa_out; aa_out=$(aa-status 2>/dev/null || true)
    pass "AppArmor" "Phát hiện aa-status; đảm bảo profile không chặn Cilium"
    [[ "$QUIET" == "true" ]] || echo "$aa_out" | sed 's/^/        /'
  else
    info "AppArmor" "Không phát hiện aa-status"
  fi

  # Firewall (chi tiết)
  local firewalld_active=false ufw_active=false
  if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active --quiet firewalld && firewalld_active=true || true
    systemctl is-active --quiet ufw && ufw_active=true || true
  fi

  # firewalld checks
  if $firewalld_active; then
    warn "Firewall dịch vụ (firewalld)" "Đang active" "Đảm bảo rule không chặn traffic Cilium/RKE2"
    if command -v firewall-cmd >/dev/null 2>&1; then
      local zones; zones=$(firewall-cmd --get-zones 2>/dev/null || echo "")
      local found_6443=false found_9345=false found_10250=false
      local found_np_tcp=false found_np_udp=false
      local all_ports=""
      for z in $zones; do
        local ports; ports=$(firewall-cmd --zone="$z" --list-ports 2>/dev/null || echo "")
        all_ports+=" $ports"
        [[ "$ports" == *"6443/tcp"* ]] && found_6443=true
        [[ "$ports" == *"9345/tcp"* ]] && found_9345=true
        [[ "$ports" == *"10250/tcp"* ]] && found_10250=true
        [[ "$ports" == *"30000-32767/tcp"* ]] && found_np_tcp=true
        [[ "$ports" == *"30000-32767/udp"* ]] && found_np_udp=true
      done
      if $found_6443 && $found_9345 && $found_10250; then
        pass "firewalld ports" "Đã mở 6443/tcp, 9345/tcp, 10250/tcp"
      else
        local missing=()
        $found_6443 || missing+=("6443/tcp")
        $found_9345 || missing+=("9345/tcp")
        $found_10250 || missing+=("10250/tcp")
        warn "firewalld ports" "Thiếu: ${missing[*]}" "firewall-cmd --permanent --add-port=<port>/tcp; firewall-cmd --reload"
      fi
      if $found_np_tcp && $found_np_udp; then
        pass "firewalld NodePort" "Đã mở 30000-32767/tcp,udp"
      else
        warn "firewalld NodePort" "Chưa mở đủ NodePort" "firewall-cmd --permanent --add-port=30000-32767/tcp; firewall-cmd --permanent --add-port=30000-32767/udp; firewall-cmd --reload"
      fi
      # Kiểm tra thêm các cổng theo yêu cầu
      local req_tcp=(
        "179/tcp" "9345/tcp" "6443/tcp" "10250/tcp" "2379-2381/tcp" "4240/tcp" "4244/tcp" "4245/tcp"
        "4222/tcp" "9966/tcp" "4250-4251/tcp" "6060-6062/tcp" "9878-9879/tcp" "9890-9893/tcp" "9901/tcp"
        "9962-9964/tcp" "80/tcp" "443/tcp"
      )
      local req_udp=("8472/udp" "6081/udp" "51871/udp")
      local missing_fw_tcp=() missing_fw_udp=()
      for p in "${req_tcp[@]}"; do
        [[ "$all_ports" == *"$p"* ]] || missing_fw_tcp+=("$p")
      done
      for p in "${req_udp[@]}"; do
        [[ "$all_ports" == *"$p"* ]] || missing_fw_udp+=("$p")
      done
      if [[ ${#missing_fw_tcp[@]} -eq 0 && ${#missing_fw_udp[@]} -eq 0 ]]; then
        pass "firewalld thêm cổng" "Tất cả cổng yêu cầu đã mở"
      else
        local msg=""
        [[ ${#missing_fw_tcp[@]} -gt 0 ]] && msg+="TCP thiếu: ${missing_fw_tcp[*]} "
        [[ ${#missing_fw_udp[@]} -gt 0 ]] && msg+="UDP thiếu: ${missing_fw_udp[*]}"
        warn "firewalld thêm cổng" "$msg" "firewall-cmd --permanent --add-port=<port>/proto; firewall-cmd --reload"
      fi
      # Masquerade (NAT) trên firewalld
      local has_masq=false
      for z in $zones; do
        if firewall-cmd --zone="$z" --query-masquerade >/dev/null 2>&1 && firewall-cmd --zone="$z" --query-masquerade; then
          has_masq=true
          break
        fi
      done
      if $has_masq; then
        pass "firewalld masquerade" "Ít nhất một zone bật masquerade"
      else
        warn "firewalld masquerade" "Chưa bật masquerade tại các zone" "Bật NAT nếu cần: firewall-cmd --zone=<zone> --add-masquerade --permanent; firewall-cmd --reload"
      fi
    else
      info "firewalld" "Đang active nhưng không có firewall-cmd để kiểm tra chi tiết"
    fi
  else
    pass "Firewall dịch vụ (firewalld)" "Không active"
  fi

  # UFW checks
  if $ufw_active; then
    warn "Firewall dịch vụ (ufw)" "Đang active" "Đảm bảo rule không chặn traffic Cilium/RKE2"
    local ufw_status; ufw_status=$(ufw status verbose 2>/dev/null || ufw status 2>/dev/null || echo "")
    local found_6443=false found_9345=false found_10250=false
    local found_np_tcp=false found_np_udp=false
    [[ "$ufw_status" =~ 6443/tcp ]] && found_6443=true
    [[ "$ufw_status" =~ 9345/tcp ]] && found_9345=true
    [[ "$ufw_status" =~ 10250/tcp ]] && found_10250=true
    [[ "$ufw_status" =~ 30000:32767/tcp ]] && found_np_tcp=true
    [[ "$ufw_status" =~ 30000:32767/udp ]] && found_np_udp=true

    if $found_6443 && $found_9345 && $found_10250; then
      pass "ufw ports" "Đã mở 6443/tcp, 9345/tcp, 10250/tcp"
    else
      local missing=()
      $found_6443 || missing+=("6443/tcp")
      $found_9345 || missing+=("9345/tcp")
      $found_10250 || missing+=("10250/tcp")
      warn "ufw ports" "Thiếu: ${missing[*]}" "ufw allow <port>/tcp"
    fi
    if $found_np_tcp && $found_np_udp; then
      pass "ufw NodePort" "Đã mở 30000:32767/tcp,udp"
    else
      warn "ufw NodePort" "Chưa mở đủ NodePort" "ufw allow 30000:32767/tcp; ufw allow 30000:32767/udp"
    fi

    # DEFAULT_FORWARD_POLICY
    local forward_policy
    if [[ -f /etc/default/ufw ]]; then
      forward_policy=$(awk -F'=' '/^DEFAULT_FORWARD_POLICY/{print $2}' /etc/default/ufw | tr -d '"' | tr -d ' ')
    fi
    if [[ "$forward_policy" == "ACCEPT" ]]; then
      pass "ufw forward policy" "DEFAULT_FORWARD_POLICY=ACCEPT"
    else
      warn "ufw forward policy" "DEFAULT_FORWARD_POLICY không phải ACCEPT" "sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY=\"ACCEPT\"/' /etc/default/ufw; ufw reload"
    fi

    # Kiểm tra thêm các cổng theo yêu cầu
    local req_tcp=(
      "179/tcp" "9345/tcp" "6443/tcp" "10250/tcp" "2379-2381/tcp" "4240/tcp" "4244/tcp" "4245/tcp"
      "4222/tcp" "9966/tcp" "4250-4251/tcp" "6060-6062/tcp" "9878-9879/tcp" "9890-9893/tcp" "9901/tcp"
      "9962-9964/tcp" "80/tcp" "443/tcp"
    )
    local req_udp=("8472/udp" "6081/udp" "51871/udp")
    local missing_ufw_tcp=() missing_ufw_udp=()
    for p in "${req_tcp[@]}"; do
      local match="$p"
      if [[ "$p" == *"-"* ]]; then match="${p/-/:}"; fi
      echo "$ufw_status" | grep -E "(^|\s)${match}" >/dev/null || missing_ufw_tcp+=("$p")
    done
    for p in "${req_udp[@]}"; do
      local match="$p"
      if [[ "$p" == *"-"* ]]; then match="${p/-/:}"; fi
      echo "$ufw_status" | grep -E "(^|\s)${match}" >/dev/null || missing_ufw_udp+=("$p")
    done
    if [[ ${#missing_ufw_tcp[@]} -eq 0 && ${#missing_ufw_udp[@]} -eq 0 ]]; then
      pass "ufw thêm cổng" "Tất cả cổng yêu cầu đã mở"
    else
      local msg=""
      [[ ${#missing_ufw_tcp[@]} -gt 0 ]] && msg+="TCP thiếu: ${missing_ufw_tcp[*]} "
      [[ ${#missing_ufw_udp[@]} -gt 0 ]] && msg+="UDP thiếu: ${missing_ufw_udp[*]}"
      warn "ufw thêm cổng" "$msg" "ufw allow <port>/proto; ufw reload"
    fi
  else
    pass "Firewall dịch vụ (ufw)" "Không active"
  fi

  # Phát hiện backend iptables (nf_tables vs legacy)
  local ipt_v; ipt_v=$(iptables -V 2>/dev/null || true)
  local ip6t_v; ip6t_v=$(ip6tables -V 2>/dev/null || true)
  local ipt_backend="unknown" ip6t_backend="unknown"
  [[ "$ipt_v" =~ \(nf_tables\) ]] && ipt_backend="nf_tables"
  [[ "$ipt_v" =~ \(legacy\) ]] && ipt_backend="legacy"
  [[ "$ip6t_v" =~ \(nf_tables\) ]] && ip6t_backend="nf_tables"
  [[ "$ip6t_v" =~ \(legacy\) ]] && ip6t_backend="legacy"
  if [[ "$ipt_backend" == "nf_tables" && "$ip6t_backend" == "nf_tables" ]]; then
    pass "iptables backend" "iptables/ip6tables dùng nf_tables"
  elif [[ "$ipt_backend" == "legacy" || "$ip6t_backend" == "legacy" ]]; then
    warn "iptables backend" "Phát hiện backend legacy: iptables=$ipt_backend, ip6tables=$ip6t_backend" "Khuyến nghị chuyển sang nft: update-alternatives --set iptables /usr/sbin/iptables-nft; update-alternatives --set ip6tables /usr/sbin/ip6tables-nft"
  else
    info "iptables backend" "Không xác định backend: iptables='$ipt_v' ip6tables='$ip6t_v'"
  fi

  # iptables chính sách mặc định
  local pol_in; pol_in=$(iptables -S INPUT 2>/dev/null | awk '$1=="-P"{print $3}')
  local pol_out; pol_out=$(iptables -S OUTPUT 2>/dev/null | awk '$1=="-P"{print $3}')
  local pol_fwd; pol_fwd=$(iptables -S FORWARD 2>/dev/null | awk '$1=="-P"{print $3}')
  if [[ -n "$pol_in" || -n "$pol_out" || -n "$pol_fwd" ]]; then
    if [[ "$pol_in" == "DROP" || "$pol_fwd" == "DROP" ]]; then
      warn "iptables policy" "INPUT/FORWARD=DROP" "Đảm bảo các rule cho phép traffic Cilium (vxlan/direct routing)"
    else
      pass "iptables policy" "INPUT=$pol_in, OUTPUT=$pol_out, FORWARD=$pol_fwd"
    fi
  else
    info "iptables policy" "Không thể đọc chính sách (thiếu quyền hoặc iptables không cài)"
  fi

  # Kiểm tra bổ sung FORWARD: cần RELATED,ESTABLISHED
  local has_est=false
  if iptables -S FORWARD 2>/dev/null | grep -q -- "--ctstate RELATED,ESTABLISHED -j ACCEPT"; then
    has_est=true
  elif iptables -S FORWARD 2>/dev/null | grep -q -- "--ctstate ESTABLISHED,RELATED -j ACCEPT"; then
    has_est=true
  fi
  if $has_est; then
    pass "iptables FORWARD" "Có rule ACCEPT cho RELATED,ESTABLISHED"
  else
    warn "iptables FORWARD" "Thiếu rule ACCEPT cho RELATED,ESTABLISHED" "iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
  fi
}

# Escape chuỗi cho JSON
json_escape() {
  local s; s=$1
  s=${s//\/\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  printf '%s' "$s"
}

# Xuất báo cáo
emit_report() {
  local fmt="$FORMAT"
  if [[ "$fmt" == "json" ]]; then
    echo -n '{"checks":['
    local first=1
    for line in "${REPORT[@]}"; do
      IFS='|' read -r status name msg fix <<<"$line"
      [[ $first -eq 0 ]] && echo -n ',' || first=0
      local sname smsg sfix
      sname=$(json_escape "$name")
      smsg=$(json_escape "$msg")
      sfix=$(json_escape "$fix")
      printf '{"status":"%s","name":"%s","message":"%s"' "${status}" "$sname" "$smsg"
      if [[ -n "$fix" ]]; then
        printf ',"remediation":"%s"' "$sfix"
      fi
      echo -n '}'
    done
    printf '],"failures":%d}\n' "$FAIL_COUNT"
  else
    echo -e "\n========== Báo cáo Preflight =========="
    for line in "${REPORT[@]}"; do
      IFS='|' read -r status name msg fix <<<"$line"
      case "$status" in
        PASS) echo -e "[${GREEN}PASS${NC}] $name${msg:+ - $msg}" ;;
        FAIL) echo -e "[${RED}FAIL${NC}] $name${msg:+ - $msg}" ; [[ -n "$fix" ]] && echo -e "        Gợi ý: $fix" ;;
        WARN) echo -e "[${YELLOW}WARN${NC}] $name${msg:+ - $msg}" ; [[ -n "$fix" ]] && echo -e "        Mẹo: $fix" ;;
      esac
    done
    echo -e "--------------------------------------"
    echo -e "Tổng số lỗi: $FAIL_COUNT"
  fi
}

main() {
  local distro; distro=$(get_distro)
  IFS='|' read -r did dver dlike <<<"$distro"
  info "Phát hiện hệ điều hành: ID=$did VERSION_ID=$dver ID_LIKE=$dlike"

  check_kernel_version_and_modules
  check_network_and_sysctl
  check_hardware
  check_security

  emit_report

  if (( FAIL_COUNT > 0 )); then
    exit 1
  else
    exit 0
  fi
}

main "$@"

main() {
  local distro; distro=$(get_distro)
  IFS='|' read -r did dver dlike <<<"$distro"
  info "Phát hiện hệ điều hành: ID=$did VERSION_ID=$dver ID_LIKE=$dlike"

  check_kernel_version_and_modules
  check_network_and_sysctl
  check_hardware
  check_security

  emit_report

  if (( FAIL_COUNT > 0 )); then
    exit 1
  else
    exit 0
  fi
}

main "$@"

# Chi tiết firewall: firewalld
check_firewalld_details() {
  if ! command -v firewall-cmd >/dev/null 2>&1; then
    info "firewalld" "Không tìm thấy firewall-cmd"
    return
  fi
  local def_zone; def_zone=$(firewall-cmd --get-default-zone 2>/dev/null || echo "")
  local zones; zones=$(firewall-cmd --get-zones 2>/dev/null || echo "")
  local found_6443=false found_9345=false found_10250=false
  local found_np_tcp=false found_np_udp=false
  for z in $zones; do
    local ports; ports=$(firewall-cmd --zone="$z" --list-ports 2>/dev/null || echo "")
    [[ "$ports" == *"6443/tcp"* ]] && found_6443=true
    [[ "$ports" == *"9345/tcp"* ]] && found_9345=true
    [[ "$ports" == *"10250/tcp"* ]] && found_10250=true
    [[ "$ports" == *"30000-32767/tcp"* ]] && found_np_tcp=true
    [[ "$ports" == *"30000-32767/udp"* ]] && found_np_udp=true
  done
  if $found_6443 && $found_9345 && $found_10250; then
    pass "firewalld ports" "Đã mở 6443/tcp, 9345/tcp, 10250/tcp"
  else
    local missing=()
    $found_6443 || missing+=("6443/tcp")
    $found_9345 || missing+=("9345/tcp")
    $found_10250 || missing+=("10250/tcp")
    fail "firewalld ports" "Thiếu: ${missing[*]}" "firewall-cmd --permanent --add-port=<port>/tcp; firewall-cmd --reload"
  fi
  if $found_np_tcp && $found_np_udp; then
    pass "firewalld NodePort" "Đã mở 30000-32767/tcp,udp"
  else
    warn "firewalld NodePort" "Chưa mở đủ NodePort" "firewall-cmd --permanent --add-port=30000-32767/tcp --add-port=30000-32767/udp; firewall-cmd --reload"
  fi
  if [[ -n "$def_zone" ]]; then
    local mz; mz=$(firewall-cmd --zone="$def_zone" --query-masquerade 2>/dev/null || echo "no")
    info "firewalld masquerade" "Zone mặc định: $def_zone, masquerade: $mz"
  fi
}

# Chi tiết firewall: ufw
check_ufw_details() {
  if ! command -v ufw >/dev/null 2>&1; then
    info "ufw" "Không tìm thấy ufw"
    return
  fi
  local ufw_out; ufw_out=$(ufw status verbose 2>/dev/null || true)
  local status_line; status_line=$(echo "$ufw_out" | awk '/^Status:/{print $0}')
  local default_line; default_line=$(echo "$ufw_out" | awk '/^Default:/{print $0}')
  [[ -n "$status_line" ]] && info "ufw" "$status_line"
  [[ -n "$default_line" ]] && info "ufw" "$default_line"

  local has_6443=false has_9345=false has_10250=false has_np_tcp=false has_np_udp=false
  echo "$ufw_out" | grep -E '(^|\s)6443/tcp' >/dev/null && has_6443=true || true
  echo "$ufw_out" | grep -E '(^|\s)9345/tcp' >/dev/null && has_9345=true || true
  echo "$ufw_out" | grep -E '(^|\s)10250/tcp' >/dev/null && has_10250=true || true
  echo "$ufw_out" | grep -E '(^|\s)30000:32767/tcp' >/dev/null && has_np_tcp=true || true
  echo "$ufw_out" | grep -E '(^|\s)30000:32767/udp' >/dev/null && has_np_udp=true || true

  if $has_6443 && $has_9345 && $has_10250; then
    pass "ufw ports" "Đã mở 6443/tcp, 9345/tcp, 10250/tcp"
  else
    local missing=()
    $has_6443 || missing+=("6443/tcp")
    $has_9345 || missing+=("9345/tcp")
    $has_10250 || missing+=("10250/tcp")
    warn "ufw ports" "Thiếu: ${missing[*]}" "ufw allow <port>/tcp; ufw reload"
  fi

  if $has_np_tcp && $has_np_udp; then
    pass "ufw NodePort" "Đã mở 30000:32767/tcp,udp"
  else
    warn "ufw NodePort" "Chưa mở đủ NodePort" "ufw allow 30000:32767/tcp; ufw allow 30000:32767/udp; ufw reload"
  fi

  # Kiểm tra DEFAULT_FORWARD_POLICY
  local fpol=""
  if [[ -f /etc/default/ufw ]]; then
    fpol=$(awk -F'=' '/^DEFAULT_FORWARD_POLICY/{print $2}' /etc/default/ufw | tr -d '"')
    if [[ "$fpol" == "ACCEPT" ]]; then
      pass "ufw forward policy" "DEFAULT_FORWARD_POLICY=ACCEPT"
    else
      warn "ufw forward policy" "DEFAULT_FORWARD_POLICY=${fpol:-unknown}" "Sửa /etc/default/ufw: DEFAULT_FORWARD_POLICY=\"ACCEPT\" và ufw reload"
    fi
  else
    info "ufw forward policy" "Không tìm thấy /etc/default/ufw"
  fi
}

# Chi tiết iptables FORWARD
check_iptables_forward_details() {
  if ! command -v iptables >/dev/null 2>&1; then
    info "iptables" "Không tìm thấy iptables"
    return
  fi
  if iptables -C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
    pass "iptables FORWARD" "Có rule ACCEPT cho RELATED,ESTABLISHED"
  else
    warn "iptables FORWARD" "Thiếu rule RELATED,ESTABLISHED" "iptables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
  fi
}

# Phát hiện backend iptables (nf_tables vs legacy)
local ipt_v; ipt_v=$(iptables -V 2>/dev/null || true)
local ip6t_v; ip6t_v=$(ip6tables -V 2>/dev/null || true)
local ipt_backend="unknown" ip6t_backend="unknown"
[[ "$ipt_v" =~ \(nf_tables\) ]] && ipt_backend="nf_tables"
[[ "$ipt_v" =~ \(legacy\) ]] && ipt_backend="legacy"
[[ "$ip6t_v" =~ \(nf_tables\) ]] && ip6t_backend="nf_tables"
[[ "$ip6t_v" =~ \(legacy\) ]] && ip6t_backend="legacy"
if [[ "$ipt_backend" == "nf_tables" && "$ip6t_backend" == "nf_tables" ]]; then
  pass "iptables backend" "iptables/ip6tables dùng nf_tables"
elif [[ "$ipt_backend" == "legacy" || "$ip6t_backend" == "legacy" ]]; then
  warn "iptables backend" "Phát hiện backend legacy: iptables=$ipt_backend, ip6tables=$ip6t_backend" "Khuyến nghị chuyển sang nft: update-alternatives --set iptables /usr/sbin/iptables-nft; update-alternatives --set ip6tables /usr/sbin/ip6tables-nft"
else
  info "iptables backend" "Không xác định backend: iptables='$ipt_v' ip6tables='$ip6t_v'"
fi

# Escape chuỗi cho JSON
json_escape() {
  local s; s=$1
  s=${s//\/\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  printf '%s' "$s"
}

# Xuất báo cáo
emit_report() {
  local fmt="$FORMAT"
  if [[ "$fmt" == "json" ]]; then
    echo -n '{"checks":['
    local first=1
    for line in "${REPORT[@]}"; do
      IFS='|' read -r status name msg fix <<<"$line"
      [[ $first -eq 0 ]] && echo -n ',' || first=0
      local sname smsg sfix
      sname=$(json_escape "$name")
      smsg=$(json_escape "$msg")
      sfix=$(json_escape "$fix")
      printf '{"status":"%s","name":"%s","message":"%s"' "${status}" "$sname" "$smsg"
      if [[ -n "$fix" ]]; then
        printf ',"remediation":"%s"' "$sfix"
      fi
      echo -n '}'
    done
    printf '],"failures":%d}\n' "$FAIL_COUNT"
  else
    echo -e "\n========== Báo cáo Preflight =========="
    for line in "${REPORT[@]}"; do
      IFS='|' read -r status name msg fix <<<"$line"
      case "$status" in
        PASS) echo -e "[${GREEN}PASS${NC}] $name${msg:+ - $msg}" ;;
        FAIL) echo -e "[${RED}FAIL${NC}] $name${msg:+ - $msg}" ; [[ -n "$fix" ]] && echo -e "        Gợi ý: $fix" ;;
        WARN) echo -e "[${YELLOW}WARN${NC}] $name${msg:+ - $msg}" ; [[ -n "$fix" ]] && echo -e "        Mẹo: $fix" ;;
      esac
    done
    echo -e "--------------------------------------"
    echo -e "Tổng số lỗi: $FAIL_COUNT"
  fi
}

main() {
  local distro; distro=$(get_distro)
  IFS='|' read -r did dver dlike <<<"$distro"
  info "Phát hiện hệ điều hành: ID=$did VERSION_ID=$dver ID_LIKE=$dlike"

  check_kernel_version_and_modules
  check_network_and_sysctl
  check_hardware
  check_security

  emit_report

  if (( FAIL_COUNT > 0 )); then
    exit 1
  else
    exit 0
  fi
}

main "$@"