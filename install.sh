#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() {
  echo "error: $*" >&2
  exit 1
}

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "run as root: sudo bash install.sh"
  fi
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

ensure_group() {
  local group="$1"
  if getent group "${group}" >/dev/null 2>&1; then
    return 0
  fi
  if has_cmd groupadd; then
    groupadd --system "${group}" || true
    return 0
  fi
  if has_cmd addgroup; then
    addgroup --system "${group}" || true
    return 0
  fi
}

detect_iface() {
  local iface=""
  iface="$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -n 1 || true)"
  if [[ -z "${iface}" ]]; then
    die "could not auto-detect network interface. pass IFACE env var, e.g. IFACE=eth0 sudo bash install.sh"
  fi

  # If bonding is used, prefer first physical slave.
  if [[ -f "/sys/class/net/${iface}/bonding/slaves" ]]; then
    local slaves
    slaves="$(cat "/sys/class/net/${iface}/bonding/slaves" || true)"
    iface="$(awk '{print $1}' <<<"${slaves}")"
  fi

  echo "${iface}"
}

choose_iface_interactive() {
  local def_iface
  def_iface="$(detect_iface)"

  if [[ ! -t 0 ]]; then
    echo "${def_iface}"
    return 0
  fi

  local ifaces
  ifaces=()
  while IFS= read -r line; do
    local name
    name="$(awk -F': ' '{print $2}' <<<"${line}")"
    [[ "${name}" == "lo" ]] && continue
    ifaces+=("${name}")
  done < <(ip -o link show)

  if [[ ${#ifaces[@]} -eq 0 ]]; then
    echo "${def_iface}"
    return 0
  fi

  echo "Select network interface for XDP:"
  local i=1
  for iface in "${ifaces[@]}"; do
    if [[ "${iface}" == "${def_iface}" ]]; then
      echo "  ${i}) ${iface} (default)"
    else
      echo "  ${i}) ${iface}"
    fi
    i=$((i+1))
  done
  printf "Enter number (default %s): " "${def_iface}"
  read -r choice
  if [[ -z "${choice}" ]]; then
    echo "${def_iface}"
    return 0
  fi
  if [[ "${choice}" =~ ^[0-9]+$ ]]; then
    local idx=$((choice-1))
    if [[ ${idx} -ge 0 && ${idx} -lt ${#ifaces[@]} ]]; then
      echo "${ifaces[$idx]}"
      return 0
    fi
  fi
  echo "${def_iface}"
}

choose_xdp_mode_interactive() {
  local def_mode="driver"
  if [[ ! -t 0 ]]; then
    echo "${def_mode}"
    return 0
  fi
  echo "Select XDP mode:"
  echo "  1) driver (fastest, native)"
  echo "  2) generic (skb fallback)"
  echo "  3) hw (offload, if supported)"
  printf "Enter number (default %s): " "${def_mode}"
  read -r choice
  case "${choice}" in
    1|"") echo "driver" ;;
    2) echo "generic" ;;
    3) echo "hw" ;;
    *) echo "${def_mode}" ;;
  esac
}

install_deps() {
  if has_cmd apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y \
      ca-certificates curl \
      build-essential make gcc \
      clang llvm llvm-strip \
      bpftool \
      libbpf-dev libelf-dev libsystemd-dev \
      linux-headers-"$(uname -r)" \
      netcat-openbsd
    return 0
  fi

  if has_cmd dnf; then
    dnf install -y \
      ca-certificates curl \
      make gcc clang llvm \
      bpftool \
      libbpf-devel elfutils-libelf-devel systemd-devel \
      kernel-devel-"$(uname -r)" kernel-headers-"$(uname -r)" \
      nmap-ncat || true
    return 0
  fi

  if has_cmd yum; then
    yum install -y \
      ca-certificates curl \
      make gcc clang llvm \
      bpftool \
      libbpf-devel elfutils-libelf-devel systemd-devel \
      kernel-devel-"$(uname -r)" kernel-headers-"$(uname -r)" \
      nmap-ncat || true
    return 0
  fi

  die "unsupported distro: install dependencies manually (clang, llvm, bpftool, libbpf, libelf, kernel headers)"
}

build_core() {
  [[ -r /sys/kernel/btf/vmlinux ]] || die "missing BTF: /sys/kernel/btf/vmlinux not found (need kernel with BTF enabled, usually 5.4+)"
  make -C "${ROOT_DIR}/core" clean
  make -C "${ROOT_DIR}/core" all
  make -C "${ROOT_DIR}/core" install
}

install_systemd() {
  mkdir -p /etc/honeyban
  if [[ ! -f /etc/honeyban/honeyban.env ]]; then
    install -m 0644 "${ROOT_DIR}/core/packaging/config/honeyban.env" /etc/honeyban/honeyban.env
  fi
  if [[ ! -f /etc/honeyban/jails.conf ]]; then
    install -m 0644 "${ROOT_DIR}/core/packaging/config/jails.conf" /etc/honeyban/jails.conf
  fi
  mkdir -p /etc/honeyban/filters.d
  local filter_src
  for filter_src in "${ROOT_DIR}"/core/packaging/filters.d/*.conf; do
    [[ -e "${filter_src}" ]] || continue
    local filter_name
    filter_name="$(basename "${filter_src}")"
    if [[ ! -f "/etc/honeyban/filters.d/${filter_name}" ]]; then
      install -m 0644 "${filter_src}" "/etc/honeyban/filters.d/${filter_name}"
    fi
  done
  mkdir -p /etc/honeyban/actions.d
  local action_src
  for action_src in "${ROOT_DIR}"/core/packaging/actions.d/*.conf; do
    [[ -e "${action_src}" ]] || continue
    local action_name
    action_name="$(basename "${action_src}")"
    if [[ ! -f "/etc/honeyban/actions.d/${action_name}" ]]; then
      install -m 0644 "${action_src}" "/etc/honeyban/actions.d/${action_name}"
    fi
  done

  install -m 0644 "${ROOT_DIR}/core/packaging/systemd/honeyban.service" /etc/systemd/system/honeyban.service
  systemctl daemon-reload
  systemctl enable --now honeyban.service
}

main() {
  need_root

  local iface="${IFACE:-}"
  if [[ -z "${iface}" ]]; then
    iface="$(choose_iface_interactive)"
  fi

  local xdp_mode="${HONEYBAN_XDP_MODE:-}"
  if [[ -z "${xdp_mode}" ]]; then
    xdp_mode="$(choose_xdp_mode_interactive)"
  fi

  echo "Installing HoneyBan..."
  install_deps
  ensure_group honeyban
  build_core

  mkdir -p /etc/honeyban
  if [[ ! -f /etc/honeyban/honeyban.env ]]; then
    install -m 0644 "${ROOT_DIR}/core/packaging/config/honeyban.env" /etc/honeyban/honeyban.env
  fi
  if grep -q '^HONEYBAN_IFACE=' /etc/honeyban/honeyban.env; then
    sed -i "s/^HONEYBAN_IFACE=.*/HONEYBAN_IFACE=${iface}/" /etc/honeyban/honeyban.env
  else
    echo "HONEYBAN_IFACE=${iface}" >>/etc/honeyban/honeyban.env
  fi
  if grep -q '^HONEYBAN_XDP_MODE=' /etc/honeyban/honeyban.env; then
    sed -i "s/^HONEYBAN_XDP_MODE=.*/HONEYBAN_XDP_MODE=${xdp_mode}/" /etc/honeyban/honeyban.env
  else
    echo "HONEYBAN_XDP_MODE=${xdp_mode}" >>/etc/honeyban/honeyban.env
  fi

  install_systemd

  echo ""
  echo "Installed."
  echo "Service: systemctl status honeyban"
  echo "CLI:     honeyban status"
}

main "$@"
