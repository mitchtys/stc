#!/usr/bin/env sh
#-*-mode: Shell-script; coding: utf-8;-*-
_base=$(basename "$0")
_dir=$(cd -P -- "$(dirname -- "$(command -v -- "$0")")" && pwd -P || exit 126)
export _base _dir
set -xu

run() {
  echo "$@"
  "$@"
}

nuke_inactives() {
  # Loop through and nuke anything inactive first
    # Domains
    for inactive in $(virsh list --inactive | awk 'NR>2 && /^ [-]/ {print $2}'); do
      run virsh undefine "${inactive}"
    done

    # networks
    for inactive in $(virsh net-list --inactive | awk 'NR>2 &&/^ / {print $1}'); do
      run virsh net-undefine "${inactive}"
    done

    # last pools
    for inactive in $(virsh pool-list --inactive | awk 'NR>2 &&/^ / {print $1}'); do
      run virsh pool-undefine "${inactive}"
    done
}

nuke_instance() {
  instance=$1
  # Then find anything that might have been a member of the input instance
  for active in $(virsh list | awk 'NR>2 && /^ / {print $2}'); do
    if virsh dumpxml "${active}" | grep "${instance}"  > /dev/null 2>&1; then
      run virsh destroy "${active}"
    fi
  done

  for active in $(virsh net-list | awk 'NR>2 && /^ / && !/default/ {print $1}'); do
    if virsh net-dumpxml "${active}" | grep "${instance}"  > /dev/null 2>&1; then
      run virsh net-destroy "${active}"
    fi
  done

  for active in $(virsh pool-list | awk 'NR>2 && /^ / {print $1}'); do
    if virsh pool-dumpxml "${active}" | grep "${instance}"  > /dev/null 2>&1; then
      run virsh pool-destroy "${active}"
    fi
  done
}

for inst in "$@"; do
  nuke_instance "${inst}"
done

nuke_inactives
