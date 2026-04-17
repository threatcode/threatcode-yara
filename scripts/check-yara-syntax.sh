#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rule_dir="${repo_root}/yara"
build_dir="$(mktemp -d)"
trap 'rm -rf "${build_dir}"' EXIT

external_var_rules=(
  "generic_anomalies.yar"
  "general_cloaking.yar"
  "gen_webshells_ext_vars.yar"
  "thor_inverse_matches.yar"
  "yara_mixed_ext_vars.yar"
  "configured_vulns_ext_vars.yar"
  "gen_fake_amsi_dll.yar"
  "expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar"
  "expl_connectwise_screenconnect_vuln_feb24.yar"
  "gen_mal_3cx_compromise_mar23.yar"
  "gen_susp_obfuscation.yar"
  "gen_vcruntime140_dll_sideloading.yar"
  "yara-rules_vuln_drivers_strict_renamed.yar"
)

yarac_args=(
  -w
  -d filename=placeholder.bin
  -d filepath=/tmp/placeholder.bin
  -d extension=bin
  -d "filetype=ASCII text"
  -d filemode=0
  -d md5=00000000000000000000000000000000
  -d id=1
  -d owner=root
  -d group=root
  -d unpack_parent=
  -d unpack_source=
)

rules=("${rule_dir}"/*.yar "${rule_dir}"/*.yara)

if [ "${#rules[@]}" -eq 0 ]; then
  echo "No YARA rules found in ${rule_dir}" >&2
  exit 1
fi

is_external_var_rule() {
  local rule_name
  local allowed_rule

  rule_name="$(basename "$1")"

  for allowed_rule in "${external_var_rules[@]}"; do
    if [ "${rule_name}" = "${allowed_rule}" ]; then
      return 0
    fi
  done

  return 1
}

for rule_name in "${external_var_rules[@]}"; do
  if [ ! -f "${rule_dir}/${rule_name}" ]; then
    echo "Configured external-variable rule not found: ${rule_dir}/${rule_name}" >&2
    exit 1
  fi
done

strict_count=0
external_var_count=0
failed=0
compiler_log="$(mktemp)"
trap 'rm -rf "${build_dir}" "${compiler_log}"' EXIT

for rule in "${rules[@]}"; do
  if is_external_var_rule "${rule}"; then
    external_var_count=$((external_var_count + 1))
  else
    strict_count=$((strict_count + 1))
  fi
done

echo "Validating ${#rules[@]} YARA rule files (${strict_count} strict, ${external_var_count} with external variables)"

for rule in "${rules[@]}"; do
  if is_external_var_rule "${rule}"; then
    if ! yarac "${yarac_args[@]}" "${rule}" "${build_dir}/$(basename "${rule}").compiled" >"${compiler_log}" 2>&1; then
      echo "External-variable syntax check failed: ${rule}" >&2
      cat "${compiler_log}" >&2
      failed=1
    fi
  else
    if ! yarac -w "${rule}" "${build_dir}/$(basename "${rule}").compiled" >"${compiler_log}" 2>&1; then
      echo "Strict syntax check failed: ${rule}" >&2
      cat "${compiler_log}" >&2
      failed=1
    fi
  fi
done

if [ "${failed}" -ne 0 ]; then
  exit 1
fi

echo "YARA syntax validation passed"
