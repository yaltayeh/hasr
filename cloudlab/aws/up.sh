#!/bin/sh
# Plan the demo with this machine's current public IP as the only source
# allowed on port 443, then stop: the author reads the plan and applies it.
#
#   AWS_PROFILE=hasr-admin cloudlab/aws/up.sh
#   then: cd cloudlab/aws && terraform apply demo.tfplan
#
# The IP is never printed. It is passed as TF_VAR_my_ip (environment, not the
# command line). The plan output, which contains it, goes to run/plan.log
# (gitignored); only redacted summary lines are shown.
set -eu
cd "$(dirname "$0")"
CHECKIP_URL=${CHECKIP_URL:-https://checkip.amazonaws.com}

# A value in terraform.tfvars would silently override TF_VAR_my_ip.
if grep -Eq '^[[:space:]]*(my_ip|allowed_cidr)[[:space:]]*=' terraform.tfvars 2>/dev/null; then
  echo "terraform.tfvars sets the IP (my_ip or allowed_cidr): remove that line, it would override TF_VAR_my_ip" >&2
  exit 2
fi

# valid_ipv4 accepts exactly four dot-separated decimal octets, each 0-255.
valid_ipv4() {
  case $1 in
    '' | *[!0-9.]* | .* | *. | *..*) return 1 ;;
  esac
  old_ifs=$IFS
  IFS=.
  # shellcheck disable=SC2086
  set -- $1
  IFS=$old_ifs
  [ $# -eq 4 ] || return 1
  for o in "$@"; do
    [ ${#o} -le 3 ] && [ "$o" -le 255 ] || return 1
  done
}

ip=$(curl -fsS -m 10 "$CHECKIP_URL" 2>/dev/null | tr -d '[:space:]') || ip=""
if ! valid_ipv4 "$ip"; then
  echo "could not read a valid public IPv4 address from $CHECKIP_URL" >&2
  exit 2
fi
TF_VAR_my_ip="$ip/32"
export TF_VAR_my_ip
unset ip

mkdir -p run
echo "planning with AWS_PROFILE=${AWS_PROFILE:-<default chain>}; the plan output is in cloudlab/aws/run/plan.log" >&2
status=0
terraform plan -input=false -no-color -out=demo.tfplan >run/plan.log 2>&1 || status=$?
# Summary only, with any IPv4 address redacted.
grep -E '^(Plan:|No changes|Error|  # )' run/plan.log | sed -E 's/[0-9]{1,3}(\.[0-9]{1,3}){3}/<ip>/g' >&2 || true
if [ "$status" -ne 0 ]; then
  echo "terraform plan failed (exit $status); see cloudlab/aws/run/plan.log" >&2
  exit "$status"
fi
echo "review: terraform show demo.tfplan    apply: terraform apply demo.tfplan" >&2
