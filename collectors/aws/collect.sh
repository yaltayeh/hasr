#!/bin/sh
# Hasr AWS collector: a read-only inventory of load balancers, their TLS
# policies and listener certificates, and ACM certificates.
#
#   collectors/aws/collect.sh -o RAW_DIR --region REGION [--region REGION ...]
#
# Credentials come from the standard AWS CLI chain. Run it as a read-only
# identity, e.g. AWS_PROFILE=hasr-readonly with collectors/aws/iam-policy.json.
# It refuses to run with root credentials.
#
# It runs only `aws <service> describe-*|list-*|get-*` (tested in
# collector_test.go, and enforced again at run time by call()), writes the
# raw JSON of every call to RAW_DIR, and records each command with its exit
# status in RAW_DIR/manifest.json. A failed call is recorded, never hidden.
#
# RAW_DIR holds account IDs and ARNs: keep it out of version control. It is
# the evidence behind `hasr cloud aws --from RAW_DIR`.
set -u
export AWS_PAGER=""
umask 077

COLLECTOR_VERSION="0.1"

usage() {
  echo "usage: $0 -o RAW_DIR --region REGION [--region REGION ...]" >&2
  exit 2
}

RAW=""
REGIONS=""
while [ $# -gt 0 ]; do
  case $1 in
    -o) [ $# -ge 2 ] || usage; RAW=$2; shift 2 ;;
    --region) [ $# -ge 2 ] || usage; REGIONS="$REGIONS $2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done
[ -n "$RAW" ] && [ -n "$REGIONS" ] || usage
for r in $REGIONS; do
  case $r in
    *[!a-z0-9-]*) echo "invalid region: $r" >&2; exit 2 ;;
  esac
done

command -v aws >/dev/null 2>&1 || { echo "the AWS CLI (aws) is not installed" >&2; exit 2; }
if [ -e "$RAW" ] && [ -n "$(ls -A "$RAW" 2>/dev/null)" ]; then
  echo "$RAW exists and is not empty; use a new folder so evidence is never mixed" >&2
  exit 2
fi
mkdir -p "$RAW" || exit 2
CALLS="$RAW/.calls"
: > "$CALLS"

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# esc makes a string safe inside JSON double quotes.
esc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\n\r'; }

STARTED=$(now)
CLI_VERSION=$(aws --version 2>&1 | head -n 1)

# call OUTFILE REGION SERVICE OPERATION [ARGS...]
# Runs one read-only AWS CLI command and records it. Returns its exit status.
call() {
  out=$1 region=$2 svc=$3 op=$4
  shift 4
  case $op in
    describe-*|list-*|get-*) ;;
    *) echo "refusing a non-read operation: $svc $op" >&2; exit 3 ;;
  esac
  mkdir -p "$(dirname "$RAW/$out")"
  aws "$svc" "$op" "$@" --region "$region" --output json >"$RAW/$out" 2>"$RAW/$out.err"
  rc=$?
  [ -s "$RAW/$out.err" ] || rm -f "$RAW/$out.err"
  args=""
  for a in "$@"; do
    args="$args${args:+, }\"$(esc "$a")\""
  done
  err=""
  [ -f "$RAW/$out.err" ] && err="$out.err"
  printf '    {"service": "%s", "operation": "%s", "args": [%s], "region": "%s", "output": "%s", "stderr": "%s", "exit_status": %d}\n' \
    "$(esc "$svc")" "$(esc "$op")" "$args" "$(esc "$region")" "$(esc "$out")" "$(esc "$err")" "$rc" >>"$CALLS"
  return $rc
}

# values KEY FILE prints every string value of "KEY" in pretty-printed CLI JSON.
values() { sed -n 's/^ *"'"$1"'": "\([^"]*\)".*$/\1/p' "$2"; }

# tls_listeners FILE prints the ARNs of HTTPS and TLS listeners. A listener's own
# keys sit at a fixed indentation in the CLI's output; nested keys (such as a
# redirect's "Protocol") sit deeper and are ignored.
tls_listeners() {
  awk '
    /^            "ListenerArn": "/ { split($0, p, "\""); arn = p[4] }
    /^            "Protocol": "(HTTPS|TLS)"/ { if (arn != "") print arn }
    /^        }/ { arn = "" }
  ' "$1"
}

finish() {
  status=$1 refused=$2
  {
    printf '{\n  "kind": "hasr-aws-raw",\n  "collector_version": "%s",\n' "$COLLECTOR_VERSION"
    printf '  "cli_version": "%s",\n' "$(esc "$CLI_VERSION")"
    printf '  "started_at": "%s",\n  "finished_at": "%s",\n' "$STARTED" "$(now)"
    printf '  "regions": ['
    sep=""
    for r in $REGIONS; do printf '%s"%s"' "$sep" "$r"; sep=", "; done
    printf '],\n  "refused": "%s",\n  "calls": [\n' "$(esc "$refused")"
    sed '$!s/$/,/' "$CALLS"
    printf '  ]\n}\n'
  } >"$RAW/manifest.json"
  rm -f "$CALLS"
  exit "$status"
}

# --- Identity: refuse root ---
first_region=$(echo $REGIONS | cut -d' ' -f1)
if ! call identity.json "$first_region" sts get-caller-identity; then
  echo "could not read the caller identity; see $RAW/identity.json.err" >&2
  finish 1 "caller identity could not be read"
fi
case $(values Arn "$RAW/identity.json") in
  *:root)
    echo "refusing to run with root credentials; use a read-only identity (see collectors/aws/iam-policy.json)" >&2
    rm -f "$RAW/identity.json"
    finish 4 "root credentials"
    ;;
esac

# --- Per region ---
failed=0
for r in $REGIONS; do
  call "$r/ssl-policies.json" "$r" elbv2 describe-ssl-policies || failed=1
  if call "$r/load-balancers.json" "$r" elbv2 describe-load-balancers; then
    n=0
    for lb in $(values LoadBalancerArn "$RAW/$r/load-balancers.json" | sort -u); do
      n=$((n + 1))
      call "$r/lb-$n-tags.json" "$r" elbv2 describe-tags --resource-arns "$lb" || failed=1
      if call "$r/lb-$n-listeners.json" "$r" elbv2 describe-listeners --load-balancer-arn "$lb"; then
        m=0
        for l in $(tls_listeners "$RAW/$r/lb-$n-listeners.json"); do
          m=$((m + 1))
          call "$r/lb-$n-listener-$m-certificates.json" "$r" elbv2 describe-listener-certificates --listener-arn "$l" || failed=1
        done
      else
        failed=1
      fi
    done
  else
    failed=1
  fi

  # Without --includes, list-certificates returns RSA 1024/2048 certificates only.
  if call "$r/certificates.json" "$r" acm list-certificates \
      --includes keyTypes=RSA_1024,RSA_2048,RSA_3072,RSA_4096,EC_prime256v1,EC_secp384r1,EC_secp521r1; then
    k=0
    for c in $(values CertificateArn "$RAW/$r/certificates.json" | sort -u); do
      k=$((k + 1))
      call "$r/cert-$k-describe.json" "$r" acm describe-certificate --certificate-arn "$c" || failed=1
      call "$r/cert-$k-pem.json" "$r" acm get-certificate --certificate-arn "$c" || failed=1
      call "$r/cert-$k-tags.json" "$r" acm list-tags-for-certificate --certificate-arn "$c" || failed=1
    done
  else
    failed=1
  fi
done

if [ "$failed" -ne 0 ]; then
  echo "some calls failed; they are recorded in $RAW/manifest.json" >&2
fi
echo "wrote $RAW" >&2
finish "$failed" ""
