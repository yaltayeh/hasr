#!/bin/sh
# After `terraform destroy`: check that nothing of the demo is left
# (DECISIONS.md, "Demo infrastructure"). Read-only; prints PASS/FAIL per check
# and counts only, never IDs or ARNs.
#
#   AWS_PROFILE=hasr-admin cloudlab/aws/check-clean.sh
#
# The author checks billing the next day (step 5).
set -u
cd "$(dirname "$0")"
export AWS_PAGER=""
REGION=${REGION:-eu-north-1}
PREFIX=${PREFIX:-hasr-demo}
R="--region $REGION --output text"
fail=0

check() { # NAME COUNT
  if [ "$2" = "0" ]; then echo "PASS  $1"; else echo "FAIL  $1: $2 left"; fail=1; fi
}
count() { # counts non-empty, non-"None" words of the command's text output
  out=$("$@" 2>&1) || { echo "ERR"; return; }
  printf '%s\n' "$out" | tr '\t' '\n' | grep -cv -e '^$' -e '^None$'
}

# 1. Terraform state
check "terraform state is empty" "$(terraform state list 2>/dev/null | grep -c .)"

# 2. Tag search (can lag behind deletions; not enough on its own)
check "no resource tagged Project=$PREFIX" \
  "$(count aws resourcegroupstaggingapi get-resources $R --tag-filters Key=Project,Values=$PREFIX --query 'ResourceTagMappingList[].ResourceARN')"

# 3. Direct listings by type
check "load balancers named $PREFIX-*" \
  "$(count aws elbv2 describe-load-balancers $R --query "LoadBalancers[?starts_with(LoadBalancerName, '$PREFIX')].LoadBalancerName")"
check "ACM certificates in $REGION (demo account: expect none)" \
  "$(count aws acm list-certificates $R --includes keyTypes=RSA_1024,RSA_2048,RSA_3072,RSA_4096,EC_prime256v1,EC_secp384r1,EC_secp521r1 --query 'CertificateSummaryList[].CertificateArn')"
for kind in vpcs:Vpcs[].VpcId subnets:Subnets[].SubnetId security-groups:SecurityGroups[].GroupId \
            internet-gateways:InternetGateways[].InternetGatewayId route-tables:RouteTables[].RouteTableId; do
  name=${kind%%:*} q=${kind#*:}
  check "$name tagged Project=$PREFIX" "$(count aws ec2 describe-$name $R --filters Name=tag:Project,Values=$PREFIX --query "$q")"
done
check "security-group-rules tagged Project=$PREFIX" \
  "$(count aws ec2 describe-security-group-rules $R --filters Name=tag:Project,Values=$PREFIX --query 'SecurityGroupRules[].SecurityGroupRuleId')"
check "network interfaces of the demo load balancers" \
  "$(count aws ec2 describe-network-interfaces $R --filters "Name=description,Values=ELB app/$PREFIX-*" --query 'NetworkInterfaces[].NetworkInterfaceId')"
if aws iam get-role --role-name hasr-readonly $R >/dev/null 2>&1; then
  check "IAM role hasr-readonly" 1
else
  check "IAM role hasr-readonly" 0
fi

# 4. Hasr's own view: the collector (as this admin profile) finds no load balancers
tmp=$(mktemp -d)
if ../../collectors/aws/collect.sh -o "$tmp/raw" --region "$REGION" >/dev/null 2>&1 &&
   ../../hasr cloud aws --from "$tmp/raw" >"$tmp/aws.json" 2>/dev/null; then
  check "hasr cloud aws: endpoints" "$(grep -c '"resource_kind"' "$tmp/aws.json")"
else
  echo "FAIL  hasr cloud aws could not run (see the collector's manifest)"; fail=1
fi
rm -rf "$tmp"

[ "$fail" -eq 0 ] && echo "nothing of the demo is left in $REGION" || echo "something is left: see FAIL lines"
exit "$fail"
