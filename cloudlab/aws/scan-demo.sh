#!/bin/sh
# Scan the demo load balancers, only while the Terraform state lists them
# (DECISIONS.md, "Demo infrastructure"). After `terraform destroy` their
# addresses go back to AWS and must never be scanned.
#
#   cloudlab/aws/scan-demo.sh      writes cloudlab/aws/run/{mapping.csv,scan.json}
#
# run/ is gitignored: the mapping holds the load balancers' DNS names.
set -eu
cd "$(dirname "$0")"
HASR=${HASR:-../../hasr}

state=$(terraform state list 2>/dev/null || true)
for r in aws_lb.pq aws_lb.default; do
  case $state in
    *"$r"*) ;;
    *) echo "$r is not in the Terraform state: refusing to scan" >&2; exit 2 ;;
  esac
done

pq=$(terraform output -raw pq_dns_name)
def=$(terraform output -raw default_dns_name)
mkdir -p run
cat >run/mapping.csv <<EOF
target,system,service,owner,data_classification,data_shelf_life_years,migration_years,third_party,constraints
$pq:443,Demo load balancer with PQ policy (sample),HTTPS,Demo team (sample),Secret,,,in-house,
$def:443,Demo load balancer with default policy (sample),HTTPS,Demo team (sample),Secret,,,in-house,
EOF

status=0
"$HASR" scan --targets run/mapping.csv >run/scan.json || status=$?
echo "wrote cloudlab/aws/run/mapping.csv and cloudlab/aws/run/scan.json (scan exit $status)" >&2
exit "$status"
