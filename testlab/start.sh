#!/bin/sh
# Start the three local TLS test servers decided in DECISIONS.md (step 1).
# They listen on 127.0.0.1 only. Stop them with testlab/stop.sh.
#
# Expected probe results (fixed by these configs):
#   a) 127.0.0.1:8443  TLS 1.3  group X25519MLKEM768  cert ECDSA P-256, ECDSA-SHA256
#   b) 127.0.0.1:8444  TLS 1.3  group X25519          cert ECDSA P-256, ECDSA-SHA256
#   c) 127.0.0.1:8445  TLS 1.2  group X25519 (ECDHE)  cert RSA 2048,   SHA256-RSA
#                      and also accepts TLS 1.1 and TLS 1.0 (SECLEVEL=0), and RSA key
#                      transport suites (DEFAULT@SECLEVEL=0 includes TLS_RSA_*)
# The cipher suite is not fixed by these configs: the server follows the
# client's preference, which depends on the client's CPU (AES hardware or not).
set -eu
cd "$(dirname "$0")"
OPENSSL="${OPENSSL:-openssl}"
mkdir -p run

echo "using: $("$OPENSSL" version)"

# Self-signed test certificates, valid 30 days. Generated once, reused afterwards.
[ -f run/ec.crt ] || "$OPENSSL" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -sha256 -days 30 -noenc -subj "/CN=testlab-ec-p256" \
  -keyout run/ec.key -out run/ec.crt 2>/dev/null
[ -f run/rsa.crt ] || "$OPENSSL" req -x509 -newkey rsa:2048 \
  -sha256 -days 30 -noenc -subj "/CN=testlab-rsa-2048" \
  -keyout run/rsa.key -out run/rsa.crt 2>/dev/null

start() {
  name=$1; shift
  if [ -f "run/$name.pid" ] && kill -0 "$(cat "run/$name.pid")" 2>/dev/null; then
    echo "already running: $name (pid $(cat "run/$name.pid"))"
    return
  fi
  nohup "$OPENSSL" s_server -quiet -www "$@" >"run/$name.log" 2>&1 </dev/null &
  echo $! >"run/$name.pid"
  echo "started $name (pid $!): $*"
}

# a) hybrid PQ: X25519MLKEM768 + x25519
start a-hybrid-pq -accept 127.0.0.1:8443 -cert run/ec.crt -key run/ec.key -groups X25519MLKEM768:x25519
# b) classical only: x25519 / P-256
start b-classical -accept 127.0.0.1:8444 -cert run/ec.crt -key run/ec.key -groups x25519:P-256
# c) legacy: TLS 1.2 max, RSA-2048 certificate, also TLS 1.1 and 1.0.
#    OpenSSL refuses TLS 1.0/1.1 at its default security level; SECLEVEL=0 re-enables them.
start c-legacy -accept 127.0.0.1:8445 -cert run/rsa.crt -key run/rsa.key -no_tls1_3 -cipher 'DEFAULT@SECLEVEL=0'
