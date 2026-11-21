# shellcheck shell=sh
# Certificates for the registry checks in tests/linux-host.sh, made in the
# engine's container before the engine starts, as a company root is
# installed before Kiri runs: two roots, each signing a registry's
# certificate (kiri-trusted.test, kiri-other.test). Only the first goes into
# the system's store (/etc/ssl/certs/ca-certificates.crt, where
# update-ca-certificates puts it), so the second stands for a root nobody
# installed. Made once; a restart of the container keeps them.
[ -f /tls/trusted.pem ] && exit 0
command -v openssl >/dev/null || exit 0
mkdir -p /tls && cd /tls || exit 0
for ca in trusted other; do
  openssl req -x509 -newkey rsa:2048 -nodes -days 3 -subj "/CN=Kiri test root ($ca)" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
    -keyout "$ca-root.key" -out "$ca-root.pem" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/CN=kiri-$ca.test" -keyout "$ca.key" -out "$ca.csr" 2>/dev/null
  printf 'subjectAltName=DNS:kiri-%s.test\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' "$ca" > "$ca.ext"
  openssl x509 -req -in "$ca.csr" -CA "$ca-root.pem" -CAkey "$ca-root.key" -CAcreateserial -days 3 \
    -extfile "$ca.ext" -out "$ca.pem" 2>/dev/null
done
chmod 644 ./*.key
cat trusted-root.pem >> /etc/ssl/certs/ca-certificates.crt
