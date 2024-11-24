#!/bin/sh
TDIR=`mktemp -d`

cat <<-EOF > "${TDIR}/argon2.module.ldif"
dn: cn=module{0},cn=config
changetype: add
objectClass: olcModuleList
cn: module{0}
olcModulePath: /opt/bitnami/openldap/lib/openldap/
olcModuleLoad: argon2.so

dn: olcDatabase={-1}frontend,cn=config
changetype: modify
add: olcPasswordHash
olcPasswordHash: {ARGON2}
EOF

echo "Setup Argon2:"
cat "${TDIR}/argon2.module.ldif"

# install argon2 module
slapmodify -d1                             `# debug: Trace`             \
           -n0                             `# database #0 (cn=config)`  \
           -F /bitnami/openldap/slapd.d                                 \
           -l "${TDIR}/argon2.module.ldif"

# cleanup
rm -rfv "${TDIR}"
