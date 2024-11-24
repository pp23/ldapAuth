#!/bin/bash

test -n "${EXAMPLE_USER_PASSWORD}" || { echo "EXAMPLE_USER_PASSWORD not set."; exit 1; }
TDIR=`mktemp -d`

cat<<-EOF>"${TDIR}/example.user.ldif"
dn: cn=example,ou=users,dc=example,dc=org
cn: example
sn: Bar2
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
userPassword: $(slappasswd -o module-load=argon2.so -h "{ARGON2}" -s "${EXAMPLE_USER_PASSWORD}")
uid: example
uidNumber: 1002
gidNumber: 1002
homeDirectory: /home/example
EOF

slapadd -d1                            `# debug: Trace`                     \
        -n2                            `# database #2 (dc=example,dc=org)`  \
        -F /bitnami/openldap/slapd.d                                        \
        -l "${TDIR}/example.user.ldif"

rm -rfv "${TDIR}"
