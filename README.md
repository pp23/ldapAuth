# Archonauth

A full file based configurable authorization server with a LDAP IdP backend.

## Development

### OpenLDAP

OpenLDAP is the database which contains all users of the system. The passwords are stored encrypted in the OpenLDAP database.

Configuration: https://github.com/bitnami/containers/blob/main/bitnami/openldap/README.md

#### Common search queries

```
# query all subentries of dc=example,dc=org

ldapsearch -H ldap://localhost:1389 -x -s sub  -D "cn=admin,dc=example,dc=org" -b "dc=example,dc=org" -LLL -W
```

```
# query config of ldap database
# requires LDAP_CONFIG_ADMIN_ENABLED=yes

ldapsearch -H ldap://localhost:1389 -x   -D "cn=admin,cn=config" -b 'cn=config' -LLL -W
```

#### Argon2 user passwords

User passwords get stored Argon2 encrypted in the database. The Argon2 module installation happens via `customSchemaFiles`.

##### Docker OpenLDAP with Argon2

* Run an OpenLDAP docker container with an example user with argon2 hashed password:
```
docker run --rm \
 -v $PWD/argon2.module.sh:/docker-entrypoint-initdb.d/0001.argon2.module.sh:ro \    # init script to install the argon2-module
 -v $PWD/example-user-argon2.sh:/docker-entrypoint-initdb.d/0002.example.user.sh \  # example user with argon2 password
 -e EXAMPLE_USER_PASSWORD=<EXAMPLE_USER_PASSWORD> \                                 # required password of the example user
 -e LDAP_ADMIN=admin \
 -e LDAP_ADMIN_PASSWORD=<ADMIN_PASSWORD> \
 -e LDAP_ROOT=dc=example,dc=org \
 -e LDAP_ADMIN_DN=cn=admin,dc=example,dc=org \
 -e BITNAMI_DEBUG=true \
 -e LDAP_CONFIG_ADMIN_ENABLED=yes \  # required to view cn=config
 -e LDAP_CONFIG_ADMIN_PASSWORD=<CONFIG_ADMIN_PASSWORD> \
 --name "ldap" \
 bitnami/openldap:2.6.3
```
* View the users:
```
docker exec ldap ldapsearch -H "ldap://localhost:1389" -D "cn=admin,dc=example,dc=org" -b "dc=example,dc=org" -w "<ADMIN_PASSWORD>"
```
* Test login of the example user:
```
docker exec ldap ldapwhoami -H "ldap://localhost:1389" -D "cn=example,ou=users,dc=example,dc=org" -w "<EXAMPLE_USER_PASSWORD>"
# dn:cn=example,ou=users,dc=example,dc=org
```

##### Local setup instructions

To activate the argon2 module, load the argon2 module:

```
# /tmp/module.ldif

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
```

Run this command to apply the changes:

```
ldapmodify -H "ldap://localhost:1389" -D 'cn=admin,cn=config' -W -f /tmp/modules.ldif
```

The user passwords in the mdb database can now be hashed with argon2. To generate a new argon2 password hash, run this command:

```
slappasswd -o module-load=argon2.so -h "{ARGON2}" -s "secret"
```

Modify or add a new user with this password hash:

```
# /tmp/user.ldif

dn: cn=user02,ou=users,dc=example,dc=org
changetype: modify
replace: userPassword
userPassword: {ARGON2}$argon2i$v=19$m=4096,t=3,p=1$meXM2zjTZGSS+2TwYaMleQ$78D+CTr55GKuqYS55OOwq2FW9nMqyOQqbGEtX5Vs6jQ
```

Run this command to apply the change:

```
ldapmodify -H "ldap://localhost:1389" -D 'cn=admin,dc=example,dc=org' -W -x -f /tmp/user.ldif
```

To verify the password change, run this command:

```
ldapwhoami -H "ldap://localhost:1389" -D 'cn=user02,ou=users,dc=example,dc=org' -w "secret"
```

If no error occured and you see the entry, the password change was successful.

#### Further reading

* https://www.kania-online.de/2fa-und-openldap-mit-argon2-als-passwordhash/
* https://stackoverflow.com/questions/76826627/how-to-implement-argon2-hash-on-openldap
* https://www.puzzle.ch/de/blog/articles/2023/08/08/enhancing-openldap-security-with-argon2

### LDAPAuthentication

* LDAPAuth is a middleware which uses the [ldapAuth plugin](github.com/wiltonsr/ldapAuth)
* The initial test uses the Traefik dashboard which allows access only after a basic authentication against the LDAP
* A LDAP user from above can be used to authenticate
* Forward the dashboard on http://localhost:9000/dashboard/#/ with this command:
```
kubectl port-forward -n traefik $(kubectl get pods --selector "app.kubernetes.io/name=traefik" --output=name -n traefik) 9000:9000
```

>***Note:*** After a cluster restart, sometimes traefik cannot load the ldapauth middleware which results in the error log msg: `msg="invalid middleware \"traefik-ldapauth@kubernetescrd\" configuration: invalid middleware type or middleware does not exist"` Workaround is to restart traefik
