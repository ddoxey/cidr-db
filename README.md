# cidr-db
CIDR Database

Store a collection of CIDRS and quickly determine which of them match a given
IPv4 address.

# build

./build.sh

# test

./test.sh

# CLI

```
$ build/bin/cidrdb_cli --in data/sample-cidrs.list --db data/sample-cidrs.cdb --ip 85.143.160.10
85.143.160.0/21
```

```
$ build/bin/cidrdb_cli --db data/sample-cidrs.cdb --ip 85.143.160.10
85.143.160.0/21
```

# HTTP server

```
$ build/bin/cidrdb_rest 127.0.0.1 8080 data/sample-cidrs.cdb
```

```
$ curl -H 'Accept: application/json' 'http://localhost:8080/' -d $'85.143.160.10\n62.76.40.0'
[{"ip":"85.143.160.10","valid":true,"cidrs":["85.143.160.0/21"]},{"ip":"62.76.40.0","valid":true,"cidrs":["62.76.40.0/21"]}]

$ curl -H 'Accept: application/x-yaml' 'http://localhost:8080/' -d $'85.143.160.10\n62.76.40.0'
---
-  ip: 85.143.160.10
   valid: true
   cidrs:
   - 85.143.160.0/21
-  ip: 62.76.40.0
   valid: true
   cidrs:
   - 62.76.40.0/21
```
