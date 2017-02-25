# Transform MySQL Queries

[![GoDoc](https://godoc.org/github.com/go-mysql/query?status.svg)](https://godoc.org/github.com/go-mysql/query)

This package provides functions for transforming MySQL queries. Most important is `query.Fingerprint`:

```go
package main

import (
    "fmt"
    "github.com/go-mysql/query"
)

func main() {
    f := query.Fingerprint(
        "SELECT c FROM t WHERE id IN (1,2,3) AND ts < '2017-01-01 00:00:00'",
    )
    fmt.Println(f)
}
```

Output: `select c from t where id in(?+) and ts < ?`

That fingerprint can be transformed into a unique ID:

```go
id := query.Id(f) // return "EA2376FD2AFF00BA"
```

Fingerprints and IDs are used to parse and aggregate queries from the MySQL slow log.

## Acknowledgement

This code was originally copied from [percona/go-mysql](https://github.com/percona/go-mysql/query) @ `2a6037d7d809b18ebd6d735b397f2321879af611`. See that project for original contributors and copyright.

This project is a fork to continue development of percona/go-mysql as separate packages. GitHub only allows forking a project once, which is why the code has been copied.
