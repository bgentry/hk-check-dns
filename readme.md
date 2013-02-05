
## Lookup of all A or CNAME records for a domain

```bash
$ curl http://localhost:5000/lookup/www.cnn.co.uk
```

```json
{
  "LastNS": "8.8.8.8",
  "CNAME": [
    "cnn.co.uk."
  ],
  "A": []
}
```

### Cache-free lookups

```bash
$ curl http://localhost:5000/lookup/www.herokuapp.com?nocache=true
```

```json
{
  "LastNS": "ns-662.awsdns-18.net.",
  "CNAME": [],
  "A": [
    "184.72.248.52",
    "54.243.194.238"
  ]
}
```

```bash
$ curl http://localhost:5000/lookup/www.heroku.com?nocache=true
```

```json
{
  "LastNS": "ns1.p19.dynect.net.",
  "CNAME": [
    "kyoto-7460.herokussl-b.com."
  ],
  "A": []
}
```

## Verify that one hostname targets another

```bash
$ curl http://localhost:5000/verify_target/www.rapgenius.com/proxy.heroku.com?nocache=true -s | jq '.'
```

```json
{
  "status": "ok",
  "message": "direct CNAME match",
  "code": 1
}
```

```bash
$ curl http://localhost:5000/verify_target/www.mwmanning.com/mattmanning.herokuapp.com?nocache=true -s | jq '.'
```

```json
{
  "status": "ok",
  "message": "direct CNAME match",
  "code": 1
}
```

```bash
$ curl http://localhost:5000/verify_target/mwmanning.com/mattmanning.herokuapp.com?nocache=true -s | jq '.'
```

```json
{
  "status": "warning",
  "message": "ALIAS or Static IP match",
  "code": 2
}
```

```bash
$ curl http://localhost:5000/verify_target/www.mwmanning.com/mattmanning.heroku.com?nocache=true -s | jq '.'
```

```json
{
  "status": "error",
  "message": "no matches",
  "code": 0
}
```
