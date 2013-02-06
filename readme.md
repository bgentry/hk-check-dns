
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
  "data": {
    "www.rapgenius.com.": {
      "LastNS": "ns39.domaincontrol.com.",
      "CNAME": "proxy.heroku.com.",
      "A": []
    }
  },
  "message": "direct CNAME match",
  "code": 1,
  "status": "ok"
}
```

```bash
$ curl http://localhost:5000/verify_target/www.mwmanning.com/mattmanning.herokuapp.com?nocache=true -s | jq '.'
```

```json
{
  "data": {
    "www.mwmanning.com.": {
      "LastNS": "ns1.dnsimple.com.",
      "CNAME": "mattmanning.herokuapp.com.",
      "A": []
    }
  },
  "message": "direct CNAME match",
  "code": 1,
  "status": "ok"
}
```

```bash
$ curl http://localhost:5000/verify_target/mwmanning.com/mattmanning.herokuapp.com?nocache=true -s | jq '.'
```

```json
{
  "data": {
    "mwmanning.com.": {
      "LastNS": "ns1.dnsimple.com.",
      "CNAME": "",
      "A": [
        "54.243.97.145"
      ]
    },
    "mattmanning.herokuapp.com.": {
      "LastNS": "ns-662.awsdns-18.net.",
      "CNAME": "",
      "A": [
        "23.23.231.180",
        "184.72.248.52"
      ]
    }
  },
  "message": "ALIAS or Static IP match",
  "code": 2,
  "status": "warning"
}
```

```bash
$ curl http://localhost:5000/verify_target/www.mwmanning.com/mattmanning.heroku.com?nocache=true -s | jq '.'
```

```json
{
  "data": {
    "www.mwmanning.com.": {
      "LastNS": "ns1.dnsimple.com.",
      "CNAME": "mattmanning.herokuapp.com.",
      "A": []
    },
    "mattmanning.heroku.com.": {
      "LastNS": "ns1.p19.dynect.net.",
      "CNAME": "proxy.heroku.com.",
      "A": []
    }
  },
  "message": "no matches",
  "code": 0,
  "status": "no_match"
}
```

### Include a `target_alias`

This lets the resolver know that the target record is an ALIAS record, and lets
it compare against the ALIAS target's IPs / A records rather than those returned
by the target itself.

```bash
$ curl "http://localhost:5000/verify_target/mwmanning.com/mattmanning.herokuapp.com?nocache=true&target_alias=argon-stack-12345.us-east-1.elb.amazonaws.com" -s | jq '.'
```

```json
{
  "data": {
    "mwmanning.com.": {
      "LastNS": "ns4.dnsimple.com.",
      "CNAME": "",
      "A": [
        "50.19.249.227",
        "54.243.85.64"
      ]
    },
    "argon-stack-12345.us-east-1.elb.amazonaws.com.": {
      "LastNS": "ns-947.amazonaws.com.",
      "CNAME": "",
      "A": [
        "107.20.162.205",
        "54.243.194.238",
        "23.23.231.180",
        "23.23.204.240",
        "184.72.248.52",
        "50.19.249.227",
        "184.73.167.111",
        "54.243.90.245",
        "50.19.86.241",
        "54.243.85.64",
        "54.243.92.108",
        "107.22.226.64",
        "54.243.97.145",
        "23.21.239.236",
        "50.19.92.116",
        "107.20.236.186",
        "23.21.162.250",
        "23.23.113.171"
      ]
    }
  },
  "message": "ALIAS or Static IP match",
  "code": 2,
  "status": "warning"
}
```
