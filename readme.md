
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
