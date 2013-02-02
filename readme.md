
## Cache-free lookup of all A or CNAME records for a domain

```bash
$ curl http://localhost:5000/www.cnn.co.uk
```

```json
{
  "LastNS": "ns3.timewarner.net.",
  "CNAME": [
    "cnn.co.uk."
  ],
  "A": []
}
```

```bash
$ curl http://localhost:5000/www.herokuapp.com
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
$ curl http://localhost:5000/www.heroku.com
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
