# Web Requests   

# HyperText Transfer Protocol (HTTP)

```bash

curl http://83.136.254.47:58290/download.php 

```

# HTTP Requests and Responses

```bash
curl http://83.136.254.47:58290/ -v  

```

# HTTP Headers

The server above loads the flag after the page is loaded. Use the Network tab in the browser devtools to see what requests are made by the page, and find the request to the flag.


# GET

```bash

curl -X GET http://admin:admin@94.237.57.13:30504/search.php?search=flag



```

# POST

```bash
curl -X POST -d '{"search":"flag"}' -b 'PHPSESSID=nbg05p4dd43h2vrvs5cl0oi054' -H 'Content-Type: application/json' http://83.136.255.217:58573/search.php



```