# ail-feeder-ccrawl

## General description.
Ail feeder CCrawl is a simple API backend to make a bridge between AIL and Common Crawl index. This API permit to retrieve indexed data from the index of common crawl since 2015. This index should be build and indexed in a clickhouse database on premise before being queriable.

## What is ?

[AIL ](https://www.ail-project.org/)is the framework developed by CIRCL for automated information leak analysis.

[Common Crawl](https://commoncrawl.org/) is a nonprofit project that continuously crawls the public web since 2015 and provides free access to large web datasets.

## What does it provides.

3 Asynchronous API endpoint are provided.

- /get_uris_for_fqdn : This endpoint retrieve full URIS for a given FQDN
- /get_uris_for_hash : This endpoint retrieve full URIS for a given Sha1 Hash (body of page)
- /get_fqdns_for_dom : This endpoint retrieve distinct FQDNs for a given DOMAIN

## Examples

### Request collected uris for FQDN "www.circl.lu"

initial query
```
curl -X POST http://ail-feeder-ccrawl:8000/get_uris_for_fqdn \
    -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer VeryNiceAPIKey' \
    -d '{
             "fqdn": "www.circl.lu",
             "years": [2024, 2025]
        }'
{"job_id":"70d9bbde-f43a-489a-a9dc-31bea7cb9b90"}
```

Getting status
```
curl http://ail-feeder-ccrawl:8000/get_uris_for_fqdn/70d9bbde-f43a-489a-a9dc-31bea7cb9b90 \
    -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer VeryNiceAPIKey' \
{"stage":50.0,"status":"RUNNING"}
```

Final result
```
curl http://ail-feeder-ccrawl:8000/get_uris_for_fqdn/70d9bbde-f43a-489a-a9dc-31bea7cb9b90 \
    -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer VeryNiceAPIKey' | jq .
{
  "result": [
    {
      "sha1": "783b1eff6765fa5ee07646ba9c6a7f1dcda376fe",
      "timestamp": 1708646400,
      "url": "https://www.circl.lu/advisory/CVE-2015-5721/"
    },
    {
      "sha1": "46444dbcc38a0a1dd397b72e2035d40ca4568b56",
      "timestamp": 1708646400,
      "url": "https://www.circl.lu/contact/"
    },
    [REDACTED]
    {
      "sha1": "20019274a4245a5ad2442fd7a72556bda4924c1f",
      "timestamp": 1708646400,
      "url": "https://www.circl.lu/doc/misp/administration/"
    }
  ],
  "stage": "100",
  "status": "DONE"
}
```

### Request uris for a given page content hash

initial query, the hash type is SHA1
```
curl -X POST http://ail-feeder-ccrawl:8000/get_uris_for_hash \
    -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer VeryNiceAPIKey' \
    -d '{
             "hash": "783b1eff6765fa5ee07646ba9c6a7f1dcda376fe",
             "years": [2024, 2025]
        }'
{"job_id":"70d9bbde-f43a-489a-a9dc-31bea7cb9b90"}
```

Getting status

```
curl http://ail-feeder-ccrawl:8000/get_uris_for_hash/70d9bbde-f43a-489a-a9dc-31bea7cb9b90 \
    -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer VeryNiceAPIKey' \
{"stage":50.0,"status":"RUNNING"}
```

Final result
```
curl http://ail-feeder-ccrawl:8000/get_uris_for_hash/70d9bbde-f43a-489a-a9dc-31bea7cb9b90 \
    -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer VeryNiceAPIKey' | jq .
{
  "result": [
    {
      "sha1": "783b1eff6765fa5ee07646ba9c6a7f1dcda376fe",
      "timestamp": 1708646400,
      "url": "https://www.circl.lu/advisory/CVE-2015-5721/"
    }
  ],
  "stage": "100",
  "status": "DONE"
}
```

### Request collected uris for FQDN "www.circl.lu"

initial query
```
curl -X POST http://ail-feeder-ccrawl:8000/get_uris_for_fqdn \
    -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer VeryNiceAPIKey' \
    -d '{
             "fqdn": "www.circl.lu",
             "years": [2024, 2025]
        }'
{"job_id":"70d9bbde-f43a-489a-a9dc-31bea7cb9b90"}
```

Getting status
```
curl http://ail-feeder-ccrawl:8000/get_uris_for_fqdn/70d9bbde-f43a-489a-a9dc-31bea7cb9b90 \
    -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer VeryNiceAPIKey' \
{"stage":50.0,"status":"RUNNING"}
```

Final result
```
curl http://ail-feeder-ccrawl:8000/get_uris_for_fqdn/70d9bbde-f43a-489a-a9dc-31bea7cb9b90 \
    -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer VeryNiceAPIKey' | jq .
{
  "result": [
    {
      "sha1": "783b1eff6765fa5ee07646ba9c6a7f1dcda376fe",
      "timestamp": 1708646400,
      "url": "https://www.circl.lu/advisory/CVE-2015-5721/"
    },
    {
      "sha1": "46444dbcc38a0a1dd397b72e2035d40ca4568b56",
      "timestamp": 1708646400,
      "url": "https://www.circl.lu/contact/"
    },
    [REDACTED]
    {
      "sha1": "20019274a4245a5ad2442fd7a72556bda4924c1f",
      "timestamp": 1708646400,
      "url": "https://www.circl.lu/doc/misp/administration/"
    }
  ],
  "stage": "100",
  "status": "DONE"
}
```
### Request collected FQDNs for domain "circl.lu"

Initial Query
```
curl -X POST http://ail-feeder-ccrawl:8000/get_uris_for_fqdn \
    -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer VeryNiceAPIKey' \
    -d '{
             "domain": "circl.lu",
             "years": [2024, 2025]
        }'
{"job_id":"153babfe-48c2-4ed4-b93d-348eb60d9681"}
```

Getting status
```
curl http://ail-feeder-ccrawl:8000/get_fqdns_for_dom/153babfe-48c2-4ed4-b93d-348eb60d9681 \
    -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer VeryNiceAPIKey' \
{"stage":50.0,"status":"RUNNING"}
```

Final result
```
curl http://ail-feeder-ccrawl:8000/get_fqdns_for_dom/153babfe-48c2-4ed4-b93d-348eb60d9681 \
   -H 'Content-Type: application/json' \ 
   -H 'Authorization: Bearer VeryNiceAPIKey' | jq .
{
  "result": [
    "helga.circl.lu",
    "openpgp.circl.lu",
    [REDACTED]
    "lookyloo.circl.lu",
    "www.circl.lu"
  ],
  "stage": "100",
  "status": "DONE"
}
```