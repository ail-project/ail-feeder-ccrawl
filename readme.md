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


