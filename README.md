# http2.lol

This repository contains a *PoC* of a browser identification mechanism that leverages an HTTP/2 **active** stack fingerprinting technique.

It is made of three different parts:

* a Flask web server that exposes an HTML/JS page to force the browser to refresh a specific asset (`server.py`)
* an HTTP/2 fake server that answers browser requests to fetch an asset with specific HTTP/2 tests (`server_http2.py`)
* a Fingerprint knowledge base that analyzes the HTTP/2 tests results to compute the browser stack (`fingerprint.py`)

It should be noted, that a redis server is used as a shared memory storage between the flask server and the fake http2 server.

**IMHO**: the most interesting part of this project is how I automaticaly computed the different test cases used to fingerprint the browser :) 

For more details, you can:

* refer to the short presentation available in the `doc/` directory
* send me your question per email (`my_firstname@miskin.fr`) or per Twitter DM `@Lapeluche`
* buy me a `beer` and get even more details.
