#!/usr/bin/env python3
# Written by Paul Clevett
# (C)Copyright IntelligentWolf Ltd
# https://wolf.uk.com
#
# Stub S3 server for exercising the connection test's bucket-scoped-key
# fallback (storage::test_s3_connection probe 2): answers ListBuckets
# (GET /) with the AWS-style 403 AccessDenied that a bucket-scoped key
# gets from AWS/IDrive e2/B2, and answers ListObjectsV2 on one bucket
# ("scopedbucket") with a valid empty listing. MinIO cannot stand in for
# this shape — it FILTERS ListBuckets to accessible buckets instead of
# denying it, even with an explicit Deny on s3:ListAllMyBuckets
# (verified live 2026-08-18, mc RELEASE.2025-08-13).
#
# Usage:
#   python3 tools/s3stub.py &   # listens on 127.0.0.1:19001
#   WS_S3_TEST_SCOPED_ENDPOINT=http://127.0.0.1:19001 \
#   WS_S3_TEST_SCOPED_KEY=anykey WS_S3_TEST_SCOPED_SECRET=anysecret \
#   WS_S3_TEST_SCOPED_BUCKET=scopedbucket \
#   ... cargo test connection_test_live -- --ignored --nocapture
from http.server import BaseHTTPRequestHandler, HTTPServer

LIST_OBJECTS = b"""<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<Name>scopedbucket</Name><Prefix></Prefix><KeyCount>0</KeyCount>
<MaxKeys>1</MaxKeys><IsTruncated>false</IsTruncated>
</ListBucketResult>"""

ACCESS_DENIED = b"""<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>AccessDenied</Code><Message>Access Denied.</Message></Error>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split('?')[0]
        if path.startswith('/scopedbucket'):
            body, code = LIST_OBJECTS, 200
        else:
            body, code = ACCESS_DENIED, 403
        self.send_response(code)
        self.send_header('Content-Type', 'application/xml')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == '__main__':
    HTTPServer(('127.0.0.1', 19001), Handler).serve_forever()
