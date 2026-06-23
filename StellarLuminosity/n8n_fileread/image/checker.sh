#!/usr/bin/env bash
# CHECKER-level health probe for n8n-fileread.
#
# GETs the form endpoint and verifies the response is the real n8n-rendered
# Document Submission form, not a stub 200. A plain echo/stub server would
# not return the n8n form HTML containing our workflow's formTitle.
#
# Mode 555, root-owned. Exits 0 on pass.

set -e

PORT=5678

RESPONSE=$(curl -sf --max-time 8 "http://127.0.0.1:${PORT}/form/document-upload" 2>/dev/null) || {
    echo "checker: form endpoint unreachable" >&2
    exit 1
}

if echo "$RESPONSE" | grep -qi "Document Submission"; then
    echo "checker: n8n form page returned correctly"
    exit 0
else
    echo "checker: form page missing expected content" >&2
    echo "checker: first 300 chars: ${RESPONSE:0:300}" >&2
    exit 1
fi
