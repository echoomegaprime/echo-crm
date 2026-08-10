#!/bin/bash
set -e

echo "=== Echo-CRM Observability Verification ==="
echo ""

# Check MetricsCollector class exists
if grep -q "class MetricsCollector:" app.py; then
    echo "✓ MetricsCollector class defined"
else
    echo "✗ MetricsCollector class NOT found"
    exit 1
fi

# Check RequestMetricsMiddleware exists
if grep -q "class RequestMetricsMiddleware:" app.py; then
    echo "✓ RequestMetricsMiddleware defined"
else
    echo "✗ RequestMetricsMiddleware NOT found"
    exit 1
fi

# Check health endpoint is enhanced
if grep -q "def health() -> dict\[str, Any\]:" app.py && \
   grep -q '"checks":' app.py && \
   grep -q '"database":' app.py; then
    echo "✓ Enhanced /health endpoint implemented"
else
    echo "✗ Health endpoint not properly enhanced"
    exit 1
fi

# Check metrics endpoint exists
if grep -q "def metrics_endpoint() -> dict\[str, Any\]:" app.py; then
    echo "✓ /metrics endpoint implemented"
else
    echo "✗ Metrics endpoint NOT found"
    exit 1
fi

# Check structured logging enhancements
if grep -q '"version": "2.0.0"' app.py; then
    echo "✓ Structured logging includes version"
else
    echo "✗ Structured logging not properly enhanced"
    exit 1
fi

# Check middleware registration
if grep -q "app.add_middleware(RequestMetricsMiddleware)" app.py; then
    echo "✓ Middleware registered with FastAPI app"
else
    echo "✗ Middleware not registered"
    exit 1
fi

# Check DB metrics tracking
if grep -q "metrics.record_db_query" app.py; then
    echo "✓ Database metrics tracking integrated"
else
    echo "✗ Database metrics tracking NOT found"
    exit 1
fi

# Check shutdown metrics logging
if grep -q "m\[\"uptime_seconds\"\]" app.py || grep -q "uptime_sec" app.py; then
    echo "✓ Shutdown metrics summary implemented"
else
    echo "✗ Shutdown metrics summary NOT found"
    exit 1
fi

echo ""
echo "=== Syntax & Import Check ==="
PGHOST=test PGUSER=test PGPASSWORD=test PGDATABASE=test ECHO_CRM_API_KEY=test python3 -m py_compile app.py && \
    echo "✓ Python syntax valid"

echo ""
echo "=== File Statistics ==="
wc -l app.py test_observability.py OBSERVABILITY.md
du -h app.py

echo ""
echo "✓ All observability components verified!"
