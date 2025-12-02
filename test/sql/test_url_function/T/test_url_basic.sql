-- name: test_url_basic
-- description: Basic tests for URL() function with JSON config
-- Note: Uses jsonplaceholder.typicode.com as a reliable public API
-- Response format: {"status": <code>, "body": <content>} or {"status": -1, "body": null, "error": "<message>"}

-- Test 1: NULL input returns NULL
SELECT url(NULL);

-- Test 2: Empty string returns JSON with error
SELECT json_query(url(''), '$.status') as status;

-- Test 3: Invalid URL returns JSON with error
SELECT json_query(url('not a valid url'), '$.status') as status;

-- Test 4: Simple GET request (1-arg form) - check status code
SELECT json_query(url('https://jsonplaceholder.typicode.com/posts/1'), '$.status') as status;

-- Test 5: GET and parse JSON response body (1-arg form)
SELECT json_query(
    json_query(url('https://jsonplaceholder.typicode.com/posts/1'), '$.body'),
    '$.id'
) as post_id;

-- Test 6: POST with JSON config (body as object - auto stringify)
SELECT json_query(
    json_query(url(
        'https://jsonplaceholder.typicode.com/posts',
        '{"method": "POST", "headers": {"Content-Type": "application/json"}, "body": {"title": "test post", "body": "hello world", "userId": 1}, "timeout_ms": 30000}'
    ), '$.body'),
    '$.title'
) as created_title;

-- Test 7: DELETE request with JSON config
SELECT json_query(url(
    'https://jsonplaceholder.typicode.com/posts/1',
    '{"method": "DELETE"}'
), '$.status') as status;

-- Test 8: Request with SSL options (disable verification)
SELECT json_query(url(
    'https://jsonplaceholder.typicode.com/posts/1',
    '{"ssl_verify": false}'
), '$.status') as status;

-- Test 9: Invalid domain returns JSON with status -1 (network error)
SELECT json_query(url(
    'https://invalid-domain-that-does-not-exist-12345.com/api',
    '{"timeout_ms": 5000}'
), '$.status') as status;

-- Test 10: HTTP 404 error returns JSON with status 404
SELECT json_query(url(
    'https://jsonplaceholder.typicode.com/posts/99999',
    '{}'
), '$.status') as status;

-- Test 11: GET with custom headers using JSON config
SELECT json_query(url(
    'https://jsonplaceholder.typicode.com/posts/1',
    '{"headers": {"Accept": "application/json"}}'
), '$.status') as status;

-- Test 12: Very short timeout returns JSON with status -1 (timeout error)
SELECT json_query(url(
    'https://jsonplaceholder.typicode.com/posts/1',
    '{"timeout_ms": 1}'
), '$.status') as status;

-- Test 13: Large response (100 posts ~27KB) - should work within 1MB limit
SELECT json_query(url(
    'https://jsonplaceholder.typicode.com/posts',
    '{}'
), '$.status') as status;

-- Test 14: Very large response (photos ~25MB) - exceeds 1MB limit, returns error
SELECT json_query(url(
    'https://jsonplaceholder.typicode.com/photos',
    '{"timeout_ms": 60000}'
), '$.status') as status;

-- Test 15: POST with body as string (not auto-stringify)
SELECT json_query(url(
    'https://jsonplaceholder.typicode.com/posts',
    '{"method": "POST", "headers": {"Content-Type": "text/plain"}, "body": "plain text body"}'
), '$.status') as status;

-- ============================================================
-- Slack Webhook Integration Tests
-- ============================================================

-- Test 16: Slack Webhook - Simple Message
SELECT json_query(url(
    'https://hooks.slack.com/services/INVALID/WEBHOOK/URL',
    '{"method": "POST", "headers": {"Content-Type": "application/json"}, "body": {"text": "Test 16: Simple message from StarRocks URL function"}}'
), '$.status') as status;

-- Test 17: Slack Webhook - Rich Message with Block Kit (Sales Report)
SELECT json_query(url(
    'https://hooks.slack.com/services/INVALID/WEBHOOK/URL',
    '{"method": "POST", "headers": {"Content-Type": "application/json"}, "body": {"blocks": [{"type": "header", "text": {"type": "plain_text", "text": "Sales Summary from StarRocks", "emoji": true}}, {"type": "section", "fields": [{"type": "mrkdwn", "text": "*North:* $125,000.50"}, {"type": "mrkdwn", "text": "*South:* $98,000.25"}, {"type": "mrkdwn", "text": "*East:* $156,000.75"}, {"type": "mrkdwn", "text": "*West:* $142,000.00"}]}]}}'
), '$.status') as status;

-- Test 18: Slack Webhook - Alert with Attachments (CPU Alert)
SELECT json_query(url(
    'https://hooks.slack.com/services/INVALID/WEBHOOK/URL',
    '{"method": "POST", "headers": {"Content-Type": "application/json"}, "body": {"attachments": [{"color": "#ff0000", "title": "High CPU Alert", "text": "Server node-01 CPU usage exceeded 90%", "fields": [{"title": "Server", "value": "node-01", "short": true}, {"title": "CPU", "value": "92.5%", "short": true}, {"title": "Memory", "value": "78.3%", "short": true}, {"title": "Status", "value": "Critical", "short": true}], "footer": "StarRocks Monitoring"}]}}'
), '$.status') as status;

-- ============================================================
-- SSL Verification Tests (using badssl.com test sites)
-- ============================================================

-- Test 19: Self-signed certificate with ssl_verify=true (default) - should fail
SELECT json_query(url('https://self-signed.badssl.com/'), '$.status') as status;

-- Test 20: Self-signed certificate with ssl_verify=false - should succeed
SELECT json_query(url('https://self-signed.badssl.com/', '{"ssl_verify": false}'), '$.status') as status;

-- Test 21: Expired certificate with ssl_verify=true (default) - should fail
SELECT json_query(url('https://expired.badssl.com/'), '$.status') as status;

-- Test 22: Expired certificate with ssl_verify=false - should succeed
SELECT json_query(url('https://expired.badssl.com/', '{"ssl_verify": false}'), '$.status') as status;
