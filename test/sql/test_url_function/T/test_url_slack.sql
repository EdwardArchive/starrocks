-- name: test_url_slack
-- description: Integration test with real Slack webhook
-- Note: This test requires a valid Slack webhook URL
-- Set the webhook URL as an environment variable: SLACK_WEBHOOK_URL

-- Test 1: Send a simple message to Slack
-- Replace YOUR_SLACK_WEBHOOK_URL with actual webhook URL
-- SELECT url(
--     'YOUR_SLACK_WEBHOOK_URL',
--     'POST',
--     map{'Content-Type': 'application/json'},
--     '{"text": "Test message from StarRocks URL() function"}'
-- );

-- Test 2: Send a formatted message with blocks
-- SELECT url(
--     'YOUR_SLACK_WEBHOOK_URL',
--     'POST',
--     map{'Content-Type': 'application/json'},
--     '{
--         "blocks": [
--             {
--                 "type": "header",
--                 "text": {
--                     "type": "plain_text",
--                     "text": "StarRocks URL() Function Test"
--                 }
--             },
--             {
--                 "type": "section",
--                 "text": {
--                     "type": "mrkdwn",
--                     "text": "*Status:* Success\\n*Timestamp:* 2024-12-01"
--                 }
--             }
--         ]
--     }'
-- );

-- Test 3: Send query results to Slack
-- CREATE TABLE sales_summary (region VARCHAR(50), total_sales DECIMAL(10,2));
-- INSERT INTO sales_summary VALUES
--     ('North', 125000.50),
--     ('South', 98000.25),
--     ('East', 156000.75),
--     ('West', 142000.00);

-- SELECT url(
--     'YOUR_SLACK_WEBHOOK_URL',
--     'POST',
--     map{'Content-Type': 'application/json'},
--     CONCAT(
--         '{"text": "Sales Summary:\\n',
--         'North: $', CAST(SUM(CASE WHEN region='North' THEN total_sales END) AS VARCHAR), '\\n',
--         'South: $', CAST(SUM(CASE WHEN region='South' THEN total_sales END) AS VARCHAR), '\\n',
--         'East: $', CAST(SUM(CASE WHEN region='East' THEN total_sales END) AS VARCHAR), '\\n',
--         'West: $', CAST(SUM(CASE WHEN region='West' THEN total_sales END) AS VARCHAR),
--         '"}'
--     )
-- ) as slack_response
-- FROM sales_summary;

-- DROP TABLE sales_summary;

-- Test 4: Error handling - invalid webhook URL
SELECT url(
    'https://hooks.slack.com/services/INVALID/WEBHOOK/URL',
    'POST',
    map{'Content-Type': 'application/json'},
    '{"text": "This should fail"}'
);
