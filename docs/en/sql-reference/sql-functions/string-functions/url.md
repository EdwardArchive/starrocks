---
displayed_sidebar: docs
---

# url

Executes an HTTP request and returns the response body as a string. This function enables direct integration with external REST APIs from within SQL queries.

## Syntax

```Haskell
VARCHAR url(VARCHAR url)
VARCHAR url(VARCHAR url, VARCHAR method)
VARCHAR url(VARCHAR url, VARCHAR method, MAP<VARCHAR, VARCHAR> headers)
VARCHAR url(VARCHAR url, VARCHAR method, MAP<VARCHAR, VARCHAR> headers, VARCHAR body, INT timeout_ms)
VARCHAR url(VARCHAR url, VARCHAR method, MAP<VARCHAR, VARCHAR> headers, VARCHAR body, INT timeout_ms, MAP<VARCHAR, VARCHAR> options)
```

## Parameters

- `url`: The target URL for the HTTP request. Must be a valid HTTP or HTTPS URL.
- `method`: (Optional) HTTP method. Supported values: `GET` (default), `POST`, `PUT`. Case-insensitive.
- `headers`: (Optional) MAP of custom HTTP headers. Example: `map{'Content-Type': 'application/json', 'Authorization': 'Bearer token'}`.
- `body`: (Optional) Request body for POST/PUT requests.
- `timeout_ms`: (Optional) Request timeout in milliseconds. Defaults to session variable `url_default_timeout_ms` (30000ms).
- `options`: (Optional) MAP of additional options:
  - `ssl_verify_peer`: `'true'` or `'false'` to enable/disable SSL peer verification (default: `true`)
  - `ssl_verify_host`: `'true'` or `'false'` to enable/disable SSL host verification (default: `true`)
  - `ca_cert`: Path to custom CA certificate file
  - `username`: Username for HTTP Basic Authentication
  - `password`: Password for HTTP Basic Authentication

## Return value

Returns a VARCHAR containing the HTTP response body. Returns NULL if:
- The URL is invalid or empty
- The HTTP request fails
- The response exceeds `url_max_response_size` (session variable, default 1MB)
- A network error occurs

## Session variables

Configure URL function behavior using session variables:

```SQL
-- Set maximum response size (default: 1048576 bytes = 1MB)
SET url_max_response_size = 2097152;

-- Set default timeout (default: 30000 milliseconds = 30 seconds)
SET url_default_timeout_ms = 60000;

-- Enable/disable SSL verification (default: true)
SET url_ssl_verify_peer = false;
SET url_ssl_verify_host = false;

-- Set custom CA certificate path
SET url_ca_cert_path = '/path/to/ca.crt';
```

## Global configuration

Administrators can enforce SSL verification globally via `fe.conf`:

```Properties
# Force SSL verification (users cannot disable it)
url_ssl_verification_required = true
```

## Examples

### Example 1: Simple GET request

```SQL
SELECT url('https://api.example.com/status');
```

```Plain Text
+----------------------------------------+
| url('https://api.example.com/status')  |
+----------------------------------------+
| {"status":"ok","version":"1.0"}        |
+----------------------------------------+
```

### Example 2: POST with JSON body

```SQL
SELECT url(
    'https://api.example.com/users',
    'POST',
    map{'Content-Type': 'application/json'},
    '{"name":"John","email":"john@example.com"}',
    5000
);
```

### Example 3: API enrichment in query

```SQL
-- Enrich user data with external API
CREATE TABLE users (id INT, name VARCHAR(100));
INSERT INTO users VALUES (1, 'Alice'), (2, 'Bob');

SELECT
    id,
    name,
    url(CONCAT('https://api.example.com/user/', id), 'GET') as profile
FROM users;
```

### Example 4: Slack webhook integration

```SQL
SELECT url(
    'https://hooks.slack.com/services/YOUR/WEBHOOK/URL',
    'POST',
    map{'Content-Type': 'application/json'},
    CONCAT('{"text":"Sales today: $',
           CAST(SUM(amount) AS VARCHAR),
           '"}')
)
FROM sales
WHERE date = CURRENT_DATE();
```

### Example 5: HTTP Basic Authentication

```SQL
SELECT url(
    'https://api.example.com/secure',
    'GET',
    map{},
    '',
    30000,
    map{'username': 'admin', 'password': 'secret'}
);
```

### Example 6: Disable SSL verification

```SQL
-- For testing with self-signed certificates
SELECT url(
    'https://internal-api.local/data',
    'GET',
    map{},
    '',
    30000,
    map{'ssl_verify_peer': 'false', 'ssl_verify_host': 'false'}
);
```

## Usage notes

- **Performance**: Each row executes a separate HTTP request. For large datasets, consider:
  - Filtering rows before applying `url()`
  - Using `LIMIT` to control batch size
  - Increasing `url_default_timeout_ms` for slow APIs

- **Error Handling**: Failed requests return NULL with a warning in logs. Check query logs for details.

- **Security**:
  - Sensitive headers (e.g., `Authorization`) appear in query logs. Future versions will support automatic masking.
  - SSL verification is enabled by default. Only disable for trusted internal endpoints.
  - Administrators can enforce SSL verification globally via `url_ssl_verification_required`.

- **Response Size**: Responses exceeding `url_max_response_size` will fail. Increase the limit if needed:
  ```SQL
  SET url_max_response_size = 10485760; -- 10MB
  ```

- **Rate Limiting**: The function does not implement rate limiting. Respect external API limits or implement throttling at the application level.

## Keywords

URL, HTTP, REST, API, WEBHOOK
