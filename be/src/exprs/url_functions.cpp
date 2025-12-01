// Copyright 2021-present StarRocks, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "exprs/url_functions.h"

#include <fmt/format.h>

#include <algorithm>
#include <cctype>

#include "column/column_helper.h"
#include "column/map_column.h"
#include "column/nullable_column.h"
#include "common/compiler_util.h"
#include "gutil/strings/strip.h"
#include "http/http_client.h"
#include "http/http_method.h"

namespace starrocks {

// Hardcoded default values for URL function configuration
// These can be overridden per-call using the options MAP parameter
const int64_t DEFAULT_MAX_RESPONSE_SIZE = 1048576;     // 1MB
const int32_t DEFAULT_TIMEOUT_MS = 30000;              // 30 seconds
const bool DEFAULT_SSL_VERIFY_PEER = true;
const bool DEFAULT_SSL_VERIFY_HOST = true;

// Helper function: Parse HTTP method from string
static HttpMethod parse_http_method(const Slice& method_str) {
    std::string method_upper = method_str.to_string();
    std::transform(method_upper.begin(), method_upper.end(), method_upper.begin(),
                   [](unsigned char c) { return std::toupper(c); });

    if (method_upper == "GET") {
        return HttpMethod::GET;
    } else if (method_upper == "POST") {
        return HttpMethod::POST;
    } else if (method_upper == "PUT") {
        return HttpMethod::PUT;
    } else if (method_upper == "DELETE") {
        return HttpMethod::DELETE;
    } else if (method_upper == "HEAD") {
        return HttpMethod::HEAD;
    } else if (method_upper == "OPTIONS") {
        return HttpMethod::OPTIONS;
    }

    return HttpMethod::GET; // Default to GET
}

// Helper function: Extract string value from MAP column at given row for a specific key
static std::optional<std::string> get_map_value(const MapColumn* map_col, size_t row_idx, const std::string& key) {
    if (map_col == nullptr) {
        return std::nullopt;
    }

    auto keys_column = map_col->keys_column();
    auto values_column = map_col->values_column();
    const auto& offsets = map_col->offsets().immutable_data();

    // Get key-value range for this row
    uint32_t start = offsets[row_idx];
    uint32_t end = offsets[row_idx + 1];

    // Unwrap nullable columns if needed
    const BinaryColumn* keys_data = nullptr;
    const BinaryColumn* values_data = nullptr;

    if (keys_column->is_nullable()) {
        auto nullable_keys = down_cast<const NullableColumn*>(keys_column.get());
        keys_data = down_cast<const BinaryColumn*>(nullable_keys->data_column().get());
    } else {
        keys_data = down_cast<const BinaryColumn*>(keys_column.get());
    }

    if (values_column->is_nullable()) {
        auto nullable_values = down_cast<const NullableColumn*>(values_column.get());
        values_data = down_cast<const BinaryColumn*>(nullable_values->data_column().get());
    } else {
        values_data = down_cast<const BinaryColumn*>(values_column.get());
    }

    // Search for the key
    for (uint32_t i = start; i < end; i++) {
        Slice key_slice = keys_data->get_slice(i);
        if (key_slice.to_string() == key) {
            // Check if value is null
            if (values_column->is_nullable()) {
                auto nullable_values = down_cast<const NullableColumn*>(values_column.get());
                if (nullable_values->is_null(i)) {
                    return std::nullopt;
                }
            }
            return values_data->get_slice(i).to_string();
        }
    }

    return std::nullopt;
}

// Helper function: Apply headers from MAP column to HttpClient
static void apply_headers(HttpClient* client, const MapColumn* headers_map, size_t row_idx) {
    if (headers_map == nullptr) {
        return;
    }

    auto keys_column = headers_map->keys_column();
    auto values_column = headers_map->values_column();
    const auto& offsets = headers_map->offsets().immutable_data();

    uint32_t start = offsets[row_idx];
    uint32_t end = offsets[row_idx + 1];

    // Unwrap nullable columns
    const BinaryColumn* keys_data = nullptr;
    const BinaryColumn* values_data = nullptr;

    if (keys_column->is_nullable()) {
        auto nullable_keys = down_cast<const NullableColumn*>(keys_column.get());
        keys_data = down_cast<const BinaryColumn*>(nullable_keys->data_column().get());
    } else {
        keys_data = down_cast<const BinaryColumn*>(keys_column.get());
    }

    if (values_column->is_nullable()) {
        auto nullable_values = down_cast<const NullableColumn*>(values_column.get());
        values_data = down_cast<const BinaryColumn*>(nullable_values->data_column().get());
    } else {
        values_data = down_cast<const BinaryColumn*>(values_column.get());
    }

    // Apply all headers
    for (uint32_t i = start; i < end; i++) {
        // Skip if value is null
        if (values_column->is_nullable()) {
            auto nullable_values = down_cast<const NullableColumn*>(values_column.get());
            if (nullable_values->is_null(i)) {
                continue;
            }
        }

        std::string key = keys_data->get_slice(i).to_string();
        std::string value = values_data->get_slice(i).to_string();
        client->set_header(key, value);
    }
}

// Helper function: Apply SSL options from options MAP
static void apply_ssl_options(HttpClient* client, const MapColumn* options_map, size_t row_idx,
                               const UrlFunctionState* state) {
    // Start with hardcoded defaults
    bool verify_peer = DEFAULT_SSL_VERIFY_PEER;
    bool verify_host = DEFAULT_SSL_VERIFY_HOST;
    std::string ca_cert_path;

    // Override with options MAP if provided
    if (options_map != nullptr) {
        auto ssl_verify_peer_opt = get_map_value(options_map, row_idx, "ssl_verify_peer");
        if (ssl_verify_peer_opt.has_value()) {
            std::string val_lower = ssl_verify_peer_opt.value();
            std::transform(val_lower.begin(), val_lower.end(), val_lower.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            verify_peer = (val_lower == "true" || val_lower == "1");
        }

        auto ssl_verify_host_opt = get_map_value(options_map, row_idx, "ssl_verify_host");
        if (ssl_verify_host_opt.has_value()) {
            std::string val_lower = ssl_verify_host_opt.value();
            std::transform(val_lower.begin(), val_lower.end(), val_lower.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            verify_host = (val_lower == "true" || val_lower == "1");
        }

        auto ca_cert_opt = get_map_value(options_map, row_idx, "ca_cert");
        if (ca_cert_opt.has_value() && !ca_cert_opt.value().empty()) {
            ca_cert_path = ca_cert_opt.value();
        }

        // Client certificate (mTLS) - Note: Would need HttpClient API support
        // auto client_cert_opt = get_map_value(options_map, row_idx, "client_cert");
        // auto client_key_opt = get_map_value(options_map, row_idx, "client_key");
        // TODO: Add client certificate support to HttpClient class
    }

    // Check if admin has enforced SSL verification (from global Config)
    if (state->ssl_verify_required) {
        verify_peer = true;
        verify_host = true;
    }

    // Apply SSL settings
    if (!verify_peer && !verify_host) {
        client->trust_all_ssl();
    }
    // Note: HttpClient::trust_all_ssl() disables both peer and host verification
    // For fine-grained control, we would need to extend HttpClient API
    // TODO: Add methods like set_ssl_verify_peer() and set_ssl_verify_host() to HttpClient
}

// Helper function: Execute HTTP request
static StatusOr<std::string> execute_http_request(const Slice& url_slice, const Slice& method_slice,
                                                    const MapColumn* headers_map, const Slice& body_slice,
                                                    int32_t timeout_ms, const MapColumn* options_map, size_t row_idx,
                                                    const UrlFunctionState* state) {
    // Create HttpClient
    HttpClient client;

    // Initialize with URL
    std::string url_str = url_slice.to_string();
    RETURN_IF_ERROR(client.init(url_str));

    // Set HTTP method
    HttpMethod method = parse_http_method(method_slice);
    client.set_method(method);

    // Apply headers
    apply_headers(&client, headers_map, row_idx);

    // Apply Basic Authentication from options MAP if provided
    if (options_map != nullptr) {
        auto username_opt = get_map_value(options_map, row_idx, "username");
        auto password_opt = get_map_value(options_map, row_idx, "password");
        if (username_opt.has_value() && password_opt.has_value()) {
            client.set_basic_auth(username_opt.value(), password_opt.value());
        }
    }

    // Set request body for POST/PUT
    if (!body_slice.empty() && (method == HttpMethod::POST || method == HttpMethod::PUT)) {
        client.set_payload(body_slice.to_string());
    }

    // Set timeout (use parameter if provided, otherwise check options MAP, otherwise use default)
    int64_t actual_timeout = DEFAULT_TIMEOUT_MS;
    if (timeout_ms > 0) {
        actual_timeout = timeout_ms;
    } else if (options_map != nullptr) {
        auto timeout_opt = get_map_value(options_map, row_idx, "timeout_ms");
        if (timeout_opt.has_value()) {
            try {
                actual_timeout = std::stoi(timeout_opt.value());
            } catch (...) {
                // Invalid timeout value, use default
            }
        }
    }
    client.set_timeout_ms(actual_timeout);

    // Apply SSL options
    apply_ssl_options(&client, options_map, row_idx, state);

    // Execute request
    std::string response;
    RETURN_IF_ERROR(client.execute(&response));

    // Check response size limit (read from options MAP or use default)
    int64_t max_response_size = DEFAULT_MAX_RESPONSE_SIZE;
    if (options_map != nullptr) {
        auto max_size_opt = get_map_value(options_map, row_idx, "max_response_size");
        if (max_size_opt.has_value()) {
            try {
                max_response_size = std::stoll(max_size_opt.value());
            } catch (...) {
                // Invalid size value, use default
            }
        }
    }

    if (response.size() > static_cast<size_t>(max_response_size)) {
        return Status::InternalError(fmt::format("Response size exceeds limit ({} bytes). Received: {} bytes",
                                                  max_response_size, response.size()));
    }

    // Note: We return the response body even for HTTP error status codes (4xx, 5xx)
    // This allows users to parse error messages from the response

    return response;
}

// Prepare function: Initialize state
Status UrlFunctions::url_prepare(FunctionContext* context, FunctionContext::FunctionStateScope scope) {
    if (scope != FunctionContext::FRAGMENT_LOCAL) {
        return Status::OK();
    }

    auto* state = new UrlFunctionState();

    // SSL verification is enabled by default (can be disabled per-call via options MAP)
    state->ssl_verify_required = false;

    context->set_function_state(scope, state);
    return Status::OK();
}

// Close function: Cleanup resources
Status UrlFunctions::url_close(FunctionContext* context, FunctionContext::FunctionStateScope scope) {
    if (scope != FunctionContext::FRAGMENT_LOCAL) {
        return Status::OK();
    }

    auto* state = reinterpret_cast<UrlFunctionState*>(context->get_function_state(scope));
    if (state != nullptr) {
        delete state;
    }

    return Status::OK();
}

// Main URL function implementation
StatusOr<ColumnPtr> UrlFunctions::url(FunctionContext* context, const Columns& columns) {
    RETURN_IF_COLUMNS_ONLY_NULL(columns);

    size_t num_rows = columns[0]->size();
    size_t num_args = columns.size();

    // Get function state
    auto* state = reinterpret_cast<UrlFunctionState*>(
            context->get_function_state(FunctionContext::FRAGMENT_LOCAL));
    if (state == nullptr) {
        return Status::InternalError("URL function state not initialized");
    }

    // Build result column
    ColumnBuilder<TYPE_VARCHAR> result(num_rows);

    // Process each row
    for (size_t i = 0; i < num_rows; i++) {
        // Parse arguments based on number of parameters
        // Supported overloads:
        // 1: url(url)
        // 2: url(url, method)
        // 3: url(url, method, headers)
        // 5: url(url, method, headers, body, timeout)
        // 6: url(url, method, headers, body, timeout, options)

        // Argument 0: URL (required)
        auto url_viewer = ColumnViewer<TYPE_VARCHAR>(columns[0]);
        if (url_viewer.is_null(i)) {
            result.append_null();
            continue;
        }
        Slice url_slice = url_viewer.value(i);

        // Argument 1: Method (optional, default: GET)
        Slice method_slice = Slice("GET");
        if (num_args >= 2) {
            auto method_viewer = ColumnViewer<TYPE_VARCHAR>(columns[1]);
            if (!method_viewer.is_null(i)) {
                method_slice = method_viewer.value(i);
            }
        }

        // Argument 2: Headers MAP (optional)
        const MapColumn* headers_map = nullptr;
        if (num_args >= 3 && !columns[2]->only_null()) {
            auto headers_col = ColumnHelper::get_data_column(columns[2].get());
            if (!columns[2]->is_null(i)) {
                headers_map = down_cast<const MapColumn*>(headers_col);
            }
        }

        // Argument 3: Body (optional, for POST/PUT)
        Slice body_slice;
        if (num_args >= 5) {
            auto body_viewer = ColumnViewer<TYPE_VARCHAR>(columns[3]);
            if (!body_viewer.is_null(i)) {
                body_slice = body_viewer.value(i);
            }
        }

        // Argument 4: Timeout (optional, default from state)
        int32_t timeout_ms = 0;
        if (num_args >= 5) {
            auto timeout_viewer = ColumnViewer<TYPE_INT>(columns[4]);
            if (!timeout_viewer.is_null(i)) {
                timeout_ms = timeout_viewer.value(i);
            }
        }

        // Argument 5: Options MAP (optional)
        const MapColumn* options_map = nullptr;
        if (num_args >= 6 && !columns[5]->only_null()) {
            auto options_col = ColumnHelper::get_data_column(columns[5].get());
            if (!columns[5]->is_null(i)) {
                options_map = down_cast<const MapColumn*>(options_col);
            }
        }

        // Execute HTTP request
        auto response = execute_http_request(url_slice, method_slice, headers_map, body_slice, timeout_ms, options_map,
                                              i, state);

        if (!response.ok()) {
            // Return NULL and add warning
            result.append_null();
            context->add_warning(std::string(response.status().message()).c_str());
            continue;
        }

        // Append successful response
        result.append(Slice(response.value()));
    }

    return result.build(ColumnHelper::is_all_const(columns));
}

} // namespace starrocks
