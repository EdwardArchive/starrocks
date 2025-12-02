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
#include <simdjson.h>

#include <algorithm>
#include <cctype>
#include <map>

#include "column/column_helper.h"
#include "http/http_client.h"
#include "http/http_method.h"

namespace starrocks {

// URL configuration parsed from JSON config string
struct UrlConfig {
    std::string method = "GET";
    std::map<std::string, std::string> headers;
    std::string body;
    int32_t timeout_ms = 30000;
    bool ssl_verify = true;
    std::string username;
    std::string password;
};

// Default values for URL function configuration
const int64_t DEFAULT_MAX_RESPONSE_SIZE = 1048576;  // 1MB

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

// Helper function: Escape string for JSON
static std::string escape_json_string(const std::string& s) {
    std::string result;
    result.reserve(s.size() + 16);  // Reserve some extra space for escapes
    for (char c : s) {
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    // Control characters - encode as \uXXXX
                    result += fmt::format("\\u{:04x}", static_cast<unsigned char>(c));
                } else {
                    result += c;
                }
        }
    }
    return result;
}

// Helper function: Parse JSON config string into UrlConfig struct
static StatusOr<UrlConfig> parse_config(const std::string& config_json) {
    UrlConfig config;

    simdjson::ondemand::parser parser;
    simdjson::padded_string padded(config_json);

    auto doc_result = parser.iterate(padded);
    if (doc_result.error()) {
        return Status::InvalidArgument(
                fmt::format("Invalid JSON config: {}", simdjson::error_message(doc_result.error())));
    }

    simdjson::ondemand::document doc = std::move(doc_result.value());
    simdjson::ondemand::object obj;
    if (doc.get_object().get(obj)) {
        return Status::InvalidArgument("Config must be a JSON object");
    }

    // method
    std::string_view method_sv;
    if (!obj["method"].get_string().get(method_sv)) {
        config.method = std::string(method_sv);
    }

    // timeout_ms
    int64_t timeout;
    if (!obj["timeout_ms"].get_int64().get(timeout)) {
        config.timeout_ms = static_cast<int32_t>(timeout);
    }

    // ssl_verify
    bool ssl_verify;
    if (!obj["ssl_verify"].get_bool().get(ssl_verify)) {
        config.ssl_verify = ssl_verify;
    }

    // username, password
    std::string_view username_sv, password_sv;
    if (!obj["username"].get_string().get(username_sv)) {
        config.username = std::string(username_sv);
    }
    if (!obj["password"].get_string().get(password_sv)) {
        config.password = std::string(password_sv);
    }

    // headers (object)
    simdjson::ondemand::object headers_obj;
    if (!obj["headers"].get_object().get(headers_obj)) {
        for (auto field : headers_obj) {
            auto key_result = field.escaped_key();
            if (key_result.error()) continue;
            std::string_view key = key_result.value();
            std::string_view value;
            if (!field.value().get_string().get(value)) {
                config.headers[std::string(key)] = std::string(value);
            }
        }
    }

    // body: object/array면 stringify, string이면 그대로
    simdjson::ondemand::value body_val;
    if (!obj["body"].get(body_val)) {
        auto body_type = body_val.type();
        if (!body_type.error()) {
            if (body_type.value() == simdjson::ondemand::json_type::object ||
                body_type.value() == simdjson::ondemand::json_type::array) {
                // JSON stringify
                auto json_str = simdjson::to_json_string(body_val);
                if (!json_str.error()) {
                    config.body = std::string(json_str.value());
                }
            } else if (body_type.value() == simdjson::ondemand::json_type::string) {
                // string
                std::string_view body_sv;
                if (!body_val.get_string().get(body_sv)) {
                    config.body = std::string(body_sv);
                }
            }
        }
    }

    return config;
}

// Helper function: Check if string is valid JSON
static bool is_valid_json(const std::string& s) {
    if (s.empty()) return false;
    // Simple heuristic: starts with { or [ and is balanced
    char first = s[0];
    if (first != '{' && first != '[') return false;
    // Try to find matching end
    char last = s.back();
    return (first == '{' && last == '}') || (first == '[' && last == ']');
}

// Helper function: Build JSON response string
// Returns: {"status": <code>, "body": <json_or_string>} or {"status": -1, "body": null, "error": "<message>"}
// If body is valid JSON, it's embedded directly; otherwise it's escaped as a string
static std::string build_json_response(long http_status, const std::string& body) {
    if (is_valid_json(body)) {
        // Body is JSON - embed directly without escaping
        return fmt::format(R"({{"status": {}, "body": {}}})", http_status, body);
    } else {
        // Body is plain text - escape as string
        return fmt::format(R"({{"status": {}, "body": "{}"}})", http_status, escape_json_string(body));
    }
}

static std::string build_json_error_response(const std::string& error_message) {
    return fmt::format(R"({{"status": -1, "body": null, "error": "{}"}})", escape_json_string(error_message));
}

// Helper function: Execute HTTP request with UrlConfig
static StatusOr<std::string> execute_http_request_with_config(const Slice& url_slice, const UrlConfig& config,
                                                               const UrlFunctionState* state) {
    HttpClient client;

    // Initialize with URL
    std::string url_str = url_slice.to_string();
    Status init_status = client.init(url_str);
    if (!init_status.ok()) {
        return build_json_error_response(std::string(init_status.message()));
    }

    // Disable CURLOPT_FAILONERROR to get HTTP error responses
    client.set_fail_on_error(false);

    // Set HTTP method
    HttpMethod method = parse_http_method(Slice(config.method));
    client.set_method(method);

    // Apply headers from config
    for (const auto& [key, value] : config.headers) {
        client.set_header(key, value);
    }

    // Apply body
    if (!config.body.empty() && (method == HttpMethod::POST || method == HttpMethod::PUT)) {
        client.set_payload(config.body);
    }

    // Apply timeout
    client.set_timeout_ms(config.timeout_ms);

    // Apply SSL settings
    if (!config.ssl_verify && !state->ssl_verify_required) {
        client.trust_all_ssl();
    }

    // Apply Basic Auth
    if (!config.username.empty()) {
        client.set_basic_auth(config.username, config.password);
    }

    // Execute request
    std::string response;
    Status exec_status = client.execute(&response);

    // Get HTTP status code
    long http_status = client.get_http_status();

    // Check for network/curl errors
    if (!exec_status.ok()) {
        return build_json_error_response(std::string(exec_status.message()));
    }

    // Check response size limit
    if (response.size() > static_cast<size_t>(DEFAULT_MAX_RESPONSE_SIZE)) {
        return build_json_error_response(fmt::format("Response size exceeds limit ({} bytes). Received: {} bytes",
                                                     DEFAULT_MAX_RESPONSE_SIZE, response.size()));
    }

    // Return JSON response with HTTP status code and body
    return build_json_response(http_status, response);
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

// Main URL function implementation (1-arg: simple GET request)
StatusOr<ColumnPtr> UrlFunctions::url(FunctionContext* context, const Columns& columns) {
    RETURN_IF_COLUMNS_ONLY_NULL(columns);

    size_t num_rows = columns[0]->size();

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
        // Argument 0: URL (required)
        auto url_viewer = ColumnViewer<TYPE_VARCHAR>(columns[0]);
        if (url_viewer.is_null(i)) {
            result.append_null();
            continue;
        }
        Slice url_slice = url_viewer.value(i);

        // Execute simple GET request with default config
        UrlConfig default_config;
        auto response = execute_http_request_with_config(url_slice, default_config, state);

        if (!response.ok()) {
            result.append_null();
            context->add_warning(std::string(response.status().message()).c_str());
            continue;
        }

        result.append(Slice(response.value()));
    }

    return result.build(ColumnHelper::is_all_const(columns));
}

// URL function with JSON config string (2-arg overload)
// url(url, config_json)
StatusOr<ColumnPtr> UrlFunctions::url_with_config(FunctionContext* context, const Columns& columns) {
    RETURN_IF_COLUMNS_ONLY_NULL(columns);

    size_t num_rows = columns[0]->size();

    // Get function state
    auto* state =
            reinterpret_cast<UrlFunctionState*>(context->get_function_state(FunctionContext::FRAGMENT_LOCAL));
    if (state == nullptr) {
        return Status::InternalError("URL function state not initialized");
    }

    // Build result column
    ColumnBuilder<TYPE_VARCHAR> result(num_rows);

    // Process each row
    for (size_t i = 0; i < num_rows; i++) {
        // Argument 0: URL (required)
        auto url_viewer = ColumnViewer<TYPE_VARCHAR>(columns[0]);
        if (url_viewer.is_null(i)) {
            result.append_null();
            continue;
        }
        Slice url_slice = url_viewer.value(i);

        // Argument 1: JSON config string (required)
        auto config_viewer = ColumnViewer<TYPE_VARCHAR>(columns[1]);
        if (config_viewer.is_null(i)) {
            // No config provided, use defaults
            UrlConfig default_config;
            auto response = execute_http_request_with_config(url_slice, default_config, state);
            if (!response.ok()) {
                result.append_null();
                context->add_warning(std::string(response.status().message()).c_str());
                continue;
            }
            result.append(Slice(response.value()));
            continue;
        }

        Slice config_slice = config_viewer.value(i);
        std::string config_json = config_slice.to_string();

        // Parse JSON config
        auto config_result = parse_config(config_json);
        if (!config_result.ok()) {
            result.append_null();
            context->add_warning(std::string(config_result.status().message()).c_str());
            continue;
        }

        // Execute HTTP request with config
        auto response = execute_http_request_with_config(url_slice, config_result.value(), state);
        if (!response.ok()) {
            result.append_null();
            context->add_warning(std::string(response.status().message()).c_str());
            continue;
        }

        result.append(Slice(response.value()));
    }

    return result.build(ColumnHelper::is_all_const(columns));
}

} // namespace starrocks

#include "gen_cpp/opcode/UrlFunctions.inc"
