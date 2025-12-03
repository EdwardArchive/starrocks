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

#pragma once

#include "column/column.h"
#include "column/column_builder.h"
#include "column/column_viewer.h"
#include "exprs/function_context.h"
#include "exprs/function_helper.h"

namespace starrocks {

// State structure for HTTP request function
// Stores only the global admin-enforced SSL verification setting
struct HttpRequestFunctionState {
    bool ssl_verify_required;     // Admin-enforced SSL verification (global setting from Config)
};

class HttpRequestFunctions {
public:
    /**
     * HTTP request function with JSON config string
     *
     * Signature:
     * - http_request(url VARCHAR) -> VARCHAR
     * - http_request(url VARCHAR, config VARCHAR) -> VARCHAR
     *
     * Config JSON format:
     * {
     *     "method": "GET|POST|PUT|DELETE",  // default: "GET"
     *     "headers": {"key": "value", ...},        // default: {}
     *     "body": <string|object>,                 // default: null (object auto-stringify)
     *     "timeout_ms": 30000,                     // default: 30000
     *     "ssl_verify": true,                      // default: true
     *     "username": "user",                      // default: null
     *     "password": "pass"                       // default: null
     * }
     */
    DEFINE_VECTORIZED_FN(http_request);

    DEFINE_VECTORIZED_FN(http_request_with_config);

    /**
     * Prepare function - Called once per fragment
     * Reads global Config and initializes HttpRequestFunctionState
     */
    static Status http_request_prepare(FunctionContext* context, FunctionContext::FunctionStateScope scope);

    /**
     * Close function - Called once per fragment
     * Cleanup resources allocated in prepare
     */
    static Status http_request_close(FunctionContext* context, FunctionContext::FunctionStateScope scope);
};

} // namespace starrocks
