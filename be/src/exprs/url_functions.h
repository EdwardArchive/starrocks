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

// State structure for URL function
// Stores only the global admin-enforced SSL verification setting
struct UrlFunctionState {
    bool ssl_verify_required;     // Admin-enforced SSL verification (global setting from Config)
};

class UrlFunctions {
public:
    /**
     * URL function with JSON config string
     *
     * Signature:
     * - url(url VARCHAR) -> VARCHAR
     * - url(url VARCHAR, config VARCHAR) -> VARCHAR
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
    DEFINE_VECTORIZED_FN(url);

    DEFINE_VECTORIZED_FN(url_with_config);

    /**
     * Prepare function - Called once per fragment
     * Reads global Config and initializes UrlFunctionState
     */
    static Status url_prepare(FunctionContext* context, FunctionContext::FunctionStateScope scope);

    /**
     * Close function - Called once per fragment
     * Cleanup resources allocated in prepare
     */
    static Status url_close(FunctionContext* context, FunctionContext::FunctionStateScope scope);
};

} // namespace starrocks
