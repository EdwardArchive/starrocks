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

#include <glog/logging.h>
#include <gtest/gtest.h>

#include <memory>

#include "column/column_helper.h"
#include "column/map_column.h"
#include "exprs/function_helper.h"
#include "exprs/mock_vectorized_expr.h"
#include "exprs/http_request_functions.h"
#include "runtime/runtime_state.h"
#include "testutil/assert.h"
#include "testutil/parallel_test.h"

namespace starrocks {

class HttpRequestFunctionsTest : public ::testing::Test {
protected:
    void SetUp() override {
        _runtime_state = std::make_unique<RuntimeState>(TQueryGlobals());
        _ctx = FunctionContext::create_test_context();
    }

    void TearDown() override {
        _ctx.reset();
        _runtime_state.reset();
    }

    // Helper function to create 8-column input for http_request function
    // Columns: url, method, body, headers, timeout_ms, ssl_verify, username, password
    Columns create_http_request_columns(const ColumnPtr& url_column, size_t num_rows) {
        Columns columns;
        columns.emplace_back(url_column);

        // method (default: 'GET')
        auto method_column = BinaryColumn::create();
        for (size_t i = 0; i < num_rows; i++) {
            method_column->append("GET");
        }
        columns.emplace_back(method_column);

        // body (default: '')
        auto body_column = BinaryColumn::create();
        for (size_t i = 0; i < num_rows; i++) {
            body_column->append("");
        }
        columns.emplace_back(body_column);

        // headers (default: '{}')
        auto headers_column = BinaryColumn::create();
        for (size_t i = 0; i < num_rows; i++) {
            headers_column->append("{}");
        }
        columns.emplace_back(headers_column);

        // timeout_ms (default: 30000)
        auto timeout_column = Int32Column::create();
        for (size_t i = 0; i < num_rows; i++) {
            timeout_column->append(30000);
        }
        columns.emplace_back(timeout_column);

        // ssl_verify (default: true)
        auto ssl_verify_column = BooleanColumn::create();
        for (size_t i = 0; i < num_rows; i++) {
            ssl_verify_column->append(true);
        }
        columns.emplace_back(ssl_verify_column);

        // username (default: '')
        auto username_column = BinaryColumn::create();
        for (size_t i = 0; i < num_rows; i++) {
            username_column->append("");
        }
        columns.emplace_back(username_column);

        // password (default: '')
        auto password_column = BinaryColumn::create();
        for (size_t i = 0; i < num_rows; i++) {
            password_column->append("");
        }
        columns.emplace_back(password_column);

        return columns;
    }

    // Helper to create 8 null columns for null input test
    Columns create_null_columns(size_t num_rows) {
        Columns columns;
        for (int i = 0; i < 8; i++) {
            columns.emplace_back(ColumnHelper::create_const_null_column(num_rows));
        }
        return columns;
    }

    std::unique_ptr<RuntimeState> _runtime_state;
    std::unique_ptr<FunctionContext> _ctx;
};

// Basic prepare and close test
PARALLEL_TEST_F(HttpRequestFunctionsTest, prepareCloseTest) {
    // Test http_request_prepare
    FunctionContext::FunctionStateScope scope = FunctionContext::FRAGMENT_LOCAL;
    ASSERT_OK(HttpRequestFunctions::http_request_prepare(_ctx.get(), scope));

    // Verify state is created
    auto* state = reinterpret_cast<HttpRequestFunctionState*>(_ctx->get_function_state(scope));
    ASSERT_NE(nullptr, state);

    // Verify default values
    // ssl_verify_required is false by default (admin can enable via Config)
    ASSERT_FALSE(state->ssl_verify_required);

    // Test http_request_close
    ASSERT_OK(HttpRequestFunctions::http_request_close(_ctx.get(), scope));
}

// Test NULL input handling - when URL is NULL, result should be NULL
PARALLEL_TEST_F(HttpRequestFunctionsTest, nullInputTest) {
    FunctionContext::FunctionStateScope scope = FunctionContext::FRAGMENT_LOCAL;
    ASSERT_OK(HttpRequestFunctions::http_request_prepare(_ctx.get(), scope));

    // Create 8 null columns (url, method, body, headers, timeout_ms, ssl_verify, username, password)
    Columns columns = create_null_columns(10);

    auto result = HttpRequestFunctions::http_request(_ctx.get(), columns);
    ASSERT_TRUE(result.ok());
    ASSERT_TRUE(result.value()->only_null());
    ASSERT_EQ(10, result.value()->size());

    ASSERT_OK(HttpRequestFunctions::http_request_close(_ctx.get(), scope));
}

// Test empty URL - returns JSON error response with status -1
PARALLEL_TEST_F(HttpRequestFunctionsTest, emptyUrlTest) {
    FunctionContext::FunctionStateScope scope = FunctionContext::FRAGMENT_LOCAL;
    ASSERT_OK(HttpRequestFunctions::http_request_prepare(_ctx.get(), scope));

    // Create URL column with empty string
    auto url_column = BinaryColumn::create();
    url_column->append("");
    Columns columns = create_http_request_columns(url_column, 1);

    auto result = HttpRequestFunctions::http_request(_ctx.get(), columns);
    ASSERT_TRUE(result.ok());
    ASSERT_EQ(1, result.value()->size());
    // Empty URL returns JSON error response, not NULL
    ASSERT_FALSE(result.value()->is_null(0));
    // Response should contain status -1 (error)
    auto* binary_col = ColumnHelper::get_binary_column(result.value().get());
    std::string response = binary_col->get_slice(0).to_string();
    ASSERT_TRUE(response.find("\"status\": -1") != std::string::npos ||
                response.find("\"status\":-1") != std::string::npos);

    ASSERT_OK(HttpRequestFunctions::http_request_close(_ctx.get(), scope));
}

// Test invalid URL format - returns JSON error response with status -1
PARALLEL_TEST_F(HttpRequestFunctionsTest, invalidUrlTest) {
    FunctionContext::FunctionStateScope scope = FunctionContext::FRAGMENT_LOCAL;
    ASSERT_OK(HttpRequestFunctions::http_request_prepare(_ctx.get(), scope));

    // Create URL column with invalid URL
    auto url_column = BinaryColumn::create();
    url_column->append("not a valid url");
    Columns columns = create_http_request_columns(url_column, 1);

    auto result = HttpRequestFunctions::http_request(_ctx.get(), columns);
    ASSERT_TRUE(result.ok());
    ASSERT_EQ(1, result.value()->size());
    // Invalid URL returns JSON error response, not NULL
    ASSERT_FALSE(result.value()->is_null(0));
    // Response should contain status -1 (error)
    auto* binary_col = ColumnHelper::get_binary_column(result.value().get());
    std::string response = binary_col->get_slice(0).to_string();
    ASSERT_TRUE(response.find("\"status\": -1") != std::string::npos ||
                response.find("\"status\":-1") != std::string::npos);

    ASSERT_OK(HttpRequestFunctions::http_request_close(_ctx.get(), scope));
}

// Note: Full HTTP functionality testing requires a running HTTP server.
// These tests will be covered in SQL integration tests using:
// 1. Local HTTP server with libevent
// 2. Real-world integration tests
// See: test/sql/test_http_request_function/

} // namespace starrocks
