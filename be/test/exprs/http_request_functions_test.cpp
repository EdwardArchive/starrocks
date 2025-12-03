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

// Test NULL input handling
PARALLEL_TEST_F(HttpRequestFunctionsTest, nullInputTest) {
    FunctionContext::FunctionStateScope scope = FunctionContext::FRAGMENT_LOCAL;
    ASSERT_OK(HttpRequestFunctions::http_request_prepare(_ctx.get(), scope));

    Columns columns;
    auto null_column = ColumnHelper::create_const_null_column(10);
    columns.emplace_back(null_column);

    auto result = HttpRequestFunctions::http_request(_ctx.get(), columns);
    ASSERT_TRUE(result.ok());
    ASSERT_TRUE(result.value()->only_null());
    ASSERT_EQ(10, result.value()->size());

    ASSERT_OK(HttpRequestFunctions::http_request_close(_ctx.get(), scope));
}

// Test empty URL
PARALLEL_TEST_F(HttpRequestFunctionsTest, emptyUrlTest) {
    FunctionContext::FunctionStateScope scope = FunctionContext::FRAGMENT_LOCAL;
    ASSERT_OK(HttpRequestFunctions::http_request_prepare(_ctx.get(), scope));

    Columns columns;
    auto url_column = BinaryColumn::create();
    url_column->append("");
    columns.emplace_back(url_column);

    auto result = HttpRequestFunctions::http_request(_ctx.get(), columns);
    ASSERT_TRUE(result.ok());
    // Empty URL should return NULL
    ASSERT_TRUE(result.value()->is_null(0));

    ASSERT_OK(HttpRequestFunctions::http_request_close(_ctx.get(), scope));
}

// Test invalid URL format
PARALLEL_TEST_F(HttpRequestFunctionsTest, invalidUrlTest) {
    FunctionContext::FunctionStateScope scope = FunctionContext::FRAGMENT_LOCAL;
    ASSERT_OK(HttpRequestFunctions::http_request_prepare(_ctx.get(), scope));

    Columns columns;
    auto url_column = BinaryColumn::create();
    url_column->append("not a valid url");
    columns.emplace_back(url_column);

    auto result = HttpRequestFunctions::http_request(_ctx.get(), columns);
    ASSERT_TRUE(result.ok());
    // Invalid URL should return NULL with warning
    ASSERT_TRUE(result.value()->is_null(0));

    ASSERT_OK(HttpRequestFunctions::http_request_close(_ctx.get(), scope));
}

// Note: Full HTTP functionality testing requires a running HTTP server.
// These tests will be covered in SQL integration tests using:
// 1. Local HTTP server with libevent
// 2. Real-world integration tests
// See: test/sql/test_http_request_function/

} // namespace starrocks
