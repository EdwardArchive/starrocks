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

// S2 Serialization Snapshot Generator
//
// This utility generates hex-encoded binary snapshots of GEO shapes encoded
// with the CURRENT S2 library version. The output hex strings should be
// hardcoded into s2_serialization_compat_test.cpp as test constants.
//
// Usage:
//   1. Build and run this test WITH THE OLD S2 VERSION (v0.9.0) BEFORE upgrading.
//   2. Copy the hex output from stdout into the kV090*Hex constants in
//      s2_serialization_compat_test.cpp.
//   3. After upgrading S2, the compat test will verify old data can still be decoded.

#include "geo/geo_types.h"

#include <gtest/gtest.h>

#include <iomanip>
#include <iostream>
#include <sstream>

#include "geo/wkt_parse.h"

namespace starrocks {

static std::string to_hex(const std::string& binary) {
    std::ostringstream ss;
    for (unsigned char c : binary) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return ss.str();
}

class S2CompatSnapshotGen : public ::testing::Test {};

TEST_F(S2CompatSnapshotGen, GeneratePointSnapshot) {
    GeoPoint point;
    auto status = point.from_coord(116.123, 63.546);
    ASSERT_EQ(GEO_PARSE_OK, status);

    std::string buf;
    point.encode_to(&buf);

    std::cout << "=== Point: ST_Point(116.123, 63.546) ===" << std::endl;
    std::cout << "Size: " << buf.size() << " bytes" << std::endl;
    std::cout << "Hex: " << to_hex(buf) << std::endl;
    std::cout << "WKT: " << point.as_wkt() << std::endl;
    std::cout << std::endl;
}

TEST_F(S2CompatSnapshotGen, GenerateLineStringSnapshot) {
    const char* wkt = "LINESTRING (30 10, 10 30, 40 40)";
    GeoParseStatus status;
    std::unique_ptr<GeoShape> line(GeoShape::from_wkt(wkt, strlen(wkt), &status));
    ASSERT_EQ(GEO_PARSE_OK, status);
    ASSERT_NE(nullptr, line.get());

    std::string buf;
    line->encode_to(&buf);

    std::cout << "=== LineString: LINESTRING (30 10, 10 30, 40 40) ===" << std::endl;
    std::cout << "Size: " << buf.size() << " bytes" << std::endl;
    std::cout << "Hex: " << to_hex(buf) << std::endl;
    std::cout << "WKT: " << line->as_wkt() << std::endl;
    std::cout << std::endl;
}

TEST_F(S2CompatSnapshotGen, GeneratePolygonSnapshot) {
    const char* wkt = "POLYGON ((10 10, 50 10, 50 50, 10 50, 10 10))";
    GeoParseStatus status;
    std::unique_ptr<GeoShape> polygon(GeoShape::from_wkt(wkt, strlen(wkt), &status));
    ASSERT_EQ(GEO_PARSE_OK, status);
    ASSERT_NE(nullptr, polygon.get());

    std::string buf;
    polygon->encode_to(&buf);

    std::cout << "=== Polygon: POLYGON ((10 10, 50 10, 50 50, 10 50, 10 10)) ===" << std::endl;
    std::cout << "Size: " << buf.size() << " bytes" << std::endl;
    std::cout << "Hex: " << to_hex(buf) << std::endl;
    std::cout << "WKT: " << polygon->as_wkt() << std::endl;
    std::cout << std::endl;
}

TEST_F(S2CompatSnapshotGen, GeneratePolygonWithHoleSnapshot) {
    const char* wkt = "POLYGON ((10 10, 50 10, 50 50, 10 50, 10 10), (20 20, 40 20, 40 40, 20 40, 20 20))";
    GeoParseStatus status;
    std::unique_ptr<GeoShape> polygon(GeoShape::from_wkt(wkt, strlen(wkt), &status));
    ASSERT_EQ(GEO_PARSE_OK, status);
    ASSERT_NE(nullptr, polygon.get());

    std::string buf;
    polygon->encode_to(&buf);

    std::cout << "=== Polygon with Hole ===" << std::endl;
    std::cout << "Size: " << buf.size() << " bytes" << std::endl;
    std::cout << "Hex: " << to_hex(buf) << std::endl;
    std::cout << "WKT: " << polygon->as_wkt() << std::endl;
    std::cout << std::endl;

    // Also verify contains behavior for reference
    GeoPoint in_ring, in_hole, outside;
    in_ring.from_coord(15, 15);
    in_hole.from_coord(25, 25);
    outside.from_coord(5, 5);
    std::cout << "Contains (15,15) in ring: " << (polygon->contains(&in_ring) ? "true" : "false") << std::endl;
    std::cout << "Contains (25,25) in hole: " << (polygon->contains(&in_hole) ? "true" : "false") << std::endl;
    std::cout << "Contains (5,5) outside: " << (polygon->contains(&outside) ? "true" : "false") << std::endl;
    std::cout << std::endl;
}

TEST_F(S2CompatSnapshotGen, GenerateCircleSnapshot) {
    GeoCircle circle;
    auto status = circle.init(110.123, 64, 1000);
    ASSERT_EQ(GEO_PARSE_OK, status);

    std::string buf;
    circle.encode_to(&buf);

    std::cout << "=== Circle: CIRCLE ((110.123, 64), 1000) ===" << std::endl;
    std::cout << "Size: " << buf.size() << " bytes" << std::endl;
    std::cout << "Hex: " << to_hex(buf) << std::endl;
    std::cout << "WKT: " << circle.as_wkt() << std::endl;
    std::cout << std::endl;
}

TEST_F(S2CompatSnapshotGen, GenerateAllSnapshotsCompact) {
    // Generate all snapshots in a compact format for easy copy-paste
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  COPY THESE INTO s2_serialization_compat_test.cpp" << std::endl;
    std::cout << "========================================" << std::endl;

    // Point
    {
        GeoPoint point;
        point.from_coord(116.123, 63.546);
        std::string buf;
        point.encode_to(&buf);
        std::cout << "const std::string kV090PointHex = \"" << to_hex(buf) << "\";" << std::endl;
    }

    // LineString
    {
        const char* wkt = "LINESTRING (30 10, 10 30, 40 40)";
        GeoParseStatus status;
        std::unique_ptr<GeoShape> shape(GeoShape::from_wkt(wkt, strlen(wkt), &status));
        std::string buf;
        shape->encode_to(&buf);
        std::cout << "const std::string kV090LineHex = \"" << to_hex(buf) << "\";" << std::endl;
    }

    // Polygon
    {
        const char* wkt = "POLYGON ((10 10, 50 10, 50 50, 10 50, 10 10))";
        GeoParseStatus status;
        std::unique_ptr<GeoShape> shape(GeoShape::from_wkt(wkt, strlen(wkt), &status));
        std::string buf;
        shape->encode_to(&buf);
        std::cout << "const std::string kV090PolygonHex = \"" << to_hex(buf) << "\";" << std::endl;
    }

    // Polygon with hole
    {
        const char* wkt =
                "POLYGON ((10 10, 50 10, 50 50, 10 50, 10 10), (20 20, 40 20, 40 40, 20 40, 20 20))";
        GeoParseStatus status;
        std::unique_ptr<GeoShape> shape(GeoShape::from_wkt(wkt, strlen(wkt), &status));
        std::string buf;
        shape->encode_to(&buf);
        std::cout << "const std::string kV090PolygonHoleHex = \"" << to_hex(buf) << "\";" << std::endl;
    }

    // Circle
    {
        GeoCircle circle;
        circle.init(110.123, 64, 1000);
        std::string buf;
        circle.encode_to(&buf);
        std::cout << "const std::string kV090CircleHex = \"" << to_hex(buf) << "\";" << std::endl;
    }

    std::cout << "========================================" << std::endl;
}

} // namespace starrocks
