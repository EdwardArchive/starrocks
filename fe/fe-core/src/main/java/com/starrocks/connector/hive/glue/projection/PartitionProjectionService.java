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

package com.starrocks.connector.hive.glue.projection;

import com.starrocks.catalog.HiveTable;
import com.starrocks.catalog.PartitionKey;
import com.starrocks.catalog.Table;
import com.starrocks.connector.hive.Partition;
import com.starrocks.connector.hive.RemoteFileInputFormat;
import com.starrocks.connector.hive.TextFileFormatDesc;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Service for handling Partition Projection in AWS Glue/Athena tables.
 *
 * Partition Projection allows defining partition values dynamically through
 * table properties, eliminating the need to store partition metadata in the
 * metastore. This is particularly useful for:
 * - Time-series data with predictable partition patterns
 * - Tables with a large number of partitions
 * - Reducing metastore load and query latency
 *
 * @see <a href="https://docs.aws.amazon.com/athena/latest/ug/partition-projection.html">
 *      AWS Athena Partition Projection</a>
 */
public class PartitionProjectionService {

    private static final Logger LOG = LogManager.getLogger(PartitionProjectionService.class);

    /**
     * Checks if partition projection is enabled for the given table.
     *
     * @param table the table to check
     * @return true if partition projection is enabled
     */
    public boolean isEnabled(Table table) {
        if (!(table instanceof HiveTable)) {
            return false;
        }
        HiveTable hiveTable = (HiveTable) table;
        Map<String, String> properties = hiveTable.getProperties();
        return PartitionProjectionProperties.isProjectionEnabled(properties);
    }

    /**
     * Creates a PartitionProjection configuration from table properties.
     *
     * @param table the Hive table
     * @return the partition projection configuration
     * @throws IllegalArgumentException if the configuration is invalid
     */
    public PartitionProjection createProjection(HiveTable table) {
        Map<String, String> properties = table.getProperties();
        List<String> partitionColumnNames = table.getPartitionColumnNames();
        String baseLocation = table.getTableLocation();

        // Parse projection properties
        PartitionProjectionProperties projProps = PartitionProjectionProperties.parse(properties);

        // Get storage location template
        Optional<String> storageLocationTemplate = projProps.getStorageLocationTemplate();

        // Get input format and text file format desc from storage format
        RemoteFileInputFormat inputFormat = getInputFormat(table);
        TextFileFormatDesc textFileFormatDesc = getTextFileFormatDesc(table);

        // Create column projections for each partition column
        Map<String, ColumnProjection> columnProjections = new HashMap<>();
        for (String columnName : partitionColumnNames) {
            ColumnProjection projection = createColumnProjection(columnName, projProps);
            columnProjections.put(columnName, projection);
        }

        return new PartitionProjection(
                baseLocation,
                storageLocationTemplate,
                columnProjections,
                partitionColumnNames,
                inputFormat,
                textFileFormatDesc
        );
    }

    private RemoteFileInputFormat getInputFormat(HiveTable table) {
        if (table.getStorageFormat() == null) {
            return RemoteFileInputFormat.PARQUET;
        }
        switch (table.getStorageFormat()) {
            case PARQUET:
                return RemoteFileInputFormat.PARQUET;
            case ORC:
                return RemoteFileInputFormat.ORC;
            case TEXTFILE:
                return RemoteFileInputFormat.TEXT;
            case AVRO:
                return RemoteFileInputFormat.AVRO;
            case SEQUENCEFILE:
                return RemoteFileInputFormat.SEQUENCE;
            case RCFILE:
                return RemoteFileInputFormat.RCBINARY;
            default:
                return RemoteFileInputFormat.UNKNOWN;
        }
    }

    private TextFileFormatDesc getTextFileFormatDesc(HiveTable table) {
        // Return null for non-text formats
        if (table.getStorageFormat() == null ||
                table.getStorageFormat() != com.starrocks.connector.hive.HiveStorageFormat.TEXTFILE) {
            return null;
        }
        // For text format, use default delimiters if not specified
        Map<String, String> serdeProps = table.getSerdeProperties();
        String fieldDelimiter = serdeProps.getOrDefault("field.delim", "\001");
        String lineDelimiter = serdeProps.getOrDefault("line.delim", "\n");
        String collectionDelimiter = serdeProps.getOrDefault("collection.delim", "\002");
        String mapKeyDelimiter = serdeProps.getOrDefault("mapkey.delim", "\003");

        return new TextFileFormatDesc(fieldDelimiter, lineDelimiter, collectionDelimiter, mapKeyDelimiter);
    }

    private ColumnProjection createColumnProjection(String columnName,
                                                     PartitionProjectionProperties projProps) {
        PartitionProjectionProperties.ColumnProjectionConfig config = projProps.getColumnConfig(columnName);
        if (config == null) {
            throw new IllegalArgumentException(
                    "Missing projection configuration for partition column: " + columnName +
                            ". Please add 'projection." + columnName + ".type' property.");
        }

        PartitionProjectionProperties.ProjectionType type = config.getType();
        Map<String, String> props = config.getProperties();

        switch (type) {
            case ENUM:
                return new EnumProjection(
                        columnName,
                        getRequiredProperty(props, "values", columnName)
                );

            case INTEGER:
                return new IntegerProjection(
                        columnName,
                        getRequiredProperty(props, "range", columnName),
                        config.getOptionalProperty("interval"),
                        config.getOptionalProperty("digits")
                );

            case DATE:
                return new DateProjection(
                        columnName,
                        getRequiredProperty(props, "range", columnName),
                        getRequiredProperty(props, "format", columnName),
                        config.getOptionalProperty("interval"),
                        config.getOptionalProperty("interval.unit")
                );

            case INJECTED:
                return new InjectedProjection(columnName);

            default:
                throw new IllegalArgumentException(
                        "Unknown projection type: " + type + " for column: " + columnName);
        }
    }

    private String getRequiredProperty(Map<String, String> props, String key, String columnName) {
        String value = props.get(key);
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(
                    "Missing required property 'projection." + columnName + "." + key + "'");
        }
        return value;
    }

    /**
     * Gets projected partitions for the given partition keys.
     *
     * This method creates virtual partitions based on the projection configuration
     * without querying the metastore. The partition locations are computed from
     * the table's base location and optional storage location template.
     *
     * @param table the Hive table with projection enabled
     * @param partitionKeys partition keys from query predicates
     * @return map of partition name to Partition object
     */
    public Map<String, Partition> getProjectedPartitions(HiveTable table,
                                                          List<PartitionKey> partitionKeys) {
        LOG.debug("Getting projected partitions for table: {}.{}",
                table.getCatalogDBName(), table.getCatalogTableName());

        PartitionProjection projection = createProjection(table);
        List<String> partitionColumnNames = table.getPartitionColumnNames();

        // Extract filter values from partition keys
        Map<String, Optional<Object>> partitionFilters = new HashMap<>();

        if (!partitionKeys.isEmpty()) {
            // Use the first partition key to extract filter values
            // This assumes all partition keys have the same column structure
            PartitionKey firstKey = partitionKeys.get(0);
            for (int i = 0; i < partitionColumnNames.size() && i < firstKey.getKeys().size(); i++) {
                String columnName = partitionColumnNames.get(i);
                Object value = firstKey.getKeys().get(i).getRealValue();
                partitionFilters.put(columnName, Optional.ofNullable(value));
            }
        } else {
            // No filter values - use empty optionals
            for (String columnName : partitionColumnNames) {
                partitionFilters.put(columnName, Optional.empty());
            }
        }

        Map<String, Partition> result = projection.getProjectedPartitions(partitionFilters);

        LOG.debug("Generated {} projected partitions for table: {}.{}",
                result.size(), table.getCatalogDBName(), table.getCatalogTableName());

        return result;
    }

    /**
     * Gets projected partitions using explicit filter values.
     *
     * @param table the Hive table with projection enabled
     * @param partitionFilters map of column name to filter value
     * @return map of partition name to Partition object
     */
    public Map<String, Partition> getProjectedPartitions(HiveTable table,
                                                          Map<String, Optional<Object>> partitionFilters) {
        PartitionProjection projection = createProjection(table);
        return projection.getProjectedPartitions(partitionFilters);
    }
}
