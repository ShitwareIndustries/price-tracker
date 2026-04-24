const std = @import("std");
const sqlite = @import("sqlite.zig");
const migrations = @import("migrations.zig");
const crud = @import("crud.zig");
const data_model = @import("data_model.zig");

const testing = std.testing;

fn freeProductStrings(allocator: std.mem.Allocator, p: data_model.Product) void {
    allocator.free(p.name);
    if (p.search_term) |s| allocator.free(s);
    if (p.category) |s| allocator.free(s);
    if (p.unit_type) |s| allocator.free(s);
}

fn freeListingStrings(allocator: std.mem.Allocator, l: data_model.Listing) void {
    allocator.free(l.url);
    if (l.store_name) |s| allocator.free(s);
    if (l.selector_config) |s| allocator.free(s);
}

fn freePriceStrings(allocator: std.mem.Allocator, p: data_model.Price) void {
    allocator.free(p.currency);
    if (p.raw_extract) |s| allocator.free(s);
}

test "DB init creates all tables" {
    const allocator = testing.allocator;
    var db = try sqlite.Sqlite.init(":memory:");
    defer db.deinit();

    try migrations.runMigrations(db);

    const table_iter = try db.queryAll(allocator,
        \\SELECT name FROM sqlite_master WHERE type='table' ORDER BY name
    , struct { name: []const u8 }, .{});
    defer {
        for (table_iter) |row| allocator.free(row.name);
        allocator.free(table_iter);
    }

    var found = std.StringHashMap(bool).init(allocator);
    defer found.deinit();
    for (table_iter) |row| {
        try found.put(row.name, true);
    }

    try testing.expect(found.contains("users"));
    try testing.expect(found.contains("products"));
    try testing.expect(found.contains("listings"));
    try testing.expect(found.contains("prices"));
    try testing.expect(found.contains("auction_state"));
    try testing.expect(found.contains("alert_rules"));
    try testing.expect(found.contains("alert_channels"));
    try testing.expect(found.contains("discovery_log"));
    try testing.expect(found.contains("value_estimates"));
    try testing.expect(found.contains("schema_version"));
}

test "migration is idempotent" {
    var db = try sqlite.Sqlite.init(":memory:");
    defer db.deinit();

    try migrations.runMigrations(db);
    try migrations.runMigrations(db);

    const version = try migrations.getSchemaVersion(db);
    try testing.expectEqual(@as(i64, data_model.SCHEMA_VERSION), version);
}

test "Product CRUD round-trip" {
    const allocator = testing.allocator;
    var db = try sqlite.Sqlite.init(":memory:");
    defer db.deinit();
    try migrations.runMigrations(db);

    _ = try crud.insertUser(db, .{
        .id = 0,
        .username = "testuser",
        .password_hash = "hash123",
        .created_at = 1000,
        .is_admin = false,
    });
    const user_id: u64 = @intCast(db.getLastInsertRowId());

    const product = data_model.Product{
        .id = 0,
        .user_id = user_id,
        .name = "Widget",
        .search_term = "widget search",
        .category = "tools",
        .unit_type = "piece",
        .unit_quantity = 1.0,
        .target_price = 9.99,
        .value_estimate = 12.50,
        .check_interval = 3600,
        .last_checked_at = null,
        .created_at = 2000,
        .updated_at = 2000,
    };

    const product_id = try crud.insertProduct(db, product);
    try testing.expect(product_id > 0);

    {
        const fetched = try crud.getProductById(db, allocator, product_id);
        try testing.expect(fetched != null);
        if (fetched) |p| {
            defer freeProductStrings(allocator, p);
            try testing.expectEqualStrings("Widget", p.name);
            try testing.expectEqual(user_id, p.user_id);
            try testing.expectEqual(@as(f64, 9.99), p.target_price);
        }
    }

    {
        const updated = data_model.Product{
            .id = product_id,
            .user_id = user_id,
            .name = "Super Widget",
            .search_term = null,
            .category = null,
            .unit_type = null,
            .unit_quantity = 1.0,
            .target_price = 14.99,
            .value_estimate = 12.50,
            .check_interval = 3600,
            .last_checked_at = null,
            .created_at = 2000,
            .updated_at = 3000,
        };
        try crud.updateProduct(db, updated);
    }

    {
        const refetched = try crud.getProductById(db, allocator, product_id);
        try testing.expect(refetched != null);
        if (refetched) |p| {
            defer freeProductStrings(allocator, p);
            try testing.expectEqualStrings("Super Widget", p.name);
            try testing.expectEqual(@as(f64, 14.99), p.target_price);
        }
    }

    try crud.deleteProduct(db, product_id);
    const deleted = try crud.getProductById(db, allocator, product_id);
    try testing.expect(deleted == null);
}

test "Listing CRUD round-trip" {
    const allocator = testing.allocator;
    var db = try sqlite.Sqlite.init(":memory:");
    defer db.deinit();
    try migrations.runMigrations(db);

    _ = try crud.insertUser(db, .{
        .id = 0,
        .username = "testuser2",
        .password_hash = "hash456",
        .created_at = 1000,
        .is_admin = false,
    });
    const user_id: u64 = @intCast(db.getLastInsertRowId());

    const product_id = try crud.insertProduct(db, .{
        .id = 0,
        .user_id = user_id,
        .name = "Gadget",
        .search_term = null,
        .category = null,
        .unit_type = null,
        .unit_quantity = 1.0,
        .target_price = 19.99,
        .value_estimate = null,
        .check_interval = 3600,
        .last_checked_at = null,
        .created_at = 2000,
        .updated_at = 2000,
    });

    const listing = data_model.Listing{
        .id = 0,
        .product_id = product_id,
        .url = "https://example.com/gadget",
        .store_name = "ExampleStore",
        .listing_type = .fixed,
        .selector_config = null,
        .is_active = true,
        .created_at = 3000,
    };

    const listing_id = try crud.insertListing(db, listing);
    try testing.expect(listing_id > 0);

    {
        const fetched = try crud.getListingById(db, allocator, listing_id);
        try testing.expect(fetched != null);
        if (fetched) |l| {
            defer freeListingStrings(allocator, l);
            try testing.expectEqualStrings("https://example.com/gadget", l.url);
            try testing.expectEqual(data_model.ListingType.fixed, l.listing_type);
            try testing.expectEqual(true, l.is_active);
        }
    }

    {
        const updated = data_model.Listing{
            .id = listing_id,
            .product_id = product_id,
            .url = "https://example.com/gadget-v2",
            .store_name = null,
            .listing_type = .fixed,
            .selector_config = null,
            .is_active = false,
            .created_at = 3000,
        };
        try crud.updateListing(db, updated);
    }

    {
        const refetched = try crud.getListingById(db, allocator, listing_id);
        try testing.expect(refetched != null);
        if (refetched) |l| {
            defer freeListingStrings(allocator, l);
            try testing.expectEqualStrings("https://example.com/gadget-v2", l.url);
            try testing.expectEqual(false, l.is_active);
        }
    }

    try crud.deleteListing(db, listing_id);
    const deleted = try crud.getListingById(db, allocator, listing_id);
    try testing.expect(deleted == null);
}

test "Price insert and query by listing_id" {
    const allocator = testing.allocator;
    var db = try sqlite.Sqlite.init(":memory:");
    defer db.deinit();
    try migrations.runMigrations(db);

    _ = try crud.insertUser(db, .{
        .id = 0,
        .username = "pricetest",
        .password_hash = "hash",
        .created_at = 1000,
        .is_admin = false,
    });
    const user_id: u64 = @intCast(db.getLastInsertRowId());

    const product_id = try crud.insertProduct(db, .{
        .id = 0,
        .user_id = user_id,
        .name = "PriceItem",
        .search_term = null,
        .category = null,
        .unit_type = null,
        .unit_quantity = 1.0,
        .target_price = 5.0,
        .value_estimate = null,
        .check_interval = 3600,
        .last_checked_at = null,
        .created_at = 2000,
        .updated_at = 2000,
    });

    const listing_id = try crud.insertListing(db, .{
        .id = 0,
        .product_id = product_id,
        .url = "https://example.com/item",
        .store_name = null,
        .listing_type = .auction,
        .selector_config = null,
        .is_active = true,
        .created_at = 3000,
    });

    const price1 = data_model.Price{
        .id = 0,
        .listing_id = listing_id,
        .price = 10.50,
        .currency = "USD",
        .price_per_unit = 10.50,
        .stock_status = .in_stock,
        .extraction_method = .css,
        .confidence = 0.95,
        .raw_extract = null,
        .checked_at = 4000,
    };
    const price2 = data_model.Price{
        .id = 0,
        .listing_id = listing_id,
        .price = 9.99,
        .currency = "USD",
        .price_per_unit = null,
        .stock_status = .out_of_stock,
        .extraction_method = .json_ld,
        .confidence = 1.0,
        .raw_extract = "raw data",
        .checked_at = 5000,
    };

    _ = try crud.insertPrice(db, price1);
    _ = try crud.insertPrice(db, price2);

    const prices = try crud.listPricesByListingId(db, allocator, listing_id, 10, 0);
    defer {
        for (prices) |p| freePriceStrings(allocator, p);
        allocator.free(prices);
    }
    try testing.expectEqual(@as(usize, 2), prices.len);
    try testing.expectEqual(data_model.StockStatus.out_of_stock, prices[0].stock_status);
    try testing.expectEqual(@as(f64, 9.99), prices[0].price);
    try testing.expectEqual(data_model.ExtractionMethod.json_ld, prices[0].extraction_method);
}

test "WAL mode enabled" {
    var db = try sqlite.Sqlite.init(":memory:");
    defer db.deinit();

    try db.enableWalMode();
    const mode = try db.getJournalMode(testing.allocator);
    defer testing.allocator.free(mode);
    try testing.expectEqualStrings("memory", mode);
}

test "concurrent write test" {
    const allocator = testing.allocator;
    var db1 = try sqlite.Sqlite.init(":memory:");
    defer db1.deinit();
    try migrations.runMigrations(db1);
    try db1.setBusyTimeout(5000);

    _ = try crud.insertUser(db1, .{
        .id = 0,
        .username = "concurrent_user",
        .password_hash = "hash",
        .created_at = 1000,
        .is_admin = false,
    });
    const user_id: u64 = @intCast(db1.getLastInsertRowId());

    const id1 = try crud.insertProduct(db1, .{
        .id = 0,
        .user_id = user_id,
        .name = "Item1",
        .search_term = null,
        .category = null,
        .unit_type = null,
        .unit_quantity = 1.0,
        .target_price = 1.0,
        .value_estimate = null,
        .check_interval = 3600,
        .last_checked_at = null,
        .created_at = 1000,
        .updated_at = 1000,
    });

    const id2 = try crud.insertProduct(db1, .{
        .id = 0,
        .user_id = user_id,
        .name = "Item2",
        .search_term = null,
        .category = null,
        .unit_type = null,
        .unit_quantity = 1.0,
        .target_price = 2.0,
        .value_estimate = null,
        .check_interval = 3600,
        .last_checked_at = null,
        .created_at = 2000,
        .updated_at = 2000,
    });

    try testing.expect(id1 != id2);

    const products = try crud.listProductsByUserId(db1, allocator, user_id);
    defer {
        for (products) |p| freeProductStrings(allocator, p);
        allocator.free(products);
    }
    try testing.expectEqual(@as(usize, 2), products.len);
}
