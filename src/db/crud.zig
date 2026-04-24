const std = @import("std");
const sqlite = @import("sqlite.zig");
const data_model = @import("data_model.zig");

pub const CrudError = error{
    NotFound,
    InsertFailed,
    UpdateFailed,
    DeleteFailed,
    QueryFailed,
    InvalidEnum,
};

pub fn insertProduct(db: sqlite.Sqlite, product: data_model.Product) !u64 {
    try db.execBind(
        \\INSERT INTO products (user_id, name, search_term, category, unit_type, unit_quantity, target_price, value_estimate, check_interval, last_checked_at, created_at, updated_at)
        \\VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
    , .{
        product.user_id,
        product.name,
        product.search_term,
        product.category,
        product.unit_type,
        product.unit_quantity,
        product.target_price,
        product.value_estimate,
        product.check_interval,
        product.last_checked_at,
        product.created_at,
        product.updated_at,
    });
    return @intCast(db.getLastInsertRowId());
}

pub fn getProductById(db: sqlite.Sqlite, allocator: std.mem.Allocator, id: u64) !?data_model.Product {
    return db.queryOne(allocator,
        \\SELECT id, user_id, name, search_term, category, unit_type, unit_quantity, target_price, value_estimate, check_interval, last_checked_at, created_at, updated_at
        \\FROM products WHERE id = ?1
    , data_model.Product, .{id});
}

pub fn listProductsByUserId(db: sqlite.Sqlite, allocator: std.mem.Allocator, user_id: u64) ![]data_model.Product {
    return db.queryAll(allocator,
        \\SELECT id, user_id, name, search_term, category, unit_type, unit_quantity, target_price, value_estimate, check_interval, last_checked_at, created_at, updated_at
        \\FROM products WHERE user_id = ?1 ORDER BY created_at DESC
    , data_model.Product, .{user_id});
}

pub fn updateProduct(db: sqlite.Sqlite, product: data_model.Product) !void {
    try db.execBind(
        \\UPDATE products SET name = ?1, search_term = ?2, category = ?3, unit_type = ?4, unit_quantity = ?5, target_price = ?6, value_estimate = ?7, check_interval = ?8, last_checked_at = ?9, updated_at = ?10
        \\WHERE id = ?11
    , .{
        product.name,
        product.search_term,
        product.category,
        product.unit_type,
        product.unit_quantity,
        product.target_price,
        product.value_estimate,
        product.check_interval,
        product.last_checked_at,
        product.updated_at,
        product.id,
    });
}

pub fn deleteProduct(db: sqlite.Sqlite, id: u64) !void {
    try db.execBind("DELETE FROM products WHERE id = ?1", .{id});
}

pub fn insertListing(db: sqlite.Sqlite, listing: data_model.Listing) !u64 {
    const listing_type_str = @tagName(listing.listing_type);
    try db.execBind(
        \\INSERT INTO listings (product_id, url, store_name, listing_type, selector_config, is_active, created_at)
        \\VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
    , .{
        listing.product_id,
        listing.url,
        listing.store_name,
        listing_type_str,
        listing.selector_config,
        listing.is_active,
        listing.created_at,
    });
    return @intCast(db.getLastInsertRowId());
}

pub fn getListingById(db: sqlite.Sqlite, allocator: std.mem.Allocator, id: u64) !?data_model.Listing {
    const row = try db.queryOne(allocator,
        \\SELECT id, product_id, url, store_name, listing_type, selector_config, is_active, created_at
        \\FROM listings WHERE id = ?1
    , ListingRow, .{id});
    if (row) |r| {
        defer freeListingRowEnumStrings(allocator, r);
        return try listingRowToListing(r);
    }
    return null;
}

pub fn listListingsByProductId(db: sqlite.Sqlite, allocator: std.mem.Allocator, product_id: u64) ![]data_model.Listing {
    const rows = try db.queryAll(allocator,
        \\SELECT id, product_id, url, store_name, listing_type, selector_config, is_active, created_at
        \\FROM listings WHERE product_id = ?1 ORDER BY created_at DESC
    , ListingRow, .{product_id});

    var listings = try allocator.alloc(data_model.Listing, rows.len);
    for (rows, 0..) |row, i| {
        listings[i] = listingRowToListing(row) catch {
            for (rows) |r| freeListingRowStrings(allocator, r);
            allocator.free(rows);
            return CrudError.InvalidEnum;
        };
    }
    for (rows) |r| freeListingRowEnumStrings(allocator, r);
    allocator.free(rows);
    return listings;
}

pub fn updateListing(db: sqlite.Sqlite, listing: data_model.Listing) !void {
    const listing_type_str = @tagName(listing.listing_type);
    try db.execBind(
        \\UPDATE listings SET url = ?1, store_name = ?2, listing_type = ?3, selector_config = ?4, is_active = ?5
        \\WHERE id = ?6
    , .{
        listing.url,
        listing.store_name,
        listing_type_str,
        listing.selector_config,
        listing.is_active,
        listing.id,
    });
}

pub fn deleteListing(db: sqlite.Sqlite, id: u64) !void {
    try db.execBind("DELETE FROM listings WHERE id = ?1", .{id});
}

pub fn insertPrice(db: sqlite.Sqlite, price: data_model.Price) !u64 {
    const stock_status_str = @tagName(price.stock_status);
    const extraction_method_str = @tagName(price.extraction_method);
    try db.execBind(
        \\INSERT INTO prices (listing_id, price, currency, price_per_unit, stock_status, extraction_method, confidence, raw_extract, checked_at)
        \\VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
    , .{
        price.listing_id,
        price.price,
        price.currency,
        price.price_per_unit,
        stock_status_str,
        extraction_method_str,
        price.confidence,
        price.raw_extract,
        price.checked_at,
    });
    return @intCast(db.getLastInsertRowId());
}

pub fn listPricesByListingId(db: sqlite.Sqlite, allocator: std.mem.Allocator, listing_id: u64, limit: u32, offset: u32) ![]data_model.Price {
    const rows = try db.queryAll(allocator,
        \\SELECT id, listing_id, price, currency, price_per_unit, stock_status, extraction_method, confidence, raw_extract, checked_at
        \\FROM prices WHERE listing_id = ?1 ORDER BY checked_at DESC LIMIT ?2 OFFSET ?3
    , PriceRow, .{ listing_id, limit, offset });

    var prices = try allocator.alloc(data_model.Price, rows.len);
    for (rows, 0..) |row, i| {
        prices[i] = priceRowToPrice(row) catch {
            for (rows) |r| freePriceRowStrings(allocator, r);
            allocator.free(rows);
            return CrudError.InvalidEnum;
        };
    }
    for (rows) |r| freePriceRowEnumStrings(allocator, r);
    allocator.free(rows);
    return prices;
}

pub fn listPricesByProductId(db: sqlite.Sqlite, allocator: std.mem.Allocator, product_id: u64) ![]data_model.Price {
    const rows = try db.queryAll(allocator,
        \\SELECT p.id, p.listing_id, p.price, p.currency, p.price_per_unit, p.stock_status, p.extraction_method, p.confidence, p.raw_extract, p.checked_at
        \\FROM prices p
        \\JOIN listings l ON p.listing_id = l.id
        \\WHERE l.product_id = ?1
        \\ORDER BY p.checked_at DESC
    , PriceRow, .{product_id});

    var prices = try allocator.alloc(data_model.Price, rows.len);
    for (rows, 0..) |row, i| {
        prices[i] = priceRowToPrice(row) catch {
            for (rows) |r| freePriceRowStrings(allocator, r);
            allocator.free(rows);
            return CrudError.InvalidEnum;
        };
    }
    for (rows) |r| freePriceRowEnumStrings(allocator, r);
    allocator.free(rows);
    return prices;
}

pub fn insertUser(db: sqlite.Sqlite, user: data_model.User) !u64 {
    try db.execBind(
        \\INSERT INTO users (username, password_hash, created_at, is_admin)
        \\VALUES (?1, ?2, ?3, ?4)
    , .{
        user.username,
        user.password_hash,
        user.created_at,
        user.is_admin,
    });
    return @intCast(db.getLastInsertRowId());
}

pub fn getUserByUsername(db: sqlite.Sqlite, allocator: std.mem.Allocator, username: []const u8) !?data_model.User {
    return db.queryOne(allocator,
        \\SELECT id, username, password_hash, created_at, is_admin
        \\FROM users WHERE username = ?1
    , data_model.User, .{username});
}

pub fn getUserById(db: sqlite.Sqlite, allocator: std.mem.Allocator, id: u64) !?data_model.User {
    return db.queryOne(allocator,
        \\SELECT id, username, password_hash, created_at, is_admin
        \\FROM users WHERE id = ?1
    , data_model.User, .{id});
}

pub fn updateUserPassword(db: sqlite.Sqlite, id: u64, password_hash: []const u8) !void {
    try db.execBind(
        \\UPDATE users SET password_hash = ?1 WHERE id = ?2
    , .{ password_hash, id });
}

const ListingRow = struct {
    id: u64,
    product_id: u64,
    url: []const u8,
    store_name: ?[]const u8,
    listing_type: []const u8,
    selector_config: ?[]const u8,
    is_active: bool,
    created_at: i64,
};

const PriceRow = struct {
    id: u64,
    listing_id: u64,
    price: f64,
    currency: []const u8,
    price_per_unit: ?f64,
    stock_status: []const u8,
    extraction_method: []const u8,
    confidence: f64,
    raw_extract: ?[]const u8,
    checked_at: i64,
};

fn listingRowToListing(row: ListingRow) !data_model.Listing {
    return data_model.Listing{
        .id = row.id,
        .product_id = row.product_id,
        .url = row.url,
        .store_name = row.store_name,
        .listing_type = std.meta.stringToEnum(data_model.ListingType, row.listing_type) orelse return CrudError.InvalidEnum,
        .selector_config = row.selector_config,
        .is_active = row.is_active,
        .created_at = row.created_at,
    };
}

fn priceRowToPrice(row: PriceRow) !data_model.Price {
    return data_model.Price{
        .id = row.id,
        .listing_id = row.listing_id,
        .price = row.price,
        .currency = row.currency,
        .price_per_unit = row.price_per_unit,
        .stock_status = std.meta.stringToEnum(data_model.StockStatus, row.stock_status) orelse return CrudError.InvalidEnum,
        .extraction_method = std.meta.stringToEnum(data_model.ExtractionMethod, row.extraction_method) orelse return CrudError.InvalidEnum,
        .confidence = row.confidence,
        .raw_extract = row.raw_extract,
        .checked_at = row.checked_at,
    };
}

fn freePriceRowEnumStrings(allocator: std.mem.Allocator, row: PriceRow) void {
    allocator.free(row.stock_status);
    allocator.free(row.extraction_method);
}

fn freePriceRowStrings(allocator: std.mem.Allocator, row: PriceRow) void {
    allocator.free(row.currency);
    if (row.raw_extract) |s| allocator.free(s);
    freePriceRowEnumStrings(allocator, row);
}

fn freeListingRowEnumStrings(allocator: std.mem.Allocator, row: ListingRow) void {
    allocator.free(row.listing_type);
}

fn freeListingRowStrings(allocator: std.mem.Allocator, row: ListingRow) void {
    allocator.free(row.url);
    if (row.store_name) |s| allocator.free(s);
    if (row.selector_config) |s| allocator.free(s);
    freeListingRowEnumStrings(allocator, row);
}
