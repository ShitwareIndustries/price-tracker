pub const User = struct {
    id: u64,
    username: []const u8,
    password_hash: []const u8,
    created_at: i64,
    is_admin: bool,
};

pub const Product = struct {
    id: u64,
    user_id: u64,
    name: []const u8,
    search_term: ?[]const u8,
    category: ?[]const u8,
    unit_type: ?[]const u8,
    unit_quantity: f64,
    target_price: f64,
    value_estimate: ?f64,
    check_interval: u32,
    last_checked_at: ?i64,
    created_at: i64,
    updated_at: i64,
};

pub const ListingType = enum {
    fixed,
    auction,
    bid,
};

pub const Listing = struct {
    id: u64,
    product_id: u64,
    url: []const u8,
    store_name: ?[]const u8,
    listing_type: ListingType,
    selector_config: ?[]const u8,
    is_active: bool,
    created_at: i64,
};

pub const StockStatus = enum {
    in_stock,
    out_of_stock,
    limited,
};

pub const ExtractionMethod = enum {
    json_ld,
    css,
    regex,
    ai,
    auction_api,
};

pub const Price = struct {
    id: u64,
    listing_id: u64,
    price: f64,
    currency: []const u8,
    price_per_unit: ?f64,
    stock_status: StockStatus,
    extraction_method: ExtractionMethod,
    confidence: f64,
    raw_extract: ?[]const u8,
    checked_at: i64,
};

pub const AuctionState = struct {
    id: u64,
    listing_id: u64,
    current_bid: ?f64,
    buy_now_price: ?f64,
    bid_count: u32,
    end_time: ?i64,
    reserve_met: bool,
    updated_at: i64,
};

pub const AlertRuleType = enum {
    below_target,
    drop_percent,
    back_in_stock,
    auction_ending,
    value_deal,
};

pub const AlertRule = struct {
    id: u64,
    product_id: u64,
    rule_type: AlertRuleType,
    threshold: ?f64,
    channels: []const u8,
    is_active: bool,
    last_fired_at: ?i64,
    created_at: i64,
};

pub const AlertChannelType = enum {
    discord,
    gotify,
    ntfy,
};

pub const AlertChannel = struct {
    id: u64,
    user_id: u64,
    channel_type: AlertChannelType,
    config: []const u8,
    is_enabled: bool,
    created_at: i64,
};

pub const DiscoveryLog = struct {
    id: u64,
    user_id: u64,
    search_term: []const u8,
    searxng_results: []const u8,
    ai_candidates: ?[]const u8,
    accepted_urls: ?[]const u8,
    searched_at: i64,
};

pub const ValueEstimate = struct {
    id: u64,
    product_id: u64,
    estimated_value: f64,
    reasoning: []const u8,
    comparable_urls: []const u8,
    model_used: []const u8,
    estimated_at: i64,
};

pub const SCHEMA_VERSION = 1;

pub fn createSchema() []const u8 {
    return
    \\-- Schema version tracking
    \\CREATE TABLE IF NOT EXISTS schema_version (
    \\  version INTEGER PRIMARY KEY,
    \\  applied_at INTEGER NOT NULL
    \\);
    \\
    \\-- Users (multi-user support)
    \\CREATE TABLE IF NOT EXISTS users (
    \\  id INTEGER PRIMARY KEY AUTOINCREMENT,
    \\  username TEXT NOT NULL UNIQUE,
    \\  password_hash TEXT NOT NULL,
    \\  created_at INTEGER NOT NULL,
    \\  is_admin INTEGER NOT NULL DEFAULT 0
    \\);
    \\
    \\-- Products: the abstract item the user wants to track
    \\CREATE TABLE IF NOT EXISTS products (
    \\  id INTEGER PRIMARY KEY AUTOINCREMENT,
    \\  user_id INTEGER NOT NULL REFERENCES users(id),
    \\  name TEXT NOT NULL,
    \\  search_term TEXT,
    \\  category TEXT,
    \\  unit_type TEXT,
    \\  unit_quantity REAL DEFAULT 1.0,
    \\  target_price REAL NOT NULL DEFAULT 0.0,
    \\  value_estimate REAL,
    \\  check_interval INTEGER NOT NULL DEFAULT 3600,
    \\  last_checked_at INTEGER,
    \\  created_at INTEGER NOT NULL,
    \\  updated_at INTEGER NOT NULL
    \\);
    \\
    \\-- Listings: one product can have multiple store URLs (multi-link)
    \\CREATE TABLE IF NOT EXISTS listings (
    \\  id INTEGER PRIMARY KEY AUTOINCREMENT,
    \\  product_id INTEGER NOT NULL REFERENCES products(id),
    \\  url TEXT NOT NULL,
    \\  store_name TEXT,
    \\  listing_type TEXT NOT NULL DEFAULT 'fixed',
    \\  selector_config TEXT,
    \\  is_active INTEGER NOT NULL DEFAULT 1,
    \\  created_at INTEGER NOT NULL
    \\);
    \\
    \\-- Price snapshots: immutable time-series
    \\CREATE TABLE IF NOT EXISTS prices (
    \\  id INTEGER PRIMARY KEY AUTOINCREMENT,
    \\  listing_id INTEGER NOT NULL REFERENCES listings(id),
    \\  price REAL NOT NULL,
    \\  currency TEXT NOT NULL DEFAULT 'USD',
    \\  price_per_unit REAL,
    \\  stock_status TEXT NOT NULL DEFAULT 'in_stock',
    \\  extraction_method TEXT NOT NULL,
    \\  confidence REAL NOT NULL DEFAULT 1.0,
    \\  raw_extract TEXT,
    \\  checked_at INTEGER NOT NULL
    \\);
    \\
    \\-- Auction state: tracks live auction data
    \\CREATE TABLE IF NOT EXISTS auction_state (
    \\  id INTEGER PRIMARY KEY AUTOINCREMENT,
    \\  listing_id INTEGER NOT NULL REFERENCES listings(id),
    \\  current_bid REAL,
    \\  buy_now_price REAL,
    \\  bid_count INTEGER NOT NULL DEFAULT 0,
    \\  end_time INTEGER,
    \\  reserve_met INTEGER NOT NULL DEFAULT 0,
    \\  updated_at INTEGER NOT NULL
    \\);
    \\
    \\-- Alert rules: per-product notification configuration
    \\CREATE TABLE IF NOT EXISTS alert_rules (
    \\  id INTEGER PRIMARY KEY AUTOINCREMENT,
    \\  product_id INTEGER NOT NULL REFERENCES products(id),
    \\  rule_type TEXT NOT NULL,
    \\  threshold REAL,
    \\  channels TEXT NOT NULL,
    \\  is_active INTEGER NOT NULL DEFAULT 1,
    \\  last_fired_at INTEGER,
    \\  created_at INTEGER NOT NULL
    \\);
    \\
    \\-- Alert channel configs: per-user notification settings
    \\CREATE TABLE IF NOT EXISTS alert_channels (
    \\  id INTEGER PRIMARY KEY AUTOINCREMENT,
    \\  user_id INTEGER NOT NULL REFERENCES users(id),
    \\  channel_type TEXT NOT NULL,
    \\  config TEXT NOT NULL,
    \\  is_enabled INTEGER NOT NULL DEFAULT 1,
    \\  created_at INTEGER NOT NULL
    \\);
    \\
    \\-- AI discovery log
    \\CREATE TABLE IF NOT EXISTS discovery_log (
    \\  id INTEGER PRIMARY KEY AUTOINCREMENT,
    \\  user_id INTEGER NOT NULL REFERENCES users(id),
    \\  search_term TEXT NOT NULL,
    \\  searxng_results TEXT,
    \\  ai_candidates TEXT,
    \\  accepted_urls TEXT,
    \\  searched_at INTEGER NOT NULL
    \\);
    \\
    \\-- Value estimates: AI-computed fair market value
    \\CREATE TABLE IF NOT EXISTS value_estimates (
    \\  id INTEGER PRIMARY KEY AUTOINCREMENT,
    \\  product_id INTEGER NOT NULL REFERENCES products(id),
    \\  estimated_value REAL NOT NULL,
    \\  reasoning TEXT,
    \\  comparable_urls TEXT,
    \\  model_used TEXT,
    \\  estimated_at INTEGER NOT NULL
    \\);
    \\
    \\-- Indexes
    \\CREATE INDEX IF NOT EXISTS idx_prices_listing_time ON prices(listing_id, checked_at);
    \\CREATE INDEX IF NOT EXISTS idx_products_user ON products(user_id);
    \\CREATE INDEX IF NOT EXISTS idx_listings_product ON listings(product_id);
    \\CREATE INDEX IF NOT EXISTS idx_alert_rules_product ON alert_rules(product_id, is_active);
    \\CREATE INDEX IF NOT EXISTS idx_discovery_user ON discovery_log(user_id, searched_at);
    ;
}
