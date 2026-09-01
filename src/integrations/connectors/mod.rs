// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Built-in connector implementations for third-party services.

pub mod netbird;
pub mod truenas;
pub mod unifi;

use std::collections::HashMap;
use super::Connector;

/// Register all built-in connectors into the given map.
pub fn register_all(map: &mut HashMap<String, Box<dyn Connector>>) {
    map.insert("netbird".to_string(), Box::new(netbird::NetBirdConnector));
    map.insert("truenas".to_string(), Box::new(truenas::TrueNasConnector));
    map.insert("unifi".to_string(), Box::new(unifi::UnifiConnector));
}
