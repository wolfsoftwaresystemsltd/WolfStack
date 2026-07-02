use wolfstack::networking::router::RouterConfig;
fn main() {
    let cfg = RouterConfig::default();
    let json = serde_json::to_string_pretty(&cfg).unwrap();
    println!("Size: {} bytes", json.len());
    println!("Lines: {}", json.lines().count());
    println!("{}", json);
}
