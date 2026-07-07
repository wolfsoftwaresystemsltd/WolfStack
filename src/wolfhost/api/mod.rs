pub mod dashboard;
pub mod customers;
pub mod plans;
pub mod services;
pub mod invoices;
pub mod tickets;
pub mod branding;
pub mod database;
pub mod servers;
pub mod dns;
pub mod directadmin;
pub mod da_packages;
pub mod da_system;
pub mod info;
pub mod migration;

use actix_web::web;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        // Runtime info (ports, TLS) — used by the admin UI to build
        // links to the customer portal.
        .route("/info", web::get().to(info::get_info))
        // Branding
        .route("/branding", web::get().to(branding::get))
        .route("/branding", web::put().to(branding::update))
        // Database
        .route("/database", web::get().to(database::get_config))
        .route("/database", web::put().to(database::update_config))
        .route("/database/test", web::post().to(database::test_connection))
        // Servers / Infrastructure
        .route("/servers/nodes", web::get().to(servers::list_nodes))
        .route("/servers/nodes/{id}/containers", web::get().to(servers::node_containers))
        .route("/servers/nodes/{id}/stats", web::get().to(servers::node_container_stats))
        .route("/servers/templates", web::get().to(servers::list_templates))
        .route("/servers/node-ips", web::get().to(servers::get_node_ips))
        .route("/servers/node-ips", web::put().to(servers::set_node_ip))
        .route("/servers/provision", web::post().to(servers::provision_container))
        .route("/servers/provision/{task_id}/stream", web::get().to(servers::provision_stream))
        .route("/servers/provision/{task_id}/logs", web::get().to(servers::provision_logs))
        .route("/servers/containers/{name}/action", web::post().to(servers::container_action))
        .route("/servers/customer-containers", web::get().to(servers::list_customer_containers))
        // DNS
        .route("/dns/status", web::get().to(dns::status))
        .route("/dns/install", web::post().to(dns::install))
        .route("/dns/zones", web::get().to(dns::list_zones))
        .route("/dns/zones", web::post().to(dns::create_zone))
        .route("/dns/zones/{domain}", web::get().to(dns::get_zone))
        .route("/dns/zones/{domain}", web::delete().to(dns::delete_zone))
        .route("/dns/zones/{domain}/records", web::put().to(dns::set_record))
        .route("/dns/zones/{domain}/records", web::delete().to(dns::delete_record))
        // Dashboard
        .route("/dashboard/stats", web::get().to(dashboard::get_stats))
        .route("/dashboard/activity", web::get().to(dashboard::get_activity))
        // Customers
        .route("/customers", web::get().to(customers::list))
        .route("/customers", web::post().to(customers::create))
        .route("/customers/{id}", web::get().to(customers::get))
        .route("/customers/{id}", web::put().to(customers::update))
        .route("/customers/{id}", web::delete().to(customers::delete))
        .route("/customers/{id}/suspend", web::post().to(customers::suspend))
        .route("/customers/{id}/unsuspend", web::post().to(customers::unsuspend))
        // Plans
        .route("/plans", web::get().to(plans::list))
        .route("/plans", web::post().to(plans::create))
        .route("/plans/{id}", web::get().to(plans::get))
        .route("/plans/{id}", web::put().to(plans::update))
        .route("/plans/{id}", web::delete().to(plans::delete))
        // Services
        .route("/services", web::get().to(services::list))
        .route("/services", web::post().to(services::create))
        .route("/services/{id}", web::get().to(services::get))
        .route("/services/{id}", web::put().to(services::update))
        .route("/services/{id}", web::delete().to(services::delete))
        // DA-account control: suspend / unsuspend the underlying
        // DirectAdmin user. Same lever DA's UI uses; reversible.
        .route("/services/{id}/da/suspend", web::post().to(services::suspend_da))
        .route("/services/{id}/da/unsuspend", web::post().to(services::unsuspend_da))
        // Invoices
        .route("/invoices", web::get().to(invoices::list))
        .route("/invoices", web::post().to(invoices::create))
        .route("/invoices/{id}", web::get().to(invoices::get))
        .route("/invoices/{id}", web::put().to(invoices::update))
        // Tickets
        .route("/tickets", web::get().to(tickets::list))
        .route("/tickets/{id}", web::get().to(tickets::get))
        .route("/tickets/{id}", web::put().to(tickets::update))
        .route("/tickets/{id}/reply", web::post().to(tickets::reply))
        // DirectAdmin instances
        .route("/directadmin", web::get().to(directadmin::list))
        .route("/directadmin", web::post().to(directadmin::create))
        .route("/directadmin/detect", web::post().to(directadmin::detect))
        .route("/directadmin/{id}", web::get().to(directadmin::get))
        .route("/directadmin/{id}", web::put().to(directadmin::update))
        .route("/directadmin/{id}", web::delete().to(directadmin::delete))
        .route("/directadmin/{id}/test", web::post().to(directadmin::test_connection))
        .route("/directadmin/{id}/scan", web::post().to(directadmin::scan))
        .route("/directadmin/{id}/import", web::post().to(directadmin::import))
        // DirectAdmin packages — sync local Plans onto DA as user packages
        .route("/directadmin/{instance_id}/packages", web::get().to(da_packages::list_packages))
        .route("/directadmin/{instance_id}/packages/sync", web::post().to(da_packages::sync_packages))
        .route("/directadmin/{instance_id}/packages/{name}", web::delete().to(da_packages::delete_package))
        // DirectAdmin services control + system info
        .route("/directadmin/{instance_id}/services", web::get().to(da_system::list_services))
        .route("/directadmin/{instance_id}/services/action", web::post().to(da_system::service_action))
        .route("/directadmin/{instance_id}/system-info", web::get().to(da_system::system_info))
        .route("/directadmin/{instance_id}/users/{user}/2fa/disable", web::post().to(da_system::disable_2fa))
        // Migration: move a DA-backed service onto a fresh WolfStack LXC
        .route("/migrations", web::get().to(migration::list))
        .route("/migrations", web::post().to(migration::start))
        .route("/migrations/{id}", web::get().to(migration::get))
        .route("/migrations/{id}", web::delete().to(migration::cancel))
        .route("/migrations/{id}/rollback", web::post().to(migration::rollback));
}
