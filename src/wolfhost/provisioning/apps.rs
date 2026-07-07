use std::process::Command;
use serde::{Deserialize, Serialize};

fn is_proxmox() -> bool {
    Command::new("which").arg("pct").output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn lxc_exec(container: &str, cmd: &str) -> Result<String, String> {
    let output = if is_proxmox() {
        Command::new("pct")
            .args(&["exec", container, "--", "sh", "-c", cmd])
            .output()
            .map_err(|e| format!("pct exec failed: {}", e))?
    } else {
        Command::new("lxc-attach")
            .args(&["-n", container, "--", "sh", "-c", cmd])
            .output()
            .map_err(|e| format!("lxc-attach failed: {}", e))?
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.is_empty() {
            log::warn!("[{}] app install stderr: {}", container, stderr.trim());
        }
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppDefinition {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub icon: &'static str,
    pub category: &'static str,
    pub requires_db: bool,
    pub url: &'static str,
}

pub const APPS: &[AppDefinition] = &[
    AppDefinition {
        id: "wordpress",
        name: "WordPress",
        description: "The world's most popular CMS. Build blogs, portfolios, and business sites.",
        icon: "📝",
        category: "CMS",
        requires_db: true,
        url: "https://wordpress.org",
    },
    AppDefinition {
        id: "joomla",
        name: "Joomla",
        description: "Flexible CMS for building websites and powerful online applications.",
        icon: "🔵",
        category: "CMS",
        requires_db: true,
        url: "https://www.joomla.org",
    },
    AppDefinition {
        id: "drupal",
        name: "Drupal",
        description: "Enterprise-grade CMS for ambitious digital experiences.",
        icon: "💧",
        category: "CMS",
        requires_db: true,
        url: "https://www.drupal.org",
    },
    AppDefinition {
        id: "prestashop",
        name: "PrestaShop",
        description: "Open-source e-commerce platform to launch your online store.",
        icon: "🛒",
        category: "E-Commerce",
        requires_db: true,
        url: "https://www.prestashop.com",
    },
    AppDefinition {
        id: "nextcloud",
        name: "Nextcloud",
        description: "Self-hosted file sync, sharing, and collaboration platform.",
        icon: "☁️",
        category: "Productivity",
        requires_db: true,
        url: "https://nextcloud.com",
    },
    AppDefinition {
        id: "phpmyadmin",
        name: "phpMyAdmin",
        description: "Web-based MySQL/MariaDB database management tool.",
        icon: "🗃️",
        category: "Tools",
        requires_db: false,
        url: "https://www.phpmyadmin.net",
    },
    AppDefinition {
        id: "laravel",
        name: "Laravel",
        description: "Elegant PHP framework for web artisans. Fresh project scaffold.",
        icon: "🔺",
        category: "Framework",
        requires_db: true,
        url: "https://laravel.com",
    },
    AppDefinition {
        id: "ghost",
        name: "Ghost",
        description: "Modern publishing platform for blogs and newsletters. Node.js based.",
        icon: "👻",
        category: "CMS",
        requires_db: true,
        url: "https://ghost.org",
    },
    AppDefinition {
        id: "matomo",
        name: "Matomo",
        description: "Privacy-friendly web analytics. Alternative to Google Analytics.",
        icon: "📊",
        category: "Analytics",
        requires_db: true,
        url: "https://matomo.org",
    },
    AppDefinition {
        id: "roundcube",
        name: "Roundcube",
        description: "Free and open-source webmail client with a modern interface.",
        icon: "📬",
        category: "Email",
        requires_db: true,
        url: "https://roundcube.net",
    },
    AppDefinition {
        id: "adminer",
        name: "Adminer",
        description: "Lightweight single-file database management in PHP.",
        icon: "🔧",
        category: "Tools",
        requires_db: false,
        url: "https://www.adminer.org",
    },
    AppDefinition {
        id: "filebrowser",
        name: "File Browser",
        description: "Web-based file manager with upload, download, and editing.",
        icon: "📂",
        category: "Tools",
        requires_db: false,
        url: "https://filebrowser.org",
    },
];

pub fn list_apps() -> Vec<&'static AppDefinition> {
    APPS.iter().collect()
}

pub fn get_app(id: &str) -> Option<&'static AppDefinition> {
    APPS.iter().find(|a| a.id == id)
}

/// Install an app into a container. Returns a status message.
pub fn install_app(container: &str, app_id: &str, domain: &str, db_name: &str, db_user: &str, db_pass: &str) -> Result<String, String> {
    log::info!("[{}] Installing app: {}", container, app_id);

    match app_id {
        "wordpress" => install_wordpress(container, domain, db_name, db_user, db_pass),
        "joomla" => install_joomla(container, domain, db_name, db_user, db_pass),
        "drupal" => install_drupal(container, domain, db_name, db_user, db_pass),
        "prestashop" => install_prestashop(container, domain, db_name, db_user, db_pass),
        "nextcloud" => install_nextcloud(container, domain, db_name, db_user, db_pass),
        "phpmyadmin" => install_phpmyadmin(container),
        "laravel" => install_laravel(container, db_name, db_user, db_pass),
        "ghost" => install_ghost(container, domain),
        "matomo" => install_matomo(container, domain, db_name, db_user, db_pass),
        "roundcube" => install_roundcube(container, domain, db_name, db_user, db_pass),
        "adminer" => install_adminer(container),
        "filebrowser" => install_filebrowser(container),
        _ => Err(format!("Unknown app: {}", app_id)),
    }
}

/// Create a MariaDB database inside the container for an app
pub fn create_app_database(container: &str, db_name: &str, db_user: &str, db_pass: &str) -> Result<(), String> {
    log::info!("[{}] Creating database: {} (user: {})", container, db_name, db_user);

    // Install MariaDB server if not present
    lxc_exec(container, "export DEBIAN_FRONTEND=noninteractive && apt-get install -y -qq mariadb-server 2>/dev/null")?;
    lxc_exec(container, "systemctl enable mariadb && systemctl start mariadb 2>/dev/null")?;

    // Create DB and user
    let sql = format!(
        "CREATE DATABASE IF NOT EXISTS `{db}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; \
         CREATE USER IF NOT EXISTS '{user}'@'localhost' IDENTIFIED BY '{pass}'; \
         GRANT ALL PRIVILEGES ON `{db}`.* TO '{user}'@'localhost'; \
         FLUSH PRIVILEGES;",
        db = db_name,
        user = db_user,
        pass = db_pass.replace('\'', "\\'"),
    );

    lxc_exec(container, &format!("mysql -e \"{}\"", sql.replace('"', "\\\"")))?;
    log::info!("[{}] Database '{}' created", container, db_name);
    Ok(())
}

fn install_wordpress(container: &str, domain: &str, db_name: &str, db_user: &str, db_pass: &str) -> Result<String, String> {
    create_app_database(container, db_name, db_user, db_pass)?;

    lxc_exec(container, r#"cd /tmp && curl -sO https://wordpress.org/latest.tar.gz && tar -xzf latest.tar.gz"#)?;
    lxc_exec(container, "rm -rf /var/www/html/index.html && cp -a /tmp/wordpress/* /var/www/html/ && rm -rf /tmp/wordpress /tmp/latest.tar.gz")?;

    // Create wp-config.php
    let wp_config = format!(
        r#"cd /var/www/html && cp wp-config-sample.php wp-config.php && \
        sed -i "s/database_name_here/{db}/" wp-config.php && \
        sed -i "s/username_here/{user}/" wp-config.php && \
        sed -i "s/password_here/{pass}/" wp-config.php && \
        curl -s https://api.wordpress.org/secret-key/1.1/salt/ >> /tmp/wp-keys.txt && \
        python3 -c "
import re
with open('wp-config.php') as f: c = f.read()
with open('/tmp/wp-keys.txt') as f: keys = f.read()
c = re.sub(r'define\(.AUTH_KEY.*?;.*?define\(.NONCE_SALT.*?;', keys, c, flags=re.DOTALL)
with open('wp-config.php','w') as f: f.write(c)
" 2>/dev/null"#,
        db = db_name, user = db_user, pass = db_pass.replace('\'', "\\'"),
    );
    lxc_exec(container, &wp_config)?;
    lxc_exec(container, "chown -R www-data:www-data /var/www/html && chmod -R 755 /var/www/html")?;
    lxc_exec(container, "systemctl restart apache2")?;

    Ok(format!("WordPress installed! Visit http://{} to complete setup.", domain))
}

fn install_joomla(container: &str, domain: &str, db_name: &str, db_user: &str, db_pass: &str) -> Result<String, String> {
    create_app_database(container, db_name, db_user, db_pass)?;

    lxc_exec(container, "cd /tmp && curl -sL https://downloads.joomla.org/cms/joomla5/5-1-0/Joomla_5-1-0-Stable-Full_Package.tar.gz -o joomla.tar.gz 2>/dev/null || curl -sL https://downloads.joomla.org/cms/joomla4/4-4-0/Joomla_4-4-0-Stable-Full_Package.tar.gz -o joomla.tar.gz")?;
    lxc_exec(container, "rm -rf /var/www/html/index.html && cd /var/www/html && tar -xzf /tmp/joomla.tar.gz && rm -f /tmp/joomla.tar.gz")?;
    lxc_exec(container, "chown -R www-data:www-data /var/www/html && chmod -R 755 /var/www/html")?;
    lxc_exec(container, "systemctl restart apache2")?;

    Ok(format!("Joomla installed! Visit http://{} to run the installer. DB: {}, User: {}, Pass: {}", domain, db_name, db_user, db_pass))
}

fn install_drupal(container: &str, domain: &str, db_name: &str, db_user: &str, db_pass: &str) -> Result<String, String> {
    create_app_database(container, db_name, db_user, db_pass)?;

    lxc_exec(container, "cd /tmp && curl -sL https://www.drupal.org/download-latest/tar.gz -o drupal.tar.gz && tar -xzf drupal.tar.gz")?;
    lxc_exec(container, "rm -rf /var/www/html/index.html && cp -a /tmp/drupal-*/. /var/www/html/ && rm -rf /tmp/drupal-* /tmp/drupal.tar.gz")?;
    lxc_exec(container, "chown -R www-data:www-data /var/www/html && chmod -R 755 /var/www/html")?;
    lxc_exec(container, "systemctl restart apache2")?;

    Ok(format!("Drupal installed! Visit http://{} to run the installer. DB: {}, User: {}, Pass: {}", domain, db_name, db_user, db_pass))
}

fn install_prestashop(container: &str, domain: &str, db_name: &str, db_user: &str, db_pass: &str) -> Result<String, String> {
    create_app_database(container, db_name, db_user, db_pass)?;

    lxc_exec(container, "cd /tmp && curl -sL https://github.com/PrestaShop/PrestaShop/releases/download/8.1.3/prestashop_8.1.3.zip -o prestashop.zip 2>/dev/null && apt-get install -y -qq unzip 2>/dev/null && unzip -q prestashop.zip -d prestashop 2>/dev/null")?;
    lxc_exec(container, "rm -rf /var/www/html/index.html && cp -a /tmp/prestashop/* /var/www/html/ && rm -rf /tmp/prestashop /tmp/prestashop.zip")?;
    lxc_exec(container, "cd /var/www/html && unzip -qo prestashop.zip 2>/dev/null; rm -f prestashop.zip")?;
    lxc_exec(container, "chown -R www-data:www-data /var/www/html && chmod -R 755 /var/www/html")?;
    lxc_exec(container, "systemctl restart apache2")?;

    Ok(format!("PrestaShop installed! Visit http://{} to complete setup. DB: {}, User: {}, Pass: {}", domain, db_name, db_user, db_pass))
}

fn install_nextcloud(container: &str, domain: &str, db_name: &str, db_user: &str, db_pass: &str) -> Result<String, String> {
    create_app_database(container, db_name, db_user, db_pass)?;

    lxc_exec(container, "cd /tmp && curl -sL https://download.nextcloud.com/server/releases/latest.tar.bz2 -o nextcloud.tar.bz2 && tar -xjf nextcloud.tar.bz2")?;
    lxc_exec(container, "rm -rf /var/www/html/index.html && cp -a /tmp/nextcloud/* /var/www/html/ && rm -rf /tmp/nextcloud /tmp/nextcloud.tar.bz2")?;
    lxc_exec(container, "mkdir -p /var/www/html/data && chown -R www-data:www-data /var/www/html && chmod -R 755 /var/www/html")?;
    lxc_exec(container, "systemctl restart apache2")?;

    Ok(format!("Nextcloud installed! Visit http://{} to complete setup. DB: {}, User: {}, Pass: {}", domain, db_name, db_user, db_pass))
}

fn install_phpmyadmin(container: &str) -> Result<String, String> {
    lxc_exec(container, "export DEBIAN_FRONTEND=noninteractive && apt-get install -y -qq mariadb-server 2>/dev/null")?;
    lxc_exec(container, "systemctl enable mariadb && systemctl start mariadb 2>/dev/null")?;
    lxc_exec(container, "cd /tmp && curl -sL https://www.phpmyadmin.net/downloads/phpMyAdmin-latest-all-languages.tar.gz -o pma.tar.gz && tar -xzf pma.tar.gz")?;
    lxc_exec(container, "mkdir -p /var/www/html/phpmyadmin && cp -a /tmp/phpMyAdmin-*/. /var/www/html/phpmyadmin/ && rm -rf /tmp/phpMyAdmin-* /tmp/pma.tar.gz")?;
    lxc_exec(container, "cd /var/www/html/phpmyadmin && cp config.sample.inc.php config.inc.php")?;
    // Set blowfish secret
    lxc_exec(container, r#"cd /var/www/html/phpmyadmin && sed -i "s/\\$cfg\\['blowfish_secret'\\] = '';/\\$cfg['blowfish_secret'] = '$(head -c 32 /dev/urandom | base64 | head -c 32)';/" config.inc.php"#)?;
    lxc_exec(container, "chown -R www-data:www-data /var/www/html/phpmyadmin")?;

    Ok("phpMyAdmin installed at /phpmyadmin".to_string())
}

fn install_laravel(container: &str, db_name: &str, db_user: &str, db_pass: &str) -> Result<String, String> {
    create_app_database(container, db_name, db_user, db_pass)?;

    lxc_exec(container, "export DEBIAN_FRONTEND=noninteractive && apt-get install -y -qq php-mbstring php-xml php-zip unzip curl 2>/dev/null")?;
    // Install Composer
    lxc_exec(container, "curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer 2>/dev/null")?;
    // Create Laravel project
    lxc_exec(container, "cd /var/www && rm -rf html && composer create-project --prefer-dist laravel/laravel html 2>/dev/null")?;
    // Configure .env
    lxc_exec(container, &format!(
        r#"cd /var/www/html && sed -i "s/DB_DATABASE=laravel/DB_DATABASE={}/" .env && sed -i "s/DB_USERNAME=root/DB_USERNAME={}/" .env && sed -i "s/DB_PASSWORD=/DB_PASSWORD={}/" .env"#,
        db_name, db_user, db_pass
    ))?;
    lxc_exec(container, "chown -R www-data:www-data /var/www/html && chmod -R 755 /var/www/html/storage /var/www/html/bootstrap/cache")?;
    // Point Apache to /public
    lxc_exec(container, r#"sed -i 's|DocumentRoot /var/www/html|DocumentRoot /var/www/html/public|' /etc/apache2/sites-available/000-default.conf"#)?;
    lxc_exec(container, "systemctl restart apache2")?;

    Ok("Laravel project created with database configured.".to_string())
}

fn install_ghost(container: &str, domain: &str) -> Result<String, String> {
    // Ghost needs Node.js
    lxc_exec(container, "export DEBIAN_FRONTEND=noninteractive && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - 2>/dev/null && apt-get install -y -qq nodejs 2>/dev/null")?;
    lxc_exec(container, "npm install -g ghost-cli 2>/dev/null")?;
    lxc_exec(container, "mkdir -p /var/www/ghost && chown www-data:www-data /var/www/ghost")?;
    lxc_exec(container, &format!(
        "cd /var/www/ghost && ghost install local --url http://{} --no-prompt 2>/dev/null",
        domain
    ))?;

    // Set up Apache reverse proxy to Ghost (port 2368)
    let proxy_conf = format!(
        r#"ProxyPreserveHost On
ProxyPass / http://127.0.0.1:2368/
ProxyPassReverse / http://127.0.0.1:2368/"#
    );
    lxc_exec(container, "a2enmod proxy proxy_http 2>/dev/null")?;
    lxc_exec(container, &format!(
        r#"cat > /etc/apache2/sites-available/000-default.conf << 'EOF'
<VirtualHost *:80>
    ServerName {domain}
    {proxy}
</VirtualHost>
EOF"#,
        domain = domain, proxy = proxy_conf
    ))?;
    lxc_exec(container, "systemctl restart apache2")?;

    Ok(format!("Ghost installed! Visit http://{}/ghost to set up your admin account.", domain))
}

fn install_matomo(container: &str, domain: &str, db_name: &str, db_user: &str, db_pass: &str) -> Result<String, String> {
    create_app_database(container, db_name, db_user, db_pass)?;

    lxc_exec(container, "cd /tmp && curl -sL https://builds.matomo.org/matomo-latest.tar.gz -o matomo.tar.gz && tar -xzf matomo.tar.gz")?;
    lxc_exec(container, "rm -rf /var/www/html/index.html && cp -a /tmp/matomo/* /var/www/html/ && rm -rf /tmp/matomo /tmp/matomo.tar.gz")?;
    lxc_exec(container, "chown -R www-data:www-data /var/www/html && chmod -R 755 /var/www/html")?;
    lxc_exec(container, "systemctl restart apache2")?;

    Ok(format!("Matomo installed! Visit http://{} to run the installer. DB: {}, User: {}, Pass: {}", domain, db_name, db_user, db_pass))
}

fn install_roundcube(container: &str, domain: &str, db_name: &str, db_user: &str, db_pass: &str) -> Result<String, String> {
    create_app_database(container, db_name, db_user, db_pass)?;

    lxc_exec(container, "cd /tmp && curl -sL https://github.com/roundcube/roundcubemail/releases/download/1.6.6/roundcubemail-1.6.6-complete.tar.gz -o roundcube.tar.gz && tar -xzf roundcube.tar.gz")?;
    lxc_exec(container, "rm -rf /var/www/html/index.html && cp -a /tmp/roundcubemail-*/. /var/www/html/ && rm -rf /tmp/roundcubemail-* /tmp/roundcube.tar.gz")?;
    lxc_exec(container, "chown -R www-data:www-data /var/www/html && chmod -R 755 /var/www/html")?;
    lxc_exec(container, "systemctl restart apache2")?;

    Ok(format!("Roundcube installed! Visit http://{}/installer to complete setup. DB: {}, User: {}, Pass: {}", domain, db_name, db_user, db_pass))
}

fn install_adminer(container: &str) -> Result<String, String> {
    lxc_exec(container, "export DEBIAN_FRONTEND=noninteractive && apt-get install -y -qq mariadb-server 2>/dev/null")?;
    lxc_exec(container, "systemctl enable mariadb && systemctl start mariadb 2>/dev/null")?;
    lxc_exec(container, "mkdir -p /var/www/html/adminer && curl -sL https://www.adminer.org/latest.php -o /var/www/html/adminer/index.php")?;
    lxc_exec(container, "chown -R www-data:www-data /var/www/html/adminer")?;

    Ok("Adminer installed at /adminer".to_string())
}

fn install_filebrowser(container: &str) -> Result<String, String> {
    lxc_exec(container, "curl -fsSL https://raw.githubusercontent.com/filebrowser/get/master/get.sh | bash 2>/dev/null")?;
    // Create systemd service for filebrowser
    lxc_exec(container, r#"cat > /etc/systemd/system/filebrowser.service << 'EOF'
[Unit]
Description=File Browser
After=network.target

[Service]
ExecStart=/usr/local/bin/filebrowser -r /var/www/html -a 0.0.0.0 -p 8080
Restart=always
User=www-data

[Install]
WantedBy=multi-user.target
EOF"#)?;
    lxc_exec(container, "systemctl daemon-reload && systemctl enable filebrowser && systemctl start filebrowser 2>/dev/null")?;

    // Add Apache proxy for /files -> filebrowser
    lxc_exec(container, "a2enmod proxy proxy_http 2>/dev/null")?;

    Ok("File Browser installed! Running on port 8080. Default login: admin/admin".to_string())
}
