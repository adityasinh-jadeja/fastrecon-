"""
FastRecon v3 Configuration — Constants, signatures, wordlists, payloads.
Central configuration hub for all scanning modules.
"""

# ──────────────────────────────────────────────
#  Default Scan Settings
# ──────────────────────────────────────────────
DEFAULT_CONCURRENCY = 50
DEFAULT_TIMEOUT = 7
DISCOVERY_TIMEOUT = 20
PORT_SCAN_TIMEOUT = 1.5          # seconds per port connect attempt
BANNER_READ_TIMEOUT = 3          # seconds to read service banner
ENDPOINT_TIMEOUT = 5
VULN_SCAN_TIMEOUT = 7
DNS_TIMEOUT = 5

# ──────────────────────────────────────────────
#  Scan Modes
# ──────────────────────────────────────────────
SCAN_MODES = {
    "light": {
        "description": "Quick passive recon — no active vuln testing",
        "ports": "top20",
        "endpoint_wordlist": "small",
        "vuln_scan": False,
        "concurrency": 30,
    },
    "normal": {
        "description": "Balanced scan — port scan + basic vuln checks",
        "ports": "top100",
        "endpoint_wordlist": "medium",
        "vuln_scan": True,
        "concurrency": 50,
    },
    "aggressive": {
        "description": "Deep scan — full port range, all payloads",
        "ports": "top1000",
        "endpoint_wordlist": "large",
        "vuln_scan": True,
        "concurrency": 100,
    },
}

# ──────────────────────────────────────────────
#  Top Ports for Scanning
# ──────────────────────────────────────────────
TOP_20_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    993, 995, 3306, 3389, 5432, 8080, 8443, 27017, 6379, 9200,
]

TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 119,
    135, 139, 143, 161, 389, 443, 445, 465, 514, 515,
    587, 636, 993, 995, 1080, 1433, 1434, 1521, 1723, 2049,
    2082, 2083, 2086, 2087, 2095, 2096, 3000, 3128, 3306, 3389,
    4443, 4848, 5000, 5432, 5900, 5984, 5985, 5986, 6379, 6443,
    7001, 7002, 7443, 8000, 8008, 8009, 8080, 8081, 8082, 8083,
    8084, 8085, 8086, 8087, 8088, 8089, 8090, 8161, 8443, 8444,
    8445, 8880, 8888, 9000, 9001, 9042, 9043, 9060, 9080, 9090,
    9091, 9200, 9300, 9443, 9999, 10000, 10250, 10443, 11211,
    15672, 27017, 27018, 28017, 50000, 50070, 61616,
]

TOP_1000_PORTS = list(range(1, 1001))

PORT_SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 81: "HTTP-Alt", 110: "POP3", 111: "RPCBind",
    119: "NNTP", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 515: "LPD", 587: "SMTP-Sub",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1433: "MSSQL", 1434: "MSSQL-Browser", 1521: "Oracle",
    1723: "PPTP", 2049: "NFS", 2082: "cPanel", 2083: "cPanel-SSL",
    2086: "WHM", 2087: "WHM-SSL", 2095: "Webmail", 2096: "Webmail-SSL",
    3000: "Grafana/Dev", 3128: "Squid", 3306: "MySQL", 3389: "RDP",
    4443: "HTTPS-Alt", 4848: "GlassFish", 5000: "Flask/Docker",
    5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB",
    5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 6379: "Redis",
    6443: "Kubernetes", 7001: "WebLogic", 7002: "WebLogic-SSL",
    7443: "HTTPS-Alt", 8000: "HTTP-Alt", 8008: "HTTP-Alt",
    8009: "AJP", 8080: "HTTP-Proxy", 8081: "HTTP-Alt",
    8082: "HTTP-Alt", 8083: "HTTP-Alt", 8084: "HTTP-Alt",
    8085: "HTTP-Alt", 8086: "InfluxDB", 8087: "HTTP-Alt",
    8088: "HTTP-Alt", 8089: "Splunk", 8090: "HTTP-Alt",
    8161: "ActiveMQ", 8443: "HTTPS-Alt", 8444: "HTTPS-Alt",
    8445: "HTTPS-Alt", 8880: "HTTP-Alt", 8888: "HTTP-Alt",
    9000: "SonarQube", 9001: "HTTP-Alt", 9042: "Cassandra",
    9043: "WebSphere", 9060: "WebSphere", 9080: "HTTP-Alt",
    9090: "Prometheus", 9091: "HTTP-Alt", 9200: "Elasticsearch",
    9300: "Elasticsearch", 9443: "HTTPS-Alt", 9999: "HTTP-Alt",
    10000: "Webmin", 10250: "Kubelet", 10443: "HTTPS-Alt",
    11211: "Memcached", 15672: "RabbitMQ", 27017: "MongoDB",
    27018: "MongoDB", 28017: "MongoDB-HTTP", 50000: "SAP",
    50070: "Hadoop", 61616: "ActiveMQ",
}

# Ports that are dangerous if exposed to the internet
DANGEROUS_PORTS = {
    6379: ("Redis", "Redis exposed without authentication — data leak / RCE risk"),
    27017: ("MongoDB", "MongoDB exposed without auth — full database access"),
    9200: ("Elasticsearch", "Elasticsearch exposed — data leak, potential RCE"),
    11211: ("Memcached", "Memcached exposed — data leak, DDoS amplification"),
    5984: ("CouchDB", "CouchDB exposed — potential unauthorized access"),
    2049: ("NFS", "NFS share exposed — potential data leak"),
    5900: ("VNC", "VNC exposed — potential unauthorized remote access"),
    3389: ("RDP", "RDP exposed — brute force & BlueKeep risk"),
    23: ("Telnet", "Telnet exposed — credentials sent in plaintext"),
    21: ("FTP", "FTP exposed — often allows anonymous access"),
    445: ("SMB", "SMB exposed — EternalBlue & ransomware risk"),
    161: ("SNMP", "SNMP exposed — information disclosure"),
    1433: ("MSSQL", "MSSQL exposed — database brute force risk"),
    3306: ("MySQL", "MySQL exposed — database brute force risk"),
    5432: ("PostgreSQL", "PostgreSQL exposed — database brute force risk"),
    10250: ("Kubelet", "Kubelet API exposed — container compromise risk"),
}

# ──────────────────────────────────────────────
#  Subdomain Takeover Signatures
# ──────────────────────────────────────────────
TAKEOVER_SIGNATURES = {
    "GitHub Pages": {
        "fingerprint": "There isn't a GitHub Pages site here.",
        "cname": "github.io",
    },
    "AWS S3": {
        "fingerprint": "NoSuchBucket",
        "cname": "s3.amazonaws.com",
    },
    "Heroku": {
        "fingerprint": "No such app",
        "cname": "herokuapp.com",
    },
    "Tumblr": {
        "fingerprint": "Whatever you were looking for doesn't currently exist at this address.",
        "cname": "tumblr.com",
    },
    "Shopify": {
        "fingerprint": "Sorry, this shop is currently unavailable.",
        "cname": "myshopify.com",
    },
    "Fastly": {
        "fingerprint": "Fastly error: unknown domain",
        "cname": "fastly.net",
    },
    "Pantheon": {
        "fingerprint": "The gods are wise, but do not know of the site which you seek.",
        "cname": "pantheonsite.io",
    },
    "Zendesk": {
        "fingerprint": "Help Center Closed",
        "cname": "zendesk.com",
    },
    "TeamWork": {
        "fingerprint": "Oops - We didn't find your site.",
        "cname": "teamwork.com",
    },
    "Helpjuice": {
        "fingerprint": "We could not find what you're looking for.",
        "cname": "helpjuice.com",
    },
    "HelpScout": {
        "fingerprint": "No settings were found for this company:",
        "cname": "helpscoutdocs.com",
    },
    "Cargo": {
        "fingerprint": "If you're moving your domain away from Cargo you must make this change through your registrar",
        "cname": "cargocollective.com",
    },
    "UserVoice": {
        "fingerprint": "This UserVoice subdomain is currently available!",
        "cname": "uservoice.com",
    },
    "Surge.sh": {
        "fingerprint": "project not found",
        "cname": "surge.sh",
    },
    "AWS CloudFront": {
        "fingerprint": "The request could not be satisfied",
        "cname": "cloudfront.net",
    },
    "Wordpress.com": {
        "fingerprint": "Do you want to register",
        "cname": "wordpress.com",
    },
    "Unbounce": {
        "fingerprint": "The requested URL was not found on this server",
        "cname": "unbouncepages.com",
    },
    "HubSpot": {
        "fingerprint": "Domain not found",
        "cname": "sites.hubspot.net",
    },
    "Ghost": {
        "fingerprint": "The thing you were looking for is no longer here",
        "cname": "ghost.io",
    },
    "Tilda": {
        "fingerprint": "Please renew your subscription",
        "cname": "tilda.ws",
    },
}

# ──────────────────────────────────────────────
#  Cloud Storage Bucket Patterns
# ──────────────────────────────────────────────
BUCKET_SUFFIXES = [
    "", "-backup", "-backups", "-dev", "-development",
    "-staging", "-stage", "-prod", "-production",
    "-assets", "-data", "-private", "-public",
    "-logs", "-media", "-uploads", "-static",
    "-files", "-content", "-archive", "-db",
    "-database", "-internal", "-test", "-testing",
    "-images", "-docs", "-cdn", "-web", "-api",
    "-config", "-secrets", "-keys", "-terraform",
    "-infra", "-deploy", "-ci", "-build",
]

CLOUD_PROVIDERS = {
    "AWS S3": "https://{bucket}.s3.amazonaws.com/",
    "GCP Storage": "https://storage.googleapis.com/{bucket}/",
    "Azure Blob": "https://{bucket}.blob.core.windows.net/",
    "Firebase RTDB": "https://{bucket}.firebaseio.com/.json",
    "Firebase Storage": "https://firebasestorage.googleapis.com/v0/b/{bucket}/o",
}

# ──────────────────────────────────────────────
#  Endpoint Discovery Wordlists
# ──────────────────────────────────────────────
ENDPOINT_PATHS_SMALL = [
    # Admin / Login
    "/admin", "/login", "/wp-admin", "/wp-login.php", "/administrator",
    "/dashboard", "/cpanel", "/manage", "/portal",
    # API
    "/api", "/api/v1", "/api/v2", "/graphql", "/swagger",
    "/swagger-ui.html", "/openapi.json", "/api-docs",
    # Sensitive files
    "/.env", "/.git/config", "/.git/HEAD", "/.gitignore",
    "/.svn/entries", "/.DS_Store", "/.htaccess", "/.htpasswd",
    "/web.config", "/crossdomain.xml", "/clientaccesspolicy.xml",
    # Info disclosure
    "/robots.txt", "/sitemap.xml", "/humans.txt", "/security.txt",
    "/.well-known/security.txt",
    "/phpinfo.php", "/info.php", "/server-status", "/server-info",
    "/debug", "/trace", "/elmah.axd",
    # Backups
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql",
    "/database.sql", "/dump.sql", "/data.sql",
    # Config files
    "/config.php", "/config.yml", "/config.json", "/settings.py",
    "/wp-config.php", "/configuration.php",
]

ENDPOINT_PATHS_MEDIUM = ENDPOINT_PATHS_SMALL + [
    # More admin paths
    "/admin/login", "/admin/dashboard", "/panel", "/console",
    "/manager", "/management", "/webadmin", "/sysadmin",
    "/admin.php", "/admin.html", "/admin/config",
    "/user/login", "/accounts/login", "/signin", "/signup",
    "/register", "/auth/login", "/auth",
    # More API endpoints
    "/api/v3", "/api/users", "/api/admin", "/api/config",
    "/api/health", "/api/status", "/api/debug",
    "/rest", "/rest/api", "/v1", "/v2",
    "/graphql/console", "/graphiql",
    # Frameworks
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
    "/actuator/mappings", "/actuator/configprops",
    "/_debug", "/__debug__",
    "/rails/info", "/rails/mailers",
    "/druid/index.html", "/solr/admin",
    # Documentation
    "/docs", "/doc", "/documentation", "/help",
    "/readme", "/README.md", "/CHANGELOG.md",
    # DevOps
    "/jenkins", "/hudson", "/bamboo", "/ci",
    "/nagios", "/monitoring", "/health", "/healthcheck",
    "/metrics", "/prometheus", "/grafana",
    "/.circleci/config.yml", "/.github",
    # Version control
    "/.git/", "/.svn/", "/.hg/",
    "/.git/logs/HEAD", "/.git/refs/",
    # Backups & archives
    "/www.zip", "/site.zip", "/web.zip",
    "/htdocs.zip", "/public.zip",
    "/backup/", "/bak/", "/old/", "/temp/", "/tmp/",
    # Error pages
    "/404", "/500", "/error", "/errors",
    # Common CMS
    "/wp-content/", "/wp-includes/", "/wp-json/",
    "/wp-json/wp/v2/users",
    "/joomla/", "/drupal/", "/magento/",
    "/feed", "/feed/atom", "/rss",
    # Cloud / infra
    "/aws.yml", "/docker-compose.yml", "/Dockerfile",
    "/.dockerenv", "/composer.json", "/package.json",
    "/Gemfile", "/Pipfile", "/requirements.txt",
    # Auth / tokens
    "/oauth", "/oauth/token", "/oauth/authorize",
    "/token", "/.npmrc", "/.pypirc",
]

ENDPOINT_PATHS_LARGE = ENDPOINT_PATHS_MEDIUM + [
    # Even more paths for aggressive mode
    "/cgi-bin/", "/cgi-bin/test.cgi", "/fcgi-bin/",
    "/phpmyadmin/", "/pma/", "/mysql/", "/myadmin/",
    "/pgadmin/", "/adminer.php", "/adminer/",
    "/webmail/", "/roundcube/", "/squirrelmail/",
    "/owa/", "/exchange/", "/autodiscover/",
    "/remote/login", "/vpn/", "/ssl-vpn/",
    "/xmlrpc.php", "/wp-trackback.php",
    "/wp-cron.php", "/wp-mail.php",
    "/license.txt", "/readme.html",
    "/INSTALL.txt", "/UPGRADE.txt",
    "/node_modules/", "/vendor/",
    "/bower_components/", "/dist/",
    "/build/", "/target/",
    "/uploads/", "/upload/", "/files/",
    "/images/", "/img/", "/static/",
    "/assets/", "/media/", "/resources/",
    "/include/", "/includes/", "/inc/",
    "/lib/", "/libs/", "/library/",
    "/test/", "/tests/", "/testing/",
    "/spec/", "/specs/",
    "/demo/", "/sample/", "/example/",
    "/staging/", "/dev/", "/development/",
    "/beta/", "/alpha/", "/sandbox/",
    "/app/", "/application/", "/src/",
    "/proxy/", "/proxy.php",
    "/redirect/", "/goto/", "/out/",
    "/ckeditor/", "/tinymce/", "/editor/",
    "/filemanager/", "/elfinder/",
    "/socket.io/", "/sockjs/",
    "/websocket/", "/ws/",
    "/.bash_history", "/.ssh/",
    "/.aws/credentials", "/.kube/config",
    "/id_rsa", "/id_rsa.pub",
    "/etc/passwd", "/etc/shadow",
    "/proc/self/environ",
    "/WEB-INF/web.xml", "/META-INF/",
    "/status", "/stat", "/stats",
    "/log/", "/logs/", "/logging/",
    "/trace/", "/traces/",
    "/env", "/environment",
    "/config/", "/configs/", "/conf/",
    "/setup/", "/install/", "/installer/",
    "/update/", "/upgrade/",
]

# ──────────────────────────────────────────────
#  Technology Fingerprints
# ──────────────────────────────────────────────
TECH_SIGNATURES = {
    # CMS
    "WordPress": {
        "body": ["wp-content", "wp-includes", "wp-json", "/xmlrpc.php"],
        "headers": {},
        "meta": "generator.*wordpress",
    },
    "Joomla": {
        "body": ["/media/jui/", "/components/com_"],
        "headers": {},
        "meta": "generator.*joomla",
    },
    "Drupal": {
        "body": ["Drupal.settings", "/sites/default/files"],
        "headers": {"x-generator": "drupal"},
        "meta": "generator.*drupal",
    },
    "Shopify": {
        "body": ["cdn.shopify.com", "Shopify.theme"],
        "headers": {"x-shopid": ""},
        "meta": "",
    },
    # Frameworks
    "React": {
        "body": ["__REACT_DEVTOOLS_GLOBAL_HOOK__", "_reactRootContainer", "data-reactroot"],
        "headers": {},
        "meta": "",
    },
    "Next.js": {
        "body": ["__NEXT_DATA__", "_next/static", "next/head"],
        "headers": {"x-powered-by": "next.js"},
        "meta": "",
    },
    "Angular": {
        "body": ["ng-version", "ng-app", "angular.min.js"],
        "headers": {},
        "meta": "",
    },
    "Vue.js": {
        "body": ["vue.min.js", "vue.js", "__vue__", "data-v-"],
        "headers": {},
        "meta": "",
    },
    "jQuery": {
        "body": ["jquery.min.js", "jquery.js", "jQuery("],
        "headers": {},
        "meta": "",
    },
    "Django": {
        "body": ["csrfmiddlewaretoken", "__admin_media_prefix__"],
        "headers": {},
        "meta": "",
    },
    "Laravel": {
        "body": ["laravel_session", "csrf-token"],
        "headers": {"x-powered-by": "laravel"},
        "meta": "",
    },
    "Ruby on Rails": {
        "body": ["csrf-token", "data-turbolinks", "action_dispatch"],
        "headers": {"x-powered-by": "phusion passenger"},
        "meta": "",
    },
    "Express.js": {
        "body": [],
        "headers": {"x-powered-by": "express"},
        "meta": "",
    },
    "ASP.NET": {
        "body": ["__VIEWSTATE", "__EVENTVALIDATION", "aspnetForm"],
        "headers": {"x-powered-by": "asp.net", "x-aspnet-version": ""},
        "meta": "",
    },
    "Spring Boot": {
        "body": [],
        "headers": {"x-application-context": ""},
        "meta": "",
    },
    "Flask": {
        "body": [],
        "headers": {"server": "werkzeug"},
        "meta": "",
    },
    # Servers
    "nginx": {
        "body": [],
        "headers": {"server": "nginx"},
        "meta": "",
    },
    "Apache": {
        "body": [],
        "headers": {"server": "apache"},
        "meta": "",
    },
    "IIS": {
        "body": [],
        "headers": {"server": "microsoft-iis"},
        "meta": "",
    },
    "LiteSpeed": {
        "body": [],
        "headers": {"server": "litespeed"},
        "meta": "",
    },
    # CDN / WAF
    "Cloudflare": {
        "body": [],
        "headers": {"server": "cloudflare", "cf-ray": ""},
        "meta": "",
    },
    "AWS CloudFront": {
        "body": [],
        "headers": {"x-amz-cf-id": "", "via": "cloudfront"},
        "meta": "",
    },
    "Akamai": {
        "body": [],
        "headers": {"x-akamai-transformed": ""},
        "meta": "",
    },
    "Sucuri WAF": {
        "body": ["Sucuri WebSite Firewall"],
        "headers": {"x-sucuri-id": ""},
        "meta": "",
    },
    "AWS WAF": {
        "body": [],
        "headers": {"x-amzn-waf": ""},
        "meta": "",
    },
    # Analytics / tracking
    "Google Analytics": {
        "body": ["google-analytics.com", "gtag(", "GoogleAnalyticsObject"],
        "headers": {},
        "meta": "",
    },
    "Google Tag Manager": {
        "body": ["googletagmanager.com", "GTM-"],
        "headers": {},
        "meta": "",
    },
}

# ──────────────────────────────────────────────
#  Vulnerability Scanner Payloads
# ──────────────────────────────────────────────
XSS_PAYLOADS = [
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    "<img src=x onerror=alert(1)>",
    "{{7*7}}",
    "${7*7}",
    "javascript:alert(1)",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "'; DROP TABLE users--",
    "1' AND '1'='1",
    "1 UNION SELECT NULL--",
    "' WAITFOR DELAY '0:0:5'--",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "\\\\evil.com",
    "/\\evil.com",
    "https://evil.com/%2F..",
]

CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:crlf=true",
    "%0aSet-Cookie:crlf=true",
    "\\r\\nSet-Cookie:crlf=true",
    "%E5%98%8D%E5%98%8ASet-Cookie:crlf=true",
]

# URL parameter names commonly vulnerable to injection
INJECTABLE_PARAMS = [
    "q", "s", "search", "query", "keyword",
    "id", "page", "url", "redirect", "next",
    "return", "returnUrl", "goto", "target",
    "rurl", "dest", "destination", "redir",
    "redirect_uri", "redirect_url", "callback",
    "path", "file", "folder", "name",
    "user", "username", "email",
    "sort", "order", "column", "dir",
    "lang", "language", "locale",
    "category", "cat", "type", "action",
    "view", "template", "module",
]

# SQL error patterns for detection
SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"microsoft ole db provider for sql server",
    r"microsoft sql native client error",
    r"invalid query",
    r"sql syntax.*error",
    r"ora-\d{5}",
    r"pg_query\(\): query failed",
    r"pgsql error",
    r"sqlite3\.operationalerror",
    r"sqlstate\[",
    r"jdbc\.sqldataexception",
    r"syntax error at or near",
    r"unterminated.*string",
    r"org\.postgresql\.util\.psqlexception",
    r"com\.mysql\.jdbc\.exceptions",
]

# ──────────────────────────────────────────────
#  Security Header Definitions
# ──────────────────────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "weight": 20,
        "description": "Forces HTTPS connections — prevents SSL-stripping attacks",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "ideal": "max-age=31536000",
    },
    "Content-Security-Policy": {
        "weight": 25,
        "description": "Prevents XSS, clickjacking, and code injection attacks",
        "recommendation": "Add a restrictive CSP. Start with: Content-Security-Policy: default-src 'self'",
        "ideal": "default-src 'self'",
        "bad_values": ["unsafe-inline", "unsafe-eval", "*"],
    },
    "X-Frame-Options": {
        "weight": 15,
        "description": "Prevents clickjacking by controlling iframe embedding",
        "recommendation": "Add: X-Frame-Options: DENY (or SAMEORIGIN if iframes needed)",
        "ideal": "DENY",
    },
    "X-Content-Type-Options": {
        "weight": 10,
        "description": "Prevents MIME-type sniffing attacks",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
        "ideal": "nosniff",
    },
    "X-XSS-Protection": {
        "weight": 5,
        "description": "Legacy XSS filter (deprecated but still useful for old browsers)",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block",
        "ideal": "1; mode=block",
    },
    "Referrer-Policy": {
        "weight": 10,
        "description": "Controls how much referrer info is sent with requests",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "ideal": "strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "weight": 10,
        "description": "Controls browser feature access (camera, mic, geolocation)",
        "recommendation": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "ideal": "camera=(), microphone=(), geolocation=()",
    },
    "X-Permitted-Cross-Domain-Policies": {
        "weight": 5,
        "description": "Controls Adobe Flash/PDF cross-domain data loading",
        "recommendation": "Add: X-Permitted-Cross-Domain-Policies: none",
        "ideal": "none",
    },
}

# Header score to grade mapping
HEADER_GRADES = [
    (90, "A+", "#06d6a0"),
    (80, "A", "#06d6a0"),
    (70, "B", "#118ab2"),
    (60, "C", "#ffd166"),
    (50, "D", "#f77f00"),
    (0, "F", "#ef476f"),
]

# ──────────────────────────────────────────────
#  Webhook Validation
# ──────────────────────────────────────────────
DISCORD_WEBHOOK_PREFIX = "https://discord.com/api/webhooks/"
SLACK_WEBHOOK_PREFIX = "https://hooks.slack.com/"

# ──────────────────────────────────────────────
#  Banner
# ──────────────────────────────────────────────
BANNER = r"""
  ______          __  ____
 / ____/___ ___  / /_/ __ \___  _________  ____
/ /_  / __ `/ / / __/ /_/ / _ \/ ___/ __ \/ __ \
/ __/ / /_/ /  / /_/ _, _/  __/ /__/ /_/ / / / /
/_/    \__,_/   \__/_/ |_|\___/\___/\____/_/ /_/
                                          v{version}
"""
