#!/usr/bin/env python3
"""
SecretFinder - Pattern Definitions
Extended regex patterns with severity classification.
Rewritten & Enhanced by: https://github.com/Xnuvers007/SecretFinder
Original: https://github.com/m4ll0k/SecretFinder
"""

from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


# Each pattern: (regex_string, severity, description)
PATTERNS: dict[str, tuple[str, Severity, str]] = {
    # ── Google ──────────────────────────────────────────────────────────────
    "google_api_key": (
        r'AIza[0-9A-Za-z\-_]{35}',
        Severity.CRITICAL,
        "Google API Key",
    ),
    "google_oauth2": (
        r'ya29\.[0-9A-Za-z\-_]+',
        Severity.CRITICAL,
        "Google OAuth2 Access Token",
    ),
    "google_captcha": (
        r'6L[0-9A-Za-z\-_]{38}|^6[0-9a-zA-Z_\-]{39}$',
        Severity.MEDIUM,
        "Google reCAPTCHA Site Key",
    ),
    "firebase_key": (
        r'AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}',
        Severity.CRITICAL,
        "Firebase Server Key",
    ),

    # ── Amazon / AWS ─────────────────────────────────────────────────────────
    "aws_access_key_id": (
        r'(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])',
        Severity.CRITICAL,
        "AWS Access Key ID (broad)",
    ),
    "aws_access_key_id_strict": (
        r'A[SK]IA[0-9A-Z]{16}',
        Severity.CRITICAL,
        "AWS Access Key ID",
    ),
    "aws_secret_access_key": (
        r'(?i)aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}',
        Severity.CRITICAL,
        "AWS Secret Access Key",
    ),
    "aws_mws_token": (
        r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        Severity.CRITICAL,
        "Amazon MWS Auth Token",
    ),
    "amazon_s3_url": (
        r'[a-zA-Z0-9\-\.\_]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9\-\.\_]+|s3\.amazonaws\.com/[a-zA-Z0-9\-\.\_]+',
        Severity.MEDIUM,
        "Amazon S3 Bucket URL",
    ),

    # ── Azure ────────────────────────────────────────────────────────────────
    "azure_storage_key": (
        r'DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}',
        Severity.CRITICAL,
        "Azure Storage Connection String",
    ),
    "azure_sas_token": (
        r'sv=\d{4}-\d{2}-\d{2}&s[a-z]=&sig=[A-Za-z0-9%+/=]+',
        Severity.HIGH,
        "Azure SAS Token",
    ),

    # ── Facebook / Meta ───────────────────────────────────────────────────────
    "facebook_access_token": (
        r'EAACEdEose0cBA[0-9A-Za-z]+',
        Severity.CRITICAL,
        "Facebook Access Token",
    ),
    "facebook_app_secret": (
        r'(?i)(facebook|fb)(.{0,20})([0-9a-f]{32})',
        Severity.CRITICAL,
        "Facebook App Secret",
    ),

    # ── GitHub ──────────────────────────────────────────────────────────────
    "github_token_classic": (
        r'ghp_[A-Za-z0-9]{36}',
        Severity.CRITICAL,
        "GitHub Personal Access Token (Classic)",
    ),
    "github_token_fine": (
        r'github_pat_[A-Za-z0-9_]{82}',
        Severity.CRITICAL,
        "GitHub Fine-Grained PAT",
    ),
    "github_oauth": (
        r'gho_[A-Za-z0-9]{36}',
        Severity.CRITICAL,
        "GitHub OAuth Token",
    ),
    "github_credential_url": (
        r'[a-zA-Z0-9_\-]*:[a-zA-Z0-9_\-]+@github\.com',
        Severity.CRITICAL,
        "GitHub Credential in URL",
    ),

    # ── GitLab ──────────────────────────────────────────────────────────────
    "gitlab_token": (
        r'glpat-[A-Za-z0-9\-_]{20}',
        Severity.CRITICAL,
        "GitLab Personal Access Token",
    ),

    # ── Stripe ──────────────────────────────────────────────────────────────
    "stripe_live_key": (
        r'sk_live_[0-9a-zA-Z]{24}',
        Severity.CRITICAL,
        "Stripe Live Secret Key",
    ),
    "stripe_restricted_key": (
        r'rk_live_[0-9a-zA-Z]{24}',
        Severity.HIGH,
        "Stripe Restricted Key",
    ),
    "stripe_publishable_key": (
        r'pk_live_[0-9a-zA-Z]{24}',
        Severity.MEDIUM,
        "Stripe Live Publishable Key",
    ),

    # ── Twilio ──────────────────────────────────────────────────────────────
    "twilio_api_key": (
        r'SK[0-9a-fA-F]{32}',
        Severity.HIGH,
        "Twilio API Key",
    ),
    "twilio_account_sid": (
        r'AC[a-zA-Z0-9_\-]{32}',
        Severity.HIGH,
        "Twilio Account SID",
    ),
    "twilio_app_sid": (
        r'AP[a-zA-Z0-9_\-]{32}',
        Severity.MEDIUM,
        "Twilio App SID",
    ),
    "hex_32_bit": (
        r'\b[a-fA-F0-9]{32}\b',
        Severity.MEDIUM,
        "Hex String (32-bit)",
    ),
    "hex_64_bit": (
        r'\b[a-fA-F0-9]{64}\b',
        Severity.MEDIUM,
        "Hex String (64-bit)",
    ),

    # ── Slack ────────────────────────────────────────────────────────────────
    "slack_bot_token": (
        r'xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}',
        Severity.CRITICAL,
        "Slack Bot Token",
    ),
    "slack_user_token": (
        r'xoxp-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]+',
        Severity.CRITICAL,
        "Slack User Token",
    ),
    "slack_workspace_token": (
        r'xoxa-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]+',
        Severity.CRITICAL,
        "Slack Workspace Token",
    ),
    "slack_webhook": (
        r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
        Severity.HIGH,
        "Slack Incoming Webhook URL",
    ),

    # ── Square ──────────────────────────────────────────────────────────────
    "square_access_token": (
        r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
        Severity.CRITICAL,
        "Square Access Token",
    ),
    "square_oauth_secret": (
        r'sq0csp-[0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
        Severity.CRITICAL,
        "Square OAuth Secret",
    ),

    # ── PayPal / Braintree ───────────────────────────────────────────────────
    "paypal_braintree_token": (
        r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
        Severity.CRITICAL,
        "PayPal/Braintree Access Token",
    ),

    # ── Mailgun / SendGrid / Mailchimp ────────────────────────────────────────
    "mailgun_api_key": (
        r'key-[0-9a-zA-Z]{32}',
        Severity.HIGH,
        "Mailgun API Key",
    ),
    "sendgrid_api_key": (
        r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}',
        Severity.HIGH,
        "SendGrid API Key",
    ),
    "mailchimp_api_key": (
        r'[0-9a-f]{32}-us[0-9]{1,2}',
        Severity.HIGH,
        "Mailchimp API Key",
    ),

    # ── Private Keys / Certs ─────────────────────────────────────────────────
    "rsa_private_key": (
        r'-----BEGIN RSA PRIVATE KEY-----',
        Severity.CRITICAL,
        "RSA Private Key",
    ),
    "dsa_private_key": (
        r'-----BEGIN DSA PRIVATE KEY-----',
        Severity.CRITICAL,
        "DSA Private Key",
    ),
    "ec_private_key": (
        r'-----BEGIN EC PRIVATE KEY-----',
        Severity.CRITICAL,
        "EC Private Key",
    ),
    "pgp_private_key": (
        r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
        Severity.CRITICAL,
        "PGP Private Key Block",
    ),
    "generic_private_key": (
        r'-----BEGIN [^\s]+ PRIVATE KEY-----',
        Severity.CRITICAL,
        "Generic Private Key",
    ),

    # ── JWT ──────────────────────────────────────────────────────────────────
    "json_web_token": (
        r'ey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-\.+/=]{10,}',
        Severity.HIGH,
        "JSON Web Token (JWT)",
    ),

    # ── Authorization Headers ─────────────────────────────────────────────────
    "authorization_basic": (
        r'(?i)basic\s+[a-zA-Z0-9=:_+/\-]{10,200}',
        Severity.HIGH,
        "HTTP Basic Auth Header",
    ),
    "authorization_bearer": (
        r'(?i)bearer\s+[a-zA-Z0-9_\-\.=:+/]{10,500}',
        Severity.HIGH,
        "HTTP Bearer Token",
    ),
    "api_key_generic": (
        r'(?i)(api[_\-\s]?key|apikey)\s*[=:]\s*["\']?[a-zA-Z0-9_\-]{16,64}["\']?',
        Severity.HIGH,
        "Generic API Key Assignment",
    ),

    # ── Database / Connection Strings ─────────────────────────────────────────
    "database_connection_string": (
        r'(?i)(mongodb|mysql|postgres|postgresql|redis|mssql|oracle)\://[^\s\'"<>]+',
        Severity.CRITICAL,
        "Database Connection String",
    ),
    "jdbc_connection": (
        r'jdbc:[a-z]+://[^\s\'"<>]{10,}',
        Severity.CRITICAL,
        "JDBC Connection String",
    ),

    # ── Credentials in code ───────────────────────────────────────────────────
    "possible_credentials": (
        r'(?i)(password|passwd|pwd|secret|credentials?)\s*[`=:"\[]+\s*[^\s,;\]]{4,}',
        Severity.HIGH,
        "Possible Hardcoded Credentials",
    ),
    "hardcoded_secret": (
        r'(?i)(client_secret|app_secret|secret_key|consumer_secret)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{8,}["\']?',
        Severity.CRITICAL,
        "Hardcoded Secret Key",
    ),

    # ── Heroku ───────────────────────────────────────────────────────────────
    "heroku_api_key": (
        r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
        Severity.HIGH,
        "Heroku API Key (UUID format)",
    ),

    # ── NPM / Package Tokens ──────────────────────────────────────────────────
    "npm_token": (
        r'npm_[A-Za-z0-9]{36}',
        Severity.HIGH,
        "NPM Access Token",
    ),

    # ── Discord ──────────────────────────────────────────────────────────────
    "discord_bot_token": (
        r'[MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27}',
        Severity.CRITICAL,
        "Discord Bot Token",
    ),
    "discord_webhook": (
        r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+',
        Severity.HIGH,
        "Discord Webhook URL",
    ),

    # ── Telegram ─────────────────────────────────────────────────────────────
    "telegram_bot_token": (
        r'[0-9]{9}:[a-zA-Z0-9_\-]{35}',
        Severity.CRITICAL,
        "Telegram Bot Token",
    ),

    # ── Twitter / X ──────────────────────────────────────────────────────────
    "twitter_access_token": (
        r'(?i)twitter(.{0,20})[0-9a-z]{35,44}',
        Severity.HIGH,
        "Twitter Access Token",
    ),
    "twitter_bearer_token": (
        r'AAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]+',
        Severity.HIGH,
        "Twitter Bearer Token",
    ),

    # ── Shopify ──────────────────────────────────────────────────────────────
    "shopify_token": (
        r'shpat_[a-fA-F0-9]{32}|shpca_[a-fA-F0-9]{32}|shppa_[a-fA-F0-9]{32}',
        Severity.CRITICAL,
        "Shopify API Token",
    ),

    # ── Artifactory / JFrog ───────────────────────────────────────────────────
    "artifactory_token": (
        r'(?i)AKCp[a-zA-Z0-9]{10,}',
        Severity.HIGH,
        "Artifactory Token",
    ),

    # ── Mapbox ──────────────────────────────────────────────────────────────
    "mapbox_token": (
        r'pk\.eyJ1Ijoi[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+',
        Severity.MEDIUM,
        "Mapbox Public Token",
    ),

    # ── Internal / Sensitive URLs ─────────────────────────────────────────────
    "internal_ip": (
        r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
        Severity.LOW,
        "Internal IP Address",
    ),
    "localhost_endpoint": (
        r'(?i)(https?://(localhost|127\.0\.0\.1|0\.0\.0\.0)(:\d+)?[/\w\-\.]*)',
        Severity.LOW,
        "Localhost Endpoint",
    ),

    # ── Misc sensitive info ────────────────────────────────────────────────────
    "social_security_number": (
        r'\b\d{3}-\d{2}-\d{4}\b',
        Severity.CRITICAL,
        "Possible Social Security Number (SSN)",
    ),
    "email_address": (
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
        Severity.LOW,
        "Email Address",
    ),
    "ipv4_address": (
        r'\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
        Severity.INFO,
        "IPv4 Address",
    ),

    # ═══════════════════════════════════════════════════════════════════════════
    # ADVANCED PATTERNS — White-Hat Professional Edition
    # Added by: https://github.com/Xnuvers007/SecretFinder
    # ═══════════════════════════════════════════════════════════════════════════

    # ── AI / LLM APIs ─────────────────────────────────────────────────────────
    "openai_api_key": (
        r'sk-[A-Za-z0-9]{48}|sk-proj-[A-Za-z0-9\-_]{90,}',
        Severity.CRITICAL,
        "OpenAI API Key",
    ),
    "openai_org_id": (
        r'org-[A-Za-z0-9]{24}',
        Severity.MEDIUM,
        "OpenAI Organization ID",
    ),
    "anthropic_api_key": (
        r'sk-ant-api\d{2}-[A-Za-z0-9\-_]{93}AA',
        Severity.CRITICAL,
        "Anthropic (Claude) API Key",
    ),
    "huggingface_token": (
        r'hf_[A-Za-z0-9]{37}',
        Severity.HIGH,
        "Hugging Face API Token",
    ),
    "cohere_api_key": (
        r'(?i)(cohere[_\-\s]?(api[_\-\s]?)?key)\s*[=:]\s*["\']?[A-Za-z0-9]{40}["\']?',
        Severity.HIGH,
        "Cohere API Key",
    ),
    "replicate_api_token": (
        r'r8_[A-Za-z0-9]{40}',
        Severity.HIGH,
        "Replicate API Token",
    ),

    # ── Cloud Provider — Azure extended ──────────────────────────────────────
    "azure_client_secret": (
        r'(?i)(azure|az)[_\-\s]?(client[_\-\s]?secret)\s*[=:]\s*["\']?[A-Za-z0-9~.\-_]{34,}["\']?',
        Severity.CRITICAL,
        "Azure Client Secret",
    ),
    "azure_tenant_id": (
        r'(?i)(azure|az)[_\-\s]?(tenant[_\-\s]?id)\s*[=:]\s*["\']?[0-9a-f\-]{36}["\']?',
        Severity.MEDIUM,
        "Azure Tenant ID",
    ),
    "azure_devops_pat": (
        r'(?i)(azure|ado|devops)[_\-\s]?token\s*[=:]\s*["\']?[A-Za-z0-9]{52}["\']?',
        Severity.CRITICAL,
        "Azure DevOps Personal Access Token",
    ),

    # ── Cloud Provider — GCP extended ────────────────────────────────────────
    "gcp_service_account": (
        r'"type"\s*:\s*"service_account"',
        Severity.CRITICAL,
        "GCP Service Account JSON",
    ),
    "gcp_private_key_id": (
        r'"private_key_id"\s*:\s*"[a-f0-9]{40}"',
        Severity.CRITICAL,
        "GCP Private Key ID",
    ),

    # ── CI/CD Secrets ─────────────────────────────────────────────────────────
    "jenkins_api_token": (
        r'(?i)jenkins[_\-\s]?(api[_\-\s]?)?token\s*[=:]\s*["\']?[A-Za-z0-9]{32,}["\']?',
        Severity.HIGH,
        "Jenkins API Token",
    ),
    "circleci_token": (
        r'(?i)circle[_\-\s]?ci[_\-\s]?token\s*[=:]\s*["\']?[A-Za-z0-9]{40}["\']?',
        Severity.HIGH,
        "CircleCI API Token",
    ),
    "travis_ci_token": (
        r'(?i)travis[_\-\s]?(ci[_\-\s]?)?token\s*[=:]\s*["\']?[A-Za-z0-9]{22}["\']?',
        Severity.HIGH,
        "Travis CI Token",
    ),
    "github_actions_secret": (
        r'(?i)(GITHUB_TOKEN|GH_TOKEN|ACTIONS_RUNTIME_TOKEN)\s*[=:]\s*[A-Za-z0-9_\-\.]{20,}',
        Severity.CRITICAL,
        "GitHub Actions Token",
    ),

    # ── HashiCorp Vault / Consul ──────────────────────────────────────────────
    "hashicorp_vault_token": (
        r'(?i)(vault[_\-\s]?token|VAULT_TOKEN)\s*[=:]\s*["\']?(hvs|s)\.[A-Za-z0-9\-_\.]{20,}["\']?',
        Severity.CRITICAL,
        "HashiCorp Vault Token",
    ),
    "consul_token": (
        r'(?i)(consul[_\-\s]?token|CONSUL_TOKEN)\s*[=:]\s*["\']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["\']?',
        Severity.HIGH,
        "HashiCorp Consul Token",
    ),

    # ── Kubernetes ───────────────────────────────────────────────────────────
    "kubernetes_service_account_token": (
        r'(?i)(kube[_\-\s]?token|k8s[_\-\s]?token|KUBERNETES_TOKEN)\s*[=:]\s*["\']?ey[A-Za-z0-9_\-]{50,}["\']?',
        Severity.CRITICAL,
        "Kubernetes Service Account Token",
    ),
    "kubernetes_secret_manifest": (
        r'kind:\s*Secret[\s\S]{0,200}data:',
        Severity.HIGH,
        "Kubernetes Secret Manifest",
    ),

    # ── Cloudflare ───────────────────────────────────────────────────────────
    "cloudflare_api_token": (
        r'(?i)(cloudflare[_\-\s]?(api[_\-\s]?)?token)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{40}["\']?',
        Severity.CRITICAL,
        "Cloudflare API Token",
    ),
    "cloudflare_api_key": (
        r'(?i)(cloudflare[_\-\s]?(api[_\-\s]?)?key|CF_API_KEY)\s*[=:]\s*["\']?[A-Za-z0-9]{37}["\']?',
        Severity.CRITICAL,
        "Cloudflare Global API Key",
    ),
    "cloudflare_origin_ca": (
        r'v1\.0-[A-Za-z0-9]{152}',
        Severity.HIGH,
        "Cloudflare Origin CA Key",
    ),

    # ── Payment / Fintech ─────────────────────────────────────────────────────
    "razorpay_key": (
        r'rzp_(?:live|test)_[A-Za-z0-9]{14}',
        Severity.CRITICAL,
        "Razorpay API Key",
    ),
    "adyen_api_key": (
        r'AQE[a-zA-Z0-9+/]{60,}',
        Severity.CRITICAL,
        "Adyen API Key",
    ),
    "plaid_secret": (
        r'(?i)(plaid[_\-\s]?secret|plaid[_\-\s]?client[_\-\s]?id)\s*[=:]\s*["\']?[a-z0-9]{30,}["\']?',
        Severity.CRITICAL,
        "Plaid API Secret",
    ),

    # ── Social / Productivity ─────────────────────────────────────────────────
    "linear_api_key": (
        r'lin_api_[A-Za-z0-9]{40}',
        Severity.HIGH,
        "Linear API Key",
    ),
    "notion_token": (
        r'secret_[A-Za-z0-9]{43}',
        Severity.HIGH,
        "Notion Integration Token",
    ),
    "airtable_api_key": (
        r'(?i)(airtable[_\-\s]?(api[_\-\s]?)?key|pat[A-Za-z0-9]{14}\.[A-Za-z0-9]{64})',
        Severity.HIGH,
        "Airtable API Key",
    ),
    "asana_token": (
        r'(?i)(asana[_\-\s]?token)\s*[=:]\s*["\']?[0-9]{16}["\']?',
        Severity.HIGH,
        "Asana Personal Access Token",
    ),
    "zendesk_token": (
        r'(?i)(zendesk[_\-\s]?token|zendesk[_\-\s]?api[_\-\s]?key)\s*[=:]\s*["\']?[A-Za-z0-9]{40}["\']?',
        Severity.HIGH,
        "Zendesk API Token",
    ),
    "jira_api_token": (
        r'(?i)(jira[_\-\s]?token|atlassian[_\-\s]?token)\s*[=:]\s*["\']?[A-Za-z0-9]{24}["\']?',
        Severity.HIGH,
        "Jira/Atlassian API Token",
    ),

    # ── Sensitive Endpoints / Recon (White-Hat) ───────────────────────────────
    "admin_panel_url": (
        r'(?i)https?://[^\s\'"<>]+/(admin|administrator|wp-admin|cpanel|phpmyadmin|manager|dashboard)[^\s\'"<>]*',
        Severity.MEDIUM,
        "Admin Panel URL",
    ),
    "api_endpoint_versioned": (
        r'(?i)https?://[^\s\'"<>]+/api/v[0-9]+[^\s\'"<>]*',
        Severity.LOW,
        "Versioned API Endpoint",
    ),
    "swagger_openapi_endpoint": (
        r'(?i)https?://[^\s\'"<>]+/(swagger|openapi|api-docs|redoc)[^\s\'"<>]*',
        Severity.MEDIUM,
        "Swagger / OpenAPI Docs Endpoint",
    ),
    "debug_endpoint": (
        r'(?i)https?://[^\s\'"<>]+/(debug|test|dev|staging|qa|uat|sandbox)[^\s\'"<>]*',
        Severity.MEDIUM,
        "Debug / Test Endpoint",
    ),
    "graphql_endpoint": (
        r'(?i)(https?://[^\s\'"<>]+/graphql[^\s\'"<>]*|__schema|__typename|IntrospectionQuery)',
        Severity.MEDIUM,
        "GraphQL Endpoint / Introspection",
    ),
    "metrics_endpoint": (
        r'(?i)https?://[^\s\'"<>]+/(metrics|healthz|health|readyz|livez|status)[^\s\'"<>]*',
        Severity.LOW,
        "Metrics / Health Endpoint",
    ),
    "s3_presigned_url": (
        r'https://[a-zA-Z0-9\-\.]+\.s3\.[a-z0-9\-]+\.amazonaws\.com/[^\s\'"<>]+\?[^\s\'"<>]*X-Amz-Signature=[^\s\'"<>]+',
        Severity.HIGH,
        "AWS S3 Pre-Signed URL",
    ),

    # ── Environment Variable Leaks ────────────────────────────────────────────
    "process_env_leak": (
        r'process\.env\.[A-Z_]{5,}',
        Severity.MEDIUM,
        "Node.js process.env Variable Reference",
    ),
    "env_file_var": (
        r'(?m)^[A-Z_]{4,}\s*=\s*[^\s#]{4,}',
        Severity.HIGH,
        "Possible .env File Variable",
    ),
    "dotenv_assignment": (
        r'(?i)(SECRET|TOKEN|KEY|PASSWORD|PASS|PWD|AUTH|CREDENTIAL)\s*=\s*[^\s\n\r]{6,}',
        Severity.HIGH,
        "Dotenv-style Secret Assignment",
    ),

    # ── Source Map / Debug Artifacts ──────────────────────────────────────────
    "source_map_reference": (
        r'//# sourceMappingURL=.+\.map',
        Severity.LOW,
        "Source Map Reference (may expose original source)",
    ),
    "webpack_source_map": (
        r'webpack://[^\s\'"<>]+',
        Severity.LOW,
        "Webpack Source Map Path",
    ),

    # ── Firebase / Firestore config ───────────────────────────────────────────
    "firebase_config_object": (
        r'(?i)(apiKey|authDomain|databaseURL|projectId|storageBucket|messagingSenderId)\s*:\s*["\'][^\'"]{5,}["\']',
        Severity.MEDIUM,
        "Firebase Config Property",
    ),
    "firestore_database_url": (
        r'https://[a-zA-Z0-9\-]+\.firebaseio\.com',
        Severity.MEDIUM,
        "Firebase Realtime Database URL",
    ),

    # ── Crypto / Blockchain ───────────────────────────────────────────────────
    "ethereum_private_key": (
        r'(?i)(eth[_\-\s]?private[_\-\s]?key|PRIVATE_KEY)\s*[=:]\s*["\']?0x[a-fA-F0-9]{64}["\']?',
        Severity.CRITICAL,
        "Ethereum Private Key",
    ),
    "mnemonic_phrase": (
        r'(?i)(mnemonic|seed[_\-\s]?phrase)\s*[=:]\s*["\']?([a-z]+\s){11,23}[a-z]+["\']?',
        Severity.CRITICAL,
        "Cryptocurrency Mnemonic Phrase",
    ),
    "bitcoin_private_key_wif": (
        r'[5KL][1-9A-HJ-NP-Za-km-z]{51}',
        Severity.CRITICAL,
        "Bitcoin Private Key (WIF format)",
    ),

    # ── Database extended ─────────────────────────────────────────────────────
    "elasticsearch_url": (
        r'(?i)https?://[^\s\'"<>]+:[0-9]{4,5}/[_a-zA-Z][^\s\'"<>]*\?pretty',
        Severity.HIGH,
        "Elasticsearch Endpoint",
    ),
    "redis_url_with_auth": (
        r'redis://:[^\s@]+@[^\s\'"<>]+:[0-9]{4,5}',
        Severity.CRITICAL,
        "Redis URL with Password",
    ),
    "mongodb_srv": (
        r'mongodb\+srv://[^:]+:[^@]+@[^\s\'"<>]+',
        Severity.CRITICAL,
        "MongoDB SRV Connection String",
    ),
    "postgresql_dsn": (
        r'postgres(?:ql)?://[^:]+:[^@]+@[^\s\'"<>]+/[^\s\'"<>]+',
        Severity.CRITICAL,
        "PostgreSQL DSN with Credentials",
    ),

    # ── Misc Tokens / Secrets ─────────────────────────────────────────────────
    "generic_secret_assignment": (
        r'(?i)["\']?(access_token|auth_token|api_secret|app_key|secret_token)["\']?\s*[=:]\s*["\'][A-Za-z0-9_\-\.]{20,}["\']',
        Severity.HIGH,
        "Generic Secret Token Assignment",
    ),
    "base64_encoded_secret": (
        r'(?i)(secret|password|key|token)\s*[=:]\s*["\']?(?:[A-Za-z0-9+/]{40,}={0,2})["\']?',
        Severity.HIGH,
        "Possible Base64-Encoded Secret",
    ),
    "private_ip_in_code": (
        r'(?i)(host|hostname|server|endpoint|backend|origin)\s*[=:]\s*["\']?(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(:[0-9]{2,5})?["\']?',
        Severity.MEDIUM,
        "Private IP Hardcoded in Source",
    ),
    "sensitive_comment": (
        r'(?i)//\s*(todo|fixme|hack|bug|xxx|password|secret|token|key|auth|credential)[^\n]{0,100}',
        Severity.LOW,
        "Sensitive Comment in Code",
    ),

    "docs_file_extension": (
        r'(?i)\.(xlsx|xlsm|xlsb|xls|csv|xml|mht|mhtml|html|htm|xltx|xltm|xlt|txt|prn|dif|slk|xlam|xla|pdf|xps|ods|docx|docm|doc|dotx|dotm|dot|rtf|odt)',
        Severity.LOW,
        "Sensitive Document File Extension",
    ),
    "bitcoin_address": (
        r'\b[13][a-km-zA-HJ-NP-Z0-9]{26,33}\b',
        Severity.MEDIUM,
        "Bitcoin Address",
    ),
    "zipcode_us_cn": (
        r'\b\d{5}(-\d{4})?\b|\b[ABCEGHJKLMNPRSTVXY]\d[A-Z] *\d[A-Z]\d\b',
        Severity.INFO,
        "US/CN Zip Code",
    ),
    "google_cloud_platform_auth": (
        r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b',
        Severity.HIGH,
        "GCP Auth Token / UUID",
    ),
    "google_cloud_platform_api": (
        r'\b[A-Za-z0-9_]{21}--[A-Za-z0-9_]{8}\b',
        Severity.HIGH,
        "GCP API Token",
    ),
    "instagram_token": (
        r'\b[0-9a-fA-F]{7}\.[0-9a-fA-F]{32}\b',
        Severity.HIGH,
        "Instagram Access Token",
    ),
    "gmail_auth_token_v2": (
        r'[0-9]{12}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
        Severity.MEDIUM,
        "Gmail Client ID / Auth Token",
    ),
    "global_postal_code": (
        r'\b\d{5}(?:[-\s]\d{4})?\b|\b[A-Z]\d[A-Z]\s?\d[A-Z]\d\b|\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b|\b\d{3}-\d{4}\b|\b\d{4,6}\b',
        Severity.INFO,
        "Global Postal/Zip Code",
    ),
}


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH:     1,
    Severity.MEDIUM:   2,
    Severity.LOW:      3,
    Severity.INFO:     4,
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "\033[91m",   # bright red
    Severity.HIGH:     "\033[31m",   # red
    Severity.MEDIUM:   "\033[33m",   # yellow
    Severity.LOW:      "\033[34m",   # blue
    Severity.INFO:     "\033[37m",   # white/grey
}

SEVERITY_HTML_COLORS = {
    Severity.CRITICAL: "#ff4d4d",
    Severity.HIGH:     "#ff8c00",
    Severity.MEDIUM:   "#ffd700",
    Severity.LOW:      "#00bcd4",
    Severity.INFO:     "#9e9e9e",
}
