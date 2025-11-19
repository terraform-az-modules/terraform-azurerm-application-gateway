##-----------------------------------------------------------------------------
## Variables
##-----------------------------------------------------------------------------
variable "label_order" {
  type        = list(any)
  default     = ["name", "environment", "location"]
  description = "Label order, e.g. `name`,`application`,`centralus`."
}

variable "resource_group_name" {
  type        = string
  default     = ""
  description = "Name of the resource group"
}

variable "location" {
  type        = string
  default     = ""
  description = "The location/region to keep all your network resources."
}

variable "enable_http2" {
  type        = bool
  default     = false
  description = "Is HTTP2 enabled on the application gateway resource?"
}

variable "custom_name" {
  type        = string
  default     = null
  description = "Define your custom name to override default naming convention"
}

variable "resource_position_prefix" {
  type        = bool
  default     = true
  description = <<EOT
Controls the placement of the resource type keyword (e.g., "vnet", "ddospp") in the resource name.

- If true, the keyword is prepended: "vnet-core-dev".
- If false, the keyword is appended: "core-dev-vnet".

This helps maintain naming consistency based on organizational preferences.
EOT
}

variable "extra_tags" {
  type        = map(string)
  default     = null
  description = "Additional tags (e.g. map(`BusinessUnit`,`XYZ`)."
}

variable "deployment_mode" {
  type        = string
  default     = "terraform"
  description = "Specifies how the infrastructure/resource is deployed"
}

variable "zones" {
  type        = list(string)
  default     = [] #["1", "2", "3"]
  description = "A collection of availability zones"
}

variable "firewall_policy_id" {
  type        = string
  default     = null
  description = "The ID of the Web Application Firewall Policy"
}

variable "sku" {
  type = object({
    name     = string
    tier     = string
    capacity = optional(number)
  })
  description = "The sku pricing model of v1 and v2"
}

variable "autoscale_configuration" {
  type = object({
    min_capacity = number
    max_capacity = optional(number)
  })
  default     = null
  description = "Minimum or Maximum capacity for autoscaling"
}

variable "external_waf_enabled" {
  description = "Indicates if an external WAF is provided"
  type        = bool
  default     = false
}

variable "backend_address_pools" {
  type = list(object({
    name         = optional(string)
    fqdns        = optional(list(string))
    ip_addresses = optional(list(string))
  }))
  description = "List of backend address pools"
  default     = []
}


variable "backend_http_settings" {
  type = list(object({
    name                                = string
    cookie_based_affinity               = string
    affinity_cookie_name                = optional(string)
    path                                = optional(string)
    enable_https                        = bool
    probe_name                          = optional(string)
    request_timeout                     = number
    port                                = optional(number)
    host_name                           = optional(string)
    pick_host_name_from_backend_address = optional(bool)
    authentication_certificate = optional(object({
      name = string
    }))
    trusted_root_certificate_names = optional(list(string))
    connection_draining = optional(object({
      enable_connection_draining = bool
      drain_timeout_sec          = number
    }))
  }))
  description = "List of backend HTTP settings."
}

variable "http_listeners" {
  type = list(object({
    name                 = string
    host_name            = optional(string)
    frontend_port_name   = optional(string)
    host_names           = optional(list(string))
    require_sni          = optional(bool)
    ssl_certificate_name = optional(string)
    firewall_policy_id   = optional(string)
    ssl_profile_name     = optional(string)
    custom_error_configuration = optional(list(object({
      status_code           = string
      custom_error_page_url = string
    })))
  }))
  description = "List of HTTP/HTTPS listeners. SSL Certificate name is required"
}

variable "request_routing_rules" {
  type = list(object({
    name                        = string
    rule_type                   = string
    http_listener_name          = string
    backend_address_pool_name   = optional(string)
    backend_http_settings_name  = optional(string)
    redirect_configuration_name = optional(string)
    rewrite_rule_set_name       = optional(string)
    url_path_map_name           = optional(string)
    priority                    = number
  }))
  default     = []
  description = "List of Request routing rules to be used for listeners."
}

variable "authentication_certificates" {
  type = list(object({
    name = string
    data = string
  }))
  default     = []
  description = "Authentication certificates to allow the backend with Azure Application Gateway"
}

variable "trusted_root_certificates" {
  type = list(object({
    name = string
    data = string
  }))
  default     = []
  description = "Trusted root certificates to allow the backend with Azure Application Gateway"
}

variable "ssl_policy" {
  type = object({
    disabled_protocols   = optional(list(string))
    policy_type          = optional(string)
    policy_name          = optional(string)
    cipher_suites        = optional(list(string))
    min_protocol_version = optional(string)
  })
  default     = null
  description = "Application Gateway SSL configuration"
}

variable "ssl_certificates" {
  type = list(object({
    name                = string
    data                = optional(string)
    password            = optional(string)
    key_vault_secret_id = optional(string)
  }))
  default     = []
  description = "List of SSL certificates data for Application gateway"
}

variable "identity_ids" {
  type        = set(string)
  default     = null
  description = "Specifies a list with a single user managed identity id to be assigned to the Application Gateway"
}

variable "health_probes" {
  type = list(object({
    name                                      = string
    host                                      = string
    interval                                  = number
    path                                      = string
    timeout                                   = number
    unhealthy_threshold                       = number
    port                                      = optional(number)
    pick_host_name_from_backend_http_settings = optional(bool)
    minimum_servers                           = optional(number)
    match = optional(object({
      body        = optional(string)
      status_code = optional(list(string))
    }))
  }))
  default     = []
  description = "List of Health probes used to test backend pools health."
}

variable "url_path_maps" {
  type = list(object({
    name                                = string
    default_backend_http_settings_name  = optional(string)
    default_backend_address_pool_name   = optional(string)
    default_redirect_configuration_name = optional(string)
    default_rewrite_rule_set_name       = optional(string)
    path_rules = list(object({
      name                        = string
      backend_address_pool_name   = optional(string)
      backend_http_settings_name  = optional(string)
      paths                       = list(string)
      redirect_configuration_name = optional(string)
      rewrite_rule_set_name       = optional(string)
      firewall_policy_id          = optional(string)
    }))
  }))
  default     = []
  description = "List of URL path maps associated to path-based rules."
}

variable "redirect_configuration" {
  type        = list(map(string))
  default     = []
  description = "list of maps for redirect configurations"
}

variable "custom_error_configuration" {
  type        = list(map(string))
  default     = []
  description = "Global level custom error configuration for application gateway"
}

variable "rewrite_rule_set" {
  type        = any
  default     = []
  description = "List of rewrite rule set including rewrite rules"
}


variable "name" {
  type        = string
  default     = ""
  description = "Name  (e.g. `app` or `cluster`)."
}

variable "environment" {
  type        = string
  default     = "dev"
  description = "Environment (e.g. `prod`, `dev`, `staging`)."
}

variable "repository" {
  type        = string
  default     = ""
  description = "Terraform current module repo"
}

variable "managedby" {
  type        = string
  default     = ""
  description = "ManagedBy, eg ''."
}

variable "subnet_id" {
  description = "Id of the subnet to deploy Application Gateway."
  type        = string
  default     = null
}

variable "frontend_port_settings" {
  type = list(object({
    name = string
    port = number
  }))
  description = "Frontend port settings. Each port setting contains the name and the port for the frontend port."
}

variable "enable_private_endpoint" {
  type        = bool
  default     = false
  description = "Boolean to enable private endpoint for Function App"
}

variable "private_endpoint_subnet_id" {
  type        = string
  default     = ""
  description = "Subnet ID for private endpoint"
}

variable "existing_private_dns_zone" {
  type        = string
  default     = null
  description = "value of existing private dns zone"
}

variable "diff_sub" {
  type        = bool
  default     = false
  description = "Flag to tell whether dns zone is in different sub or not."
}

variable "appgw_private" {
  type        = bool
  default     = false
  description = "Boolean variable to create a private Application Gateway. When `true`, the default http listener will listen on private IP instead of the public IP."
}

variable "appgw_private_ip_addr" {
  type        = string
  default     = null
  description = "Private IP for Application Gateway. Used when variable `appgw_private` is set to `true`."
}

variable "pvt_ip_subnet_id" {
  type        = string
  default     = null
  description = "Id of the subnet to deploy Application Gateway."
}

variable "frontend_ip_configuration_name" {
  type        = string
  default     = null
  description = "Frontend ip configuration name"
}

variable "frontend_priv_ip_configuration_name" {
  type        = string
  default     = null
  description = "Frontend private ip configuration name"
}

variable "private_dns_zone_ids" {
  type        = string
  default     = null
  description = "The ID of the private DNS zone."
}

# Private link configuration
variable "enable_private_link_configuration" {
  type        = bool
  default     = false
  description = "Set to true to enable private link configuration for Application Gateway."
}

variable "private_link_configuration" {
  type = list(object({
    name = string
    ip_configuration = object({
      name                          = string
      primary                       = bool
      private_ip_address_allocation = string
      subnet_id                     = string
    })
  }))
  default     = []
  description = "List of private link configurations for Application Gateway."
}

variable "request_body_inspect_limit_in_kb" {
  type        = number
  default     = 128
  description = "The maximum request body inspection size in KB for the policy."

  validation {
    condition     = var.request_body_inspect_limit_in_kb >= 8 && var.request_body_inspect_limit_in_kb <= 2000
    error_message = "The request body inspection limit must be between 8 and 2000 KB."
  }
}

variable "max_request_body_size_in_kb" {
  type        = number
  default     = 128
  description = "The maximum request body size in KB for the policy."

  validation {
    condition     = var.max_request_body_size_in_kb >= 8 && var.max_request_body_size_in_kb <= 2000
    error_message = "The request body size must be between 8 and 2000 KB."
  }
}

variable "file_upload_limit_in_mb" {
  type        = number
  default     = 100
  description = "The maximum file upload size in MB for the policy."

  validation {
    condition     = var.file_upload_limit_in_mb >= 1 && var.file_upload_limit_in_mb <= 4000
    error_message = "The file upload limit must be between 1 and 4000 MB."
  }
}


variable "managed_rule_exclusions" {
  type = list(object({
    match_variable          = string
    selector_match_operator = string
    selector                = string
    rule_set = optional(object({
      type = string
      rule_groups = optional(list(object({
        rule_group_name = string
        excluded_rules  = list(number)
      })), [])
    }))
  }))
  default     = []
  description = "A mapping of managed rule exclusions to associate with the policy."

  validation {
    condition = alltrue([for exclusion in var.managed_rule_exclusions : contains([
      "RequestArgKeys", "RequestArgNames", "RequestArgValues",
      "RequestCookieKeys", "RequestCookieNames", "RequestCookieValues",
      "RequestHeaderKeys", "RequestHeaderNames", "RequestHeaderValues"
    ], exclusion.match_variable)])
    error_message = "All managed rule exclusion match variables must be RequestArgKeys, RequestArgNames, RequestArgValues, RequestCookieKeys, RequestCookieNames, RequestCookieValues, RequestHeaderKeys, RequestHeaderNames or RequestHeaderValues."
  }

  validation {
    condition     = alltrue([for exclusion in var.managed_rule_exclusions : contains(["Contains", "EndsWith", "Equals", "EqualsAny", "StartsWith"], exclusion.selector_match_operator)])
    error_message = "All managed rule exclusion selector match operators must be Contains, EndsWith, Equals, EqualsAny or StartsWith."
  }

  validation {
    condition     = alltrue([for exclusion in var.managed_rule_exclusions : contains(["OWASP", "Microsoft_DefaultRuleSet"], exclusion.rule_set.type) if exclusion.rule_set != null])
    error_message = "All managed rule exclusion rule set types must be OWASP or Microsoft_DefaultRuleSet."
  }

  validation {
    condition = alltrue([for exclusion in var.managed_rule_exclusions :
      alltrue([for rule_group in exclusion.rule_set.rule_groups :
        contains([
          "BadBots", "crs_20_protocol_violations", "crs_21_protocol_anomalies", "crs_23_request_limits", "crs_30_http_policy", "crs_35_bad_robots",
          "crs_40_generic_attacks", "crs_41_sql_injection_attacks", "crs_41_xss_attacks", "crs_42_tight_security", "crs_45_trojans", "crs_49_inbound_blocking",
          "General", "GoodBots", "KnownBadBots", "Known-CVEs", "REQUEST-911-METHOD-ENFORCEMENT", "REQUEST-913-SCANNER-DETECTION", "REQUEST-920-PROTOCOL-ENFORCEMENT",
          "REQUEST-921-PROTOCOL-ATTACK", "REQUEST-930-APPLICATION-ATTACK-LFI", "REQUEST-931-APPLICATION-ATTACK-RFI", "REQUEST-932-APPLICATION-ATTACK-RCE",
          "REQUEST-933-APPLICATION-ATTACK-PHP", "REQUEST-941-APPLICATION-ATTACK-XSS", "REQUEST-942-APPLICATION-ATTACK-SQLI", "REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION",
          "REQUEST-944-APPLICATION-ATTACK-JAVA", "UnknownBots", "METHOD-ENFORCEMENT", "PROTOCOL-ENFORCEMENT", "PROTOCOL-ATTACK", "LFI", "RFI", "RCE", "PHP", "NODEJS", "XSS",
          "SQLI", "FIX", "JAVA", "MS-ThreatIntel-WebShells", "MS-ThreatIntel-AppSec", "MS-ThreatIntel-SQLI", "MS-ThreatIntel-CVEs", "MS-ThreatIntel-AppSec", "MS-ThreatIntel-SQLI",
          "MS-ThreatIntel-CVEs"
        ], rule_group.rule_group_name)
    ]) if exclusion.rule_set != null])
    error_message = "All managed rule exclusion rule group names must be BadBots, crs_20_protocol_violations, crs_21_protocol_anomalies, crs_23_request_limits, crs_30_http_policy, crs_35_bad_robots, crs_40_generic_attacks, crs_41_sql_injection_attacks, crs_41_xss_attacks, crs_42_tight_security, crs_45_trojans, crs_49_inbound_blocking, General, GoodBots, KnownBadBots, Known-CVEs, REQUEST-911-METHOD-ENFORCEMENT, REQUEST-913-SCANNER-DETECTION, REQUEST-920-PROTOCOL-ENFORCEMENT, REQUEST-921-PROTOCOL-ATTACK, REQUEST-930-APPLICATION-ATTACK-LFI, REQUEST-931-APPLICATION-ATTACK-RFI, REQUEST-932-APPLICATION-ATTACK-RCE, REQUEST-933-APPLICATION-ATTACK-PHP, REQUEST-941-APPLICATION-ATTACK-XSS, REQUEST-942-APPLICATION-ATTACK-SQLI, REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION, REQUEST-944-APPLICATION-ATTACK-JAVA, UnknownBots, METHOD-ENFORCEMENT, PROTOCOL-ENFORCEMENT, PROTOCOL-ATTACK, LFI, RFI, RCE, PHP, NODEJS, XSS, SQLI, FIX, JAVA, MS-ThreatIntel-WebShells, MS-ThreatIntel-AppSec, MS-ThreatIntel-SQLI, MS-ThreatIntel-CVEs, MS-ThreatIntel-AppSec, MS-ThreatIntel-SQLI and MS-ThreatIntel-CVEs"
  }

  validation {
    condition = alltrue([for exclusion in var.managed_rule_exclusions :
      alltrue([for rule_group in exclusion.rule_set.rule_groups :
        alltrue([for rule in rule_group.excluded_rules :
          can(regex("^[0-9]{6}$", tonumber(rule)))
        ])
      ]) if exclusion.rule_set != null]
    )
    error_message = "All managed rule exclusion rules must be 6-digit numbers."
  }
}

variable "enabled" {
  type        = bool
  default     = true
  description = "Set to false to prevent the module from creating any resources."
}

variable "enable_diagnostic" {
  type        = bool
  default     = false
  description = "Set to false to prevent the module from creating the diagnostic setting for the NSG Resource.."
}

variable "workspace_id" {
  type        = string
  default     = null
  description = "log analytics workspace id to pass it to destination details of diagnostic setting of NSG."
}

variable "instance_count" {
  type        = number
  default     = 1
  description = "No. of instance count for resource deployed"
}

variable "gateway_ip_configuration_name" {
  type        = string
  default     = "appgw-gwipc"
  description = "Gateway ip configuration name"
}

variable "metric_enabled" {
  type        = bool
  default     = true
  description = "Boolean flag to specify whether Metrics should be enabled for the Application Gateway. Defaults to true."
}

variable "appgw_logs" {
  type = object({
    enabled        = bool
    category       = optional(list(string))
    category_group = optional(list(string))
  })

  default = {
    enabled  = true
    category = ["ApplicationGatewayAccessLog", "ApplicationGatewayPerformanceLog", "ApplicationGatewayFirewallLog"]
  }
  description = "values for Application gateway logs. The `category` attribute is optional and can be used to specify which categories of logs to enable. If not specified, all categories will be enabled."
}
