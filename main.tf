##-----------------------------------------------------------------------------
## Resources
##-----------------------------------------------------------------------------

module "labels" {
  source          = "terraform-az-modules/tags/azurerm"
#   version         = "1.0.0"
  name            = var.custom_name == null ? var.name : var.custom_name
  location        = var.location
  environment     = var.environment
  managedby       = var.managedby
  label_order     = var.label_order
  repository      = var.repository
  deployment_mode = var.deployment_mode
  extra_tags      = var.extra_tags
}

##----------------------------------------------------------------------------- 
## Below Resource will create public ip
##-----------------------------------------------------------------------------
resource "azurerm_public_ip" "pip" {
  count               = var.enabled ? 1 : 0
  name                = var.resource_position_prefix ? format("pip-appgw-%s-%s", local.name, var.instance_count) : format("%s-pip-appgw-%s", local.name, var.instance_count)
  location            = local.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"   # WAF_v2 requires Static IPs for Standard SKU
  sku                 = "Standard" # Explicitly setting Standard SKU for WAF_v2
  tags                = module.labels.tags
}

##----------------------------------------------------------------------------- 
## Application Gateway Resource
##-----------------------------------------------------------------------------
resource "azurerm_application_gateway" "main" {
  count               = var.enabled ? 1 : 0
  name                = var.resource_position_prefix ? format("appgw-%s", local.name) : format("%s-appgw", local.name )
  resource_group_name = var.resource_group_name
  location            = local.location
  enable_http2        = var.enable_http2
  zones               = var.zones
  firewall_policy_id  = var.firewall_policy_id != null ? var.firewall_policy_id : null
  tags                = module.labels.tags


  sku {
    name     = local.sku_name
    tier     = local.sku_tier
    capacity = var.autoscale_configuration == null ? var.sku.capacity : null
  }

  dynamic "autoscale_configuration" {
    for_each = var.autoscale_configuration != null ? [var.autoscale_configuration] : []
    content {
      min_capacity = lookup(autoscale_configuration.value, "min_capacity")
      max_capacity = lookup(autoscale_configuration.value, "max_capacity")
    }
  }

  # Private Link Configuration
  dynamic "private_link_configuration" {
    for_each = var.enable_private_link_configuration ? var.private_link_configuration : []
    content {
      name = private_link_configuration.value.name

      ip_configuration {
        name                          = private_link_configuration.value.ip_configuration.name
        primary                       = private_link_configuration.value.ip_configuration.primary
        private_ip_address_allocation = private_link_configuration.value.ip_configuration.private_ip_address_allocation
        subnet_id                     = private_link_configuration.value.ip_configuration.subnet_id
      }
    }
  }

  gateway_ip_configuration {
    name      = var.gateway_ip_configuration_name
    subnet_id = local.subnet_id
  }


  frontend_ip_configuration {
    name                 = var.frontend_ip_configuration_name
    public_ip_address_id = azurerm_public_ip.pip[0].id
  }

  dynamic "frontend_ip_configuration" {
    for_each = var.appgw_private ? ["enabled"] : []
    content {
      name                            = var.frontend_priv_ip_configuration_name
      private_ip_address_allocation   = var.appgw_private ? "Static" : null
      private_ip_address              = var.appgw_private ? var.appgw_private_ip_addr : null
      subnet_id                       = var.appgw_private ? var.pvt_ip_subnet_id : null
      private_link_configuration_name = var.appgw_private ? local.private_link_configuration_name : null
    }
  }


  dynamic "frontend_port" {
    for_each = var.frontend_port_settings
    content {
      name = frontend_port.value.name
      port = frontend_port.value.port
    }
  }

  dynamic "backend_address_pool" {
    for_each = var.backend_address_pools
    content {
      name         = backend_address_pool.value.name
      fqdns        = backend_address_pool.value.fqdns
      ip_addresses = backend_address_pool.value.ip_addresses
    }
  }


  dynamic "backend_http_settings" {
    for_each = var.backend_http_settings
    content {
      name                                = backend_http_settings.value.name
      cookie_based_affinity               = lookup(backend_http_settings.value, "cookie_based_affinity", "Disabled")
      affinity_cookie_name                = lookup(backend_http_settings.value, "affinity_cookie_name", null)
      path                                = lookup(backend_http_settings.value, "path", "/")
      port                                = backend_http_settings.value.enable_https ? lookup(backend_http_settings.value, "port", 443) : lookup(backend_http_settings.value, "port", 80)
      probe_name                          = lookup(backend_http_settings.value, "probe_name", null)
      protocol                            = backend_http_settings.value.enable_https ? "Https" : "Http"
      request_timeout                     = lookup(backend_http_settings.value, "request_timeout", 30)
      host_name                           = backend_http_settings.value.pick_host_name_from_backend_address == false ? lookup(backend_http_settings.value, "host_name") : null
      pick_host_name_from_backend_address = lookup(backend_http_settings.value, "pick_host_name_from_backend_address", false)

      dynamic "authentication_certificate" {
        for_each = backend_http_settings.value.authentication_certificate[*]
        content {
          name = authentication_certificate.value.name
        }
      }

      trusted_root_certificate_names = lookup(backend_http_settings.value, "trusted_root_certificate_names", null)

      dynamic "connection_draining" {
        for_each = backend_http_settings.value.connection_draining[*]
        content {
          enabled           = connection_draining.value.enable_connection_draining
          drain_timeout_sec = connection_draining.value.drain_timeout_sec
        }
      }
    }
  }

  dynamic "http_listener" {
    for_each = var.http_listeners
    content {
      name                           = http_listener.value.name
      frontend_ip_configuration_name = var.appgw_private == true ? var.frontend_priv_ip_configuration_name : var.frontend_ip_configuration_name
      frontend_port_name             = lookup(http_listener.value, "frontend_port_name", null)
      host_name                      = lookup(http_listener.value, "host_name", null)
      host_names                     = lookup(http_listener.value, "host_names", null)
      protocol                       = http_listener.value.ssl_certificate_name == null ? "Http" : "Https"
      require_sni                    = http_listener.value.ssl_certificate_name != null ? http_listener.value.require_sni : null
      ssl_certificate_name           = http_listener.value.ssl_certificate_name
      firewall_policy_id             = http_listener.value.firewall_policy_id
      ssl_profile_name               = http_listener.value.ssl_profile_name

      dynamic "custom_error_configuration" {
        for_each = http_listener.value.custom_error_configuration != null ? lookup(http_listener.value, "custom_error_configuration", {}) : []
        content {
          custom_error_page_url = lookup(custom_error_configuration.value, "custom_error_page_url", null)
          status_code           = lookup(custom_error_configuration.value, "status_code", null)
        }
      }
    }
  }

  dynamic "request_routing_rule" {
    for_each = var.request_routing_rules
    content {
      name                        = request_routing_rule.value.name
      rule_type                   = lookup(request_routing_rule.value, "rule_type", "Basic")
      http_listener_name          = request_routing_rule.value.http_listener_name
      backend_address_pool_name   = request_routing_rule.value.redirect_configuration_name == null ? request_routing_rule.value.backend_address_pool_name : null
      backend_http_settings_name  = request_routing_rule.value.redirect_configuration_name == null ? request_routing_rule.value.backend_http_settings_name : null
      redirect_configuration_name = lookup(request_routing_rule.value, "redirect_configuration_name", null)
      rewrite_rule_set_name       = lookup(request_routing_rule.value, "rewrite_rule_set_name", null)
      url_path_map_name           = lookup(request_routing_rule.value, "url_path_map_name", null)
      priority                    = request_routing_rule.value.priority
    }
  }

  #----------------------------------------------------------
  # Authentication SSL Certificate Configuration (Optional)
  #----------------------------------------------------------
  dynamic "authentication_certificate" {
    for_each = var.authentication_certificates
    content {
      name = authentication_certificate.value.name
      data = filebase64(authentication_certificate.value.data)
    }
  }

  #----------------------------------------------------------
  # Trusted Root SSL Certificate Configuration (Optional)
  #----------------------------------------------------------
  dynamic "trusted_root_certificate" {
    for_each = var.trusted_root_certificates
    content {
      name = trusted_root_certificate.value.name
      data = filebase64(trusted_root_certificate.value.data)
    }
  }

  #----------------------------------------------------------------------------------------------------------------------------------------------------------------------
  # SSL Policy for Application Gateway (Optional)
  # Application Gateway has three predefined security policies to get the appropriate level of security
  # AppGwSslPolicy20150501 - MinProtocolVersion(TLSv1_0), AppGwSslPolicy20170401 - MinProtocolVersion(TLSv1_1), AppGwSslPolicy20170401S - MinProtocolVersion(TLSv1_2)
  #----------------------------------------------------------------------------------------------------------------------------------------------------------------------
  dynamic "ssl_policy" {
    for_each = var.ssl_policy != null ? [var.ssl_policy] : []
    content {
      disabled_protocols   = var.ssl_policy.policy_type == null && var.ssl_policy.policy_name == null ? var.ssl_policy.disabled_protocols : null
      policy_type          = lookup(var.ssl_policy, "policy_type", "Predefined")
      policy_name          = var.ssl_policy.policy_type == "Predefined" ? var.ssl_policy.policy_name : null
      cipher_suites        = var.ssl_policy.policy_type == "Custom" ? var.ssl_policy.cipher_suites : null
      min_protocol_version = var.ssl_policy.min_protocol_version
    }
  }

  dynamic "ssl_certificate" {
    for_each = var.ssl_certificates
    content {
      name                = ssl_certificate.value.name
      data                = ssl_certificate.value.key_vault_secret_id == null ? filebase64(ssl_certificate.value.data) : null
      password            = ssl_certificate.value.key_vault_secret_id == null ? ssl_certificate.value.password : null
      key_vault_secret_id = lookup(ssl_certificate.value, "key_vault_secret_id", null)
    }
  }



  identity {
    type         = "UserAssigned"
    identity_ids = var.identity_ids != null ? var.identity_ids : [azurerm_user_assigned_identity.identity[0].id]
  }

  dynamic "probe" {
    for_each = var.health_probes
    content {
      name                                      = probe.value.name
      host                                      = lookup(probe.value, "host", "127.0.0.1")
      interval                                  = lookup(probe.value, "interval", 30)
      protocol                                  = probe.value.port == 443 ? "Https" : "Http"
      path                                      = lookup(probe.value, "path", "/")
      timeout                                   = lookup(probe.value, "timeout", 30)
      unhealthy_threshold                       = lookup(probe.value, "unhealthy_threshold", 3)
      port                                      = lookup(probe.value, "port", 443)
      pick_host_name_from_backend_http_settings = lookup(probe.value, "pick_host_name_from_backend_http_settings", false)
      minimum_servers                           = lookup(probe.value, "minimum_servers", 0)
      match {
        body        = lookup(probe.value, "match_body", null)
        status_code = lookup(probe.value, "match_status_code", ["200"])
      }
    }
  }

  dynamic "url_path_map" {
    for_each = var.url_path_maps
    content {
      name                                = url_path_map.value.name
      default_backend_address_pool_name   = url_path_map.value.default_redirect_configuration_name == null ? url_path_map.value.default_backend_address_pool_name : null
      default_backend_http_settings_name  = url_path_map.value.default_redirect_configuration_name == null ? url_path_map.value.default_backend_http_settings_name : null
      default_redirect_configuration_name = lookup(url_path_map.value, "default_redirect_configuration_name", null)
      default_rewrite_rule_set_name       = lookup(url_path_map.value, "default_rewrite_rule_set_name", null)

      dynamic "path_rule" {
        for_each = lookup(url_path_map.value, "path_rules")
        content {
          name                        = path_rule.value.name
          backend_address_pool_name   = path_rule.value.backend_address_pool_name
          backend_http_settings_name  = path_rule.value.backend_http_settings_name
          paths                       = flatten(path_rule.value.paths)
          redirect_configuration_name = lookup(path_rule.value, "redirect_configuration_name", null)
          rewrite_rule_set_name       = lookup(path_rule.value, "rewrite_rule_set_name", null)
          firewall_policy_id          = lookup(path_rule.value, "firewall_policy_id", null)
        }
      }
    }
  }

  dynamic "redirect_configuration" {
    for_each = var.redirect_configuration
    content {
      name                 = lookup(redirect_configuration.value, "name", null)
      redirect_type        = lookup(redirect_configuration.value, "redirect_type", "Permanent")
      target_listener_name = lookup(redirect_configuration.value, "target_listener_name", null)
      target_url           = lookup(redirect_configuration.value, "target_url", null)
      include_path         = lookup(redirect_configuration.value, "include_path", "true")
      include_query_string = lookup(redirect_configuration.value, "include_query_string", "true")
    }
  }

  dynamic "custom_error_configuration" {
    for_each = var.custom_error_configuration
    content {
      custom_error_page_url = lookup(custom_error_configuration.value, "custom_error_page_url", null)
      status_code           = lookup(custom_error_configuration.value, "status_code", null)
    }
  }

  dynamic "rewrite_rule_set" {
    for_each = var.rewrite_rule_set
    content {
      name = var.rewrite_rule_set.name

      dynamic "rewrite_rule" {
        for_each = lookup(var.rewrite_rule_set, "rewrite_rules", [])
        content {
          name          = rewrite_rule.value.name
          rule_sequence = rewrite_rule.value.rule_sequence

          dynamic "condition" {
            for_each = lookup(rewrite_rule_set.value, "condition", [])
            content {
              variable    = condition.value.variable
              pattern     = condition.value.pattern
              ignore_case = condition.value.ignore_case
              negate      = condition.value.negate
            }
          }

          dynamic "request_header_configuration" {
            for_each = lookup(rewrite_rule.value, "request_header_configuration", [])
            content {
              header_name  = request_header_configuration.value.header_name
              header_value = request_header_configuration.value.header_value
            }
          }

          dynamic "response_header_configuration" {
            for_each = lookup(rewrite_rule.value, "response_header_configuration", [])
            content {
              header_name  = response_header_configuration.value.header_name
              header_value = response_header_configuration.value.header_value
            }
          }

          dynamic "url" {
            for_each = lookup(rewrite_rule.value, "url", [])
            content {
              path         = url.value.path
              query_string = url.value.query_string
              reroute      = url.value.reroute
            }
          }
        }
      }
    }
  }

  lifecycle {
    prevent_destroy = false

  }

}


##----------------------------------------------------------------------------- 
## Below resource will create User Assigned Identity
##-----------------------------------------------------------------------------
resource "azurerm_user_assigned_identity" "identity" {
  count               = var.identity_ids != null ? 0 : 1
  name                = var.resource_position_prefix ? format("uai-appgw-%s", local.name) : format("%s-uai-appgw", local.name )
  location            = local.location
  resource_group_name = var.resource_group_name
}

##-----------------------------------------------------------------------------
# Private Endpoint - Create a private endpoint for the Key Vault
##-----------------------------------------------------------------------------
resource "azurerm_private_endpoint" "pep" {
  count               = var.enabled && var.enable_private_endpoint ? 1 : 0
  name                = format(var.resource_position_prefix ? "pe-appgw-%s" : "%s-pe-appgw", local.name)
  location            = local.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_endpoint_subnet_id
  tags                = module.labels.tags
  private_dns_zone_group {
    name                 = format(var.resource_position_prefix ? "appgw-dns-zone-group-%s" : "%s-appgw-dns-zone-group", local.name)
    private_dns_zone_ids = [var.private_dns_zone_ids]
  }
  private_service_connection {
    name                           = format(var.resource_position_prefix ? "psc-appgw-%s" : "%s-psc-appgw", local.name)
    is_manual_connection           = false
    private_connection_resource_id = azurerm_application_gateway.main[0].id
    subresource_names              = ["gateway"]
  }
  lifecycle {
    ignore_changes = [
      tags,
    ]
  }
}

##----------------------------------------------------------------------------- 
## Diagnostic settings
##-----------------------------------------------------------------------------
resource "azurerm_monitor_diagnostic_setting" "appgw-law" {
  count = var.enabled && var.enable_diagnostic ? 1 : 0
  # name                           = format("appgw-log")
  name                       = format(var.resource_position_prefix ? "diag-appgw-%s" : "%s-diag-appgw", local.name)
  target_resource_id         = azurerm_application_gateway.main[0].id
  log_analytics_workspace_id = var.workspace_id

#   dynamic "enabled_log" {
#     for_each = ["ApplicationGatewayAccessLog", "ApplicationGatewayPerformanceLog", "ApplicationGatewayFirewallLog"]
#     content {
#       category = enabled_log.value
#     }
#   }

  dynamic "enabled_log" {
    for_each = var.appgw_logs.enabled ? var.appgw_logs.category != null ? var.appgw_logs.category : var.appgw_logs.category_group : []
    content {
      category       = var.appgw_logs.category != null ? enabled_log.value : null
      category_group = var.appgw_logs.category == null ? enabled_log.value : null
    }
  }

  dynamic "enabled_metric" {
    for_each = var.metric_enabled ? ["AllMetrics"] : []
    content {
      category = enabled_metric.value
    }
  }

  lifecycle {
    ignore_changes = [log_analytics_destination_type]
  }
}