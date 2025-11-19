##-----------------------------------------------------------------------------
## Locals
##-----------------------------------------------------------------------------
locals {
  label_order = var.label_order
}

locals {
  name             = var.custom_name != null ? var.custom_name : module.labels.id
  sku_name = var.external_waf_enabled ? "WAF_v2" : "Standard_v2"
  sku_tier = var.external_waf_enabled ? "WAF_v2" : "Standard_v2"
  private_link_configuration_name = "pvt-link"
  location              = var.location
  subnet_id             = var.subnet_id
  # private_dns_zone_name = var.enable_private_endpoint ? var.existing_private_dns_zone == null ? azurerm_private_dns_zone.dnszone[0].name : var.existing_private_dns_zone : null
}