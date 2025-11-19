##-----------------------------------------------------------------------------
## Outputs
##-----------------------------------------------------------------------------
output "label_order" {
  value       = local.label_order
  description = "Label order."
}

output "application_gateway_id" {
  description = "The ID of the Application Gateway"
  value       = azurerm_application_gateway.main[0].id
}

output "public_ip" {
  description = "public ip address id"
  value       = azurerm_public_ip.pip[0].id
}