# In your output you need to select the correct resource based on the value of var.private_endpoints_manage_dns_zone_group:
output "private_endpoints" {
  description = <<DESCRIPTION
  A map of the private endpoints created.
  DESCRIPTION
  value       = var.private_endpoints_manage_dns_zone_group ? azurerm_private_endpoint.this_managed_dns_zone_groups : azurerm_private_endpoint.this_unmanaged_dns_zone_groups
}

# Module owners should include the full resource via a 'resource' output
# https://azure.github.io/Azure-Verified-Modules/specs/terraform/#id-tffr2---category-outputs---additional-terraform-outputs
output "resource" {
  description = "This is the full output for the resource."
  value       = azurerm_api_management.this
}

output "resource_id" {
  description = "This is the full output for the resource."
  value       = azurerm_api_management.this.id
}

output "resource_gateway_url" {
  description = "This is the output for the gateway url."
  value       = azurerm_api_management.this.gateway_url
}

output "resource_developer_portal_url" {
  description = "This is the output for the gateway url."
  value       = azurerm_api_management.this.developer_portal_url
}
