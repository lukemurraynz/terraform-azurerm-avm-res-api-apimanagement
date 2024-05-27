variable "location" {
  type        = string
  description = "Azure region where the resource should be deployed."
  nullable    = false
}

variable "name" {
  type        = string
  description = "The name of this resource."

  validation {
    condition     = can(regex("^[a-zA-Z]([a-zA-Z0-9-_.()]{0,48}[a-zA-Z0-9()])?$", var.name))
    error_message = "The name must be between 1 and 50 characters long, start with a letter, end with a letter or digit, and can only contain letters, digits, hyphens (-), underscores (_), parentheses ((, )), and periods (.)."
  }
}

variable "publisher_email" {
  type        = string
  description = "(Required) The email of publisher/company."
  nullable    = false
}

variable "publisher_name" {
  type        = string
  description = "(Required) The name of publisher/company."
  nullable    = false
}

# This is required for most resource modules
variable "resource_group_name" {
  type        = string
  description = "The resource group where the resources will be deployed."
}

variable "sku_name" {
  type        = string
  description = "(Required) `sku_name` is a string consisting of two parts separated by an underscore(\\_). The first part is the `name`, valid values include: `Consumption`, `Developer`, `Basic`, `Standard` and `Premium`. The second part is the `capacity` (e.g. the number of deployed units of the `sku`), which must be a positive `integer` (e.g. `Developer_1`)."
  nullable    = false
}

variable "additional_location" {
  type = list(object({
    capacity             = optional(number)
    gateway_disabled     = optional(bool)
    location             = string
    public_ip_address_id = optional(string)
    zones                = optional(set(string))
    virtual_network_configuration = optional(object({
      subnet_id = string
    }))
  }))
  default     = null
  description = <<-EOT
 - `capacity` - (Optional) The number of compute units in this region. Defaults to the capacity of the main region.
 - `gateway_disabled` - (Optional) Only valid for an Api Management service deployed in multiple locations. This can be used to disable the gateway in this additional location.
 - `location` - (Required) The name of the Azure Region in which the API Management Service should be expanded to.
 - `public_ip_address_id` - (Optional) ID of a standard SKU IPv4 Public IP.
 - `zones` - (Optional) A list of availability zones. Changing this forces a new resource to be created.

 ---
 `virtual_network_configuration` block supports the following:
 - `subnet_id` - (Required) The id of the subnet that will be used for the API Management.
EOT
}

variable "certificate" {
  type = list(object({
    certificate_password = optional(string)
    encoded_certificate  = string
    store_name           = string
  }))
  default     = null
  description = <<-EOT
 - `certificate_password` - (Optional) The password for the certificate.
 - `encoded_certificate` - (Required) The Base64 Encoded PFX or Base64 Encoded X.509 Certificate.
 - `store_name` - (Required) The name of the Certificate Store where this certificate should be stored. Possible values are `CertificateAuthority` and `Root`.
EOT
}

variable "client_certificate_enabled" {
  type        = bool
  default     = null
  description = "(Optional) Enforce a client certificate to be presented on each request to the gateway? This is only supported when SKU type is `Consumption`."
}

# required AVM interfaces
# remove only if not supported by the resource
# tflint-ignore: terraform_unused_declarations
variable "customer_managed_key" {
  type = object({
    key_vault_resource_id = string
    key_name              = string
    key_version           = optional(string, null)
    user_assigned_identity = optional(object({
      resource_id = string
    }), null)
  })
  default     = null
  description = <<DESCRIPTION
A map describing customer-managed keys to associate with the resource. This includes the following properties:
- `key_vault_resource_id` - The resource ID of the Key Vault where the key is stored.
- `key_name` - The name of the key.
- `key_version` - (Optional) The version of the key. If not specified, the latest version is used.
- `user_assigned_identity` - (Optional) An object representing a user-assigned identity with the following properties:
  - `resource_id` - The resource ID of the user-assigned identity.
DESCRIPTION  
}

variable "delegation" {
  type = object({
    subscriptions_enabled     = optional(bool)
    url                       = optional(string)
    user_registration_enabled = optional(bool)
    validation_key            = optional(string)
  })
  default     = null
  description = <<-EOT
 - `subscriptions_enabled` - (Optional) Should subscription requests be delegated to an external url? Defaults to `false`.
 - `url` - (Optional) The delegation URL.
 - `user_registration_enabled` - (Optional) Should user registration requests be delegated to an external url? Defaults to `false`.
 - `validation_key` - (Optional) A base64-encoded validation key to validate, that a request is coming from Azure API Management.
EOT
}

variable "diagnostic_settings" {
  type = map(object({
    name                                     = optional(string, null)
    log_categories                           = optional(set(string), [])
    log_groups                               = optional(set(string), ["allLogs"])
    metric_categories                        = optional(set(string), ["AllMetrics"])
    log_analytics_destination_type           = optional(string, "Dedicated")
    workspace_resource_id                    = optional(string, null)
    storage_account_resource_id              = optional(string, null)
    event_hub_authorization_rule_resource_id = optional(string, null)
    event_hub_name                           = optional(string, null)
    marketplace_partner_resource_id          = optional(string, null)
  }))
  default     = {}
  description = <<DESCRIPTION
A map of diagnostic settings to create on the Key Vault. The map key is deliberately arbitrary to avoid issues where map keys maybe unknown at plan time.

- `name` - (Optional) The name of the diagnostic setting. One will be generated if not set, however this will not be unique if you want to create multiple diagnostic setting resources.
- `log_categories` - (Optional) A set of log categories to send to the log analytics workspace. Defaults to `[]`.
- `log_groups` - (Optional) A set of log groups to send to the log analytics workspace. Defaults to `["allLogs"]`.
- `metric_categories` - (Optional) A set of metric categories to send to the log analytics workspace. Defaults to `["AllMetrics"]`.
- `log_analytics_destination_type` - (Optional) The destination type for the diagnostic setting. Possible values are `Dedicated` and `AzureDiagnostics`. Defaults to `Dedicated`.
- `workspace_resource_id` - (Optional) The resource ID of the log analytics workspace to send logs and metrics to.
- `storage_account_resource_id` - (Optional) The resource ID of the storage account to send logs and metrics to.
- `event_hub_authorization_rule_resource_id` - (Optional) The resource ID of the event hub authorization rule to send logs and metrics to.
- `event_hub_name` - (Optional) The name of the event hub. If none is specified, the default event hub will be selected.
- `marketplace_partner_resource_id` - (Optional) The full ARM resource ID of the Marketplace resource to which you would like to send Diagnostic LogsLogs.
DESCRIPTION  
  nullable    = false

  validation {
    condition     = alltrue([for _, v in var.diagnostic_settings : contains(["Dedicated", "AzureDiagnostics"], v.log_analytics_destination_type)])
    error_message = "Log analytics destination type must be one of: 'Dedicated', 'AzureDiagnostics'."
  }
  validation {
    condition = alltrue(
      [
        for _, v in var.diagnostic_settings :
        v.workspace_resource_id != null || v.storage_account_resource_id != null || v.event_hub_authorization_rule_resource_id != null || v.marketplace_partner_resource_id != null
      ]
    )
    error_message = "At least one of `workspace_resource_id`, `storage_account_resource_id`, `marketplace_partner_resource_id`, or `event_hub_authorization_rule_resource_id`, must be set."
  }
}

variable "enable_telemetry" {
  type        = bool
  default     = true
  description = <<DESCRIPTION
This variable controls whether or not telemetry is enabled for the module.
For more information see <https://aka.ms/avm/telemetryinfo>.
If it is set to false, then no telemetry will be collected.
DESCRIPTION
}

variable "gateway_disabled" {
  type        = bool
  default     = null
  description = "(Optional) Disable the gateway in main region? This is only supported when `additional_location` is set."
}

variable "hostname_configuration" {
  type = object({
    developer_portal = optional(list(object({
      certificate                     = optional(string)
      certificate_password            = optional(string)
      host_name                       = string
      key_vault_id                    = optional(string)
      negotiate_client_certificate    = optional(bool)
      ssl_keyvault_identity_client_id = optional(string)
    })))
    management = optional(list(object({
      certificate                     = optional(string)
      certificate_password            = optional(string)
      host_name                       = string
      key_vault_id                    = optional(string)
      negotiate_client_certificate    = optional(bool)
      ssl_keyvault_identity_client_id = optional(string)
    })))
    portal = optional(list(object({
      certificate                     = optional(string)
      certificate_password            = optional(string)
      host_name                       = string
      key_vault_id                    = optional(string)
      negotiate_client_certificate    = optional(bool)
      ssl_keyvault_identity_client_id = optional(string)
    })))
    proxy = optional(list(object({
      certificate                     = optional(string)
      certificate_password            = optional(string)
      default_ssl_binding             = optional(bool)
      host_name                       = string
      key_vault_id                    = optional(string)
      negotiate_client_certificate    = optional(bool)
      ssl_keyvault_identity_client_id = optional(string)
    })))
    scm = optional(list(object({
      certificate                     = optional(string)
      certificate_password            = optional(string)
      host_name                       = string
      key_vault_id                    = optional(string)
      negotiate_client_certificate    = optional(bool)
      ssl_keyvault_identity_client_id = optional(string)
    })))
  })
  default     = null
  description = <<-EOT

 ---
 `developer_portal` block supports the following:
 - `certificate` - (Optional) One or more `certificate` blocks (up to 10) as defined below.
 - `certificate_password` - 
 - `host_name` - 
 - `key_vault_id` - 
 - `negotiate_client_certificate` - 
 - `ssl_keyvault_identity_client_id` - 

 ---
 `management` block supports the following:
 - `certificate` - (Optional) One or more `certificate` blocks (up to 10) as defined below.
 - `certificate_password` - 
 - `host_name` - 
 - `key_vault_id` - 
 - `negotiate_client_certificate` - 
 - `ssl_keyvault_identity_client_id` - 

 ---
 `portal` block supports the following:
 - `certificate` - (Optional) One or more `certificate` blocks (up to 10) as defined below.
 - `certificate_password` - 
 - `host_name` - 
 - `key_vault_id` - 
 - `negotiate_client_certificate` - 
 - `ssl_keyvault_identity_client_id` - 

 ---
 `proxy` block supports the following:
 - `certificate` - (Optional) The Base64 Encoded Certificate.
 - `certificate_password` - (Optional) The password associated with the certificate provided above.
 - `default_ssl_binding` - (Optional) Is the certificate associated with this Hostname the Default SSL Certificate? This is used when an SNI header isn't specified by a client. Defaults to `false`.
 - `host_name` - (Required) The Hostname to use for the Management API.
 - `key_vault_id` - (Optional) The ID of the Key Vault Secret containing the SSL Certificate, which must be should be of the type `application/x-pkcs12`.
 - `negotiate_client_certificate` - (Optional) Should Client Certificate Negotiation be enabled for this Hostname? Defaults to `false`.
 - `ssl_keyvault_identity_client_id` - (Optional) The Managed Identity Client ID to use to access the Key Vault. This Identity must be specified in the `identity` block to be used.

 ---
 `scm` block supports the following:
 - `certificate` - (Optional) One or more `certificate` blocks (up to 10) as defined below.
 - `certificate_password` - 
 - `host_name` - 
 - `key_vault_id` - 
 - `negotiate_client_certificate` - 
 - `ssl_keyvault_identity_client_id` - 
EOT
}

variable "lock" {
  type = object({
    kind = string
    name = optional(string, null)
  })
  default     = null
  description = <<DESCRIPTION
Controls the Resource Lock configuration for this resource. The following properties can be specified:

- `kind` - (Required) The type of lock. Possible values are `\"CanNotDelete\"` and `\"ReadOnly\"`.
- `name` - (Optional) The name of the lock. If not specified, a name will be generated based on the `kind` value. Changing this forces the creation of a new resource.
DESCRIPTION

  validation {
    condition     = var.lock != null ? contains(["CanNotDelete", "ReadOnly"], var.lock.kind) : true
    error_message = "The lock level must be one of: 'None', 'CanNotDelete', or 'ReadOnly'."
  }
}

# tflint-ignore: terraform_unused_declarations
variable "managed_identities" {
  type = object({
    system_assigned            = optional(bool, false)
    user_assigned_resource_ids = optional(set(string), [])
  })
  default     = {}
  description = <<DESCRIPTION
Controls the Managed Identity configuration on this resource. The following properties can be specified:

- `system_assigned` - (Optional) Specifies if the System Assigned Managed Identity should be enabled.
- `user_assigned_resource_ids` - (Optional) Specifies a list of User Assigned Managed Identity resource IDs to be assigned to this resource.
DESCRIPTION
  nullable    = false
}

variable "min_api_version" {
  type        = string
  default     = null
  description = "(Optional) The version which the control plane API calls to API Management service are limited with version equal to or newer than."
}

variable "notification_sender_email" {
  type        = string
  default     = null
  description = "(Optional) Email address from which the notification will be sent."
}

variable "policy" {
  type = list(object({
    xml_content = string
    xml_link    = string
  }))
  default     = null
  description = <<-EOT
 - `xml_content` - (Optional) The XML Content for this Policy.
 - `xml_link` - (Optional) A link to an API Management Policy XML Document, which must be publicly available.
EOT
}

# In this example we only support one service, e.g. Key Vault.
# If your service has multiple private endpoint services, then expose the service name.

# This variable is used to determine if the private_dns_zone_group block should be included,
# or if it is to be managed externally, e.g. using Azure Policy.
# https://github.com/Azure/terraform-azurerm-avm-res-keyvault-vault/issues/32
# Alternatively you can use AzAPI, which does not have this issue.
variable "private_endpoints_manage_dns_zone_group" {
  type        = bool
  default     = true
  nullable    = false
  description = "Whether to manage private DNS zone groups with this module. If set to false, you must manage private DNS zone groups externally, e.g. using Azure Policy."
}

variable "private_endpoints" {
  type = map(object({
    name = optional(string, null)
    role_assignments = optional(map(object({
      role_definition_id_or_name             = string
      principal_id                           = string
      description                            = optional(string, null)
      skip_service_principal_aad_check       = optional(bool, false)
      condition                              = optional(string, null)
      condition_version                      = optional(string, null)
      delegated_managed_identity_resource_id = optional(string, null)
      principal_type                         = optional(string, null)
    })), {})
    lock = optional(object({
      kind = string
      name = optional(string, null)
    }), null)
    tags                                    = optional(map(string), null)
    subnet_resource_id                      = string
    subresource_name                        = string
    private_dns_zone_group_name             = optional(string, "default")
    private_dns_zone_resource_ids           = optional(set(string), [])
    application_security_group_associations = optional(map(string), {})
    private_service_connection_name         = optional(string, null)
    network_interface_name                  = optional(string, null)
    location                                = optional(string, null)
    resource_group_name                     = optional(string, null)
    ip_configurations = optional(map(object({
      name               = string
      private_ip_address = string
    })), {})
  }))
  default     = {}
  description = <<DESCRIPTION
A map of private endpoints to create on the resource. The map key is deliberately arbitrary to avoid issues where map keys maybe unknown at plan time.

- `name` - (Optional) The name of the private endpoint. One will be generated if not set.
- `role_assignments` - (Optional) A map of role assignments to create on the private endpoint. The map key is deliberately arbitrary to avoid issues where map keys maybe unknown at plan time. See `var.role_assignments` for more information.
- `lock` - (Optional) The lock level to apply to the private endpoint. Default is `None`. Possible values are `None`, `CanNotDelete`, and `ReadOnly`.
- `tags` - (Optional) A mapping of tags to assign to the private endpoint.
- `subnet_resource_id` - The resource ID of the subnet to deploy the private endpoint in.
- `subresource_name` - The service name of the private endpoint.  Possible value are `blob`, 'dfs', 'file', `queue`, `table`, and `web`.
- `private_dns_zone_group_name` - (Optional) The name of the private DNS zone group. One will be generated if not set.
- `private_dns_zone_resource_ids` - (Optional) A set of resource IDs of private DNS zones to associate with the private endpoint. If not set, no zone groups will be created and the private endpoint will not be associated with any private DNS zones. DNS records must be managed external to this module.
- `application_security_group_resource_ids` - (Optional) A map of resource IDs of application security groups to associate with the private endpoint. The map key is deliberately arbitrary to avoid issues where map keys maybe unknown at plan time.
- `private_service_connection_name` - (Optional) The name of the private service connection. One will be generated if not set.
- `network_interface_name` - (Optional) The name of the network interface. One will be generated if not set.
- `location` - (Optional) The Azure location where the resources will be deployed. Defaults to the location of the resource group.
- `resource_group_name` - (Optional) The resource group where the resources will be deployed. Defaults to the resource group of the resource.
- `ip_configurations` - (Optional) A map of IP configurations to create on the private endpoint. If not specified the platform will create one. The map key is deliberately arbitrary to avoid issues where map keys maybe unknown at plan time.
  - `name` - The name of the IP configuration.
  - `private_ip_address` - The private IP address of the IP configuration.
DESCRIPTION
  nullable    = false
}


# You need an additional resource when not managing private_dns_zone_group with this module:



variable "protocols" {
  type = object({
    enable_http2 = optional(bool)
  })
  default     = null
  description = <<-EOT
 - `enable_http2` - (Optional) Should HTTP/2 be supported by the API Management Service? Defaults to `false`.
EOT
}

variable "public_ip_address_id" {
  type        = string
  default     = null
  description = "(Optional) ID of a standard SKU IPv4 Public IP."
}

variable "public_network_access_enabled" {
  type        = bool
  default     = null
  description = "(Optional) Is public access to the service allowed? Defaults to `true`."
}

variable "role_assignments" {
  type = map(object({
    role_definition_id_or_name             = string
    principal_id                           = string
    description                            = optional(string, null)
    skip_service_principal_aad_check       = optional(bool, false)
    condition                              = optional(string, null)
    condition_version                      = optional(string, null)
    delegated_managed_identity_resource_id = optional(string, null)
    principal_type                         = optional(string, null)
  }))
  default     = {}
  nullable    = false
  description = <<DESCRIPTION
  A map of role assignments to create on the <RESOURCE>. The map key is deliberately arbitrary to avoid issues where map keys maybe unknown at plan time.
  
  - `role_definition_id_or_name` - The ID or name of the role definition to assign to the principal.
  - `principal_id` - The ID of the principal to assign the role to.
  - `description` - (Optional) The description of the role assignment.
  - `skip_service_principal_aad_check` - (Optional) If set to true, skips the Azure Active Directory check for the service principal in the tenant. Defaults to false.
  - `condition` - (Optional) The condition which will be used to scope the role assignment.
  - `condition_version` - (Optional) The version of the condition syntax. Leave as `null` if you are not using a condition, if you are then valid values are '2.0'.
  - `delegated_managed_identity_resource_id` - (Optional) The delegated Azure Resource Id which contains a Managed Identity. Changing this forces a new resource to be created. This field is only used in cross-tenant scenario.
  - `principal_type` - (Optional) The type of the `principal_id`. Possible values are `User`, `Group` and `ServicePrincipal`. It is necessary to explicitly set this attribute when creating role assignments if the principal creating the assignment is constrained by ABAC rules that filters on the PrincipalType attribute.
  
  > Note: only set `skip_service_principal_aad_check` to true if you are assigning a role to a service principal.
  DESCRIPTION
}


variable "security" {
  type = object({
    enable_backend_ssl30                                = optional(bool)
    enable_backend_tls10                                = optional(bool)
    enable_backend_tls11                                = optional(bool)
    enable_frontend_ssl30                               = optional(bool)
    enable_frontend_tls10                               = optional(bool)
    enable_frontend_tls11                               = optional(bool)
    tls_ecdhe_ecdsa_with_aes128_cbc_sha_ciphers_enabled = optional(bool)
    tls_ecdhe_ecdsa_with_aes256_cbc_sha_ciphers_enabled = optional(bool)
    tls_ecdhe_rsa_with_aes128_cbc_sha_ciphers_enabled   = optional(bool)
    tls_ecdhe_rsa_with_aes256_cbc_sha_ciphers_enabled   = optional(bool)
    tls_rsa_with_aes128_cbc_sha256_ciphers_enabled      = optional(bool)
    tls_rsa_with_aes128_cbc_sha_ciphers_enabled         = optional(bool)
    tls_rsa_with_aes128_gcm_sha256_ciphers_enabled      = optional(bool)
    tls_rsa_with_aes256_cbc_sha256_ciphers_enabled      = optional(bool)
    tls_rsa_with_aes256_cbc_sha_ciphers_enabled         = optional(bool)
    tls_rsa_with_aes256_gcm_sha384_ciphers_enabled      = optional(bool)
    triple_des_ciphers_enabled                          = optional(bool)
  })
  default     = null
  description = <<-EOT
 - `enable_backend_ssl30` - (Optional) Should SSL 3.0 be enabled on the backend of the gateway? Defaults to `false`.
 - `enable_backend_tls10` - (Optional) Should TLS 1.0 be enabled on the backend of the gateway? Defaults to `false`.
 - `enable_backend_tls11` - (Optional) Should TLS 1.1 be enabled on the backend of the gateway? Defaults to `false`.
 - `enable_frontend_ssl30` - (Optional) Should SSL 3.0 be enabled on the frontend of the gateway? Defaults to `false`.
 - `enable_frontend_tls10` - (Optional) Should TLS 1.0 be enabled on the frontend of the gateway? Defaults to `false`.
 - `enable_frontend_tls11` - (Optional) Should TLS 1.1 be enabled on the frontend of the gateway? Defaults to `false`.
 - `tls_ecdhe_ecdsa_with_aes128_cbc_sha_ciphers_enabled` - (Optional) Should the `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA` cipher be enabled? Defaults to `false`.
 - `tls_ecdhe_ecdsa_with_aes256_cbc_sha_ciphers_enabled` - (Optional) Should the `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA` cipher be enabled? Defaults to `false`.
 - `tls_ecdhe_rsa_with_aes128_cbc_sha_ciphers_enabled` - (Optional) Should the `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` cipher be enabled? Defaults to `false`.
 - `tls_ecdhe_rsa_with_aes256_cbc_sha_ciphers_enabled` - (Optional) Should the `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA` cipher be enabled? Defaults to `false`.
 - `tls_rsa_with_aes128_cbc_sha256_ciphers_enabled` - (Optional) Should the `TLS_RSA_WITH_AES_128_CBC_SHA256` cipher be enabled? Defaults to `false`.
 - `tls_rsa_with_aes128_cbc_sha_ciphers_enabled` - (Optional) Should the `TLS_RSA_WITH_AES_128_CBC_SHA` cipher be enabled? Defaults to `false`.
 - `tls_rsa_with_aes128_gcm_sha256_ciphers_enabled` - (Optional) Should the `TLS_RSA_WITH_AES_128_GCM_SHA256` cipher be enabled? Defaults to `false`.
 - `tls_rsa_with_aes256_cbc_sha256_ciphers_enabled` - (Optional) Should the `TLS_RSA_WITH_AES_256_CBC_SHA256` cipher be enabled? Defaults to `false`.
 - `tls_rsa_with_aes256_cbc_sha_ciphers_enabled` - (Optional) Should the `TLS_RSA_WITH_AES_256_CBC_SHA` cipher be enabled? Defaults to `false`.
 - `tls_rsa_with_aes256_gcm_sha384_ciphers_enabled` - (Optional) Should the `TLS_RSA_WITH_AES_256_GCM_SHA384` cipher be enabled? Defaults to `false`.
 - `triple_des_ciphers_enabled` - (Optional) Should the `TLS_RSA_WITH_3DES_EDE_CBC_SHA` cipher be enabled for alL TLS versions (1.0, 1.1 and 1.2)?
EOT
}

variable "sign_in" {
  type = object({
    enabled = bool
  })
  default     = null
  description = <<-EOT
 - `enabled` - (Required) Should anonymous users be redirected to the sign in page?
EOT
}

variable "sign_up" {
  type = object({
    enabled = bool
    terms_of_service = object({
      consent_required = bool
      enabled          = bool
      text             = optional(string)
    })
  })
  default     = null
  description = <<-EOT
 - `enabled` - (Required) Can users sign up on the development portal?

 ---
 `terms_of_service` block supports the following:
 - `consent_required` - (Required) Should the user be asked for consent during sign up?
 - `enabled` - (Required) Should Terms of Service be displayed during sign up?.
 - `text` - (Optional) The Terms of Service which users are required to agree to in order to sign up.
EOT
}

# tflint-ignore: terraform_unused_declarations
variable "tags" {
  type        = map(string)
  default     = null
  description = "(Optional) Tags of the resource."
}

variable "tenant_access" {
  type = object({
    enabled = bool
  })
  default     = null
  description = <<-EOT
 - `enabled` - (Required) Should the access to the management API be enabled?
EOT
}

variable "timeouts" {
  type = object({
    create = optional(string)
    delete = optional(string)
    read   = optional(string)
    update = optional(string)
  })
  default     = null
  description = <<-EOT
 - `create` - (Defaults to 3 hours) Used when creating the API Management Service.
 - `delete` - (Defaults to 3 hours) Used when deleting the API Management Service.
 - `read` - (Defaults to 5 minutes) Used when retrieving the API Management Service.
 - `update` - (Defaults to 3 hours) Used when updating the API Management Service.
EOT
}

variable "virtual_network_configuration" {
  type = object({
    subnet_id = string
  })
  default     = null
  description = <<-EOT
 - `subnet_id` - (Required) The id of the subnet that will be used for the API Management.
EOT
}

variable "virtual_network_type" {
  type        = string
  default     = null
  description = "(Optional) The type of virtual network you want to use, valid values include: `None`, `External`, `Internal`. Defaults to `None`."
}

variable "zones" {
  type        = set(string)
  default     = null
  description = "(Optional) Specifies a list of Availability Zones in which this API Management service should be located."
}
