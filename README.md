<!-- BEGIN_TF_DOCS -->
# terraform-azurerm-avm-template

This is a template repo for Terraform Azure Verified Modules.

Things to do:

1. Set up a GitHub repo environment called `test`.
1. Configure environment protection rule to ensure that approval is required before deploying to this environment.
1. Create a user-assigned managed identity in your test subscription.
1. Create a role assignment for the managed identity on your test subscription, use the minimum required role.
1. Configure federated identity credentials on the user assigned managed identity. Use the GitHub environment.
1. Search and update TODOs within the code and remove the TODO comments once complete.

> [!IMPORTANT]
> As the overall AVM framework is not GA (generally available) yet - the CI framework and test automation is not fully functional and implemented across all supported languages yet - breaking changes are expected, and additional customer feedback is yet to be gathered and incorporated. Hence, modules **MUST NOT** be published at version `1.0.0` or higher at this time.
>
> All module **MUST** be published as a pre-release version (e.g., `0.1.0`, `0.1.1`, `0.2.0`, etc.) until the AVM framework becomes GA.
>
> However, it is important to note that this **DOES NOT** mean that the modules cannot be consumed and utilized. They **CAN** be leveraged in all types of environments (dev, test, prod etc.). Consumers can treat them just like any other IaC module and raise issues or feature requests against them as they learn from the usage of the module. Consumers should also read the release notes for each version, if considering updating to a more recent version of a module to see if there are any considerations or breaking changes etc.

<!-- markdownlint-disable MD033 -->
## Requirements

The following requirements are needed by this module:

- <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) (>= 1.5.0)

- <a name="requirement_azurerm"></a> [azurerm](#requirement\_azurerm) (>= 3.105.0, < 4.0)

- <a name="requirement_random"></a> [random](#requirement\_random) (>= 3.6.2, < 4.0)

## Providers

The following providers are used by this module:

- <a name="provider_azurerm"></a> [azurerm](#provider\_azurerm) (>= 3.105.0, < 4.0)

- <a name="provider_random"></a> [random](#provider\_random) (>= 3.6.2, < 4.0)

## Resources

The following resources are used by this module:

- [azurerm_api_management.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/api_management) (resource)
- [azurerm_management_lock.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/management_lock) (resource)
- [azurerm_private_endpoint.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_endpoint) (resource)
- [azurerm_private_endpoint.this_managed_dns_zone_groups](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_endpoint) (resource)
- [azurerm_private_endpoint.this_unmanaged_dns_zone_groups](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_endpoint) (resource)
- [azurerm_private_endpoint_application_security_group_association.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_endpoint_application_security_group_association) (resource)
- [azurerm_resource_group_template_deployment.telemetry](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/resource_group_template_deployment) (resource)
- [azurerm_role_assignment.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_assignment) (resource)
- [random_id.telem](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/id) (resource)

<!-- markdownlint-disable MD013 -->
## Required Inputs

The following input variables are required:

### <a name="input_location"></a> [location](#input\_location)

Description: Azure region where the resource should be deployed.

Type: `string`

### <a name="input_name"></a> [name](#input\_name)

Description: The name of this resource.

Type: `string`

### <a name="input_publisher_email"></a> [publisher\_email](#input\_publisher\_email)

Description: (Required) The email of publisher/company.

Type: `string`

### <a name="input_publisher_name"></a> [publisher\_name](#input\_publisher\_name)

Description: (Required) The name of publisher/company.

Type: `string`

### <a name="input_resource_group_name"></a> [resource\_group\_name](#input\_resource\_group\_name)

Description: The resource group where the resources will be deployed.

Type: `string`

### <a name="input_sku_name"></a> [sku\_name](#input\_sku\_name)

Description: (Required) `sku_name` is a string consisting of two parts separated by an underscore(\\_). The first part is the `name`, valid values include: `Consumption`, `Developer`, `Basic`, `Standard` and `Premium`. The second part is the `capacity` (e.g. the number of deployed units of the `sku`), which must be a positive `integer` (e.g. `Developer_1`).

Type: `string`

## Optional Inputs

The following input variables are optional (have default values):

### <a name="input_additional_location"></a> [additional\_location](#input\_additional\_location)

Description: - `capacity` - (Optional) The number of compute units in this region. Defaults to the capacity of the main region.
- `gateway_disabled` - (Optional) Only valid for an Api Management service deployed in multiple locations. This can be used to disable the gateway in this additional location.
- `location` - (Required) The name of the Azure Region in which the API Management Service should be expanded to.
- `public_ip_address_id` - (Optional) ID of a standard SKU IPv4 Public IP.
- `zones` - (Optional) A list of availability zones. Changing this forces a new resource to be created.

---
`virtual_network_configuration` block supports the following:
- `subnet_id` - (Required) The id of the subnet that will be used for the API Management.

Type:

```hcl
list(object({
    capacity             = optional(number)
    gateway_disabled     = optional(bool)
    location             = string
    public_ip_address_id = optional(string)
    zones                = optional(set(string))
    virtual_network_configuration = optional(object({
      subnet_id = string
    }))
  }))
```

Default: `null`

### <a name="input_certificate"></a> [certificate](#input\_certificate)

Description: - `certificate_password` - (Optional) The password for the certificate.
- `encoded_certificate` - (Required) The Base64 Encoded PFX or Base64 Encoded X.509 Certificate.
- `store_name` - (Required) The name of the Certificate Store where this certificate should be stored. Possible values are `CertificateAuthority` and `Root`.

Type:

```hcl
list(object({
    certificate_password = optional(string)
    encoded_certificate  = string
    store_name           = string
  }))
```

Default: `null`

### <a name="input_client_certificate_enabled"></a> [client\_certificate\_enabled](#input\_client\_certificate\_enabled)

Description: (Optional) Enforce a client certificate to be presented on each request to the gateway? This is only supported when SKU type is `Consumption`.

Type: `bool`

Default: `null`

### <a name="input_customer_managed_key"></a> [customer\_managed\_key](#input\_customer\_managed\_key)

Description: A map describing customer-managed keys to associate with the resource. This includes the following properties:
- `key_vault_resource_id` - The resource ID of the Key Vault where the key is stored.
- `key_name` - The name of the key.
- `key_version` - (Optional) The version of the key. If not specified, the latest version is used.
- `user_assigned_identity` - (Optional) An object representing a user-assigned identity with the following properties:
  - `resource_id` - The resource ID of the user-assigned identity.

Type:

```hcl
object({
    key_vault_resource_id = string
    key_name              = string
    key_version           = optional(string, null)
    user_assigned_identity = optional(object({
      resource_id = string
    }), null)
  })
```

Default: `null`

### <a name="input_delegation"></a> [delegation](#input\_delegation)

Description: - `subscriptions_enabled` - (Optional) Should subscription requests be delegated to an external url? Defaults to `false`.
- `url` - (Optional) The delegation URL.
- `user_registration_enabled` - (Optional) Should user registration requests be delegated to an external url? Defaults to `false`.
- `validation_key` - (Optional) A base64-encoded validation key to validate, that a request is coming from Azure API Management.

Type:

```hcl
object({
    subscriptions_enabled     = optional(bool)
    url                       = optional(string)
    user_registration_enabled = optional(bool)
    validation_key            = optional(string)
  })
```

Default: `null`

### <a name="input_diagnostic_settings"></a> [diagnostic\_settings](#input\_diagnostic\_settings)

Description: A map of diagnostic settings to create on the Key Vault. The map key is deliberately arbitrary to avoid issues where map keys maybe unknown at plan time.

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

Type:

```hcl
map(object({
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
```

Default: `{}`

### <a name="input_enable_telemetry"></a> [enable\_telemetry](#input\_enable\_telemetry)

Description: This variable controls whether or not telemetry is enabled for the module.  
For more information see <https://aka.ms/avm/telemetryinfo>.  
If it is set to false, then no telemetry will be collected.

Type: `bool`

Default: `true`

### <a name="input_gateway_disabled"></a> [gateway\_disabled](#input\_gateway\_disabled)

Description: (Optional) Disable the gateway in main region? This is only supported when `additional_location` is set.

Type: `bool`

Default: `null`

### <a name="input_hostname_configuration"></a> [hostname\_configuration](#input\_hostname\_configuration)

Description:
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

Type:

```hcl
object({
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
```

Default: `null`

### <a name="input_lock"></a> [lock](#input\_lock)

Description: Controls the Resource Lock configuration for this resource. The following properties can be specified:

- `kind` - (Required) The type of lock. Possible values are `\"CanNotDelete\"` and `\"ReadOnly\"`.
- `name` - (Optional) The name of the lock. If not specified, a name will be generated based on the `kind` value. Changing this forces the creation of a new resource.

Type:

```hcl
object({
    kind = string
    name = optional(string, null)
  })
```

Default: `null`

### <a name="input_managed_identities"></a> [managed\_identities](#input\_managed\_identities)

Description: Controls the Managed Identity configuration on this resource. The following properties can be specified:

- `system_assigned` - (Optional) Specifies if the System Assigned Managed Identity should be enabled.
- `user_assigned_resource_ids` - (Optional) Specifies a list of User Assigned Managed Identity resource IDs to be assigned to this resource.

Type:

```hcl
object({
    system_assigned            = optional(bool, false)
    user_assigned_resource_ids = optional(set(string), [])
  })
```

Default: `{}`

### <a name="input_min_api_version"></a> [min\_api\_version](#input\_min\_api\_version)

Description: (Optional) The version which the control plane API calls to API Management service are limited with version equal to or newer than.

Type: `string`

Default: `null`

### <a name="input_notification_sender_email"></a> [notification\_sender\_email](#input\_notification\_sender\_email)

Description: (Optional) Email address from which the notification will be sent.

Type: `string`

Default: `null`

### <a name="input_policy"></a> [policy](#input\_policy)

Description: - `xml_content` - (Optional) The XML Content for this Policy.
- `xml_link` - (Optional) A link to an API Management Policy XML Document, which must be publicly available.

Type:

```hcl
list(object({
    xml_content = string
    xml_link    = string
  }))
```

Default: `null`

### <a name="input_private_endpoints"></a> [private\_endpoints](#input\_private\_endpoints)

Description: A map of private endpoints to create on the resource. The map key is deliberately arbitrary to avoid issues where map keys maybe unknown at plan time.

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

Type:

```hcl
map(object({
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
```

Default: `{}`

### <a name="input_private_endpoints_manage_dns_zone_group"></a> [private\_endpoints\_manage\_dns\_zone\_group](#input\_private\_endpoints\_manage\_dns\_zone\_group)

Description: Whether to manage private DNS zone groups with this module. If set to false, you must manage private DNS zone groups externally, e.g. using Azure Policy.

Type: `bool`

Default: `true`

### <a name="input_protocols"></a> [protocols](#input\_protocols)

Description: - `enable_http2` - (Optional) Should HTTP/2 be supported by the API Management Service? Defaults to `false`.

Type:

```hcl
object({
    enable_http2 = optional(bool)
  })
```

Default: `null`

### <a name="input_public_ip_address_id"></a> [public\_ip\_address\_id](#input\_public\_ip\_address\_id)

Description: (Optional) ID of a standard SKU IPv4 Public IP.

Type: `string`

Default: `null`

### <a name="input_public_network_access_enabled"></a> [public\_network\_access\_enabled](#input\_public\_network\_access\_enabled)

Description: (Optional) Is public access to the service allowed? Defaults to `true`.

Type: `bool`

Default: `null`

### <a name="input_role_assignments"></a> [role\_assignments](#input\_role\_assignments)

Description:   A map of role assignments to create on the <RESOURCE>. The map key is deliberately arbitrary to avoid issues where map keys maybe unknown at plan time.

  - `role_definition_id_or_name` - The ID or name of the role definition to assign to the principal.
  - `principal_id` - The ID of the principal to assign the role to.
  - `description` - (Optional) The description of the role assignment.
  - `skip_service_principal_aad_check` - (Optional) If set to true, skips the Azure Active Directory check for the service principal in the tenant. Defaults to false.
  - `condition` - (Optional) The condition which will be used to scope the role assignment.
  - `condition_version` - (Optional) The version of the condition syntax. Leave as `null` if you are not using a condition, if you are then valid values are '2.0'.
  - `delegated_managed_identity_resource_id` - (Optional) The delegated Azure Resource Id which contains a Managed Identity. Changing this forces a new resource to be created. This field is only used in cross-tenant scenario.
  - `principal_type` - (Optional) The type of the `principal_id`. Possible values are `User`, `Group` and `ServicePrincipal`. It is necessary to explicitly set this attribute when creating role assignments if the principal creating the assignment is constrained by ABAC rules that filters on the PrincipalType attribute.

  > Note: only set `skip_service_principal_aad_check` to true if you are assigning a role to a service principal.

Type:

```hcl
map(object({
    role_definition_id_or_name             = string
    principal_id                           = string
    description                            = optional(string, null)
    skip_service_principal_aad_check       = optional(bool, false)
    condition                              = optional(string, null)
    condition_version                      = optional(string, null)
    delegated_managed_identity_resource_id = optional(string, null)
    principal_type                         = optional(string, null)
  }))
```

Default: `{}`

### <a name="input_security"></a> [security](#input\_security)

Description: - `enable_backend_ssl30` - (Optional) Should SSL 3.0 be enabled on the backend of the gateway? Defaults to `false`.
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

Type:

```hcl
object({
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
```

Default: `null`

### <a name="input_sign_in"></a> [sign\_in](#input\_sign\_in)

Description: - `enabled` - (Required) Should anonymous users be redirected to the sign in page?

Type:

```hcl
object({
    enabled = bool
  })
```

Default: `null`

### <a name="input_sign_up"></a> [sign\_up](#input\_sign\_up)

Description: - `enabled` - (Required) Can users sign up on the development portal?

---
`terms_of_service` block supports the following:
- `consent_required` - (Required) Should the user be asked for consent during sign up?
- `enabled` - (Required) Should Terms of Service be displayed during sign up?.
- `text` - (Optional) The Terms of Service which users are required to agree to in order to sign up.

Type:

```hcl
object({
    enabled = bool
    terms_of_service = object({
      consent_required = bool
      enabled          = bool
      text             = optional(string)
    })
  })
```

Default: `null`

### <a name="input_tags"></a> [tags](#input\_tags)

Description: (Optional) Tags of the resource.

Type: `map(string)`

Default: `null`

### <a name="input_tenant_access"></a> [tenant\_access](#input\_tenant\_access)

Description: - `enabled` - (Required) Should the access to the management API be enabled?

Type:

```hcl
object({
    enabled = bool
  })
```

Default: `null`

### <a name="input_timeouts"></a> [timeouts](#input\_timeouts)

Description: - `create` - (Defaults to 3 hours) Used when creating the API Management Service.
- `delete` - (Defaults to 3 hours) Used when deleting the API Management Service.
- `read` - (Defaults to 5 minutes) Used when retrieving the API Management Service.
- `update` - (Defaults to 3 hours) Used when updating the API Management Service.

Type:

```hcl
object({
    create = optional(string)
    delete = optional(string)
    read   = optional(string)
    update = optional(string)
  })
```

Default: `null`

### <a name="input_virtual_network_configuration"></a> [virtual\_network\_configuration](#input\_virtual\_network\_configuration)

Description: - `subnet_id` - (Required) The id of the subnet that will be used for the API Management.

Type:

```hcl
object({
    subnet_id = string
  })
```

Default: `null`

### <a name="input_virtual_network_type"></a> [virtual\_network\_type](#input\_virtual\_network\_type)

Description: (Optional) The type of virtual network you want to use, valid values include: `None`, `External`, `Internal`. Defaults to `None`.

Type: `string`

Default: `null`

### <a name="input_zones"></a> [zones](#input\_zones)

Description: (Optional) Specifies a list of Availability Zones in which this API Management service should be located.

Type: `set(string)`

Default: `null`

## Outputs

The following outputs are exported:

### <a name="output_private_endpoints"></a> [private\_endpoints](#output\_private\_endpoints)

Description:   A map of the private endpoints created.

### <a name="output_resource"></a> [resource](#output\_resource)

Description: This is the full output for the resource.

### <a name="output_resource_id"></a> [resource\_id](#output\_resource\_id)

Description: This is the full output for the resource.

## Modules

No modules.

<!-- markdownlint-disable-next-line MD041 -->
## Data Collection

The software may collect information about you and your use of the software and send it to Microsoft. Microsoft may use this information to provide services and improve our products and services. You may turn off the telemetry as described in the repository. There are also some features in the software that may enable you and Microsoft to collect data from users of your applications. If you use these features, you must comply with applicable law, including providing appropriate notices to users of your applications together with a copy of Microsoft’s privacy statement. Our privacy statement is located at <https://go.microsoft.com/fwlink/?LinkID=824704>. You can learn more about data collection and use in the help documentation and our privacy statement. Your use of the software operates as your consent to these practices.
<!-- END_TF_DOCS -->