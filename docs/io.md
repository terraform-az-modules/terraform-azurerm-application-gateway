## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| appgw\_logs | values for Application gateway logs. The `category` attribute is optional and can be used to specify which categories of logs to enable. If not specified, all categories will be enabled. | <pre>object({<br>    enabled        = bool<br>    category       = optional(list(string))<br>    category_group = optional(list(string))<br>  })</pre> | <pre>{<br>  "category": [<br>    "ApplicationGatewayAccessLog",<br>    "ApplicationGatewayPerformanceLog",<br>    "ApplicationGatewayFirewallLog"<br>  ],<br>  "enabled": true<br>}</pre> | no |
| appgw\_private | Boolean variable to create a private Application Gateway. When `true`, the default http listener will listen on private IP instead of the public IP. | `bool` | `false` | no |
| appgw\_private\_ip\_addr | Private IP for Application Gateway. Used when variable `appgw_private` is set to `true`. | `string` | `null` | no |
| authentication\_certificates | Authentication certificates to allow the backend with Azure Application Gateway | <pre>list(object({<br>    name = string<br>    data = string<br>  }))</pre> | `[]` | no |
| autoscale\_configuration | Minimum or Maximum capacity for autoscaling | <pre>object({<br>    min_capacity = number<br>    max_capacity = optional(number)<br>  })</pre> | `null` | no |
| backend\_address\_pools | List of backend address pools | <pre>list(object({<br>    name         = optional(string)<br>    fqdns        = optional(list(string))<br>    ip_addresses = optional(list(string))<br>  }))</pre> | `[]` | no |
| backend\_http\_settings | List of backend HTTP settings. | <pre>list(object({<br>    name                                = string<br>    cookie_based_affinity               = string<br>    affinity_cookie_name                = optional(string)<br>    path                                = optional(string)<br>    enable_https                        = bool<br>    probe_name                          = optional(string)<br>    request_timeout                     = number<br>    port                                = optional(number)<br>    host_name                           = optional(string)<br>    pick_host_name_from_backend_address = optional(bool)<br>    authentication_certificate = optional(object({<br>      name = string<br>    }))<br>    trusted_root_certificate_names = optional(list(string))<br>    connection_draining = optional(object({<br>      enable_connection_draining = bool<br>      drain_timeout_sec          = number<br>    }))<br>  }))</pre> | n/a | yes |
| custom\_error\_configuration | Global level custom error configuration for application gateway | `list(map(string))` | `[]` | no |
| custom\_name | Define your custom name to override default naming convention | `string` | `null` | no |
| deployment\_mode | Specifies how the infrastructure/resource is deployed | `string` | `"terraform"` | no |
| enable\_diagnostic | Set to false to prevent the module from creating the diagnostic setting for the NSG Resource.. | `bool` | `false` | no |
| enable\_private\_endpoint | Boolean to enable private endpoint for Function App | `bool` | `false` | no |
| enable\_private\_link\_configuration | Set to true to enable private link configuration for Application Gateway. | `bool` | `false` | no |
| enabled | Set to false to prevent the module from creating any resources. | `bool` | `true` | no |
| environment | Environment (e.g. `prod`, `dev`, `staging`). | `string` | `"dev"` | no |
| external\_waf\_enabled | Indicates if an external WAF is provided | `bool` | `false` | no |
| extra\_tags | Additional tags (e.g. map(`BusinessUnit`,`XYZ`). | `map(string)` | `null` | no |
| file\_upload\_limit\_in\_mb | The maximum file upload size in MB for the policy. | `number` | `100` | no |
| firewall\_policy\_id | The ID of the Web Application Firewall Policy | `string` | `null` | no |
| frontend\_ip\_configuration\_name | Frontend ip configuration name | `string` | `null` | no |
| frontend\_port\_settings | Frontend port settings. Each port setting contains the name and the port for the frontend port. | <pre>list(object({<br>    name = string<br>    port = number<br>  }))</pre> | n/a | yes |
| frontend\_priv\_ip\_configuration\_name | Frontend private ip configuration name | `string` | `null` | no |
| gateway\_ip\_configuration\_name | Gateway ip configuration name | `string` | `"appgw-gwipc"` | no |
| health\_probes | List of Health probes used to test backend pools health. | <pre>list(object({<br>    name                                      = string<br>    host                                      = string<br>    interval                                  = number<br>    path                                      = string<br>    timeout                                   = number<br>    unhealthy_threshold                       = number<br>    port                                      = optional(number)<br>    pick_host_name_from_backend_http_settings = optional(bool)<br>    minimum_servers                           = optional(number)<br>    match = optional(object({<br>      body        = optional(string)<br>      status_code = optional(list(string))<br>    }))<br>  }))</pre> | `[]` | no |
| http2\_enabled | Is HTTP2 enabled on the application gateway resource? | `bool` | `false` | no |
| http\_listeners | List of HTTP/HTTPS listeners. SSL Certificate name is required | <pre>list(object({<br>    name                 = string<br>    host_name            = optional(string)<br>    frontend_port_name   = optional(string)<br>    host_names           = optional(list(string))<br>    require_sni          = optional(bool)<br>    ssl_certificate_name = optional(string)<br>    firewall_policy_id   = optional(string)<br>    ssl_profile_name     = optional(string)<br>    custom_error_configuration = optional(list(object({<br>      status_code           = string<br>      custom_error_page_url = string<br>    })))<br>  }))</pre> | n/a | yes |
| identity\_ids | Specifies a list with a single user managed identity id to be assigned to the Application Gateway | `set(string)` | `null` | no |
| instance\_count | No. of instance count for resource deployed | `number` | `1` | no |
| label\_order | Label order, e.g. `name`,`application`,`centralus`. | `list(any)` | <pre>[<br>  "name",<br>  "environment",<br>  "location"<br>]</pre> | no |
| location | The location/region to keep all your network resources. | `string` | `""` | no |
| managed\_rule\_exclusions | A mapping of managed rule exclusions to associate with the policy. | <pre>list(object({<br>    match_variable          = string<br>    selector_match_operator = string<br>    selector                = string<br>    rule_set = optional(object({<br>      type = string<br>      rule_groups = optional(list(object({<br>        rule_group_name = string<br>        excluded_rules  = list(number)<br>      })), [])<br>    }))<br>  }))</pre> | `[]` | no |
| managedby | ManagedBy, eg ''. | `string` | `""` | no |
| max\_request\_body\_size\_in\_kb | The maximum request body size in KB for the policy. | `number` | `128` | no |
| metric\_enabled | Boolean flag to specify whether Metrics should be enabled for the Application Gateway. Defaults to true. | `bool` | `true` | no |
| name | Name  (e.g. `app` or `cluster`). | `string` | `""` | no |
| private\_dns\_zone\_ids | The ID of the private DNS zone. | `string` | `null` | no |
| private\_endpoint\_subnet\_id | Subnet ID for private endpoint | `string` | `""` | no |
| private\_link\_configuration | List of private link configurations for Application Gateway. | <pre>list(object({<br>    name = string<br>    ip_configuration = object({<br>      name                          = string<br>      primary                       = bool<br>      private_ip_address_allocation = string<br>      subnet_id                     = string<br>    })<br>  }))</pre> | `[]` | no |
| pvt\_ip\_subnet\_id | Id of the subnet to deploy Application Gateway. | `string` | `null` | no |
| redirect\_configuration | list of maps for redirect configurations | `list(map(string))` | `[]` | no |
| repository | Terraform current module repo | `string` | `""` | no |
| request\_body\_inspect\_limit\_in\_kb | The maximum request body inspection size in KB for the policy. | `number` | `128` | no |
| request\_routing\_rules | List of Request routing rules to be used for listeners. | <pre>list(object({<br>    name                        = string<br>    rule_type                   = string<br>    http_listener_name          = string<br>    backend_address_pool_name   = optional(string)<br>    backend_http_settings_name  = optional(string)<br>    redirect_configuration_name = optional(string)<br>    rewrite_rule_set_name       = optional(string)<br>    url_path_map_name           = optional(string)<br>    priority                    = number<br>  }))</pre> | `[]` | no |
| resource\_group\_name | Name of the resource group | `string` | `""` | no |
| resource\_position\_prefix | Controls the placement of the resource type keyword (e.g., "vnet", "ddospp") in the resource name.<br><br>- If true, the keyword is prepended: "vnet-core-dev".<br>- If false, the keyword is appended: "core-dev-vnet".<br><br>This helps maintain naming consistency based on organizational preferences. | `bool` | `true` | no |
| rewrite\_rule\_set | List of rewrite rule set including rewrite rules | `any` | `[]` | no |
| sku | The sku pricing model of v1 and v2 | <pre>object({<br>    name     = string<br>    tier     = string<br>    capacity = optional(number)<br>  })</pre> | n/a | yes |
| ssl\_certificates | List of SSL certificates data for Application gateway | <pre>list(object({<br>    name                = string<br>    data                = optional(string)<br>    password            = optional(string)<br>    key_vault_secret_id = optional(string)<br>  }))</pre> | `[]` | no |
| ssl\_policy | Application Gateway SSL configuration | <pre>object({<br>    disabled_protocols   = optional(list(string))<br>    policy_type          = optional(string)<br>    policy_name          = optional(string)<br>    cipher_suites        = optional(list(string))<br>    min_protocol_version = optional(string)<br>  })</pre> | `null` | no |
| subnet\_id | Id of the subnet to deploy Application Gateway. | `string` | `null` | no |
| trusted\_root\_certificates | Trusted root certificates to allow the backend with Azure Application Gateway | <pre>list(object({<br>    name = string<br>    data = string<br>  }))</pre> | `[]` | no |
| url\_path\_maps | List of URL path maps associated to path-based rules. | <pre>list(object({<br>    name                                = string<br>    default_backend_http_settings_name  = optional(string)<br>    default_backend_address_pool_name   = optional(string)<br>    default_redirect_configuration_name = optional(string)<br>    default_rewrite_rule_set_name       = optional(string)<br>    path_rules = list(object({<br>      name                        = string<br>      backend_address_pool_name   = optional(string)<br>      backend_http_settings_name  = optional(string)<br>      paths                       = list(string)<br>      redirect_configuration_name = optional(string)<br>      rewrite_rule_set_name       = optional(string)<br>      firewall_policy_id          = optional(string)<br>    }))<br>  }))</pre> | `[]` | no |
| workspace\_id | log analytics workspace id to pass it to destination details of diagnostic setting of NSG. | `string` | `null` | no |
| zones | A collection of availability zones | `list(string)` | `[]` | no |

## Outputs

| Name | Description |
|------|-------------|
| application\_gateway\_id | The ID of the Application Gateway |
| label\_order | Label order. |
| public\_ip | public ip address id |

