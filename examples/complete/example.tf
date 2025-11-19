# Azurerm Provider configuration
provider "azurerm" {
  features {}
}

data "azurerm_client_config" "current_client_config" {
  
}

##-----------------------------------------------------------------------------
## Resources
##-----------------------------------------------------------------------------

locals {
  name        = "cd"
  environment = "test"
  label_order = ["name", "environment"]
  location    = "Canada Central"
}

module "resource_group" {
  source      = "terraform-az-modules/resource-group/azurerm"
  version     = "1.0.2"
  name        = local.name
  environment = local.environment
  label_order = local.label_order
  location    = local.location
}

module "vnet" {
  source                 = "terraform-az-modules/vnet/azurerm"
  version                = "1.0.3"
  name                   = local.name
  label_order            = local.label_order
  environment            = local.environment
  resource_group_name    = module.resource_group.resource_group_name
  location               = module.resource_group.resource_group_location
  address_spaces         = ["10.0.0.0/16"]
  enable_ddos_pp         = false
  enable_network_watcher = false # To be set true when network security group flow logs are to be tracked and network watcher with specific name is to be deployed.
}

module "subnet" {
  source               = "terraform-az-modules/subnet/azurerm"
  version              = "1.0.1"
  environment          = local.environment
  label_order          = local.label_order
  resource_group_name  = module.resource_group.resource_group_name
  location             = module.resource_group.resource_group_location
  virtual_network_name = module.vnet.vnet_name
  subnets = [
    {
      name            = "subnet1"
      subnet_prefixes = ["10.0.0.0/24"]
    },
    {
      name            = "subnet2"
      subnet_prefixes = ["10.0.1.0/24"]
    }
  ]
}

##-----------------------------------------------------------------------------
## security-group module call.
##-----------------------------------------------------------------------------
module "security_group" {
  source              = "terraform-az-modules/nsg/azurerm"
  version             = "1.0.1"
  name                = local.name
  environment         = local.environment
  location            = module.resource_group.resource_group_location
  resource_group_name = module.resource_group.resource_group_name
  inbound_rules = [
    {
      name                       = "ssh"
      priority                   = 101
      access                     = "Allow"
      protocol                   = "Tcp"
      source_address_prefix      = "0.0.0.0/0"
      source_port_range          = "*"
      destination_address_prefix = "0.0.0.0/0"
      destination_port_range     = "22"
      description                = "ssh allowed port"
    },
    {
      name                       = "Http"
      priority                   = 102
      access                     = "Allow"
      protocol                   = "Tcp"
      source_address_prefix      = "0.0.0.0/0"
      source_port_range          = "*"
      destination_address_prefix = "0.0.0.0/0"
      destination_port_range     = "80"
      description                = "Http allowed port"
    },
    {
      name                       = "Https"
      priority                   = 103
      access                     = "Allow"
      protocol                   = "Tcp"
      source_address_prefix      = "0.0.0.0/0"
      source_port_range          = "*"
      destination_address_prefix = "0.0.0.0/0"
      destination_port_range     = "443"
      description                = "Https allowed port"
    }
  ]

}

# ------------------------------------------------------------------------------
# Log Analytics
# ------------------------------------------------------------------------------
module "log-analytics" {
  source                      = "terraform-az-modules/log-analytics/azurerm"
  version                     = "1.0.2"
  name                        = local.name
  environment                 = local.environment
  location                    = module.resource_group.resource_group_location
  label_order                 = local.label_order
  log_analytics_workspace_sku = "PerGB2018"
  log_analytics_workspace_id  = module.log-analytics.workspace_id
  resource_group_name         = module.resource_group.resource_group_name
}

module "application-gateway" {
  source = "./../.."
  # depends_on          = [module.virtual-machine]
  resource_group_name = module.resource_group.resource_group_name
  location            = module.resource_group.resource_group_location
  name                = local.name
  label_order         = local.label_order
  environment         = local.environment
  subnet_id           = module.subnet.subnet_ids["subnet2"]
  # virtual_network_id  = module.vnet.vnet_id
  enable_diagnostic   = true
  workspace_id        = module.log-analytics.workspace_id

  sku = {
    name     = "Standard_v2"
    tier     = "Standard_v2"
    capacity = 1
  }

  health_probes = [{
    name                = "healthProbe1"
    protocol            = "Http"
    host                = "127.0.0.1"
    path                = "/"
    interval            = 30
    timeout             = 30
    unhealthy_threshold = 3
    }
  ]

  #front-end settings
  # frontend_port_name             = "sappgw-feport"
  frontend_ip_configuration_name = "sappgw-feip"
  # frontend_priv_ip_configuration_name = "appgw-fepvtip"

  frontend_port_settings = [
    {
      name = "sappgw-feport-80" # Use frontend_port_name here
      port = 80
    },
    {
      name = "sappgw-feport-443" #same name to be used in http_listener
      port = 443
    }
  ]

  backend_address_pools = [
    {
      name         = "appgw-testgateway-01pool-vm"
      ip_addresses = module.virtual-machine.network_interface_private_ip_addresses[0]
    }
  ]

  backend_http_settings = [
    {
      name                  = "appgw-testgateway-http-set1"
      cookie_based_affinity = "Disabled"
      path                  = "/"
      port                  = 80
      enable_https          = false
      request_timeout       = 30
      # probe_name            = "appgw-testgateway-Central India-probe1" # Remove this if `health_probes` object is not defined.
      connection_draining = {
        enable_connection_draining = true
        drain_timeout_sec          = 300

      }
    },
    {
      name                  = "appgw-testgateway-http-set2"
      cookie_based_affinity = "Enabled"
      path                  = "/"
      port                  = 80
      enable_https          = false
      request_timeout       = 30
    }
  ]

  http_listeners = [
    {
      name                           = "appgw-testgatewayhtln"
      frontend_ip_configuration_name = "sappgw-feip"       # Using publicfront end ip name as http listener 
      frontend_port_name             = "sappgw-feport-80" # Assign from frontend_port_settings
      ssl_certificate_name           = null
      host_name                      = null
    }
  ]

  request_routing_rules = [
    {
      name                       = "appgw-testgateway-rqrt"
      rule_type                  = "Basic"
      http_listener_name         = "appgw-testgatewayhtln" # Match with http_listener name
      backend_address_pool_name  = "appgw-testgateway-01pool-vm"
      backend_http_settings_name = "appgw-testgateway-http-set1"
      priority                   = 100
    }
  ]


  # keyvault_id = module.vault.id

  # A list with a single user managed identity id to be assigned to access Keyvault
  # identity_ids = ["${azurermrm_user_assigned_identity.example.id}"]
}

##-----------------------------------------------------------------------------
## linux virtual-machine module call.
##-----------------------------------------------------------------------------
module "virtual-machine" {
  source  = "clouddrove/virtual-machine/azure"
  version = "2.0.3"
  #   depends_on          = [module.key_vault]
  name                = local.name
  environment         = local.environment
  resource_group_name = module.resource_group.resource_group_name
  location            = module.resource_group.resource_group_location
  is_vm_linux         = true
  user_object_id = {
    "user1" = {
      role_definition_name = "Virtual Machine Administrator Login"
      principal_id         = data.azurerm_client_config.current_client_config.object_id
    },
  }
  ## Network Interface
  subnet_id            = [module.subnet.subnet_ids["subnet1"]]
  private_ip_addresses = ["10.0.0.4"]
  #nsg
  network_interface_sg_enabled = true
  network_security_group_id    = module.security_group.id
  ## Public IP
  public_ip_enabled = true
  ## Virtual Machine
  vm_size                         = "Standard_B1s"
  public_key                      = "ssh-rsa AAAA"
  admin_username                  = "ubuntu"
  admin_password                  = "admin@1234"
  disable_password_authentication = false
  caching                         = "ReadWrite"
  disk_size_gb                    = 30
  image_publisher                 = "Canonical"
  image_offer                     = "0001-com-ubuntu-server-jammy"
  image_sku                       = "22_04-lts-gen2"
  image_version                   = "latest"
  enable_disk_encryption_set      = false
  #   key_vault_id               = module.key_vault.id
  data_disks = [
    {
      name                 = "disk1"
      disk_size_gb         = 60
      storage_account_type = "StandardSSD_LRS"
    }
  ]
  # Extension
  extensions = [{
    extension_publisher            = "Microsoft.Azure.ActiveDirectory"
    extension_name                 = "AADLogin"
    extension_type                 = "AADSSHLoginForLinux"
    extension_type_handler_version = "1.0"
    auto_upgrade_minor_version     = true
    automatic_upgrade_enabled      = false
  }]
  # 
  #### enable diagnostic setting
  diagnostic_setting_enable = false
  #   log_analytics_workspace_id = module.log-analytics.workspace_id ## when diagnostic_setting_enable enable,  add log analytics workspace id
  # 
  #vm With User Data
  #   user_data = base64encode(file("user-data.sh"))
}