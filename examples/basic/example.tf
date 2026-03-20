provider "azurerm" {
  features {}
}

module "application-gateway" {
  source = "../../"
}
