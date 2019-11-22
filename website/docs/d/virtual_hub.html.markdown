---
subcategory: "Network"
layout: "azurerm"
page_title: "Azure Resource Manager: azurerm_virtual_hub"
sidebar_current: "docs-azurerm-datasource-virtual-hub"
description: |-
  Gets information about an existing Virtual Hub
---

# Data Source: azurerm_virtual_hub

Uses this data source to access information about an existing Virtual Hub.


## Virtual Hub Usage

```hcl
data "azurerm_virtual_hub" "example" {
  resource_group = "acctestRG"
  name           = "acctestvirtualhub"
}
output "virtual_hub_id" {
  value = "${data.azurerm_virtual_hub.example.id}"
}
```


## Argument Reference

The following arguments are supported:

* `name` - (Required) The name of the Virtual Hub.

* `resource_group_name` - (Required) The Name of the Resource Group where the Virtual Hub exists.


## Attributes Reference

The following attributes are exported:

* `location` - The Azure Region where the Virtual Hub exists.

* `address_prefix` - The Address Prefix used for this Virtual Hub.

* `express_route_gateway_id` - The ID of an Express Route Gateway used for Express Route connections.

* `p2s_vpn_gateway_id` - The ID of a Point-to-Site VPN Gateway used for Point-to-Site connections.

* `route` - One or more `route` blocks as defined below.

* `s2s_vpn_gateway_id` - The ID of a Site-to-Site VPN Gateway used for Site-to-Site connections.

* `tags` - A mapping of tags to assign to the Virtual Hub.

* `virtual_wan_id` - The ID of a Virtual WAN within which the Virtual Hub exists.

---

The `route` block contains the following:

* `address_prefixes` - List of all addressPrefixes.

* `next_hop_ip_address` - NextHop ip address.
