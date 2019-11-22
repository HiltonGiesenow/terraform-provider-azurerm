package azurerm

import (
	"fmt"
	"log"

	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2019-07-01/network"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/azure"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/response"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/tf"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/validate"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/features"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/locks"
	aznetwork "github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/services/network"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/tags"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/utils"
)

var virtualHubResourceName = "azurerm_virtual_hub"

func resourceArmVirtualHub() *schema.Resource {
	return &schema.Resource{
		Create: resourceArmVirtualHubCreateUpdate,
		Read:   resourceArmVirtualHubRead,
		Update: resourceArmVirtualHubCreateUpdate,
		Delete: resourceArmVirtualHubDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: aznetwork.ValidateVirtualHubName,
			},

			"resource_group_name": azure.SchemaResourceGroupName(),

			"location": azure.SchemaLocation(),

			"address_prefix": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validate.CIDR,
			},

			"virtual_wan_id": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: azure.ValidateResourceID,
			},

			// TODO: remove this
			"p2s_vpn_gateway_id": {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: azure.ValidateResourceID,
			},

			// TODO: should this be removed?
			"express_route_gateway_id": {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: azure.ValidateResourceID,
			},

			"route": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"address_prefixes": {
							Type:     schema.TypeList,
							Required: true,
							Elem: &schema.Schema{
								Type:         schema.TypeString,
								ValidateFunc: validate.CIDR,
							},
						},
						"next_hop_ip_address": {
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: validate.IPv4Address,
						},
					},
				},
			},

			"tags": tags.Schema(),
		},
	}
}

func resourceArmVirtualHubCreateUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ArmClient).Network.VirtualHubClient
	ctx := meta.(*ArmClient).StopContext

	name := d.Get("name").(string)
	resourceGroup := d.Get("resource_group_name").(string)

	locks.ByName(name, virtualHubResourceName)
	defer locks.UnlockByName(name, virtualHubResourceName)

	if features.ShouldResourcesBeImported() && d.IsNewResource() {
		existing, err := client.Get(ctx, resourceGroup, name)
		if err != nil {
			if !utils.ResponseWasNotFound(existing.Response) {
				return fmt.Errorf("Error checking for present of existing Virtual Hub %q (Resource Group %q): %+v", name, resourceGroup, err)
			}
		}
		if existing.ID != nil && *existing.ID != "" {
			return tf.ImportAsExistsError("azurerm_virtual_hub", *existing.ID)
		}
	}

	location := azure.NormalizeLocation(d.Get("location").(string))
	addressPrefix := d.Get("address_prefix").(string)
	virtualWanId := d.Get("virtual_wan_id").(string)
	route := d.Get("route").(*schema.Set).List()
	t := d.Get("tags").(map[string]interface{})

	parameters := network.VirtualHub{
		Location: utils.String(location),
		VirtualHubProperties: &network.VirtualHubProperties{
			AddressPrefix: utils.String(addressPrefix),
			VirtualWan: &network.SubResource{
				ID: &virtualWanId,
			},
			RouteTable: expandArmVirtualHubRoute(route),
		},
		Tags: tags.Expand(t),
	}

	if v, ok := d.GetOk("p2s_vpn_gateway_id"); ok {
		p2sVpnGatewayId := v.(string)
		parameters.VirtualHubProperties.P2SVpnGateway = &network.SubResource{
			ID: &p2sVpnGatewayId,
		}
	}
	if v, ok := d.GetOk("express_route_gateway_id"); ok {
		expressRouteGatewayId := v.(string)
		parameters.VirtualHubProperties.ExpressRouteGateway = &network.SubResource{
			ID: &expressRouteGatewayId,
		}
	}

	future, err := client.CreateOrUpdate(ctx, resourceGroup, name, parameters)
	if err != nil {
		return fmt.Errorf("Error creating Virtual Hub %q (Resource Group %q): %+v", name, resourceGroup, err)
	}
	if err = future.WaitForCompletionRef(ctx, client.Client); err != nil {
		return fmt.Errorf("Error waiting for creation of Virtual Hub %q (Resource Group %q): %+v", name, resourceGroup, err)
	}

	resp, err := client.Get(ctx, resourceGroup, name)
	if err != nil {
		return fmt.Errorf("Error retrieving Virtual Hub %q (Resource Group %q): %+v", name, resourceGroup, err)
	}
	if resp.ID == nil {
		return fmt.Errorf("Cannot read Virtual Hub %q (Resource Group %q) ID", name, resourceGroup)
	}
	d.SetId(*resp.ID)

	return resourceArmVirtualHubRead(d, meta)
}

func resourceArmVirtualHubRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ArmClient).Network.VirtualHubClient
	ctx := meta.(*ArmClient).StopContext

	id, err := aznetwork.ParseVirtualHubID(d.Id())
	if err != nil {
		return err
	}
	resourceGroup := id.Base.ResourceGroup
	name := id.Name

	resp, err := client.Get(ctx, resourceGroup, name)
	if err != nil {
		if utils.ResponseWasNotFound(resp.Response) {
			log.Printf("[INFO] Virtual Hub %q does not exist - removing from state", d.Id())
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Error reading Virtual Hub %q (Resource Group %q): %+v", name, resourceGroup, err)
	}

	d.Set("name", resp.Name)
	d.Set("resource_group_name", resourceGroup)
	if location := resp.Location; location != nil {
		d.Set("location", azure.NormalizeLocation(*location))
	}
	if props := resp.VirtualHubProperties; props != nil {
		d.Set("address_prefix", props.AddressPrefix)

		var expressRouteGatewayId *string
		if props.ExpressRouteGateway != nil {
			expressRouteGatewayId = props.ExpressRouteGateway.ID
		}
		d.Set("express_route_gateway_id", expressRouteGatewayId)

		var p2sVpnGatewayId *string
		if props.P2SVpnGateway != nil {
			p2sVpnGatewayId = props.P2SVpnGateway.ID
		}
		d.Set("p2s_vpn_gateway_id", p2sVpnGatewayId)

		if err := d.Set("route", flattenArmVirtualHubRoute(props.RouteTable)); err != nil {
			return fmt.Errorf("Error setting `route`: %+v", err)
		}

		var virtualWanId *string
		if props.VirtualWan != nil {
			virtualWanId = props.VirtualWan.ID
		}
		d.Set("virtual_wan_id", virtualWanId)
	}

	return tags.FlattenAndSet(d, resp.Tags)
}

func resourceArmVirtualHubDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ArmClient).Network.VirtualHubClient
	ctx := meta.(*ArmClient).StopContext

	id, err := aznetwork.ParseVirtualHubID(d.Id())
	if err != nil {
		return err
	}
	resourceGroup := id.Base.ResourceGroup
	name := id.Name

	locks.ByName(name, virtualHubResourceName)
	defer locks.UnlockByName(name, virtualHubResourceName)

	future, err := client.Delete(ctx, resourceGroup, name)
	if err != nil {
		return fmt.Errorf("Error deleting Virtual Hub %q (Resource Group %q): %+v", name, resourceGroup, err)
	}

	if err = future.WaitForCompletionRef(ctx, client.Client); err != nil {
		if !response.WasNotFound(future.Response()) {
			return fmt.Errorf("Error waiting for deleting Virtual Hub %q (Resource Group %q): %+v", name, resourceGroup, err)
		}
	}

	return nil
}

func expandArmVirtualHubRoute(input []interface{}) *network.VirtualHubRouteTable {
	if len(input) == 0 {
		return nil
	}

	results := make([]network.VirtualHubRoute, 0)
	for _, item := range input {
		if item == nil {
			continue
		}

		v := item.(map[string]interface{})
		addressPrefixes := v["address_prefixes"].([]interface{})
		nextHopIpAddress := v["next_hop_ip_address"].(string)

		results = append(results, network.VirtualHubRoute{
			AddressPrefixes:  utils.ExpandStringSlice(addressPrefixes),
			NextHopIPAddress: utils.String(nextHopIpAddress),
		})
	}

	result := network.VirtualHubRouteTable{
		Routes: &results,
	}

	return &result
}

func flattenArmVirtualHubRoute(input *network.VirtualHubRouteTable) []interface{} {
	results := make([]interface{}, 0)
	if input == nil || input.Routes == nil {
		return results
	}

	for _, item := range *input.Routes {
		addressPrefixes := utils.FlattenStringSlice(item.AddressPrefixes)
		nextHopIpAddress := ""

		if item.NextHopIPAddress != nil {
			nextHopIpAddress = *item.NextHopIPAddress
		}

		results = append(results, map[string]interface{}{
			"address_prefixes":    addressPrefixes,
			"next_hop_ip_address": nextHopIpAddress,
		})
	}

	return results
}
