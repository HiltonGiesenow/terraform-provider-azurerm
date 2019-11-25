package network

import (
	"fmt"

	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/azure"
)

type PointToPointVpnServerConfigurationResourceID struct {
	Base azure.ResourceID

	VirtualWanName string
	Name           string
}

// TODO: tests & a validation function

func ParsePointToPointVpnServerConfigurationID(input string) (*PointToPointVpnServerConfigurationResourceID, error) {
	id, err := azure.ParseAzureResourceID(input)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] Unable to parse Virtual Wan ID %q: %+v", input, err)
	}

	// /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/virtualWans/{virtualWanName}/p2sVpnServerConfigurations/{p2SVpnServerConfigurationName}
	pointVpnServerConfigurationResourceID := PointToPointVpnServerConfigurationResourceID{
		Base:           *id,
		VirtualWanName: id.Path["virtualWans"],
		Name:           id.Path["p2sVpnServerConfigurations"],
	}

	if pointVpnServerConfigurationResourceID.VirtualWanName == "" {
		return nil, fmt.Errorf("ID was missing the `virtualWans` element")
	}

	if pointVpnServerConfigurationResourceID.Name == "" {
		return nil, fmt.Errorf("ID was missing the `p2sVpnServerConfigurations` element")
	}

	return &pointVpnServerConfigurationResourceID, nil
}
