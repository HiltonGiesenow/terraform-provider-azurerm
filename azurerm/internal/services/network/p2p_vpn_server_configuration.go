package network

import (
	"fmt"

	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/azure"
)

type VpnServerConfigurationResourceID struct {
	Base azure.ResourceID

	Name string
}

// TODO: tests & a validation function

func ParseVpnServerConfigurationID(input string) (*VpnServerConfigurationResourceID, error) {
	id, err := azure.ParseAzureResourceID(input)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] Unable to parse VPN Server Configuration ID %q: %+v", input, err)
	}

	vpnServerConfigurationResourceID := VpnServerConfigurationResourceID{
		Base: *id,
		Name: id.Path["vpnServerConfigurations"],
	}
	if vpnServerConfigurationResourceID.Name == "" {
		return nil, fmt.Errorf("ID was missing the `vpnServerConfigurations` element")
	}

	return &vpnServerConfigurationResourceID, nil
}
