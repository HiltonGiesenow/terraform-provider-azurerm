package network

import (
	"fmt"

	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/azure"
)

type VirtualHubResourceID struct {
	Base azure.ResourceID

	Name string
}

// TODO: tests & a validation function

func ParseVirtualHubID(input string) (*VirtualHubResourceID, error) {
	id, err := azure.ParseAzureResourceID(input)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] Unable to parse Virtual Hub ID %q: %+v", input, err)
	}

	virtualHub := VirtualHubResourceID{
		Base: *id,
		Name: id.Path["virtualHubs"],
	}

	if virtualHub.Name == "" {
		return nil, fmt.Errorf("ID was missing the `virtualHubs` element")
	}

	return &virtualHub, nil
}
