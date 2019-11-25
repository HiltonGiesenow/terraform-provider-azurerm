package network

import (
	"fmt"

	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/azure"
)

type VirtualWanResourceID struct {
	Base azure.ResourceID

	Name string
}

// TODO: tests & a validation function

func ParseVirtualWanID(input string) (*VirtualWanResourceID, error) {
	id, err := azure.ParseAzureResourceID(input)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] Unable to parse Virtual Wan ID %q: %+v", input, err)
	}

	virtualWan := VirtualWanResourceID{
		Base: *id,
		Name: id.Path["virtualWans"],
	}

	if virtualWan.Name == "" {
		return nil, fmt.Errorf("ID was missing the `virtualWans` element")
	}

	return &virtualWan, nil
}
