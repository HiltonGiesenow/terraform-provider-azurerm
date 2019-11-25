package azurerm

import (
	"fmt"
	"log"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2019-09-01/network"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/azure"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/tf"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/validate"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/features"
	networkSvc "github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/services/network"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/timeouts"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/utils"
)

func resourceArmVPNServerConfiguration() *schema.Resource {
	return &schema.Resource{
		Create: resourceArmVPNServerConfigurationCreateUpdate,
		Read:   resourceArmVPNServerConfigurationRead,
		Update: resourceArmVPNServerConfigurationCreateUpdate,
		Delete: resourceArmVPNServerConfigurationDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(90 * time.Minute),
			Read:   schema.DefaultTimeout(5 * time.Minute),
			Update: schema.DefaultTimeout(90 * time.Minute),
			Delete: schema.DefaultTimeout(90 * time.Minute),
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validate.NoEmptyStrings,
			},

			"resource_group_name": azure.SchemaResourceGroupName(),

			"client_revoked_certificate": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Required: true,
						},

						"thumbprint": {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},

			"client_root_certificate": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Required: true,
						},

						"public_cert_data": {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},

			"ipsec_policy": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"dh_group": {
							Type:     schema.TypeString,
							Required: true,
							ValidateFunc: validation.StringInSlice([]string{
								string(network.DHGroup1),
								string(network.DHGroup2),
								string(network.DHGroup14),
								string(network.DHGroup24),
								string(network.DHGroup2048),
								string(network.ECP256),
								string(network.ECP384),
								string(network.None),
							}, false),
						},

						"ike_encryption": {
							Type:     schema.TypeString,
							Required: true,
							ValidateFunc: validation.StringInSlice([]string{
								string(network.AES128),
								string(network.AES192),
								string(network.AES256),
								string(network.DES),
								string(network.DES3),
								string(network.GCMAES128),
								string(network.GCMAES256),
							}, false),
						},

						"ike_integrity": {
							Type:     schema.TypeString,
							Required: true,
							ValidateFunc: validation.StringInSlice([]string{
								string(network.IkeIntegrityGCMAES128),
								string(network.IkeIntegrityGCMAES256),
								string(network.IkeIntegrityMD5),
								string(network.IkeIntegritySHA1),
								string(network.IkeIntegritySHA256),
								string(network.IkeIntegritySHA384),
							}, false),
						},

						"ipsec_encryption": {
							Type:     schema.TypeString,
							Required: true,
							ValidateFunc: validation.StringInSlice([]string{
								string(network.IpsecEncryptionAES128),
								string(network.IpsecEncryptionAES192),
								string(network.IpsecEncryptionAES256),
								string(network.IpsecEncryptionDES),
								string(network.IpsecEncryptionDES3),
								string(network.IpsecEncryptionGCMAES128),
								string(network.IpsecEncryptionGCMAES192),
								string(network.IpsecEncryptionGCMAES256),
								string(network.IpsecEncryptionNone),
							}, false),
						},

						"ipsec_integrity": {
							Type:     schema.TypeString,
							Required: true,
							ValidateFunc: validation.StringInSlice([]string{
								string(network.IpsecIntegrityGCMAES128),
								string(network.IpsecIntegrityGCMAES192),
								string(network.IpsecIntegrityGCMAES256),
								string(network.IpsecIntegrityMD5),
								string(network.IpsecIntegritySHA1),
								string(network.IpsecIntegritySHA256),
							}, false),
						},

						"pfs_group": {
							Type:     schema.TypeString,
							Required: true,
							ValidateFunc: validation.StringInSlice([]string{
								string(network.PfsGroupECP256),
								string(network.PfsGroupECP384),
								string(network.PfsGroupNone),
								string(network.PfsGroupPFS1),
								string(network.PfsGroupPFS2),
								string(network.PfsGroupPFS14),
								string(network.PfsGroupPFS24),
								string(network.PfsGroupPFS2048),
								string(network.PfsGroupPFSMM),
							}, false),
						},

						"sa_lifetime_seconds": {
							Type:     schema.TypeInt,
							Required: true,
						},

						"sa_data_size_kilobytes": {
							Type:     schema.TypeInt,
							Required: true,
						},
					},
				},
			},

			"radius_server": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"address": {
							Type:     schema.TypeString,
							Required: true,
						},

						"secret": {
							Type:      schema.TypeString,
							Required:  true,
							Sensitive: true,
						},

						"client_root_certificate": {
							Type:     schema.TypeSet,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": {
										Type:     schema.TypeString,
										Required: true,
									},

									"thumbprint": {
										Type:     schema.TypeString,
										Required: true,
									},
								},
							},
						},

						// TODO: is this Required?
						"server_root_certificate": {
							Type:     schema.TypeSet,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": {
										Type:     schema.TypeString,
										Required: true,
									},

									"public_key_data": {
										Type:     schema.TypeString,
										Required: true,
									},
								},
							},
						},
					},
				},
			},

			"vpn_protocols": {
				// TODO: is this optional?
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
					ValidateFunc: validation.StringInSlice([]string{
						string(network.VpnGatewayTunnelingProtocolIkeV2),
						string(network.VpnGatewayTunnelingProtocolOpenVPN),
					}, false),
				},
			},
		},
	}
}

func resourceArmVPNServerConfigurationCreateUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ArmClient).Network.VpnServerConfigurationsClient
	ctx, cancel := timeouts.ForCreateUpdate(meta.(*ArmClient).StopContext, d)
	defer cancel()

	name := d.Get("name").(string)
	resourceGroup := d.Get("resource_group_name").(string)

	if features.ShouldResourcesBeImported() && d.IsNewResource() {
		existing, err := client.Get(ctx, resourceGroup, name)
		if err != nil {
			if !utils.ResponseWasNotFound(existing.Response) {
				return fmt.Errorf("Error checking for presence of existing VPN Server Configuration %q (Resource Group %q): %+v", name, resourceGroup, err)
			}
		}

		if existing.ID != nil && *existing.ID != "" {
			return tf.ImportAsExistsError("azurerm_vpn_server_configuration", *existing.ID)
		}
	}

	clientRevokedCertsRaw := d.Get("client_revoked_certificate").(*schema.Set).List()
	clientRevokedCerts := expandPointToSiteVpnServerConfigurationClientRevokedCertificates(clientRevokedCertsRaw)

	clientRootCertsRaw := d.Get("client_root_certificate").(*schema.Set).List()
	clientRootCerts := expandPointToSiteVpnServerConfigurationClientRootCertificates(clientRootCertsRaw)

	ipSecPoliciesRaw := d.Get("ipsec_policy").([]interface{})
	ipSecPolicies := expandPointToSiteVpnServerConfigurationIPSecPolicies(ipSecPoliciesRaw)

	vpnProtocolsRaw := d.Get("vpn_protocols").(*schema.Set).List()
	vpnProtocols := expandPointToSiteVpnServerConfigurationVPNProtocols(vpnProtocolsRaw)

	props := network.VpnServerConfigurationProperties{
		VpnClientRootCertificates:    clientRootCerts,
		VpnClientRevokedCertificates: clientRevokedCerts,
		VpnClientIpsecPolicies:       ipSecPolicies,
		VpnProtocols:                 vpnProtocols,
	}

	radiusServerRaw := d.Get("radius_server").([]interface{})
	radiusServer := expandPointToSiteVpnServerConfigurationRadiusServer(radiusServerRaw)
	if radiusServer != nil {
		props.RadiusServerAddress = utils.String(radiusServer.address)
		props.RadiusServerSecret = utils.String(radiusServer.secret)
		props.RadiusClientRootCertificates = radiusServer.clientRootCertificates
		props.RadiusServerRootCertificates = radiusServer.serverRootCertificates
	}

	parameters := network.VpnServerConfiguration{
		VpnServerConfigurationProperties: &props,
	}
	future, err := client.CreateOrUpdate(ctx, resourceGroup, name, parameters)
	if err != nil {
		return fmt.Errorf("Error creating VPN Server Configuration %q (Resource Group %q): %+v", name, resourceGroup, err)
	}
	if err := future.WaitForCompletionRef(ctx, client.Client); err != nil {
		return fmt.Errorf("Error waiting for creation of VPN Server Configuration %q (Virtual WAN %q / Resource Group %q): %+v", name, resourceGroup, err)
	}

	resp, err := client.Get(ctx, resourceGroup, name)
	if err != nil {
		return fmt.Errorf("Error retrieving VPN Server Configuration %q (Virtual WAN %q / Resource Group %q): %+v", name, resourceGroup, err)
	}

	d.SetId(*resp.ID)

	return resourceArmVPNServerConfigurationRead(d, meta)
}

func resourceArmVPNServerConfigurationRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ArmClient).Network.VpnServerConfigurationsClient
	ctx, cancel := timeouts.ForRead(meta.(*ArmClient).StopContext, d)
	defer cancel()

	id, err := networkSvc.ParseVpnServerConfigurationID(d.Id())
	if err != nil {
		return err
	}

	resourceGroup := id.Base.ResourceGroup

	resp, err := client.Get(ctx, resourceGroup, id.Name)
	if err != nil {
		if utils.ResponseWasNotFound(resp.Response) {
			log.Printf("[DEBUG] VPN Server Configuration %q was not found in Resource Group %q - removing from state!", id.Name, resourceGroup)
			d.SetId("")
			return nil
		}

		return fmt.Errorf("Error retrieving Point-To-Site VPN Server Configuration %q (Resource Group %q): %+v", id.Name, resourceGroup, err)
	}

	d.Set("name", id.Name)
	d.Set("resource_group_name", resourceGroup)

	if props := resp.VpnServerConfigurationProperties; props != nil {
		flattenedClientRootCerts := flattenPointToSiteVpnServerConfigurationClientRootCertificates(props.VpnClientRootCertificates)
		if err := d.Set("client_root_certificate", flattenedClientRootCerts); err != nil {
			return fmt.Errorf("Error setting `client_root_certificate`: %+v", err)
		}

		flattenedClientRevokedCerts := flattenPointToSiteVpnServerConfigurationClientRevokedCertificates(props.VpnClientRevokedCertificates)
		if err := d.Set("client_revoked_certificate", flattenedClientRevokedCerts); err != nil {
			return fmt.Errorf("Error setting `client_revoked_certificate`: %+v", err)
		}

		flattenedIPSecPolicies := flattenPointToSiteVpnServerConfigurationIPSecPolicies(props.VpnClientIpsecPolicies)
		if err := d.Set("ipsec_policy", flattenedIPSecPolicies); err != nil {
			return fmt.Errorf("Error setting `ipsec_policy`: %+v", err)
		}

		flattenedRadiusServer := flattenPointToSiteVpnServerConfigurationRadiusServer(props)
		if err := d.Set("radius_server", flattenedRadiusServer); err != nil {
			return fmt.Errorf("Error setting `radius_server`: %+v", err)
		}

		flattenedVpnProtocols := flattenPointToSiteVpnServerConfigurationVPNProtocols(props.VpnProtocols)
		if err := d.Set("vpn_protocols", schema.NewSet(schema.HashString, flattenedVpnProtocols)); err != nil {
			return fmt.Errorf("Error setting `vpn_protocols`: %+v", err)
		}
	}

	return nil
}

func resourceArmVPNServerConfigurationDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ArmClient).Network.VpnServerConfigurationsClient
	ctx, cancel := timeouts.ForDelete(meta.(*ArmClient).StopContext, d)
	defer cancel()

	id, err := networkSvc.ParseVpnServerConfigurationID(d.Id())
	if err != nil {
		return err
	}

	resourceGroup := id.Base.ResourceGroup

	future, err := client.Delete(ctx, resourceGroup, id.Name)
	if err != nil {
		return fmt.Errorf("Error deleting VPN Server Configuration %q (Resource Group %q): %+v", id.Name, resourceGroup, err)
	}

	if err = future.WaitForCompletionRef(ctx, client.Client); err != nil {
		return fmt.Errorf("Error waiting for deletion of VPN Server Configuration %q (Resource Group %q): %+v", id.Name, resourceGroup, err)
	}

	return nil
}

func expandPointToSiteVpnServerConfigurationClientRootCertificates(input []interface{}) *[]network.VpnServerConfigVpnClientRootCertificate {
	clientRootCertificates := make([]network.VpnServerConfigVpnClientRootCertificate, 0)

	for _, v := range input {
		raw := v.(map[string]interface{})
		clientRootCertificates = append(clientRootCertificates, network.VpnServerConfigVpnClientRootCertificate{
			Name:           utils.String(raw["name"].(string)),
			PublicCertData: utils.String(raw["public_cert_data"].(string)),
		})
	}

	return &clientRootCertificates
}

func flattenPointToSiteVpnServerConfigurationClientRootCertificates(input *[]network.VpnServerConfigVpnClientRootCertificate) []interface{} {
	if input == nil {
		return []interface{}{}
	}

	output := make([]interface{}, 0)

	for _, v := range *input {
		name := ""
		if v.Name != nil {
			name = *v.Name
		}

		publicCertData := ""
		if v.PublicCertData != nil {
			publicCertData = *v.PublicCertData
		}

		output = append(output, map[string]interface{}{
			"name":             name,
			"public_cert_data": publicCertData,
		})
	}

	return output
}

func expandPointToSiteVpnServerConfigurationClientRevokedCertificates(input []interface{}) *[]network.VpnServerConfigVpnClientRevokedCertificate {
	clientRevokedCertificates := make([]network.VpnServerConfigVpnClientRevokedCertificate, 0)

	for _, v := range input {
		raw := v.(map[string]interface{})
		clientRevokedCertificates = append(clientRevokedCertificates, network.VpnServerConfigVpnClientRevokedCertificate{
			Name:       utils.String(raw["name"].(string)),
			Thumbprint: utils.String(raw["thumbprint"].(string)),
		})
	}

	return &clientRevokedCertificates
}

func flattenPointToSiteVpnServerConfigurationClientRevokedCertificates(input *[]network.VpnServerConfigVpnClientRevokedCertificate) []interface{} {
	if input == nil {
		return []interface{}{}
	}

	output := make([]interface{}, 0)
	for _, v := range *input {
		name := ""
		if v.Name != nil {
			name = *v.Name
		}

		thumbprint := ""
		if v.Thumbprint != nil {
			thumbprint = *v.Thumbprint
		}

		output = append(output, map[string]interface{}{
			"name":       name,
			"thumbprint": thumbprint,
		})
	}
	return output
}

func expandPointToSiteVpnServerConfigurationIPSecPolicies(input []interface{}) *[]network.IpsecPolicy {
	ipSecPolicies := make([]network.IpsecPolicy, 0)

	for _, raw := range input {
		v := raw.(map[string]interface{})
		ipSecPolicies = append(ipSecPolicies, network.IpsecPolicy{
			DhGroup:             network.DhGroup(v["dh_group"].(string)),
			IkeEncryption:       network.IkeEncryption(v["ike_encryption"].(string)),
			IkeIntegrity:        network.IkeIntegrity(v["ike_integrity"].(string)),
			IpsecEncryption:     network.IpsecEncryption(v["ipsec_encryption"].(string)),
			IpsecIntegrity:      network.IpsecIntegrity(v["ipsec_integrity"].(string)),
			PfsGroup:            network.PfsGroup(v["pfs_group"].(string)),
			SaLifeTimeSeconds:   utils.Int32(int32(v["sa_lifetime_seconds"].(int))),
			SaDataSizeKilobytes: utils.Int32(int32(v["sa_data_size_kilobytes"].(int))),
		})
	}

	return &ipSecPolicies
}

func flattenPointToSiteVpnServerConfigurationIPSecPolicies(input *[]network.IpsecPolicy) []interface{} {
	if input == nil {
		return []interface{}{}
	}

	output := make([]interface{}, 0)
	for _, v := range *input {
		saDataSizeKilobytes := 0
		if v.SaDataSizeKilobytes != nil {
			saDataSizeKilobytes = int(*v.SaDataSizeKilobytes)
		}

		saLifeTimeSeconds := 0
		if v.SaLifeTimeSeconds != nil {
			saLifeTimeSeconds = int(*v.SaLifeTimeSeconds)
		}

		output = append(output, map[string]interface{}{
			"dh_group":               string(v.DhGroup),
			"ipsec_encryption":       string(v.IpsecEncryption),
			"ipsec_integrity":        string(v.IpsecIntegrity),
			"ike_encryption":         string(v.IkeEncryption),
			"ike_integrity":          string(v.IkeIntegrity),
			"pfs_group":              string(v.PfsGroup),
			"sa_data_size_kilobytes": saDataSizeKilobytes,
			"sa_lifetime_seconds":    saLifeTimeSeconds,
		})
	}
	return output
}

type vpnServerConfigurationRadiusServer struct {
	address                string
	secret                 string
	clientRootCertificates *[]network.VpnServerConfigRadiusClientRootCertificate
	serverRootCertificates *[]network.VpnServerConfigRadiusServerRootCertificate
}

func expandPointToSiteVpnServerConfigurationRadiusServer(input []interface{}) *vpnServerConfigurationRadiusServer {
	if len(input) == 0 {
		return nil
	}

	val := input[0].(map[string]interface{})

	clientRootCertificates := make([]network.VpnServerConfigRadiusClientRootCertificate, 0)
	clientRootCertsRaw := val["client_root_certificate"].(*schema.Set).List()
	for _, raw := range clientRootCertsRaw {
		v := raw.(map[string]interface{})
		clientRootCertificates = append(clientRootCertificates, network.VpnServerConfigRadiusClientRootCertificate{
			Name:       utils.String(v["name"].(string)),
			Thumbprint: utils.String(v["thumbprint"].(string)),
		})
	}

	serverRootCertificates := make([]network.VpnServerConfigRadiusServerRootCertificate, 0)
	serverRootCertsRaw := val["server_root_certificate"].(*schema.Set).List()
	for _, raw := range serverRootCertsRaw {
		v := raw.(map[string]interface{})
		serverRootCertificates = append(serverRootCertificates, network.VpnServerConfigRadiusServerRootCertificate{
			Name:           utils.String(v["name"].(string)),
			PublicCertData: utils.String(v["public_cert_data"].(string)),
		})
	}

	return &vpnServerConfigurationRadiusServer{
		address:                val["address"].(string),
		secret:                 val["secret"].(string),
		clientRootCertificates: &clientRootCertificates,
		serverRootCertificates: &serverRootCertificates,
	}
}

func flattenPointToSiteVpnServerConfigurationRadiusServer(input *network.VpnServerConfigurationProperties) []interface{} {
	if input == nil {
		return []interface{}{}
	}

	clientRootCertificates := make([]interface{}, 0)
	if input.RadiusClientRootCertificates != nil {
		for _, v := range *input.RadiusClientRootCertificates {
			name := ""
			if v.Name != nil {
				name = *v.Name
			}

			thumbprint := ""
			if v.Thumbprint != nil {
				thumbprint = *v.Thumbprint
			}

			clientRootCertificates = append(clientRootCertificates, map[string]interface{}{
				"name":       name,
				"thumbprint": thumbprint,
			})
		}
	}

	radiusAddress := ""
	if input.RadiusServerAddress != nil {
		radiusAddress = *input.RadiusServerAddress
	}

	// TODO: confirm if secret is returned or if we need to look it up
	radiusSecret := ""
	if input.RadiusServerSecret != nil {
		radiusSecret = *input.RadiusServerSecret
	}

	serverRootCertificates := make([]interface{}, 0)
	if input.RadiusServerRootCertificates != nil {
		for _, v := range *input.RadiusServerRootCertificates {
			name := ""
			if v.Name != nil {
				name = *v.Name
			}

			publicCertData := ""
			if v.PublicCertData != nil {
				publicCertData = *v.PublicCertData
			}

			serverRootCertificates = append(serverRootCertificates, map[string]interface{}{
				"name":             name,
				"public_cert_data": publicCertData,
			})
		}
	}

	return []interface{}{
		map[string]interface{}{
			"address":                 radiusAddress,
			"client_root_certificate": clientRootCertificates,
			"secret":                  radiusSecret,
			"server_root_certificate": serverRootCertificates,
		},
	}
}

func expandPointToSiteVpnServerConfigurationVPNProtocols(input []interface{}) *[]network.VpnGatewayTunnelingProtocol {
	vpnProtocols := make([]network.VpnGatewayTunnelingProtocol, 0)

	for _, v := range input {
		vpnProtocols = append(vpnProtocols, network.VpnGatewayTunnelingProtocol(v.(string)))
	}

	return &vpnProtocols
}

func flattenPointToSiteVpnServerConfigurationVPNProtocols(input *[]network.VpnGatewayTunnelingProtocol) []interface{} {
	if input == nil {
		return []interface{}{}
	}

	output := make([]interface{}, 0)

	for _, v := range *input {
		output = append(output, string(v))
	}

	return output
}
