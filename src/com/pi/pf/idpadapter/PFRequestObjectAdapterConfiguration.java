package com.pi.pf.idpadapter;

import java.util.HashSet;

import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.SelectFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;

import com.pingidentity.sdk.GuiConfigDescriptor;
import com.pingidentity.sdk.PluginDescriptor;

/**
 * The RESTPasswordCredentialValidatorConfiguration class contains PingFederate web GUI configuration parameters for the RESTPasswordCredentialValidator.
 */
public class PFRequestObjectAdapterConfiguration {

	// initialize configuration object
    protected Configuration configuration = null;

    // JWKS url
    private static final String JWKS_URL = "REST JWKS URL";
    private static final String JWKS_URL_DESC = "The URL of the JWKS endpoint, used by PingFederate to dowload the keys to validate the signature";

    // Signature Algorithm
    private static final String SINGNATURE_ALGORITHM = "Signature algorithm";
    private static final String SINGNATURE_ALGORITHM_DESC = "The algorithm used to validate the JWT signature";

    private static final String[] validAlgorithms = new String[] {""};
    
    protected String jwksUrl = null;
    protected String signatureAlgorithm = null;
    
	/**
	 * This method is called by the PingFederate server to push configuration values entered by the administrator via
	 * the dynamically rendered GUI configuration screen in the PingFederate administration console. Your implementation
	 * should use the {@link Configuration} parameter to configure its own internal state as needed. <br/>
	 * <br/>
	 * Each time the PingFederate server creates a new instance of your plugin implementation this method will be
	 * invoked with the proper configuration. All concurrency issues are handled in the server so you don't need to
	 * worry about them here. The server doesn't allow access to your plugin implementation instance until after
	 * creation and configuration is completed.
	 * 
	 * @param configuration
	 *            the Configuration object constructed from the values entered by the user via the GUI.
	 */    
    public void configure(Configuration configuration) {
        this.jwksUrl = configuration.getFieldValue(JWKS_URL);
        this.signatureAlgorithm = configuration.getFieldValue(SINGNATURE_ALGORITHM);
    }

	/**
	 * Returns the {@link PluginDescriptor} that describes this plugin to the PingFederate server. This includes how
	 * PingFederate will render the plugin in the administrative console, and metadata on how PingFederate will treat
	 * this plugin at runtime.
	 * 
	 * @return A {@link PluginDescriptor} that describes this plugin to the PingFederate server.
	 */    
    public PluginDescriptor getPluginDescriptor(PFRequestObjectAdapter adapter) {
    	RequiredFieldValidator requiredFieldValidator = new RequiredFieldValidator();
    	
    	GuiConfigDescriptor guiDescriptor = new GuiConfigDescriptor();
		guiDescriptor.setDescription("Request Object Adapter");
		
        TextFieldDescriptor serviceDescriptor = new TextFieldDescriptor(JWKS_URL, JWKS_URL_DESC);
        serviceDescriptor.addValidator(requiredFieldValidator);
        serviceDescriptor.setDefaultValue("https://client.com/JWKS");
        guiDescriptor.addField(serviceDescriptor);

        SelectFieldDescriptor restMethodDescriptor = new SelectFieldDescriptor(SINGNATURE_ALGORITHM, SINGNATURE_ALGORITHM_DESC, validAlgorithms);
        restMethodDescriptor.addValidator(requiredFieldValidator);
        guiDescriptor.addField(restMethodDescriptor);

        PluginDescriptor pluginDescriptor = new PluginDescriptor("Request Object Adapter", adapter, guiDescriptor);
        HashSet<String> attributes = new HashSet<String>();
        attributes.add("jwtBody");
        pluginDescriptor.setAttributeContractSet(attributes);
		pluginDescriptor.setSupportsExtendedContract(true);
		return pluginDescriptor;
    }
}