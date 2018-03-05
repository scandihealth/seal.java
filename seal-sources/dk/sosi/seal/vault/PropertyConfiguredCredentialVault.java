package dk.sosi.seal.vault;

import java.util.Properties;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public interface PropertyConfiguredCredentialVault extends CredentialVault {

    /**
     * Returns the underlying properties
     */
    Properties getProperties();

}
