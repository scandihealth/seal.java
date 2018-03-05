/*
 * The MIT License
 *
 * Original work sponsored and donated by National Board of e-Health (NSI), Denmark (http://www.nsi.dk)
 *
 * Copyright (C) 2011 National Board of e-Health (NSI), Denmark (http://www.nsi.dk)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * $HeadURL$
 * $Id$
 */

package dk.sosi.seal.vault;

import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Properties;

/**
 * Implementation of the <code>CredentialVault</code> interface adding support for Luna SA.<br />
 * All operations in this <code>CredentialVault</code> is actually remote operations, and requires access to Luna SA.<br />
 * Connection problems between the client and the Luna SA will result in weird exceptions at unexpected times.<br />
 * Therefore the <code>LunaCredentialVault</code> therefore does not allow direct access to the <code>KeyStore</code>.<br />
 * <br />
 * Furthermore the Luna SA does now allow data to be altered - and therefore setting a system credential pair is also not allowed!<br />
 * <br />
 * Therefore in order to utilize this class, the following things must be available:
 * <ul>
 * <li>Access to a Luna SA
 * <li>Password to a Luna SA.
 * <li>Default Luna SA partition linked to the user/password containing a alias of <code>SOSI:ALIAS_SYSTEM</code>.
 * </ul>
 * <br />
 * The password used for the Luna SA is assigned using the property <code>dk.sosi.seal.vault.LunaCredentialVault.pwd</code>.
 *
 * There should only be one instance of this class for a given installation
 *
 * @author ads
 * @author $LastChangedBy: ads@lakeside.dk $
 * @since 2.0
 */
public class LunaCredentialVault implements PropertyConfiguredCredentialVault {

    // TODO make this class a singleton

    public static final String PROPERTYNAME_LUNAHELPER = "dk.sosi.seal.vault.lunahelper";
    public static final String DEFAULT_LUNAHELPER = "dk.sosi.seal.vault.LunaCredentialVaultHelperImpl";
    public static final String PROPERTYNAME_LUNA_CREDENTIAL_VAULT_PWD = "dk.sosi.seal.vault.LunaCredentialVault.pwd";
    public static final String PROPERTYNAME_LUNA_CREDENTIAL_VAULT_SLOT = "dk.sosi.seal.vault.LunaCredentialVault.slot";
    public static final String PROPERTYNAME_CREDENTIAL_VAULT_ALIAS = "dk.sosi.seal.vault.CredentialVault.alias";

    private final Properties properties;
    private final String alias;

    private LunaCredentialVaultHelper lunaHelper;
    private volatile KeyStore lunaKS;

    public LunaCredentialVault(Properties properties) {
        this.properties = properties;
        try {
            lunaHelper = (LunaCredentialVaultHelper)Class.forName(properties.getProperty(PROPERTYNAME_LUNAHELPER, DEFAULT_LUNAHELPER)).newInstance();
            lunaHelper.initialize(properties);

            alias = properties.getProperty(PROPERTYNAME_CREDENTIAL_VAULT_ALIAS, ALIAS_SYSTEM);

        } catch (InstantiationException e) {
            throw new CredentialVaultException("Error initializing helper class", e);
        } catch (IllegalAccessException e) {
            throw new CredentialVaultException("Error initializing helper class", e);
        } catch (ClassNotFoundException e) {
            throw new CredentialVaultException("Error initializing helper class", e);
        }
    }

    public KeyStore getKeyStore() {
        throw new UnsupportedOperationException("Not supported by the LunaCredentialVault");
    }

    public CredentialPair getSystemCredentialPair() throws CredentialVaultException {
        Throwable throwable = null;

        int retryCount = 0;
        while (retryCount < 2) {
            retryCount++;

            try {
                if(getInternalKeyStore().getKey(alias, null) == null)
                    return null; // NOPMD
                return new CredentialPair((X509Certificate)getInternalKeyStore().getCertificate(alias), (PrivateKey)getInternalKeyStore().getKey(alias, null));
            } catch (NoSuchAlgorithmException ex) {
                reinitialize();
                throwable = ex;
            } catch (UnrecoverableKeyException ex) {
                reinitialize();
                throwable = ex;
            } catch (KeyStoreException ex) {
                reinitialize();
                throwable = ex;
            } catch (ProviderException ex) {
                reinitialize();
                throwable = ex;
            }
        }
        throw new CredentialVaultException("Unable to access the Luna box", throwable);
    }

    public boolean isTrustedCertificate(X509Certificate certificate) throws CredentialVaultException {
        try {
            return getInternalKeyStore().getCertificateAlias(certificate) != null;
        } catch (KeyStoreException e) {
            throw new CredentialVaultException("Unable to query underlying keystore", e);
        }
    }

    public void logout() {
        lunaHelper.logout();
    }

    public void reinitialize() {
        lunaKS = null;
        lunaHelper.reinitialize();
    }

    public void setSystemCredentialPair(CredentialPair credentialPair) throws CredentialVaultException {
        throw new UnsupportedOperationException("Not supported by the LunaCredentialVault");
    }

    public Properties getProperties() {
        return properties;
    }

    private KeyStore getInternalKeyStore() {
        KeyStore keyStore = lunaKS;
        if (keyStore == null) {
            synchronized (this) {
                keyStore = lunaKS;
                if (keyStore == null) {
                    lunaKS = keyStore = lunaHelper.getKeyStore();
                }
            }
        }
        return keyStore;
    }
}