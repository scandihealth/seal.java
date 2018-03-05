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

package dk.sosi.seal.pki;

import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.vault.CredentialVaultException;
import dk.sosi.seal.vault.LunaCredentialVault;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.security.ProviderException;
import java.util.Properties;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class LunaCredentialVaultSignatureProvider extends CredentialVaultSignatureProvider{

    private static final Log LOG = LogFactory.getLog(LunaCredentialVaultSignatureProvider.class);
    private static final String LUNA_JCA_PROVIDER = "LunaJCAProvider";

    LunaCredentialVaultSignatureProvider(CredentialVault vault, Properties properties) {
        super(vault, properties);
    }

    @Override
    public SignatureResult sign(byte[] bytes) throws PKIException {

        Exception lastException = null;
        int retryCount = 0;
        while (retryCount < 2) {
            retryCount++;
            try {
                return super.sign(bytes);
            } catch (ProviderException ex) {
                LOG.warn(ex);
                lastException = ex;
                ((LunaCredentialVault) getCredentialVault()).reinitialize();
            } catch (CredentialVaultException ex) {
                LOG.warn(ex);
                lastException = ex;
                ((LunaCredentialVault) getCredentialVault()).reinitialize();
            }
        }
        throw new PKIException("Could sign bytes in Luna HSM", lastException);
    }

    @Override
    protected String getCryptoProvider() {
        return LUNA_JCA_PROVIDER;
    }
}
