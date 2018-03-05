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

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.SignatureUtil;
import dk.sosi.seal.vault.CredentialPair;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.xml.XmlUtil;

import java.security.*;
import java.util.Properties;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class CredentialVaultSignatureProvider implements SignatureProvider {

    private final CredentialVault vault;
    private final Properties properties;

    public CredentialVaultSignatureProvider(CredentialVault vault, Properties properties) {
        if (vault == null) {
            throw new IllegalArgumentException("CredentialVault cannot be null");
        }
        this.vault = vault;
        this.properties = properties;
    }

    public SignatureResult sign(byte[] bytes) throws PKIException {

        try {
            String cryptoProvider = getCryptoProvider();
            CredentialPair credentialPair = vault.getSystemCredentialPair();

            Signature jceSign = Signature.getInstance("SHA1withRSA", cryptoProvider);
            jceSign.initSign(credentialPair.getPrivateKey());
            jceSign.update(bytes);

            String signature = XmlUtil.toBase64(jceSign.sign());
            return new SignatureResult(signature, credentialPair.getCertificate());

        } catch (NoSuchProviderException e) {
            throw new PKIException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new PKIException(e);
        } catch (SignatureException e) {
            throw new PKIException(e);
        } catch (InvalidKeyException e) {
            throw new PKIException(e);
        }
    }

    public CredentialVault getCredentialVault() {
        return vault;
    }

    protected String getCryptoProvider() {
        return SignatureUtil.getCryptoProvider(properties, SOSIFactory.PROPERTYNAME_SOSI_CRYPTOPROVIDER_SHA1WITHRSA);
    }

}
