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
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.vault.GenericCredentialVault;
import dk.sosi.seal.xml.XmlUtil;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.*;

import static junit.framework.Assert.*;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class CredentialVaultSignatureProviderTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testNullCredentialVault() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("CredentialVault cannot be null");

        SignatureProviderFactory.fromCredentialVault(null);
    }

    @Test
    public void testSigning() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        GenericCredentialVault vault = CredentialVaultTestUtil.getCredentialVault();

        CredentialVaultSignatureProvider provider = SignatureProviderFactory.fromCredentialVault(vault, null);
        String msg = "This is a test message";
        SignatureProvider.SignatureResult result = provider.sign(msg.getBytes());

        assertNotNull(result.getSignature());
        assertEquals(vault.getSystemCredentialPair().getCertificate(), result.getCertificate());

        String cryptoProvider = SignatureUtil.getCryptoProvider(null, SOSIFactory.PROPERTYNAME_SOSI_CRYPTOPROVIDER_SHA1WITHRSA);
        Signature jceSign = Signature.getInstance("SHA1withRSA", cryptoProvider);
        jceSign.initVerify(vault.getSystemCredentialPair().getCertificate());
        jceSign.update(msg.getBytes());

        assertTrue(jceSign.verify(XmlUtil.fromBase64(result.getSignature())));

    }

}
