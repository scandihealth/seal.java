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

import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.vault.GenericCredentialVault;
import dk.sosi.seal.vault.LunaCredentialVault;
import dk.sosi.seal.vault.LunaCredentialVaultTestHelper;
import org.junit.Test;

import java.util.Properties;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class TestSignatureProviderFactory {

    @Test(expected = IllegalArgumentException.class)
    public void testNullVault() {
        SignatureProviderFactory.fromCredentialVault(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNullVaultWithProperties() {
        SignatureProviderFactory.fromCredentialVault(null, System.getProperties());
    }

    @Test
    public void testConstruction() {
        GenericCredentialVault vault = CredentialVaultTestUtil.getCredentialVault();

        CredentialVaultSignatureProvider signatureProvider = SignatureProviderFactory.fromCredentialVault(vault);
        assertEquals(vault, signatureProvider.getCredentialVault());

        signatureProvider = SignatureProviderFactory.fromCredentialVault(vault, System.getProperties());
        assertEquals(vault, signatureProvider.getCredentialVault());

        signatureProvider = SignatureProviderFactory.fromCredentialVault(vault, null);
        assertEquals(vault, signatureProvider.getCredentialVault());

    }

    @Test
    public void testConstructionWithLunaCredentialVault() {
        Properties properties = new Properties();
        properties.setProperty(LunaCredentialVault.PROPERTYNAME_LUNAHELPER, LunaCredentialVaultTestHelper.class.getName());

        LunaCredentialVault vault = new LunaCredentialVault(properties);

        CredentialVaultSignatureProvider signatureProvider = SignatureProviderFactory.fromCredentialVault(vault);
        assertTrue(signatureProvider instanceof LunaCredentialVaultSignatureProvider);
        assertEquals(vault, signatureProvider.getCredentialVault());

        signatureProvider = SignatureProviderFactory.fromCredentialVault(vault, properties);
        assertTrue(signatureProvider instanceof LunaCredentialVaultSignatureProvider);
        assertEquals(vault, signatureProvider.getCredentialVault());

    }
}
