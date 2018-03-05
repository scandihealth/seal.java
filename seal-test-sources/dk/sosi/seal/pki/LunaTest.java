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

import com.chrysalisits.crypto.LunaJCAProvider;
import com.chrysalisits.crypto.LunaTokenManager;
import com.chrysalisits.cryptox.LunaJCEProvider;
import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.AuthenticationLevel;
import dk.sosi.seal.model.CareProvider;
import dk.sosi.seal.model.IDCard;
import dk.sosi.seal.model.Request;
import dk.sosi.seal.model.constants.SubjectIdentifierTypeValues;
import dk.sosi.seal.vault.CredentialPair;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.vault.LunaCredentialVault;
import dk.sosi.seal.xml.XmlUtil;
import org.junit.Ignore;
import org.junit.Test;

import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Properties;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class LunaTest {

    @Test
    @Ignore
    public void test() throws Exception {
        Security.addProvider(new LunaJCAProvider());
        Security.addProvider(new LunaJCEProvider());

        LunaTokenManager tokenManager = LunaTokenManager.getInstance();
        tokenManager.Login(1, "L5sC-W7s7-WANS-6ACT");

        KeyStore lunaKS = KeyStore.getInstance("Luna");
        lunaKS.load(null, null);
        Certificate certificate = lunaKS.getCertificate(CredentialVault.ALIAS_SYSTEM);
        assertNotNull(certificate);

        PublicKey pk = certificate.getPublicKey();
        assertNotNull(pk);

        String certificateAlias = lunaKS.getCertificateAlias(certificate);
        assertNotNull(certificateAlias);
        assertEquals(CredentialVault.ALIAS_SYSTEM, certificateAlias);

        Key key = lunaKS.getKey(CredentialVault.ALIAS_SYSTEM, null);
        assertNotNull(key);

        // lunaKS.setKeyEntry(CredentialVault.ALIAS_SYSTEM, null, null);

        LunaCredentialVault lcv = new LunaCredentialVault(prop());

        CredentialPair systemCredentialPair = lcv.getSystemCredentialPair();
        assertNotNull(systemCredentialPair);

        SOSIFactory clientFactory = CredentialVaultTestUtil.createOCES2SOSIFactory(lcv);

        CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "12345", "someOrg");
        IDCard clientIdCard = clientFactory.createNewSystemIDCard("SOSITEST", careProvider, AuthenticationLevel.VOCES_TRUSTED_SYSTEM, null, null, clientFactory.getCredentialVault().getSystemCredentialPair().getCertificate(), null);

        Request clientRequest = clientFactory.createNewRequest(true, "oces2testflow");
        clientRequest.setIDCard(clientIdCard);

        // Make request document.
        clientRequest.serialize2DOMDocument(XmlUtil.createEmptyDocument());
    }

    private Properties prop() {
        Properties prop = new Properties();
        prop.setProperty(LunaCredentialVault.PROPERTYNAME_LUNA_CREDENTIAL_VAULT_PWD, "L5sC-W7s7-WANS-6ACT");
        return prop;
    }
}
