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

package dk.sosi.seal.model;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.constants.SubjectIdentifierTypeValues;
import dk.sosi.seal.pki.Federation;
import dk.sosi.seal.pki.SOSIFederation;
import dk.sosi.seal.pki.SOSITestFederation;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.xml.XmlUtil;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.cert.X509Certificate;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class IDCardSignatureTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    private CredentialVault vault;
    private SOSIFactory sosiFactory;
    private Federation federation;

    @Before
    public void setUp() {
        vault = CredentialVaultTestUtil.getVocesCredentialVault();
        sosiFactory = new SOSIFactory(vault, System.getProperties());
        federation = new SOSITestFederation(System.getProperties()) {
            @Override
            public boolean isValidSTSCertificate(X509Certificate certificate) {
                return vault.getSystemCredentialPair().getCertificate().equals(certificate);
            }
        };
    }

    @Test
    public void testUnsignedOnModel() {
        expectedException.expect(ModelException.class);
        expectedException.expectMessage("DOM not initialized");

        createUnsignedUserIDCard(AuthenticationLevel.MOCES_TRUSTED_USER).validateSignature();
    }

    @Test
    public void testUnsignedAfterDeserialization() {
        expectedException.expect(ModelException.class);
        expectedException.expectMessage("IDCard is not signed!");

        Document document = XmlUtil.createEmptyDocument();
        Element serializedIDCard = createUnsignedUserIDCard(AuthenticationLevel.MOCES_TRUSTED_USER).serialize2DOMDocument(sosiFactory, document);
        IDCard idCard = sosiFactory.deserializeIDCard(XmlUtil.node2String(serializedIDCard));
        idCard.validateSignature();
    }

    @Test
    public void testAuthenticationLevelTooLow() {
        expectedException.expect(ModelException.class);
        expectedException.expectMessage("AuthenticationLevel does not support signature");

        createUnsignedUserIDCard(AuthenticationLevel.NO_AUTHENTICATION).validateSignature();
    }

    @Test
    public void testSignatureValidationOK() {
        createSignedUserIDCard().validateSignature();
    }

    @Test
    public void testBrokenSignature() {
        expectedException.expect(ModelException.class);
        expectedException.expectMessage("Signature on IdCard could not be validated");

        createIDCardWithBrokenSignature().validateSignature();
    }

    @Test
    public void testTrustValidation() {
        IDCard idCard = createSignedUserIDCard();
        idCard.validateSignatureAndTrust(federation);
        idCard.validateSignatureAndTrust(vault);
    }

    @Test
    public void testTrustWrongFederation() {
        expectedException.expect(ModelException.class);
        expectedException.expectMessage("The certificate that signed the security token is not trusted!");

        createSignedUserIDCard().validateSignatureAndTrust(new SOSIFederation(System.getProperties()));
    }

    @Test
    public void testTrustWrongVault() {
        expectedException.expect(ModelException.class);
        expectedException.expectMessage("The certificate that signed the security token is not trusted!");

        createSignedUserIDCard().validateSignatureAndTrust(CredentialVaultTestUtil.getOCES2CredentialVault());
    }

    @Test
    public void testBrokenSignatureTrustFederation() {
        expectedException.expect(ModelException.class);
        expectedException.expectMessage("Signature on IdCard could not be validated");

        createIDCardWithBrokenSignature().validateSignatureAndTrust(federation);
    }

    @Test
    public void testBrokenSignatureTrustVault() {
        expectedException.expect(ModelException.class);
        expectedException.expectMessage("Signature on IdCard could not be validated");

        createIDCardWithBrokenSignature().validateSignatureAndTrust(vault);
    }

    @Test
    public void testBrokenSignatureTrustWrongFederation() {
        expectedException.expect(ModelException.class);
        expectedException.expectMessage("The certificate that signed the security token is not trusted!");

        createIDCardWithBrokenSignature().validateSignatureAndTrust(new SOSITestFederation(System.getProperties()));
    }

    @Test
    public void testBrokenSignatureTrustWrongVault() {
        expectedException.expect(ModelException.class);
        expectedException.expectMessage("The certificate that signed the security token is not trusted!");

        createIDCardWithBrokenSignature().validateSignatureAndTrust(CredentialVaultTestUtil.getOCES2CredentialVault());
    }

    private UserIDCard createUnsignedUserIDCard(AuthenticationLevel authenticationLevel) {
        CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "12345", "Pelles Pølsefabrik");
        UserInfo userInfo = new UserInfo("1111111118", "Hans", "Dampf", null, null, "pølsemager", null);
        return sosiFactory.createNewUserIDCard("IT-System", userInfo, careProvider, authenticationLevel, null, null, null, null);
    }

    private UserIDCard createSignedUserIDCard() {
        UserIDCard userIDCard = createUnsignedUserIDCard(AuthenticationLevel.MOCES_TRUSTED_USER);
        Request tmpRequest = sosiFactory.createNewRequest(false, "flow");
        tmpRequest.setIDCard(userIDCard);
        userIDCard.sign(tmpRequest.serialize2DOMDocument(), sosiFactory.getSignatureProvider());
        return userIDCard;
    }

    private IDCard createIDCardWithBrokenSignature() {
        Element serializedIDCard = createSignedUserIDCard().serialize2DOMDocument(sosiFactory, XmlUtil.createEmptyDocument());
        serializedIDCard.setAttributeNS(null, "Version", "17.3");
        return sosiFactory.deserializeIDCard(XmlUtil.node2String(serializedIDCard));
    }

}
