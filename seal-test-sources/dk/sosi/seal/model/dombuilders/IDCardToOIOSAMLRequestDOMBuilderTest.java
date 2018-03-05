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

package dk.sosi.seal.model.dombuilders;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.*;
import dk.sosi.seal.model.constants.SubjectIdentifierTypeValues;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.vault.EmptyCredentialVault;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.w3c.dom.Document;

import static org.junit.Assert.assertNotNull;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class IDCardToOIOSAMLRequestDOMBuilderTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    private CredentialVault vault;

    @Before
    public void setUp() {
        vault = CredentialVaultTestUtil.getVocesCredentialVault();
    }

    @Test
    public void testIDCardMissing() {
        expectedException.expect(ModelException.class);
        expectedException.expectMessage("idcard is mandatory - but was null");

        IDCardToOIOSAMLAssertionRequestDOMBuilder builder = new IDCardToOIOSAMLAssertionRequestDOMBuilder();
        builder.setSigningVault(vault);
        builder.setAudience("http://sundhed.dk");
        builder.build();
    }

    @Test
    public void testAudienceMissing() {
        expectedException.expect(ModelException.class);
        expectedException.expectMessage("audience is mandatory - but was null");

        IDCardToOIOSAMLAssertionRequestDOMBuilder builder = new IDCardToOIOSAMLAssertionRequestDOMBuilder();
        builder.setSigningVault(vault);
        builder.setUserIDCard(createUserIdCard());
        builder.build();
    }

    @Test
    public void testValidRequest() {
        IDCardToOIOSAMLAssertionRequestDOMBuilder builder = new IDCardToOIOSAMLAssertionRequestDOMBuilder();
        builder.setSigningVault(vault);
        builder.setUserIDCard(createUserIdCard());
        builder.setAudience("http://sundhed.dk");
        Document requestDOM = builder.build();
        //System.out.println(XmlUtil.node2String(requestDOM, true, true));
        assertNotNull(requestDOM);
    }

    private UserIDCard createUserIdCard() {
        SOSIFactory sosiFactory = new SOSIFactory(new EmptyCredentialVault(), System.getProperties());
        UserInfo userInfo = new UserInfo("1111111118", "Hans", "Dampf", null, null, "Læge", null);
        CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "342465", "Christinas Balletskole");
        return sosiFactory.createNewUserIDCard("IT-System", userInfo, careProvider, AuthenticationLevel.NO_AUTHENTICATION, null, null, null, null);
    }

}
