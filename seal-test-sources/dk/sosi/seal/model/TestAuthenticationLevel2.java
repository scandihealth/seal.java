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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/model/TestAuthenticationLevel2.java $
 * $Id: TestAuthenticationLevel2.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.model;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.constants.SubjectIdentifierTypeValues;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.xml.XmlUtil;
import junit.framework.TestCase;
import org.w3c.dom.Document;

public class TestAuthenticationLevel2 extends TestCase {

	public void testSystemIdcard() throws Exception {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.Y_NUMBER, "434343", "Lægehuset på bakken");
		SystemIDCard idcard = factory.createNewSystemIDCard("itSystemName", careProvider, AuthenticationLevel.USERNAME_PASSWORD_AUTHENTICATION, "user17", "pass123", null, null);
		assertEquals(AuthenticationLevel.USERNAME_PASSWORD_AUTHENTICATION, idcard.getAuthenticationLevel());
		assertEquals("user17", idcard.getUsername());
		assertEquals("pass123", idcard.getPassword());

		Request request = factory.createNewRequest(false, "flowID");
		request.setIDCard(idcard);
		Document doc = request.serialize2DOMDocument();
		String xml = XmlUtil.node2String(doc);

		//System.out.println(XmlUtil.node2String(doc, true, true));

		Request deserializedRequest = factory.deserializeRequest(xml);
		IDCard deserializedCard = deserializedRequest.getIDCard();

		assertEquals(idcard.getAuthenticationLevel(), deserializedCard.getAuthenticationLevel());
		assertEquals(idcard.getUsername(), deserializedCard.getUsername());
		assertEquals(idcard.getPassword(), deserializedCard.getPassword());
		assertEquals(idcard, deserializedCard);

		SystemIDCard newIdcard = new SystemIDCard(idcard, "newIssuer");
		assertEquals(idcard.getAuthenticationLevel(), newIdcard.getAuthenticationLevel());
		assertEquals(idcard.getUsername(), newIdcard.getUsername());
		assertEquals(idcard.getPassword(), newIdcard.getPassword());

		try {
			factory.createNewSystemIDCard("itSystemName", careProvider, AuthenticationLevel.USERNAME_PASSWORD_AUTHENTICATION, null, "pass123", null, null);
			fail("Should fail on empty or null username");
		} catch (ModelException e) {
			//Ok
		}

		try {
			factory.createNewSystemIDCard("itSystemName", careProvider, AuthenticationLevel.USERNAME_PASSWORD_AUTHENTICATION, "", "pass123", null, null);
			fail("Should fail on empty or null username");
		} catch (ModelException e) {
			//Ok
		}

		try {
			factory.createNewSystemIDCard("itSystemName", careProvider, AuthenticationLevel.USERNAME_PASSWORD_AUTHENTICATION, "user17", null, null, null);
			fail("Should fail on empty or null password");
		} catch (ModelException e) {
			//Ok
		}

		try {
			factory.createNewSystemIDCard("itSystemName", careProvider, AuthenticationLevel.USERNAME_PASSWORD_AUTHENTICATION, "user17", "", null, null);
			fail("Should fail on empty or null password");
		} catch (ModelException e) {
			//Ok
		}

	}

	public void testUserIdcard() throws Exception {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.Y_NUMBER, "434343", "Lægehuset på bakken");
		UserInfo userInfo = new UserInfo("1111111118", "Hans", "Hansen", "hans@hansen.com", "overlæge", "doctor", "1234");
		UserIDCard idcard = factory.createNewUserIDCard("itSystemName", userInfo, careProvider, AuthenticationLevel.USERNAME_PASSWORD_AUTHENTICATION,
				"user17", "pass123", null, "alternativeIdentifier");
		assertEquals(AuthenticationLevel.USERNAME_PASSWORD_AUTHENTICATION, idcard.getAuthenticationLevel());
		assertEquals("user17", idcard.getUsername());
		assertEquals("pass123", idcard.getPassword());

		Request request = factory.createNewRequest(false, "flowID");
		request.setIDCard(idcard);
		Document doc = request.serialize2DOMDocument();
		String xml = XmlUtil.node2String(doc);

		Request deserializedRequest = factory.deserializeRequest(xml);
		IDCard deserializedCard = deserializedRequest.getIDCard();

		assertEquals(idcard.getAuthenticationLevel(), deserializedCard.getAuthenticationLevel());
		assertEquals(idcard.getUsername(), deserializedCard.getUsername());
		assertEquals(idcard.getPassword(), deserializedCard.getPassword());
		assertEquals(idcard, deserializedCard);

		UserIDCard newIdcard = new UserIDCard(idcard, "newIssuser");
		assertEquals(idcard.getAuthenticationLevel(), newIdcard.getAuthenticationLevel());
		assertEquals(idcard.getUsername(), newIdcard.getUsername());
		assertEquals(idcard.getPassword(), newIdcard.getPassword());

		try {
			factory.createNewUserIDCard("itSystemName", userInfo, careProvider, AuthenticationLevel.USERNAME_PASSWORD_AUTHENTICATION,
					null, "pass123", null, "alternativeIdentifier");
			fail("Should fail on empty or null username");
		} catch (ModelException e) {
			//Ok
		}

		try {
			factory.createNewUserIDCard("itSystemName", userInfo, careProvider, AuthenticationLevel.USERNAME_PASSWORD_AUTHENTICATION,
					"", "pass123", null, "alternativeIdentifier");
			fail("Should fail on empty or null username");
		} catch (ModelException e) {
			//Ok
		}

		try {
			factory.createNewUserIDCard("itSystemName", userInfo, careProvider, AuthenticationLevel.USERNAME_PASSWORD_AUTHENTICATION,
					"user17", null, null, "alternativeIdentifier");
			fail("Should fail on empty or null password");
		} catch (ModelException e) {
			//Ok
		}

		try {
			factory.createNewUserIDCard("itSystemName", userInfo, careProvider, AuthenticationLevel.USERNAME_PASSWORD_AUTHENTICATION,
					"user17", "", null, "alternativeIdentifier");
			fail("Should fail on empty or null password");
		} catch (ModelException e) {
			//Ok
		}

	}

}
