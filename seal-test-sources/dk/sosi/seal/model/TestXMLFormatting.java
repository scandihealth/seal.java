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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/model/TestXMLFormatting.java $
 * $Id: TestXMLFormatting.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.model;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.constants.SubjectIdentifierTypeValues;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.xml.XmlUtil;
import junit.framework.TestCase;
import org.w3c.dom.Document;

import java.security.cert.X509Certificate;
import java.util.Properties;

/**
 * Test the model package
 *
 * @author Jan Riis
 * @author $LastChangedBy: chg@lakeside.dk $
 * @since 1.0
 */
public class TestXMLFormatting extends TestCase {

	private Properties properties;

	protected void setUp() throws Exception {
		super.setUp();
		properties = SignatureUtil.setupCryptoProviderForJVM();
	}

	public void testFormattingInLibrary() throws Exception {
		SOSIFactory factory = CredentialVaultTestUtil.createSOSIFactory();
		Request request = createRequestVOCES(factory, false, "testflow", true);
		Document doc = request.serialize2DOMDocument();
		String xmlPretty = XmlUtil.node2String(doc, true, false);
		String xml =  XmlUtil.node2String(doc, false, false);

		// Check that the non-formatted message can be deserialized and hence the signature is valid
		factory.deserializeRequest(xml);

		// xmlPretty is now a "prettyprinted" version of the signed request. The signature is no longer valid, since whitespace
		// elements has been introduced into the SignedInfo element. C14N will not remove these elements.
		try {
			factory.deserializeRequest(xmlPretty);
			fail("Prettyprinting a SignedInfo element should break digital signature!");
		} catch (Exception ex) {
			// OK!
		}

		// Represent the two xml documents as DOM
		Document doc1 = XmlUtil.readXml(properties,xmlPretty,true);
		Document doc2 = XmlUtil.readXml(properties,xml,true);

		// Check that the two DOM documents differ
		assertNotNull(XmlUtil.deepDiff(doc1,doc2));

		// Check that the canonical form of the two documents differ
		assertFalse(SignatureUtil.getC14NString(doc1.getDocumentElement()).equals(SignatureUtil.getC14NString(doc2.getDocumentElement())));

		// Now remove formatting using XmlUtil
		String deFormattedXml = XmlUtil.removeFormatting(xmlPretty);

		// Check that the de-formatted message can be deserialized and hence the signature is valid
		factory.deserializeRequest(deFormattedXml);
	}

	// ==========================================
	// Helpers
	// ==========================================

	private Request createRequestVOCES(SOSIFactory factory, boolean nonRep, String flowID, boolean userIDCard) {
		return createRequest(factory, nonRep, flowID, userIDCard, AuthenticationLevel.VOCES_TRUSTED_SYSTEM);
	}

	private Request createRequest(SOSIFactory factory, boolean nonRep, String flowID, boolean userIDCard, AuthenticationLevel authLevel) {
		return createRequest(factory, nonRep, flowID, userIDCard, authLevel, "1234567890");
	}

	private Request createRequest(SOSIFactory factory, boolean nonRep, String flowID, boolean userIDCard, AuthenticationLevel authLevel, String cpr) {

		Request request = factory.createNewRequest(nonRep, flowID);

		X509Certificate certificate = null;
		if(!AuthenticationLevel.NO_AUTHENTICATION.equals(authLevel)) {
			certificate = factory.getCredentialVault().getSystemCredentialPair().getCertificate();
		}

		if (userIDCard) {
			request.setIDCard(createNewUserIdCard(factory, authLevel, certificate,cpr));
		} else {
			request.setIDCard(factory.createNewSystemIDCard(
					"testITSystem",
					new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER,
					"124454",
					"Hansens Praksis"),
					authLevel,
					null,
					null,
					certificate,
					null));
		}
		return request;
	}

	private UserIDCard createNewUserIdCard(SOSIFactory factory, AuthenticationLevel authLevel, X509Certificate certificate, String cpr) {
		return factory.createNewUserIDCard(
				"testITSystem",
				new UserInfo(cpr, "Jan", "Riis", "jan<at>lakeside.dk", "hacker", "doctor", "2101"),
				new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "124454", "Hansens Praksis"),
				authLevel,
				null,
				null,
				certificate,
				null);
	}

}
