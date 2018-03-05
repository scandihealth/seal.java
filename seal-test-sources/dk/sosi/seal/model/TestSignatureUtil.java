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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/model/TestSignatureUtil.java $
 * $Id: TestSignatureUtil.java 20767 2014-12-10 15:12:04Z ChristianGasser $
 */
package dk.sosi.seal.model;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.constants.IDValues;
import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.pki.Federation;
import dk.sosi.seal.pki.SOSITestFederation;
import dk.sosi.seal.pki.SignatureProviderFactory;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.vault.GenericCredentialVault;
import dk.sosi.seal.xml.XmlUtil;
import dk.sosi.seal.xml.XmlUtilException;
import junit.framework.TestCase;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import java.io.ByteArrayInputStream;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Properties;

/**
 * Tests the SignatureUtil class
 *
 * @author kkj
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
public class TestSignatureUtil extends TestCase {

	private GenericCredentialVault credentialVault;

	private Federation federation;

	private Properties properties;

	private static final String PERSON_XML = "<root xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">" + "<personinfo id=\"tosign\">"
			+ "<firstname>hans</firstname>" + "<lastname>hansen</lastname>" + "</personinfo>" + "</root>";

	public TestSignatureUtil() {

	}

	protected void setUp() throws Exception {
		super.setUp();
        properties = SignatureUtil.setupCryptoProviderForJVM();

		// Init credentialvault with system certificate
        credentialVault = CredentialVaultTestUtil.getCredentialVault();

		// Init SOSI TEST Federation
		federation = new SOSITestFederation(properties);
	}

	/**
	 * Sign a document, and validate the signature
	 */
	public void testSignValidate() throws Exception {

		assertNotNull("SetUp not called correctly!", credentialVault);

		Document document = XmlUtil.readXml(properties, CredentialVaultTestUtil.XML_DOCUMENT, false);

		document.getElementsByTagName("fornavn").item(0);

		String[] referenceUris = { "elmtosign" };
        final SignatureConfiguration configuration = new SignatureConfiguration(referenceUris, "elmtosign", IDValues.id);
		SignatureUtil.sign(SignatureProviderFactory.fromCredentialVault(credentialVault), document, configuration);

		Node elmSignature = document.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);
		if (!SignatureUtil.validate(elmSignature, federation, credentialVault, false))
			fail("Unable to validate signature");
		try {
			if (SignatureUtil.validate(elmSignature, federation, credentialVault, true))
				fail("Validated untrusted signature - ie not signed by STS");
		} catch (Exception e) {
			// Should fail - not signed by STS
		}
	}

	public void testSignIDCard() throws Exception {

		Document doc = XmlUtil.readXml(properties, CredentialVaultTestUtil.XML_DOCUMENT_4, true);

		doc.getElementsByTagNameNS("saml","Assertion").item(0);

        final SignatureConfiguration configuration = new SignatureConfiguration(new String[] { "IDCard" }, "IDCard", IDValues.id);
		SignatureUtil.sign(SignatureProviderFactory.fromCredentialVault(credentialVault), doc, configuration);

		Node elmSignature = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);

		if (!SignatureUtil.validate(elmSignature, federation, credentialVault, false))
			fail("Unable to validate signature");

		// Now serialize the XML, deserialize and validate again
		byte[] serialXml = XmlUtil.serializeXml2ByteArray(doc, false);
		doc = XmlUtil.readXml(properties, new InputSource(new ByteArrayInputStream(serialXml)), true);

		elmSignature = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);

		if (!SignatureUtil.validate(elmSignature, federation, credentialVault, false))
			fail("Unable to validate signature after serialization & deserialization");
	}

	public void testSignCodedDOM() throws Exception {

		Document doc = XmlUtil.createEmptyDocument();
		Element root = doc.createElement("root");
		root.setAttributeNS(NameSpaces.XMLNS_SCHEMA, "xmlns:ds", "http://www.w3.org/2000/09/xmldsig#");
		doc.appendChild(root);

		Element personinfo = doc.createElement("personinfo");
		personinfo.setAttributeNS(null, "id", "tosign");
		root.appendChild(personinfo);

		Element firstname = doc.createElement("firstname");
		firstname.appendChild(doc.createTextNode("hans"));
		personinfo.appendChild(firstname);

		Element lastname = doc.createElement("lastname");
		lastname.appendChild(doc.createTextNode("hansen"));
		personinfo.appendChild(lastname);

		// Sign the dummy document
        final SignatureConfiguration configuration = new SignatureConfiguration(new String[] { "tosign" }, "tosign", IDValues.id);
		SignatureUtil.sign(SignatureProviderFactory.fromCredentialVault(credentialVault), doc, configuration);

		Node elmSignature = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);

		if (!SignatureUtil.validate(elmSignature, federation, credentialVault, false))
			fail("Unable to validate signature");

		// Now serialize the XML, deserialize and validate again
		byte[] serialXml = XmlUtil.serializeXml2ByteArray(doc, false);
		Document serializedDoc = XmlUtil.readXml(properties, new InputSource(new ByteArrayInputStream(serialXml)), false);
		Node deepDiff = XmlUtil.deepDiff(doc, serializedDoc);
		assertNull("non-serialized and serialized-deserialized documents differ!", deepDiff);

		elmSignature = serializedDoc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);

		if (!SignatureUtil.validate(elmSignature, federation, credentialVault, false))
			fail("Unable to validate signature after serialization & deserialization");
	}

	public void testSimpleDomSerDeSer() {

		Document docA = XmlUtil.createEmptyDocument();

		Element root = docA.createElement("root");
		root.setAttributeNS(NameSpaces.XMLNS_SCHEMA, "xmlns:ds", "http://www.w3.org/2000/09/xmldsig#");
		root.setAttributeNS(null, "id", "tosign");
		docA.appendChild(root);

		Document docB = XmlUtil.createEmptyDocument();
		TransformerFactory tf = TransformerFactory.newInstance();
		try {
			Transformer trans = tf.newTransformer();
			trans.transform(new DOMSource(docA), new DOMResult(docB));
		} catch (TransformerException e) {
			throw new XmlUtilException("Unable to gctransform input", e);
		}

		// Sign doc B and see how that goes.
        final SignatureConfiguration configuration = new SignatureConfiguration(new String[] { "tosign" }, "tosign", IDValues.id);
		SignatureUtil.sign(SignatureProviderFactory.fromCredentialVault(credentialVault), docB, configuration);

		Node elmSignature = docB.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);

		if (!SignatureUtil.validate(elmSignature, federation, credentialVault, false))
			fail("Unable to validate signature");

		// Now serialize again, deserialize and validate the signature
		byte[] byteArrayB = XmlUtil.serializeXml2ByteArray(docB, false);
		Document docC = XmlUtil.readXml(properties, new InputSource(new ByteArrayInputStream(byteArrayB)), false);
		elmSignature = docC.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);
		if (!SignatureUtil.validate(elmSignature, federation, credentialVault, false))
			fail("Unable to validate signature");

	}

	public void testSignStringDOM() throws Exception {

		Document doc = XmlUtil.readXml(properties, PERSON_XML, false);

		// Sign the dummy document
		doc.getElementsByTagNameNS("saml","Assertion").item(0);
        final SignatureConfiguration configuration = new SignatureConfiguration(new String[] { "tosign" }, "tosign", IDValues.id);
		SignatureUtil.sign(SignatureProviderFactory.fromCredentialVault(credentialVault), doc, configuration);

		Node elmSignature = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);

		if (!SignatureUtil.validate(elmSignature, federation, credentialVault, false))
			fail("Unable to validate signature");

		// Now serialize the XML, deserialize and validate again
		byte[] serialXml = XmlUtil.serializeXml2ByteArray(doc, false);
		doc = XmlUtil.readXml(properties, new InputSource(new ByteArrayInputStream(serialXml)), false);

		elmSignature = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);

		if (!SignatureUtil.validate(elmSignature, federation, credentialVault, false))
			fail("Unable to validate signature after serialization & deserialization");
	}

	/**
	 * Create a digest of the System certificate, and check that the length is 20
	 */
	public void testGetDigestOfCertificate() throws Exception {

		X509Certificate cert = credentialVault.getSystemCredentialPair().getCertificate();

		String digest = SignatureUtil.getDigestOfCertificate(cert);

		byte[] digestBytes = XmlUtil.fromBase64(digest);

		assertTrue("Digest has wrong length " + digestBytes.length, digestBytes.length == 20);
	}

	public void testGetSignedInfoSha1Digest() throws Exception {

		Document documentA = XmlUtil.readXml(properties, CredentialVaultTestUtil.XML_DOCUMENT, false);
		Document documentB = XmlUtil.readXml(properties, CredentialVaultTestUtil.XML_DOCUMENT, false);
        final SignatureConfiguration configuration = new SignatureConfiguration(new String[] { "elmtosign" }, "elmtosign", IDValues.id);

		// Create an unsigned SignedInfo element on documentA
		byte[] siBytes = SignatureUtil.getSignedInfoBytes(documentA, configuration);

		// Create a full signature on documentB
        SignatureUtil.sign(SignatureProviderFactory.fromCredentialVault(credentialVault), documentB, configuration);
		Element elmSignedInfoB = (Element) documentB.getElementsByTagName("ds:SignedInfo").item(0);

		String docAString = new String(siBytes);
		String docBString = XmlUtil.node2String(elmSignedInfoB, false, false);

		String digestA = docAString.split("\\<ds:DigestValue")[1].split("\\>")[1].split("\\<")[0];
		String digestB = docBString.split("\\<ds:DigestValue")[1].split("\\>")[1].split("\\<")[0];

		assertEquals(digestA, digestB);

		// Now try and encrypt the signaturevalue from Doc A and see if it
		// matches with
		// a the signed value in doc B
		Signature jceSign = Signature.getInstance("SHA1withRSA", SignatureUtil.getCryptoProvider(properties,
				SOSIFactory.PROPERTYNAME_SOSI_CRYPTOPROVIDER_SHA1WITHRSA));

		PrivateKey key = credentialVault.getSystemCredentialPair().getPrivateKey();
		jceSign.initSign(key);
		jceSign.update(siBytes);
		byte[] docASignatureValue = jceSign.sign();
		String docA64 = XmlUtil.toBase64(docASignatureValue);

		NodeList elms = documentB.getElementsByTagName("ds:SignatureValue");
		assertTrue(elms.getLength() == 1);
		Element elmSignatureValue = (Element) elms.item(0);
		String docBSignatureValue = XmlUtil.getTextNodeValue(elmSignatureValue).replaceAll("\\s", "");

		// Compare the two
		assertEquals(docBSignatureValue, docA64);
	}

    public void testChangingNamespacePrefix() {

        Document doc = XmlUtil.readXml(properties, "<FOO:root xmlns:FOO=\"urn:bar.foo\" id=\"tosign\"/>", false);

        // Sign the dummy document
        final SignatureConfiguration configuration = new SignatureConfiguration(new String[] { "tosign" }, "tosign", IDValues.id);
        SignatureUtil.sign(SignatureProviderFactory.fromCredentialVault(credentialVault), doc, configuration);

        Node elmSignature = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);

        if (!SignatureUtil.validate(elmSignature, federation, credentialVault, false))
            fail("Unable to validate signature");

        // Now serialize the XML, deserialize and validate again
        String serialXml = XmlUtil.node2String(doc);
        serialXml = serialXml.replace("FOO", "BAR");
        doc = XmlUtil.readXml(properties, serialXml, false);

        elmSignature = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);

        if (SignatureUtil.validate(elmSignature, federation, credentialVault, false))
            fail("Changing namespace prefix should break signature ....");

    }
}
