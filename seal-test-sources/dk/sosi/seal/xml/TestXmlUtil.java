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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/xml/TestXmlUtil.java $
 * $Id: TestXmlUtil.java 33209 2016-06-02 14:25:17Z ChristianGasser $
 */
package dk.sosi.seal.xml;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.*;
import dk.sosi.seal.model.constants.MedComTags;
import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.model.constants.SubjectIdentifierTypeValues;
import dk.sosi.seal.modelbuilders.ModelPrefixResolver;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import junit.framework.TestCase;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXParseException;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * @author kkj
 * @version 1.0 Apr 27, 2006
 * @since 1.0
 */
public class TestXmlUtil extends TestCase {

	public static String DGWS_LEVEL4 = null;
	private static String DGWS_INVALID = null;
	private int failures = 0;

	static {
		try {
			Reader reader = null;
			StringWriter writer = null;
			reader = new BufferedReader(new InputStreamReader(TestXmlUtil.class.getResourceAsStream("/dgws-invalid.xml")));
			writer = new StringWriter();
			int c;
			while ((c = reader.read()) != -1) {
				writer.write(c);
			}
			writer.flush();
			DGWS_INVALID = writer.toString();

			reader = new BufferedReader(new InputStreamReader(TestXmlUtil.class.getResourceAsStream("/dgws-level4.xml")));
			writer = new StringWriter();
			while ((c = reader.read()) != -1) {
				writer.write(c);
			}
			writer.flush();
			DGWS_LEVEL4 = writer.toString();

		} catch (Exception e) {
			e.printStackTrace();
			fail("Error reading DGWS examples " + e.getMessage());
		}
	}

	private Properties properties;

	protected void setUp() throws Exception {
		super.setUp();
		properties = SignatureUtil.setupCryptoProviderForJVM();
	}

	public void testToHex() {

		byte[] toHex = new byte[] { (byte) 255, (byte) 255, (byte) 65, (byte) 170 };
		String hex = XmlUtil.toHex(toHex);
		assertTrue("Wrong conversion. Expected FFFF41AA got " + hex, "FFFF41AA".equalsIgnoreCase(hex));
	}

	public void testBase64() {

		String digest = "vUp8WhN8DeXtbEffhQRnIuZYtcQ=";

		byte[] decoded = XmlUtil.fromBase64(digest);

		String encoded = XmlUtil.toBase64(decoded);

		if (!encoded.equals(digest))
			fail("Base 64 decoding and encoding does not yield original?!");

	}

	public void testReadValidXml() {

		try {
			Document doc = XmlUtil.readXml(properties, DGWS_LEVEL4, true);

			assertNotNull(doc);

		} catch (XmlUtilException e) {
			e.printStackTrace();
			fail("Unable to validate document!");
		}
	}

	public void testReadInvalidXml() {

		try {
			XmlUtil.readXml(properties, DGWS_INVALID, true);

			fail("Parsed invalid XML?!");

		} catch (XmlUtilException e) {
			Throwable cause = e.getCause();
			String message = cause.getMessage();
			assertTrue("No cause?!", message != null);
			assertTrue("Illegal errortext?!" + message, message.indexOf("BUMMER") != 0);
		}

	}

	public void testGetElementByIdAndTagNameNS() {

		Document doc = XmlUtil.readXml(properties, DGWS_LEVEL4, true);

		Element el = XmlUtil.getElementByIdAndTagNameNS("Envelope", "http://schemas.xmlsoap.org/soap/envelope/", "Envelope", doc);

		assertNotNull(el);
		assertEquals(el.getNodeName(), "soap:Envelope");
	}

	public void testGetElementByIdAndTagNameNS2() {

		Document doc = XmlUtil.readXml(properties, DGWS_LEVEL4, false);

		Element el = XmlUtil.getElementByIdAndTagNameNS("Assertion", "urn:oasis:names:tc:SAML:2.0:assertion", "IDCard", doc);

		assertNotNull(el);
		assertEquals(el.getNodeName(), "saml:Assertion");
	}

	public void testGetElementByIdAndTagNameNSNeg() {

		Document doc = XmlUtil.readXml(properties, DGWS_LEVEL4, false);

		Element el = XmlUtil.getElementByIdAndTagNameNS("Assertion", "urn:oasis:names:tc:SAML:2.0:assertion", "NonExistentID", doc);

		assertNull(el);
	}

	public void testSerialization() {

		Document doc = XmlUtil.readXml(properties, DGWS_LEVEL4, false);

		byte[] byteA = XmlUtil.serializeXml2ByteArray(doc, false);
		byte[] byteB = XmlUtil.node2String(doc, true, false).getBytes();

		boolean result = Arrays.equals(byteA, byteB);

		assertFalse("The arrays are actually equals?!", result);
	}

	public void testSerializationEquality() throws Throwable {

		Document doc1 = XmlUtil.createEmptyDocument();

		assertNull(XmlUtil.deepDiff(doc1, doc1));

		Element domNode1 = doc1.createElement("Test");
		doc1.appendChild(domNode1);
		assertNull(XmlUtil.deepDiff(doc1, doc1));

		Document doc2 = XmlUtil.createEmptyDocument();
		assertNotNull(XmlUtil.deepDiff(doc1, doc2));

		doc2.appendChild(doc2.importNode(domNode1, true));
		assertNull(XmlUtil.deepDiff(doc1, doc2));

		// Reset doc2
		doc2 = XmlUtil.createEmptyDocument();
		Element domNode2 = (Element) doc2.importNode(domNode1, true);
		doc2.appendChild(domNode2);
		domNode2.setAttributeNS(null, "test", "test");
		assertNotNull(XmlUtil.deepDiff(doc1, doc2));

		domNode1.setAttributeNS(null, "test", "test");
		assertNull(XmlUtil.deepDiff(doc1, doc2));
		doc2 = XmlUtil.readXml(properties, XmlUtil.node2String(doc2, false, true), false);
		assertNull(XmlUtil.deepDiff(doc1, doc2));

		doc1 = XmlUtil.readXml(properties, DGWS_LEVEL4, false);
		doc2 = XmlUtil.readXml(properties, DGWS_LEVEL4, false);
		assertNull(XmlUtil.deepDiff(doc1, doc2));

		doc2 = XmlUtil.readXml(properties, XmlUtil.node2String(doc2, false, true), false);
		assertNull(XmlUtil.deepDiff(doc1, doc2));
	}

	public void testXMLDeclaration() throws Exception {
		Document doc = XmlUtil.createEmptyDocument();
		Element domNode = doc.createElement("Test");
		doc.appendChild(domNode);
		assertNull(XmlUtil.deepDiff(doc, doc));

		// Test that there are no linebreaks in a non-prettyprintet xml document
		String xml = XmlUtil.node2String(doc,false,false);
		assertEquals(xml, xml.replaceAll(">\\s*<", "><"));

		// Test that there is no linebreaks in non-prettyprinted xml documents with <?xml ...?> declaration
		xml = XmlUtil.node2String(doc,false,true);
		assertEquals(xml, xml.replaceAll(">\\s*<", "><"));

		// Test that there are a '\n' between the xml declaration and the rest of the document when prettyprinted
		domNode.appendChild(doc.createElement("Test1"));
		xml = XmlUtil.node2String(doc,true,true);
		assertEquals(xml.indexOf('>')+1,xml.indexOf("\n"));

		// Check that the prettyprinted document is equal to a not prettyprinted document, when removing all whitespaces
		String xml1 = XmlUtil.node2String(doc,false,true);
		String xml2 = xml.replaceAll(">\\s*", ">");
		assertEquals(xml1, xml2);
	}

	public void testGetTextNodeValue() throws Exception {

		Document doc = XmlUtil.createEmptyDocument();
		Element elm = doc.createElement("Test");
		String str = "This is a test!";
		elm.appendChild(doc.createTextNode(str));
		assertEquals(str, XmlUtil.getTextNodeValue(elm));
	}

	public void testGetTextNodeValueNeg1() throws Exception {

		Document doc = XmlUtil.createEmptyDocument();
		Element elm = doc.createElementNS("http://foo.bar", "TestElement");
		try {
			XmlUtil.getTextNodeValue(elm);
			fail("Should fail if the element has no child nodes");
		} catch (XmlUtilException xe) {
            assertEquals("The supplied element <TestElement xmlns=\"http://foo.bar\"/> doesn't have child nodes", xe.getMessage());
		}
	}

	public void testGetTextNodeValueNeg2() throws Exception {

		Document doc = XmlUtil.createEmptyDocument();
		Element elm = doc.createElement("Test");
		elm.appendChild(doc.createElement("Nested"));
		try {
			XmlUtil.getTextNodeValue(elm);
			fail("Should fail if the element does not have a text node child");
		} catch (XmlUtilException xe) {
            assertEquals("The first child of the supplied node (<Test><Nested/></Test>) is not a text element", xe.getMessage());
		}
	}

    public void testGetTextNodeValueNeg3() throws Exception {

        Document doc = XmlUtil.createEmptyDocument();
        Element elm = doc.createElement("TestElement");
        elm.setAttributeNS(null, "name", "example");
        try {
            XmlUtil.getTextNodeValue(elm);
            fail("Should fail if the element has no child nodes");
        } catch (XmlUtilException xe) {
            assertEquals("The supplied element <TestElement name=\"example\"/> doesn't have child nodes", xe.getMessage());
        }
    }

    public void testSTSFormats() throws Exception {

		InputStream fis;

		try {
			fis = TestXmlUtil.class.getResourceAsStream("/stslevel3request.xml");
			Document doc = XmlUtil.readXml(properties, new InputSource(fis), true);
			assertNotNull(doc);
		} catch (Exception e) {
			e.printStackTrace();
			fail("Error validating stslevel3request");
		}

		try {
			fis = TestXmlUtil.class.getResourceAsStream("/stslevel3response.xml");
			Document doc = XmlUtil.readXml(properties, new InputSource(fis), true);
			assertNotNull(doc);
		} catch (Exception e) {
			e.printStackTrace();
			fail("Error validating stslevel3reply");
		}

		try {
			fis = TestXmlUtil.class.getResourceAsStream("/stslevel4request.xml");
			Document doc = XmlUtil.readXml(properties, new InputSource(fis), true);
			assertNotNull(doc);
		} catch (Exception e) {
			e.printStackTrace();
			fail("Error validating stslevel4request");
		}

		try {
			fis = TestXmlUtil.class.getResourceAsStream("/stslevel4response.xml");
			Document doc = XmlUtil.readXml(properties, new InputSource(fis), true);
			assertNotNull(doc);
		} catch (Exception e) {
			e.printStackTrace();
			fail("Error validating stslevel4reply");
		}

	}

	public void testDocumentBuilderCaching() throws Exception {
		assertNotNull("The cached factory should have been setup at class load", XmlUtil.CACHED_DOCUMENT_BUILDER_FACTORY);

		Document doc = null;

		doc = XmlUtil.readXml(properties, DGWS_LEVEL4, false);
		assertNotNull(doc);
		assertFalse(XmlUtil.CACHED_DOCUMENT_BUILDER_FACTORY.isValidating());

		doc = XmlUtil.readXml(properties, DGWS_LEVEL4, true);
		assertNotNull(doc);
		assertTrue(XmlUtil.CACHED_DOCUMENT_BUILDER_FACTORY.isValidating());

		// Disable the cache
		Properties localProperties = new Properties(properties);
		localProperties.put(SOSIFactory.PROPERTYNAME_SOSI_USE_DOCUMENT_BUILDER_FACTORY_CACHE, "false");
		doc = XmlUtil.readXml(localProperties, DGWS_LEVEL4, false);
		assertNotNull(doc);

		// The cached document builder factory should be untouched since last invocation, and should stille be "validating"
		assertTrue(XmlUtil.CACHED_DOCUMENT_BUILDER_FACTORY.isValidating());

	}

	public void testValidation() throws Exception {
		Document doc = XmlUtil.readXml(properties, DGWS_LEVEL4, true);
		assertNotNull(doc);

		// At this point the CACHED_DOCUMENT_BUILDER_FACTORY is set up to produce schemavalidating documentbuilders.
		assertTrue(XmlUtil.CACHED_DOCUMENT_BUILDER_FACTORY.isValidating());

		// However, it should still be possible to create a non-validating documentbuilder, when supplying "false" to "getDocumentBuilder()"
		// Remove a schema-mandatory timestamp and check that the documentbuilder does *not* throw an exception when validate is set to false
		String schemaInvalidXML = removeMandatoryTimestamp();
		assertNotNull(XmlUtil.readXml(properties, schemaInvalidXML, false)); // Should run OK!


		// And finally check that a validation exception is thrown when validate=true ...
		try {
			XmlUtil.readXml(properties, schemaInvalidXML, true);
			fail("No schemavalidation exception was thrown");
		} catch (XmlUtilException xue) {
			// OK
		}
	}

	public void testThreadedAccess() throws Exception {

		final int nrThreads=15, nrSamples=10;
		final Set<Document> documentSet = Collections.synchronizedSet(new HashSet<Document>());
		final String schemaInvalidXML = removeMandatoryTimestamp();
		final Properties localProperties = new Properties(properties);

		localProperties.put(SOSIFactory.PROPERTYNAME_SOSI_USE_DOCUMENT_BUILDER_FACTORY_CACHE, "true");

		//long start = System.currentTimeMillis();
		Thread[] threads = new Thread[nrThreads];
		for(int i=0; i<threads.length; i++) {
			threads[i] = new Thread(new Runnable() {
				public void run() {
					for(int j=0; j<nrSamples;j++) {
						documentSet.add(XmlUtil.createEmptyDocument());
						boolean isValidating = (Math.random()<0.5);
						try {
							XmlUtil.readXml(localProperties, schemaInvalidXML, isValidating);
							if(isValidating) failures++;
						} catch (Exception e) {
							if(!isValidating) failures++;
						}
					}
				}
			});
			threads[i].setName("Thread:"+i);
			threads[i].start();
		}

		for(int i=0; i<threads.length; i++)
			threads[i].join();

		//System.out.println("Time="+(System.currentTimeMillis()-start)+" millis");
		assertEquals("There were synchronization errors!",0,failures);
		assertEquals(nrThreads*nrSamples, documentSet.size());
	}

    public void testLvl1RequestValidatedBySchemas() {
        Properties props = new Properties();
        props.setProperty(SOSIFactory.PROPERTYNAME_SOSI_VALIDATE_ENHANCED, "true");
        props.setProperty(SOSIFactory.PROPERTYNAME_SOSI_SEAL_MESSAGE_VERSION, "1.0_0");

    	doSchemaValidationCheck(AuthenticationLevel.NO_AUTHENTICATION,NameSpaces.SOAP_SCHEMA, NameSpaces.NS_SOAP, "Envelope", props);
    	doSchemaValidationCheck(AuthenticationLevel.NO_AUTHENTICATION,NameSpaces.MEDCOM_SCHEMA,NameSpaces.NS_MEDCOM,MedComTags.HEADER, props);
    	doSchemaValidationCheck(AuthenticationLevel.NO_AUTHENTICATION,NameSpaces.WSSE_SCHEMA,NameSpaces.NS_WSSE,"Security", props);
    	doSchemaValidationCheck(AuthenticationLevel.NO_AUTHENTICATION,NameSpaces.WSU_SCHEMA,NameSpaces.NS_WSU,"Timestamp", props);
    	doSchemaValidationCheck(AuthenticationLevel.NO_AUTHENTICATION,NameSpaces.SAML2ASSERTION_SCHEMA,NameSpaces.NS_SAML,"Assertion", props);

    	props = new Properties();
        props.setProperty(SOSIFactory.PROPERTYNAME_SOSI_VALIDATE_ENHANCED, "false");
        props.setProperty(SOSIFactory.PROPERTYNAME_SOSI_SEAL_MESSAGE_VERSION, "1.0_1");

    	doSchemaValidationCheck(AuthenticationLevel.NO_AUTHENTICATION,NameSpaces.SOAP_SCHEMA, NameSpaces.NS_SOAP, "Envelope", props);
    	doSchemaValidationCheck(AuthenticationLevel.NO_AUTHENTICATION,NameSpaces.MEDCOM_SCHEMA,NameSpaces.NS_MEDCOM,MedComTags.HEADER, props);
    	doSchemaValidationCheck(AuthenticationLevel.NO_AUTHENTICATION,NameSpaces.WSSE_SCHEMA,NameSpaces.NS_WSSE,"Security", props);
    	doSchemaValidationCheck(AuthenticationLevel.NO_AUTHENTICATION,NameSpaces.WSU_SCHEMA,NameSpaces.NS_WSU,"Timestamp", props);
    	doSchemaValidationCheck(AuthenticationLevel.NO_AUTHENTICATION,NameSpaces.SAML2ASSERTION_SCHEMA,NameSpaces.NS_SAML,"Assertion", props);

    }

    public void testLvl3RequestValidatedBySchemas() {
        Properties props = new Properties();
        props.setProperty(SOSIFactory.PROPERTYNAME_SOSI_VALIDATE_ENHANCED, "true");
        props.setProperty(SOSIFactory.PROPERTYNAME_SOSI_SEAL_MESSAGE_VERSION, "1.0_0");

    	doSchemaValidationCheck(AuthenticationLevel.VOCES_TRUSTED_SYSTEM,NameSpaces.SOAP_SCHEMA, NameSpaces.NS_SOAP, "Envelope", props);
    	doSchemaValidationCheck(AuthenticationLevel.VOCES_TRUSTED_SYSTEM,NameSpaces.MEDCOM_SCHEMA,NameSpaces.NS_MEDCOM,MedComTags.HEADER, props);
    	doSchemaValidationCheck(AuthenticationLevel.VOCES_TRUSTED_SYSTEM,NameSpaces.WSSE_SCHEMA,NameSpaces.NS_WSSE,"Security", props);
    	doSchemaValidationCheck(AuthenticationLevel.VOCES_TRUSTED_SYSTEM,NameSpaces.WSU_SCHEMA,NameSpaces.NS_WSU,"Timestamp", props);
    	doSchemaValidationCheck(AuthenticationLevel.VOCES_TRUSTED_SYSTEM,NameSpaces.SAML2ASSERTION_SCHEMA,NameSpaces.NS_SAML,"Assertion", props);
    	doSchemaValidationCheck(AuthenticationLevel.VOCES_TRUSTED_SYSTEM,NameSpaces.DSIG_SCHEMA,NameSpaces.NS_DS,"KeyInfo", props);

    	// kræver først tilretning af skemaer for at virke
//        props = new Properties();
//        props.setProperty(SOSIFactory.PROPERTYNAME_SOSI_VALIDATE_ENHANCED, "false");
//        props.setProperty(SOSIFactory.PROPERTYNAME_SOSI_SEAL_MESSAGE_VERSION, "1.0_2");
//
//    	doSchemaValidationCheck(AuthenticationLevel.VOCES_TRUSTED_SYSTEM,NameSpaces.SOAP_SCHEMA, NameSpaces.NS_SOAP, "Envelope", props);
//    	doSchemaValidationCheck(AuthenticationLevel.VOCES_TRUSTED_SYSTEM,NameSpaces.MEDCOM_SCHEMA,NameSpaces.NS_MEDCOM,MedComTags.HEADER, props);
//    	doSchemaValidationCheck(AuthenticationLevel.VOCES_TRUSTED_SYSTEM,NameSpaces.WSSE_SCHEMA,NameSpaces.NS_WSSE,"Security", props);
//    	doSchemaValidationCheck(AuthenticationLevel.VOCES_TRUSTED_SYSTEM,NameSpaces.WSU_SCHEMA,NameSpaces.NS_WSU,"Timestamp", props);
//    	doSchemaValidationCheck(AuthenticationLevel.VOCES_TRUSTED_SYSTEM,NameSpaces.SAML2ASSERTION_SCHEMA,NameSpaces.NS_SAML,"Assertion", props);
//    	doSchemaValidationCheck(AuthenticationLevel.VOCES_TRUSTED_SYSTEM,NameSpaces.DSIG_SCHEMA,NameSpaces.NS_DS,"KeyInfo", props);
}

    private void doSchemaValidationCheck(AuthenticationLevel authenticationLevel, String namespaceURI, String prefix, String localName, Properties props) {
    	// create valid request
        SOSIFactory factory = new SOSIFactory(CredentialVaultTestUtil.getCredentialVault(), props);
        Document doc = createRequestDoc(factory, authenticationLevel);

        // invalidate doc
		Node security = doc.getElementsByTagNameNS(namespaceURI, localName).item(0);
        ((Element)security).setAttributeNS(null, "dummy", "attr");
//        System.out.println(XmlUtil.node2String(doc,true,true));

        // validate check
        try {
            factory.deserializeRequest(XmlUtil.node2String(doc));
            fail();
        } catch (XmlUtilException e) {
            if(! (e.getCause() instanceof SAXParseException) )
                fail();
//            e.printStackTrace();
			assertTrue(e.getCause().getMessage().indexOf(
                    "Attribute 'dummy' is not allowed to appear in element '"+prefix+":"+localName+"'") != -1);
        }
    }

    public void testXMLTimestampTransformation() throws Exception {
    	// ignore milliseconds
    	long time = (System.currentTimeMillis() / 1000) * 1000;
		Date date = new Date(time);

		String dateString = XmlUtil.toXMLTimeStamp(date, false);
		assertEquals(date, XmlUtil.fromXMLTimeStamp(dateString));
		dateString = XmlUtil.toXMLTimeStamp(date, true);
		assertEquals(date, XmlUtil.fromXMLTimeStamp(dateString));

		dateString = XmlUtil.toXMLTimeStamp(date, false);
		SimpleDateFormat format = new SimpleDateFormat("yyyy'-'MM'-'dd'T'HH:mm:ss");
		Date parsedDate = format.parse(dateString);
		assertEquals(date, parsedDate);

		dateString = XmlUtil.toXMLTimeStamp(date, true);
		format = new SimpleDateFormat("yyyy'-'MM'-'dd'T'HH:mm:ss'Z'");
		parsedDate = format.parse(dateString);
		int offset = TimeZone.getDefault().getOffset(date.getTime());
		assertEquals(offset, date.getTime() - parsedDate.getTime());

	}

    public void testGetByteArrayAsCertificate() {
        try {
            CertificateParser.asCertificate(new byte[] {});
            fail("ModelException expected");
        } catch (ModelException e) {
            // ok
        }

        try {
            CertificateParser.asCertificate("Bla bla bla".getBytes());
            fail("ModelException expected");
        } catch (ModelException e) {
            // ok
        }
    }

    public void testParseZuluDateTime() {
        Date date = new Date();
        SimpleDateFormat dateFormat;
        String dateString;

        dateFormat = new SimpleDateFormat("yyyy'-'MM'-'dd'T'HH:mm:ss'Z'");
        dateFormat.setTimeZone(TimeZone.getTimeZone("Etc/UTC"));
        dateString = dateFormat.format(date);
        assertTrue(Math.abs(date.getTime() - XmlUtil.parseZuluDateTime(dateString).getTime()) < 1000);

        dateFormat = new SimpleDateFormat("yyyy'-'MM'-'dd'T'HH:mm:ss.SSS'Z'");
        dateFormat.setTimeZone(TimeZone.getTimeZone("Etc/UTC"));
        dateString = dateFormat.format(date);
        assertTrue(Math.abs(date.getTime() - XmlUtil.parseZuluDateTime(dateString).getTime()) < 1);

        dateFormat = new SimpleDateFormat("yyyy'-'MM'-'dd'T'HH:mm:ss");
        dateString = dateFormat.format(date);
        try {
            XmlUtil.parseZuluDateTime(dateString);
            fail();
        } catch (ModelException e) {
            // ignore
        }

        dateFormat = new SimpleDateFormat("yyyy'-'MM'-'dd'T'HH:mm:ss.SSS");
        dateString = dateFormat.format(date);
        try {
            XmlUtil.parseZuluDateTime(dateString);
            fail();
        } catch (ModelException e) {
            // ignore
        }

        try {
            XmlUtil.parseZuluDateTime(null);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals("DateTimeString cannot be null or empty", e.getMessage());
        }

        try {
            XmlUtil.parseZuluDateTime("");
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals("DateTimeString cannot be null or empty", e.getMessage());
        }


        try {
            XmlUtil.parseZuluDateTime("     ");
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals("DateTimeString cannot be null or empty", e.getMessage());
        }

        try {
            XmlUtil.parseZuluDateTime("FOO");
            fail();
        } catch (ModelException e) {
            assertEquals("DateTimeString is not formatted as Zulu-time: FOO", e.getMessage());
        }

    }

    // ===========================
    //	Private parts
    // ===========================

    private Document createRequestDoc(SOSIFactory factory, AuthenticationLevel authenticationLevel) {
        Request req = factory.createNewRequest(false, "flowid");
        CareProvider careProvider = new CareProvider(SubjectIdentifierTypeValues.CVR_NUMBER, "someID", "someOrgName");
        IDCard idcard = factory.createNewSystemIDCard("SOSITEST", careProvider, authenticationLevel, null, null,
        		factory.getCredentialVault().getSystemCredentialPair().getCertificate(), null);
        req.setIDCard(idcard);
        Document doc = req.serialize2DOMDocument();
        return doc;
    }

	private String removeMandatoryTimestamp() {
		Document doc = XmlUtil.readXml(properties, DGWS_LEVEL4, true);
		Element ts =  XmlUtil.selectSingleElement(doc, "//"+NameSpaces.NS_WSU + ":Timestamp", new ModelPrefixResolver(), true);
		ts.getParentNode().removeChild(ts);
		String schemaInvalidXML = XmlUtil.node2String(doc);
		return schemaInvalidXML;
	}
}
