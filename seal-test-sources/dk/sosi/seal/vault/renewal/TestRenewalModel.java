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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/vault/renewal/TestRenewalModel.java $
 * $Id: TestRenewalModel.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */

package dk.sosi.seal.vault.renewal;

import dk.sosi.seal.model.SignatureUtil;
import dk.sosi.seal.vault.renewal.model.RenewCertificateRequest;
import dk.sosi.seal.vault.renewal.model.RenewalAuthorization;
import dk.sosi.seal.vault.renewal.model.RequestRenewalRequest;
import dk.sosi.seal.vault.renewal.model.Response;
import dk.sosi.seal.vault.renewal.model.dombuilders.RequestDOMBuilder;
import dk.sosi.seal.vault.renewal.model.dombuilders.ResponseDOMBuilder;
import dk.sosi.seal.vault.renewal.modelbuilders.ResponseModelBuilder;
import dk.sosi.seal.xml.XmlUtil;
import junit.framework.TestCase;
import org.w3c.dom.Document;

import java.util.Properties;

public class TestRenewalModel extends TestCase {
	
	private static final String REQUEST_RENEWAL_REQUEST = 
		 "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
		+  "<soapenv:Body>"
		+    "<ns1:requestRenewal soapenv:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:ns1=\"http://localhost/\"/>"
		+  "</soapenv:Body>"
		+"</soapenv:Envelope>";
	
	private Properties properties;

	protected void setUp() throws Exception {
		super.setUp();
		properties = SignatureUtil.setupCryptoProviderForJVM();
	}
	
	public void testRequestRenewalRequest() throws Exception {
		RequestRenewalRequest request = new RequestRenewalRequest();
		
		Document doc = new RequestDOMBuilder(XmlUtil.createEmptyDocument(), request).buildDocument();
		String docs = XmlUtil.node2String(doc, true, false);

		Document fromText = XmlUtil.readXml(properties, REQUEST_RENEWAL_REQUEST, false);
		String fromTextS = XmlUtil.node2String(fromText, true, false);
		
		assertEquals(docs, fromTextS);
		
		
	}

	private static final String RENEW_CERTIFICATE_REQUEST = 
		"<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" +
			"<soapenv:Body>" +
				"<ns1:renewCertificate soapenv:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:ns1=\"http://localhost/\">" +
					"<string xsi:type=\"xsd:string\">12341234</string>" +
					"<string0 xsi:type=\"xsd:string\">1234-ABCD-1234</string0>" +
					"<bytes xsi:type=\"xsd:base64Binary\">AQ==</bytes>" +
				"</ns1:renewCertificate>" +
			"</soapenv:Body>" +
		"</soapenv:Envelope>";
	
	public void testRenewCertificateRequest() throws Exception {
		RenewCertificateRequest request = new RenewCertificateRequest("12341234", "1234-ABCD-1234", new byte[]{1});
		
		Document doc = new RequestDOMBuilder(XmlUtil.createEmptyDocument(), request).buildDocument();
		String docs = XmlUtil.node2String(doc, true, false);

		Document fromText = XmlUtil.readXml(properties, RENEW_CERTIFICATE_REQUEST, false);
		String fromTextS = XmlUtil.node2String(fromText, true, false);

		assertEquals(docs, fromTextS);
		
	}
	

	private static final String REQUEST_RENEWAL_RESPONSE = 
		"<env:Envelope " +
		    "xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
		    "xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\" " +
		    "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" " +
		    "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" +
		  "<env:Header/>" +
		  "<env:Body env:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">" +
		  	"<m:requestRenewalResponse xmlns:m=\"http://localhost/\">" +
		  	  "<result xmlns:n1=\"java:dk.certifikat.flexws.domain\" xsi:type=\"n1:RenewalAuthorization\">" +
		  	    "<referenceNumber xsi:type=\"xsd:string\">77315553</referenceNumber>" +
		  	    "<renewalAuthorizationCode xsi:type=\"xsd:string\">6KLF-LRMM-YBVB</renewalAuthorizationCode>" +
		  	    "<statusCode xsi:type=\"xsd:int\">-200</statusCode>" +
		  	    "<statusText xsi:type=\"xsd:string\">OK</statusText>" +
		  	  "</result>" +
		    "</m:requestRenewalResponse>" +
		  "</env:Body>" +
		"</env:Envelope>";
	
	public void testRequestRenewalResponse() throws Exception {
		
		ResponseModelBuilder builder = new ResponseModelBuilder();
		
		Response model = builder.buildModel(XmlUtil.readXml(properties, REQUEST_RENEWAL_RESPONSE, false));
		
		assertTrue(model instanceof RenewalAuthorization);
		RenewalAuthorization resp = (RenewalAuthorization) model;

		assertEquals("77315553", resp.getReferenceNumber());
		assertEquals("6KLF-LRMM-YBVB", resp.getRenewalAuthorizationCode());
		assertEquals("OK", resp.getStatusText());
		assertEquals(-200, resp.getStatusCode());
		
		
		//Build from model
		ResponseDOMBuilder dbuilder = new ResponseDOMBuilder(XmlUtil.createEmptyDocument(), resp);
		
		Document doc = dbuilder.buildDocument();
		
		model = builder.buildModel(doc);
		
		assertTrue(model instanceof RenewalAuthorization);
		resp = (RenewalAuthorization) model;
		assertEquals("77315553", resp.getReferenceNumber());
		assertEquals("6KLF-LRMM-YBVB", resp.getRenewalAuthorizationCode());
		assertEquals("OK", resp.getStatusText());
		assertEquals(-200, resp.getStatusCode());
		
		
	}
	
	 
}
