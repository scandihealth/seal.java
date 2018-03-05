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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/vault/renewal/TestCredentialPairRenewer.java $
 * $Id: TestCredentialPairRenewer.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.vault.renewal;

import dk.sosi.seal.MainTester;
import dk.sosi.seal.model.SignatureUtil;
import dk.sosi.seal.ssl.MockHttpsConnector;
import dk.sosi.seal.vault.CredentialPair;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.xml.CertificateParser;
import dk.sosi.seal.xml.XmlUtil;
import junit.framework.TestCase;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Properties;

public class TestCredentialPairRenewer extends TestCase {

	private Properties properties;
	
	protected void setUp() throws Exception {
		super.setUp();
		properties = SignatureUtil.setupCryptoProviderForJVM();
	}

	/*
	 * Loopback test of credential renewer. Uses mock connector, and does no real connecting to TDC.
	 */
	public void testRenew() throws Exception {
		if(!MainTester.isBCOnClasspath(properties)) {
			System.out.println("TestCredentialPairRenewer.testRenew() disabled because of BC dependency");
			return;
		}

		CredentialVault vault = CredentialVaultTestUtil.getVocesCredentialVault(properties);
		TDCCredentialPairRenewer renewer = new TDCCredentialPairRenewer(properties);
		renewer.setConnector(new MockHttpsConnector(vault));
		CredentialPair renewedPair = renewer.renew(vault.getSystemCredentialPair());
		
		try {
			renewedPair.getCertificate().checkValidity(new Date());
		} catch (Exception e) {
			fail("Got " + e);
		}

	}
	
	public void testIsChargeable() throws Exception {
		TDCCredentialPairRenewer renewer = new TDCCredentialPairRenewer(properties);

		assertFalse(renewer.isRenewalChargeable(CredentialVaultTestUtil.getVocesCredentialVault(properties).getSystemCredentialPair().getCertificate()));
		
		String thomas = "MIIFgjCCBGqgAwIBAgIEQ4iSeTANBgkqhkiG9w0BAQUFADAxMQswCQYDVQQGEwJESzEMMAoGA1UEChMDVERDMRQwEgYDVQQDEwtUREMgT0NFUyBDQTAeFw0wNjA5MjYwOTU1NTBaFw0wODA5MjYxMDI1NTBaMIGCMQswCQYDVQQGEwJESzEsMCoGA1UEChMjU0lHTkFUVVJHUlVQUEVOIEEvUyAvLyBDVlI6Mjk5MTU5MzgxRTAcBgNVBAMTFVRob21hcyBNb3N0cnVwIE55bWFuZDAlBgNVBAUTHkNWUjoyOTkxNTkzOC1SSUQ6MTE1OTE3NzU3MzA3NDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAsbVtfifq8r+QB8D3uBe+501l/0tbvGxrKBJxFCaEA2ogVgXhEX/e0cFdP1fFIPfaQm1hh6ekghDLv7qn8xb4+xA3CnEBs6tvyz1voi9fxxN4bckSs+VdPQ8te7vKdU8FEe/GDm1mbljDIVp6EO6yFqMHWhzWKrYR25TfThy5boMCAwEAAaOCAtIwggLOMA4GA1UdDwEB/wQEAwID+DArBgNVHRAEJDAigA8yMDA2MDkyNjA5NTU1MFqBDzIwMDgwOTI2MTAyNTUwWjCCATcGA1UdIASCAS4wggEqMIIBJgYKKoFQgSkBAQECBDCCARYwLwYIKwYBBQUHAgEWI2h0dHA6Ly93d3cuY2VydGlmaWthdC5kay9yZXBvc2l0b3J5MIHiBggrBgEFBQcCAjCB1TAKFgNUREMwAwIBARqBxkZvciBhbnZlbmRlbHNlIGFmIGNlcnRpZmlrYXRldCBn5mxkZXIgT0NFUyB2aWxr5XIsIENQUyBvZyBPQ0VTIENQLCBkZXIga2FuIGhlbnRlcyBmcmEgd3d3LmNlcnRpZmlrYXQuZGsvcmVwb3NpdG9yeS4gQmVt5nJrLCBhdCBUREMgZWZ0ZXIgdmlsa+VyZW5lIGhhciBldCBiZWdy5m5zZXQgYW5zdmFyIGlmdC4gcHJvZmVzc2lvbmVsbGUgcGFydGVyLjBBBggrBgEFBQcBAQQ1MDMwMQYIKwYBBQUHMAGGJWh0dHA6Ly9vY3NwLmNlcnRpZmlrYXQuZGsvb2NzcC9zdGF0dXMwJAYDVR0RBB0wG4EZdGhvbWFzQHNpZ25hdHVyZ3J1cHBlbi5kazCBhAYDVR0fBH0wezBLoEmgR6RFMEMxCzAJBgNVBAYTAkRLMQwwCgYDVQQKEwNUREMxFDASBgNVBAMTC1REQyBPQ0VTIENBMRAwDgYDVQQDEwdDUkwxNDc5MCygKqAohiZodHRwOi8vY3JsLm9jZXMuY2VydGlmaWthdC5kay9vY2VzLmNybDAfBgNVHSMEGDAWgBRgtYXsVmR+EhknZx1QFUtzrjv5EjAdBgNVHQ4EFgQU5wu0F7x9RGlOHvf0H3wiGwjah3owCQYDVR0TBAIwADAZBgkqhkiG9n0HQQAEDDAKGwRWNy4xAwIDqDANBgkqhkiG9w0BAQUFAAOCAQEAeDnObYi+qoax6o8Yk3yEnw01pTTYhzVylhN6+qKWX3CIzmuXCMrELOqdr/xF8xWcVN0EtcBczBvgC5eOsKF82+KB7HyUE5OQdOGWtO1N0CFBDGNRhUO9ZAFz5567yla/86FKGz6nu699gHZOJzTTjewPzKFYG5eraLomfQINI4JE2cdjAiiNzqVQ3xQ2i4nyV4ma6j4NIuSC6US+oBomX6rrLgWzooy4Sl4JceQK774sMvU5NQEgp3IyLcaYpr+YenJJc6eP43DYqodiKjdrvn2Qv31tJkY+MY6kvLgN8RejGrBqP+d4klx6T5bQ6D2TQaIOysc1MBfiaWS4Z/UmFQ==";

        X509Certificate cert = CertificateParser.asCertificate(XmlUtil.fromBase64(thomas));
		assertTrue(renewer.isRenewalChargeable(cert));
	}

	/**
	 * This test case performs a full renewal of the test VOCES certificate included in CredentialVaultTestUtil.
	 * 
	 * @throws Exception
	 */
//	public void testRenewRemote() throws Exception {
//		CredentialVault vault = CredentialVaultTestUtil.getVocesCredentialVault();
//		
//		CredentialPairRenewer renewer = new TDCCredentialPairRenewer();
//		CredentialPair renewedPair = renewer.renew(vault.getSystemCredentialPair());
//		
//		Date almostTwoYearsFromNow = new Date(System.currentTimeMillis() + 2*360*24*60*60*1000L);
//		
//		Date yesterDay = new Date(System.currentTimeMillis() - 24*60*60*1000L);
//		
//		try {
//			renewedPair.getFederationCertificate().checkValidity(new Date());
//			renewedPair.getFederationCertificate().checkValidity(almostTwoYearsFromNow);
//		} catch (Exception e) {
//			fail("Got " + e);
//		}
//
//		try {
//			renewedPair.getFederationCertificate().checkValidity(yesterDay);
//			fail("Cert valid yesterday");
//		} catch (Exception e) {
//		}
//	}


	/**
	 * This test case attempts to perform a full renewal of a prod POCES cert (to be supplied...). 
	 * The test should fail, since the TDC ws does not support renewal of POCES certs.
	 */
//	public void testRenewRemotePoces() throws Exception {
//		String pocesprod = "<missing>";
//		String pocespassword = "password";
//
//		CredentialVault vault = CredentialVaultTestUtil.getCredentialVaultFromPKCS12(pocesprod, pocespassword);
//		
//		CredentialPairRenewer renewer = new CredentialPairRenewerImpl();
//		CredentialPair renewedPair;
//		try {
//			renewedPair = renewer.renew(vault.getSystemCredentialPair());
//			fail("Renewal unexpectedly succesfull with poces");
//		} catch (RenewalException e1) {
//			assertTrue(e1.getMessage().indexOf("User not authorized") != -1);
//		}
//		
//	}
	
}
