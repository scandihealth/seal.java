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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/ssl/TrustedServerCertificateIssuers.java $
 * $Id: TrustedServerCertificateIssuers.java 20818 2014-12-18 11:26:29Z ChristianGasser $
 */

package dk.sosi.seal.ssl;

import dk.sosi.seal.xml.CertificateParser;
import dk.sosi.seal.xml.XmlUtil;

import java.security.cert.X509Certificate;

/**
 * Class maintains a compilation of trusted server certificate issuers used for renewal.
 * @author thomas@signaturgruppen.dk
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 20818 $
 * @since 1.0
 */
@Deprecated
public class TrustedServerCertificateIssuers {

	// GlobalSigns root certificate - root to be trusted to reach TDC webservice in test.
	public static final String GSROOT =  
		"MIIDdTCCAl2gAwIBAgILAgAAAAAA1ni3lAUwDQYJKoZIhvcNAQEEBQAwVzELMAkG"+
		"A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv"+
		"b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAw"+
		"MDBaFw0xNDAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i"+
		"YWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxT"+
		"aWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZ"+
		"jc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavp"+
		"xy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp"+
		"1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdG"+
		"snUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJ"+
		"U26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlDSgeF59N8"+
		"9iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIABjAdBgNVHQ4EFgQU"+
		"YHtmGkUNl8qJUC99BM00qP/8/UswDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B"+
		"AQQFAAOCAQEArqqf/LfSyx9fOSkoGJ40yWxPbxrwZKJwSk8ThptgKJ7ogUmYfQq7"+
		"5bCdPTbbjwVR/wkxKh/diXeeDy5slQTthsu0AD+EAk2AaioteAuubyuig0SDH81Q"+
		"gkwkr733pbTIWg/050deSY43lv6aiAU62cDbKYfmGZZHpzqmjIs8d/5GY6dT2iHR"+
		"rH5Jokvmw2dZL7OKDrssvamqQnw1wdh/1acxOk5jQzmvCLBhNIzTmKlDNPYPhyk7"+
		"ncJWWJh3w/cbrPad+D6qp1RF8PX51TFl/mtYnHGzHtdS6jIX/EBgHcl5JLL2bP2o"+
		"Zg6C3ZjL2sJETy6ge/L3ayx2EYRGinij4w==";
	
	//Thawtes root certificate - root to be trusted to reach TDC webservice.
	public static final String THAWTE_ROOT = 
		"MIIDEzCCAnygAwIBAgIBATANBgkqhkiG9w0BAQQFADCBxDELMAkGA1UEBhMCWkExF" +
		"TATBgNVBAgTDFdlc3Rlcm4gQ2FwZTESMBAGA1UEBxMJQ2FwZSBUb3duMR0wGwYDVQ" +
		"QKExRUaGF3dGUgQ29uc3VsdGluZyBjYzEoMCYGA1UECxMfQ2VydGlmaWNhdGlvbiB" +
		"TZXJ2aWNlcyBEaXZpc2lvbjEZMBcGA1UEAxMQVGhhd3RlIFNlcnZlciBDQTEmMCQG" +
		"CSqGSIb3DQEJARYXc2VydmVyLWNlcnRzQHRoYXd0ZS5jb20wHhcNOTYwODAxMDAwM" +
		"DAwWhcNMjAxMjMxMjM1OTU5WjCBxDELMAkGA1UEBhMCWkExFTATBgNVBAgTDFdlc3" +
		"Rlcm4gQ2FwZTESMBAGA1UEBxMJQ2FwZSBUb3duMR0wGwYDVQQKExRUaGF3dGUgQ29" +
		"uc3VsdGluZyBjYzEoMCYGA1UECxMfQ2VydGlmaWNhdGlvbiBTZXJ2aWNlcyBEaXZp" +
		"c2lvbjEZMBcGA1UEAxMQVGhhd3RlIFNlcnZlciBDQTEmMCQGCSqGSIb3DQEJARYXc" +
		"2VydmVyLWNlcnRzQHRoYXd0ZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAo" +
		"GBANOkUG7I/1Zr5s9dtuoMaHVHoqrC2oQl/Kj0R1HahbUgdJSGHg91yekIYfUGbTB" +
		"uFRkC6VLAYttNmZ7iagxEOM3+vuNkCXDF/rFrKbYvScg71CcEJRCXL+eQbcAoQpnX" +
		"TEPew/UhbVSfXcNY4cDk2VuwuNy0e982OsK1ZiIS1ocNAgMBAAGjEzARMA8GA1UdE" +
		"wEB/wQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAB/pMaVz7lcxG7oWDTSEwjsrZqG" +
		"9JGubaUeNgcGyEYRGhGshIPllDfU+VPaGLtwtimHp1it2ITk6eQNuozDJ0uW8NxuO" +
		"zRAvZim+aKZuZGCg70eNAKJpaPNW15yAbi8qkq43pUdniTCxZqdq5snUb9kLy78fy" +
		"GPmJvKP/iiMucEc=";
	
	public static X509Certificate[] getTrustedServerCertificateIssuers() {
        return new X509Certificate[] {CertificateParser.asCertificate(XmlUtil.fromBase64(TrustedServerCertificateIssuers.GSROOT)), CertificateParser.asCertificate(XmlUtil.fromBase64(TrustedServerCertificateIssuers.THAWTE_ROOT))};
	}
}