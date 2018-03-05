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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/pki/OCESTestCertificationAuthority.java $
 * $Id: OCESTestCertificationAuthority.java 20806 2014-12-17 12:33:55Z ChristianGasser $
 */
package dk.sosi.seal.pki;

import dk.sosi.seal.pki.impl.HashMapCertificateCache;
import dk.sosi.seal.pki.impl.PropertiesSOSIConfiguration;
import dk.sosi.seal.pki.impl.federationcert.FederationCertificateStoreAdapter;
import dk.sosi.seal.xml.CertificateParser;
import dk.sosi.seal.xml.XmlUtil;

import java.security.cert.X509Certificate;
import java.util.Properties;

/**
 * Implementation of CertificationAuthority representing the OCES test CA.
 *
 * @author ads@lakeside.dk
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 20806 $
 * @since 2.0
 */
public class OCESTestCertificationAuthority extends AbstractOCESCertificationAuthority {

    private static final String OCES1_TEST_ROOT_CERTIFICATE_BASE_64 =
        "MIIEXTCCA8agAwIBAgIEQDYX/DANBgkqhkiG9w0BAQUFADA/MQswCQYDVQQGEwJE" +
        "SzEMMAoGA1UEChMDVERDMSIwIAYDVQQDExlUREMgT0NFUyBTeXN0ZW10ZXN0IENB" +
        "IElJMB4XDTA0MDIyMDEzNTE0OVoXDTM3MDYyMDE0MjE0OVowPzELMAkGA1UEBhMC" +
        "REsxDDAKBgNVBAoTA1REQzEiMCAGA1UEAxMZVERDIE9DRVMgU3lzdGVtdGVzdCBD" +
        "QSBJSTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEArawANI56sljDsnosDU+M" +
        "p4r+RKFys9c5qy8jWZyA+7PYFs4+IZcFxnbNuHi8aAcbSFOUJF0PGpNgPEtNc+XA" +
        "K7p16iawNTYpMkHm2VoInNfwWEj/wGmtb4rKDT2a7auGk76q+Xdqnno4PRO8e7AK" +
        "EHw7pN3kiHmZCI48PTRpRx8CAwEAAaOCAmQwggJgMA8GA1UdEwEB/wQFMAMBAf8w" +
        "DgYDVR0PAQH/BAQDAgEGMIIBAwYDVR0gBIH7MIH4MIH1BgkpAQEBAQEBAQEwgecw" +
        "LwYIKwYBBQUHAgEWI2h0dHA6Ly93d3cuY2VydGlmaWthdC5kay9yZXBvc2l0b3J5" +
        "MIGzBggrBgEFBQcCAjCBpjAKFgNUREMwAwIBARqBl1REQyBUZXN0IENlcnRpZmlr" +
        "YXRlciBmcmEgZGVubmUgQ0EgdWRzdGVkZXMgdW5kZXIgT0lEIDEuMS4xLjEuMS4x" +
        "LjEuMS4xLjEuIFREQyBUZXN0IENlcnRpZmljYXRlcyBmcm9tIHRoaXMgQ0EgYXJl" +
        "IGlzc3VlZCB1bmRlciBPSUQgMS4xLjEuMS4xLjEuMS4xLjEuMS4wEQYJYIZIAYb4" +
        "QgEBBAQDAgAHMIGWBgNVHR8EgY4wgYswVqBUoFKkUDBOMQswCQYDVQQGEwJESzEM" +
        "MAoGA1UEChMDVERDMSIwIAYDVQQDExlUREMgT0NFUyBTeXN0ZW10ZXN0IENBIElJ" +
        "MQ0wCwYDVQQDEwRDUkwxMDGgL6AthitodHRwOi8vdGVzdC5jcmwub2Nlcy5jZXJ0" +
        "aWZpa2F0LmRrL29jZXMuY3JsMCsGA1UdEAQkMCKADzIwMDQwMjIwMTM1MTQ5WoEP" +
        "MjAzNzA2MjAxNDIxNDlaMB8GA1UdIwQYMBaAFByYCUcaTDi5EMUEKVvx9E6Aasx+" +
        "MB0GA1UdDgQWBBQcmAlHGkw4uRDFBClb8fROgGrMfjAdBgkqhkiG9n0HQQAEEDAO" +
        "GwhWNi4wOjQuMAMCBJAwDQYJKoZIhvcNAQEFBQADgYEApyoAjiKq6WK5XaKWUpVs" +
        "kutzohv1VcCke/3JeUVtmB+byexJMC171s4RHoqcbufcI2ASVWwu84i45MaKg/nx" +
        "oqojMyY19/W2wbQFEdsxUCnLa9e9tlWj0xS/AaKeUhk2MBOqv+hMdc71jOqc5JN7" +
        "T2Ba6ZRIY5uXkO3IGZ3XUsw=";

    private static final String OCES2_TEST_IG_ROOT_CERTIFICATE_BASE_64 =
        "MIIGRTCCBC2gAwIBAgIETHO9tTANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJE" +
        "SzESMBAGA1UEChMJVFJVU1QyNDA4MSswKQYDVQQDEyJUUlVTVDI0MDggU3lzdGVt" +
        "dGVzdCBJWCBQcmltYXJ5IENBMB4XDTEwMDgyNDEyMTAyM1oXDTM3MTIyNDEyNDAy" +
        "M1owTjELMAkGA1UEBhMCREsxEjAQBgNVBAoTCVRSVVNUMjQwODErMCkGA1UEAxMi" +
        "VFJVU1QyNDA4IFN5c3RlbXRlc3QgSVggUHJpbWFyeSBDQTCCAiIwDQYJKoZIhvcN" +
        "AQEBBQADggIPADCCAgoCggIBAMgd7UdslIik/4S2EF+i37FaxHOD+tvtJQgeMAei" +
        "0kOBFtCuu+tz6uJGWOVDRvh6SyTncdZGAlRKNZAK+ZULUnU1pdB2fbV9rhLF4q0M" +
        "BGSgjUd+DpQhUmLi2QLaZvfmmTz4melVewCtYjqCRzPULHetHQKCQIduIhMfR0EE" +
        "e38Ooy6PwLEUrYbKyq6rd0Xf2jcSV0srM3INfEULmeWld/kYPI8SH6M/XXiyvhFv" +
        "ymAYY3v9XlAWUtTSnJmqs1yU6xpQG1VwRsHQSDvyWmPluGKwELCLWKXK2sNco6Yy" +
        "RwNGcnhsjM2kPZ8nhgDJNVFFdd9AjD/qAeex54n+sJHMH/WtmOz9HWeQYrbGO+lW" +
        "W/ZXss8Z+KlMzje3pWgxYIhK8OZoRvoUKoLQ1JJH/KjgwcZxuxKzGm7uwoLGHUjg" +
        "Yr/1TzJT+sddLTK9TNL2SOwATbg+ueZ7kqIt7Uxih9203b4Y1x1rtIxa7zxtZ4Fc" +
        "MvOc8rVfEnanBdhC1nUCThPivf6HrsybD3FG/22FQdq/7ZmcOB2avn4Z1F983Wlc" +
        "o6etLHsHfqDy771bMO83aLp/bHBHqOUG7bnNaSegmK5blfEBmYkzAXFaxQnr02LK" +
        "7v54dCO8lzBya/06erErdTywSRGLN/+We/h2NVGDokv6remDdAC0XFIs4WrTSvYg" +
        "oiP/AgMBAAGjggEpMIIBJTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB" +
        "BjARBgNVHSAECjAIMAYGBFUdIAAwga4GA1UdHwSBpjCBozA6oDigNoY0aHR0cDov" +
        "L2NybC5zeXN0ZW10ZXN0OS50cnVzdDI0MDguY29tL3N5c3RlbXRlc3Q5LmNybDBl" +
        "oGOgYaRfMF0xCzAJBgNVBAYTAkRLMRIwEAYDVQQKEwlUUlVTVDI0MDgxKzApBgNV" +
        "BAMTIlRSVVNUMjQwOCBTeXN0ZW10ZXN0IElYIFByaW1hcnkgQ0ExDTALBgNVBAMT" +
        "BENSTDEwHwYDVR0jBBgwFoAUAMhRPjg1v23MAbpjBIk5L7AlcdowHQYDVR0OBBYE" +
        "FADIUT44Nb9tzAG6YwSJOS+wJXHaMA0GCSqGSIb3DQEBCwUAA4ICAQAk/ghXxPKM" +
        "5E/VwViE0UtJQKBzsaCT33Jzqx081Cmt8mfQTEhpVhiE3jMkYYj5kaN0qqHfuvip" +
        "mcpjs4qs38lpZGR13XeuHKY5QLEKo7L14DxhmJi3nfBIUMdcplQpvGZFr9zmyWZ3" +
        "DUXNdLfKLwXXZHJB5+N3TrOk/11yksibNLEDLpS/tCjYKZI3VKL/6QDdFbR1JjCy" +
        "t6hUeCG4Do2SIggst3oiKRcuPYkX6kukm1V5+vY8i0zRd48jKh3oPQFyi5StD1+o" +
        "uHYLHDr5UgueC77xJ3ZcVpyToxJjc2mxqovB5r2Zrfs9JdT/iLQDs5kvpkOuZL8F" +
        "4yPj3PgNvz1WZkQq/QwlO6EdwoAiLTzWxlnTSQ2XGYEjREkOglrLuRoBWz89ZgMC" +
        "xrMfPWbCRyTC6i5MRNmdRKUtqhe/KO2oSuO1RioIO0sTe2tnkiEmIN7kXD92R1KL" +
        "JCZB2NFaWOv+yU1GvpER2gXrlvq/yoFuU8g+72BT6UiaCsmr7L1iK7poJKDClS+A" +
        "t+5/+gvQRq9BjGtR/q4d3B8xL8Mg58rZbf6FHas6cb0c3e9iVtqSQviXO6VYPQch" +
        "X8rjBrXViDvlKXa3fwu6pzhJhJQnsM0jgSV7wEQfoRoTvkXPxwik1xyroV3qKIhx" +
        "y3pgq7fDfTxMgVDvMIhjU0+ZQ/DP4ska2g==";

    private static final String OCES2_TEST_PP_ROOT_CERTIFICATE_BASE_64 =
        "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" +
        "XD44AxIinryzhqnEWI+BxdlFaia3U7o2+HYdHw==";

    public static final X509Certificate OCES_1_TEST_ROOT_CERTIFICATE = CertificateParser.asCertificate(XmlUtil.fromBase64(OCES1_TEST_ROOT_CERTIFICATE_BASE_64));

    public static final X509Certificate OCES_2_TEST_ROOT_CERTIFICATE = CertificateParser.asCertificate(XmlUtil.fromBase64(OCES2_TEST_PP_ROOT_CERTIFICATE_BASE_64));

    /**
     * @deprecated will be removed in future Seal release
     */
    @Deprecated
    public static final X509Certificate OCES_2_TEST_IG_ROOT_CERTIFICATE = CertificateParser.asCertificate(XmlUtil.fromBase64(OCES2_TEST_IG_ROOT_CERTIFICATE_BASE_64));

    /**
     * @deprecated use {@link #OCES_2_TEST_ROOT_CERTIFICATE}
     */
    @Deprecated
    public static final X509Certificate OCES_2_TEST_PP_ROOT_CERTIFICATE = OCES_2_TEST_ROOT_CERTIFICATE;

    /**
     * Constructor for the <code>OCESTestCertificationAuthority</code> class.
     *
     * @param properties
     *            The initialization <code>Properties</code> of the system
     * @deprecated will be removed in future Seal release
     */
    @Deprecated
    public OCESTestCertificationAuthority(Properties properties, CertificateStatusChecker certificateStatusChecker, IntermediateCertificateCache intermediateCertificateCache) {
        // This is not nice at all! To be removed in next Seal release
        this(PropertiesSOSIConfiguration.createWithDefaultOcesTestProperties(properties), certificateStatusChecker, intermediateCertificateCache,
             new FederationCertificateStoreAdapter(PropertiesSOSIConfiguration.createWithDefaultOcesTestProperties(properties), new HashMapCertificateCache()));
    }

    public OCESTestCertificationAuthority(SOSIConfiguration configuration, CertificateStatusChecker certificateStatusChecker, IntermediateCertificateCache intermediateCertificateCache, FederationCertificateResolver federationCertificateResolver) {
        super(configuration, certificateStatusChecker, intermediateCertificateCache, federationCertificateResolver);
    }

    protected X509Certificate getOCES1RootCertificate() {
        return OCES_1_TEST_ROOT_CERTIFICATE;
    }

    protected X509Certificate getOCES2RootCertificate() {
        return OCES_2_TEST_ROOT_CERTIFICATE;
    }

    protected String getCertificationAuthorityName() {
        return "OCES Test";
    }

}