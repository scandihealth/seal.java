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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/pki/TestPKI.java $
 * $Id: TestPKI.java 34531 2017-09-27 12:33:08Z ChristianGasser $
 */

package dk.sosi.seal.pki;

import dk.sosi.seal.MainTester;
import dk.sosi.seal.model.ModelException;
import dk.sosi.seal.model.SignatureConfiguration;
import dk.sosi.seal.model.SignatureUtil;
import dk.sosi.seal.model.constants.IDValues;
import dk.sosi.seal.pki.impl.HashMapCertificateCache;
import dk.sosi.seal.vault.CredentialPair;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.vault.GenericCredentialVault;
import dk.sosi.seal.vault.renewal.KeyGenerator;
import dk.sosi.seal.xml.CertificateParser;
import dk.sosi.seal.xml.XmlUtil;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.junit.Assert.*;

public class TestPKI {

    private PKITestCA sosica;
    private PublicKey publicKey;
    private Properties properties;
    private boolean bcAdded;

    @Before
    public void setUp() throws Exception {
        bcAdded = MainTester.addBCAsProvider();
        properties = SignatureUtil.setupCryptoProviderForJVM();

        sosica = new PKITestCA(properties);
        publicKey = CredentialVaultTestUtil.getCredentialVault().getSystemCredentialPair().getCertificate().getPublicKey();
    }

    @After
    public void tearDown() throws Exception {
        if(bcAdded)
            MainTester.removeBCAsProvider();
    }

    @Test
    public void testCA() throws Exception {

        CertificationAuthority ca;
        try {
            ca = CertificationAuthorityFactory.create(properties, "unknown", new NaiveCertificateStatusChecker(properties), new HashMapCertificateCache());
            fail("Factory should throw exception");
        } catch (PKIException e) {
            // OK
        }

        ca = CertificationAuthorityFactory.create(properties, CertificationAuthorityFactory.OCES_SYSTEMTEST_CA, new NaiveCertificateStatusChecker(properties), CredentialVaultTestUtil.getCertificateCacheForVocesCredentialVault());
        X509Certificate cert = CredentialVaultTestUtil.getVocesCredentialVault().getSystemCredentialPair().getCertificate();
        assertTrue(ca.isValid(cert));

        // Test expired certs

        Date notAfter = new Date(System.currentTimeMillis() - 1 * 60 * 1000);
        Date notBefore = new Date(System.currentTimeMillis() - 10 * 60 * 1000);
        cert = OCESTestHelper.issueCertificate("cn=Thomas,o=Test,c=DK", "thomas@signaturgruppen.dk", publicKey, sosica.getRootCertificate().getPublicKey(), notBefore, notAfter);
        assertFalse("Certificate expected NOT valid", sosica.isValid(cert));

        // Test not yet valid cert
        notBefore = new Date(System.currentTimeMillis() + 10 * 60 * 1000);
        notAfter = new Date(System.currentTimeMillis() + 11 * 60 * 1000);
        cert = OCESTestHelper.issueCertificate("cn=Thomas,o=Test,c=DK", "thomas@signaturgruppen.dk", publicKey, sosica.getRootCertificate().getPublicKey(), notBefore, notAfter);
        assertFalse(sosica.isValid(cert));

        // Test against bad ca
        cert = CredentialVaultTestUtil.getVocesCredentialVault().getSystemCredentialPair().getCertificate();
         try{
             sosica.isValid(cert);
             fail("PKIException expected");
         } catch (PKIException e) {
             //OK
         }

    }
    @Test
    public void testRevokedCertificate() {
        CertificationAuthority ca = CertificationAuthorityFactory.create(properties, CertificationAuthorityFactory.OCES_SYSTEMTEST_CA,
                new MockCertificateStatusChecker(1), CredentialVaultTestUtil.getCertificateCacheForVocesCredentialVault());
        X509Certificate cert = CredentialVaultTestUtil.getVocesCredentialVault().getSystemCredentialPair().getCertificate();
        assertFalse(ca.isValid(cert));
    }

    @Test
    public void testFederation() throws Exception {
        // Test STS identification
        String ss1 = "CVR:12341233-UID:1111";
        
        MockFederation mf = new MockFederation(properties, sosica, ss1);
        assertEquals(sosica, mf.getCertificationAuthority());

        String dn = "CN=Thomas+SN=" + ss1 + ",o=Test,c=DK";
        X509Certificate sts = OCESTestHelper.issueCertificate(dn, "test@test.dk", publicKey, sosica.getRootCertificate().getPublicKey());

        assertTrue(mf.isValidSTSCertificate(sts));

        // Bad dn
        String ss2 = "CVR:12341233-UID:111x";
        dn = "CN=Thomas+SN=" + ss2 + ",o=Test,c=DK";
        sts = OCESTestHelper.issueCertificate(dn, "test@test.dk", publicKey, sosica.getRootCertificate().getPublicKey());

        assertFalse(mf.isValidSTSCertificate(sts));
    }

    @Test
    public void testPKIException() throws Exception {
        PKIException e = new PKIException();
        assertNull(e.getMessage());
        assertNull(e.getCause());

        PKIException ne = new PKIException("test");
        assertEquals("test", ne.getMessage());
        assertNull(ne.getCause());

        ne = new PKIException("t", e);
        assertEquals("t", ne.getMessage());
        assertEquals(e, ne.getCause());

        ne = new PKIException(e);
        assertEquals(e, ne.getCause());
        assertEquals(e.getClass().getName(), ne.getMessage());
    }

    @Test
    public void testDN() {
        DistinguishedName dn = new DistinguishedName("CN=Thomas+ serialNumber=PID:1231243,  ou=INgen,o=Signaturgruppen,C=DK");

        assertNotNull(dn.getCommonName());
        assertEquals("Thomas", dn.getCommonName());

        assertEquals("PID:1231243", dn.getSubjectSerialNumber());
        assertEquals("INgen", dn.getOrganizationalUnit());
        assertEquals("DK", dn.getCountry());
        assertEquals("Signaturgruppen", dn.getOrganization());

        CredentialVault vault = CredentialVaultTestUtil.getCredentialVaultFromPKCS12(CredentialVaultTestUtil.VOCES_EXPIRED_PKCS12, CredentialVaultTestUtil.VOCES_EXPIRED_PKCS12_PWD);
        dn = new DistinguishedName(vault.getSystemCredentialPair().getCertificate().getSubjectX500Principal());
        assertEquals("DK", dn.getCountry());
        assertEquals("CVR:19343634-UID:1165813731180", dn.getSubjectSerialNumber());
        assertEquals("JERNALDERBYENS VENNER - Vic notWhiteListedVOCES", dn.getCommonName());

        DistinguishedName other = new DistinguishedName("cn=T,ou=1,ou=2,o=Test,c=DK");
        dn = new DistinguishedName("c=DK,o=Test,ou=1,ou=2,cn=T");
        assertEquals(other, dn);
        assertEquals(other.hashCode(), dn.hashCode());
        dn = new DistinguishedName("c=DK,o=Test,ou=1,cn=T");
        assertFalse(other.equals(dn));
        dn = new DistinguishedName("c=DK,o=Test,ou=2,ou=1,cn=T");
        assertEquals(other, dn);

        Set<String> ous = dn.getOrganizationalUnits();
        assertTrue(ous.contains("2"));
        assertTrue(ous.contains("1"));

        assertFalse(dn.equals("1"));

        dn = new DistinguishedName("cn=T");
        assertNull(dn.getCountry());
        assertNull(dn.getOrganizationalUnits());

        try {
            new DistinguishedName("badoid=test");
            fail("bad dn undetected");
        } catch (PKIException e) {
            assertTrue(e.getMessage().indexOf("Unknown attribute") != -1);
        }

        try {
            new DistinguishedName("CN=A,foo,C=DK");
            fail("bad dn undetected");
        } catch (PKIException e) {
            assertEquals("javax.naming.InvalidNameException: Invalid name: CN=A,foo,C=DK", e.getMessage());
        }

        dn = new DistinguishedName("C=DK,O=TRIFORK SERVICES A/S // CVR:25520041,CN=Amaja Christiansen,Serial=CVR:25520041-RID:42041556");
        assertEquals("DK", dn.getCountry());
        assertEquals("CVR:25520041-RID:42041556", dn.getSubjectSerialNumber());
        assertEquals("TRIFORK SERVICES A/S // CVR:25520041", dn.getOrganization());
        assertEquals("Amaja Christiansen", dn.getCommonName());

        dn = new DistinguishedName("CN=Test 1602763141 + SERIALNUMBER=CVR:26912865-RID:82139564, O=No Name Import // CVR:26912865, C=DK");
        assertEquals("DK", dn.getCountry());
        assertEquals("CVR:26912865-RID:82139564", dn.getSubjectSerialNumber());
        assertEquals("No Name Import // CVR:26912865", dn.getOrganization());
        assertEquals("Test 1602763141", dn.getCommonName());
    }

    @Test
    public void testDistinguishedNameEscapedRDNs() {
        DistinguishedName distinguishedName = new DistinguishedName("CN=\"Hans Sørensen\" + SERIALNUMBER=CVR:36456336-RID:1156936634909, o=Lægerne i Nørregade // CVR:36456336, c=DK");
        assertEquals("Hans Sørensen", distinguishedName.getCommonName());
        assertEquals("DK", distinguishedName.getCountry());
        assertEquals("Lægerne i Nørregade // CVR:36456336", distinguishedName.getOrganization());
        assertEquals("CVR:36456336-RID:1156936634909", distinguishedName.getSubjectSerialNumber());
        assertNull(distinguishedName.getOrganizationalUnit());

        distinguishedName = new DistinguishedName("CN=Merlin Hughes, O=\"Baltimore Technologies, Ltd.\", ST=Dublin, C=IE");
        assertEquals("Merlin Hughes", distinguishedName.getCommonName());
        assertEquals("IE", distinguishedName.getCountry());
        assertEquals("Baltimore Technologies, Ltd.", distinguishedName.getOrganization());
        assertNull(distinguishedName.getSubjectSerialNumber());
        assertNull(distinguishedName.getOrganizationalUnit());

    }

    @Test
    public void testDistinguishedNameX509Implementations() {
        String certStr = "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";
        X509Certificate certBCImpl = parserCertificate(XmlUtil.fromBase64(certStr), true);
        X509Certificate certSunImpl = parserCertificate(XmlUtil.fromBase64(certStr), false);

        assertEquals(new DistinguishedName(certBCImpl.getSubjectX500Principal()), new DistinguishedName(certSunImpl.getSubjectX500Principal()));
        assertEquals(new DistinguishedName(certBCImpl.getIssuerX500Principal()), new DistinguishedName(certSunImpl.getIssuerX500Principal()));
    }

    @Test
    public void testDistinguishedNameEncoding() {
        String certStr = "MIIFADCCBGmgAwIBAgIEQDasCzANBgkqhkiG9w0BAQUFADA/MQswCQYDVQQGEwJESzEMMAoGA1UEChMDVERDMSIwIAYDVQQDExlUREMgT0NFUyBTeXN0ZW10ZXN0IENBIElJMB4XDTA3MDYwODA3NTA1N1oXDTA5MDYwODA4MjA1N1owfTELMAkGA1UEBhMCREsxLzAtBgNVBAoUJlREQyBUT1RBTEzYU05JTkdFUiBBL1MgLy8gQ1ZSOjI1NzY3NTM1MT0wFAYDVQQDEw1UZXN0IEJydWdlciAxMCUGA1UEBRMeQ1ZSOjI1NzY3NTM1LVJJRDoxMTE4MDYxMDIwMjMyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCvaqnWzxjfOVtULu0UDXImBSRrrFPNpwYk/gTcBaSTV9/wGzEYerYRIQr2ttsfPomkE1ZX2tHL4Q1BtuDiZw+0a6P4AfHjYBC9GA3pdr4xOZ6G7WBsMwiBO51ISvJylnfB4kOAFzQ5zEGVzpoFMDIw8kacsM+KUOAtnnA6h4UVLQIDAQABo4ICyTCCAsUwDgYDVR0PAQH/BAQDAgP4MCsGA1UdEAQkMCKADzIwMDcwNjA4MDc1MDU3WoEPMjAwOTA2MDgwODIwNTdaMEYGCCsGAQUFBwEBBDowODA2BggrBgEFBQcwAYYqaHR0cDovL3Rlc3Qub2NzcC5jZXJ0aWZpa2F0LmRrL29jc3Avc3RhdHVzMIIBAwYDVR0gBIH7MIH4MIH1BgkpAQEBAQEBAQIwgecwLwYIKwYBBQUHAgEWI2h0dHA6Ly93d3cuY2VydGlmaWthdC5kay9yZXBvc2l0b3J5MIGzBggrBgEFBQcCAjCBpjAKFgNUREMwAwIBARqBl1REQyBUZXN0IENlcnRpZmlrYXRlciBmcmEgZGVubmUgQ0EgdWRzdGVkZXMgdW5kZXIgT0lEIDEuMS4xLjEuMS4xLjEuMS4xLjIuIFREQyBUZXN0IENlcnRpZmljYXRlcyBmcm9tIHRoaXMgQ0EgYXJlIGlzc3VlZCB1bmRlciBPSUQgMS4xLjEuMS4xLjEuMS4xLjEuMi4wGgYJYIZIAYb4QgENBA0WC2VtcGxveWVlV2ViMBwGA1UdEQQVMBOBEWNlcnRpZmlrYXRAdGRjLmRrMIGWBgNVHR8EgY4wgYswVqBUoFKkUDBOMQswCQYDVQQGEwJESzEMMAoGA1UEChMDVERDMSIwIAYDVQQDExlUREMgT0NFUyBTeXN0ZW10ZXN0IENBIElJMQ0wCwYDVQQDEwRDUkw1MDGgL6AthitodHRwOi8vdGVzdC5jcmwub2Nlcy5jZXJ0aWZpa2F0LmRrL29jZXMuY3JsMB8GA1UdIwQYMBaAFByYCUcaTDi5EMUEKVvx9E6Aasx+MB0GA1UdDgQWBBQlt8pB8JxckqzTN99Lv2bpkWS1CjAJBgNVHRMEAjAAMBkGCSqGSIb2fQdBAAQMMAobBFY3LjEDAgOoMA0GCSqGSIb3DQEBBQUAA4GBAGTIAUU399zIwK4CIWbkzmNHFwy675sXNTfmhBWVytHL8Sgu//GDuTEcq7Q4rD0aEQfnXd/gP66Rot38eXVWL6IU8pYDYLN0balmAoVaJG62wihiLz95zs7LUJRBIFAtD3vWNwK9GlNQo5z4LkJbAMtyhrd/0N3i4PxR+NCMbzCa";
        X509Certificate certificate = CertificateParser.asCertificate(XmlUtil.fromBase64(certStr));
        assertEquals(new DistinguishedName("CN=Test Bruger 1 + SERIALNUMBER=CVR:25767535-RID:1118061020232, O=TDC TOTALLØSNINGER A/S // CVR:25767535, C=DK"), new DistinguishedName(certificate.getSubjectX500Principal()));
        assertEquals(new DistinguishedName("CN=TDC OCES Systemtest CA II, O=TDC, C=DK"), new DistinguishedName(certificate.getIssuerX500Principal()));
    }

    private static X509Certificate parserCertificate(byte[] value, boolean useBC) {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(value);
        try {

            CertificateFactory factory = CertificateFactory.getInstance("X.509", useBC ? "BC" : "SUN");
            final X509Certificate certificate = (X509Certificate) factory.generateCertificate(byteArrayInputStream);
            if (certificate == null) {
                throw new ModelException("Unable to create certificate from supplied value");
            } else {
                return certificate;
            }
        } catch (CertificateException e) {
            throw new ModelException("Unable to create certificate from supplied value", e);
        } catch (NoSuchProviderException e) {
            throw new ModelException("Unable to load X.509 provider", e);
        } finally {
            try {
                byteArrayInputStream.close();
            } catch (IOException e) {
                // ignore
            }
        }
    }


    @Test
    public void testTestFederation() throws Exception {
        Federation fed = new SOSITestFederation(properties, CredentialVaultTestUtil.getCertificateCacheForSTSFocesCredentialVault());
        String cert = "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";
        X509Certificate sosiTestSTS = CertificateParser.asCertificate(XmlUtil.fromBase64(cert));
        assertTrue(fed.isValidSTSCertificate(sosiTestSTS));
    }

    @Test
    public void testIsTrustedSTSCertificate() throws Exception {
        GenericCredentialVault vault = new GenericCredentialVault(SignatureUtil.setupCryptoProviderForJVM(), "password");
        
        PKITestCA ca = new PKITestCA(SignatureUtil.setupCryptoProviderForJVM());
        String stsSerial = "CVR:99994444-UID:1234123411111";
        
        MockFederation fed = new MockFederation(properties, ca, stsSerial);
        
        KeyGenerator kg = new KeyGenerator("1", System.getProperties());
        // Speed up test
        kg.setKeySize(512);
        kg.generateKeyPair();

        X509Certificate systemCert = OCESTestHelper.issueCertificate("cn=SystemCert,o=Test,c=DK", null, kg.getPublicKey(), ca.getRootCertificate().getPublicKey());
        CredentialPair systemCredentials = new CredentialPair(systemCert, kg.getPrivateKey());
        vault.setSystemCredentialPair(systemCredentials);

        kg.generateKeyPair();
        X509Certificate other = OCESTestHelper.issueCertificate("cn=Other,o=TEST,c=DK", null, kg.getPublicKey(), ca.getRootCertificate().getPublicKey());

        kg.generateKeyPair();
        X509Certificate sts = OCESTestHelper.issueCertificate("CN=STS+SN=" + stsSerial + ",o=TEST,c=DK", null, kg.getPublicKey(), ca.getRootCertificate().getPublicKey());

        assertTrue(fed.isValidCertificate(sts));
        assertTrue(fed.isValidSTSCertificate(sts));

        assertTrue(fed.isValidCertificate(other));
        assertFalse(fed.isValidSTSCertificate(other));

        assertTrue(fed.getCertificateStatus(other).isValid());

    }

    @Test
    public void testRevokeCertificate() throws Exception {
        String stsSerial = "CVR:99994444-UID:1234123411111";
        MockFederation fed = new MockFederation(properties, sosica, stsSerial);
        
        KeyGenerator kg = new KeyGenerator("1", properties);
        // Speed up test
        kg.setKeySize(512);
        kg.generateKeyPair();

        kg.generateKeyPair();
        X509Certificate other = OCESTestHelper.issueCertificate("cn=Other,o=TEST,c=DK", null, kg.getPublicKey(), sosica.getRootCertificate().getPublicKey());

        assertTrue(fed.isValidCertificate(other));
    }

    @Test
    public void testFederationTrust() throws Exception {
        GenericCredentialVault vault = new GenericCredentialVault(SignatureUtil.setupCryptoProviderForJVM(), "password");
        
        String stsSerial = "CVR:99994444-UID:1234123411111";
        MockFederation fed = new MockFederation(properties, sosica, stsSerial);
        
        KeyGenerator kg = new KeyGenerator("1", System.getProperties());
        // Speed up test
        kg.setKeySize(512);
        kg.generateKeyPair();

        X509Certificate systemCert = OCESTestHelper.issueCertificate("cn=SystemCert,o=Test,c=DK", null, kg.getPublicKey(), sosica.getRootCertificate().getPublicKey());
        CredentialPair systemCredentials = new CredentialPair(systemCert, kg.getPrivateKey());
        vault.setSystemCredentialPair(systemCredentials);

        kg.generateKeyPair();
        X509Certificate sts = OCESTestHelper.issueCertificate("CN=STS+SN=" + stsSerial + ",o=TEST,c=DK", null, kg.getPublicKey(), sosica.getRootCertificate().getPublicKey());
        CredentialPair stsCredentials = new CredentialPair(sts, kg.getPrivateKey());
        GenericCredentialVault stsVault = new GenericCredentialVault(SignatureUtil.setupCryptoProviderForJVM(), "password");
        stsVault.setSystemCredentialPair(stsCredentials);

        Document document = XmlUtil.readXml(properties, CredentialVaultTestUtil.XML_DOCUMENT, false);

        document.getElementsByTagName("fornavn").item(0);
        String[] referenceUris = { "elmtosign" };
        final SignatureConfiguration configuration = new SignatureConfiguration(referenceUris, "elmtosign", IDValues.id);
        SignatureUtil.sign(SignatureProviderFactory.fromCredentialVault(stsVault), document, configuration);

        Node elmSignature = document.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);
        if(!SignatureUtil.validate(elmSignature, fed, vault, false)) {
            fail("Unable to validate signature");
        }

        assertTrue(SignatureUtil.validate(elmSignature, fed, vault, true));
        assertTrue(fed.isValidSTSCertificate(sts));
    }
}