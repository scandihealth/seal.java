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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/pki/PKITestCA.java $
 * $Id: PKITestCA.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.pki;

import dk.sosi.seal.xml.CertificateParser;
import dk.sosi.seal.xml.XmlUtil;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Properties;

public class PKITestCA implements CertificationAuthority {

    private final static String ROOTCERT = "MIIC/DCCAeSgAwIBAgIDD0JAMA0GCSqGSIb3DQEBBQUAMC4xCzAJBgNVBAYTAkRLMQ0wCwYDVQQKEwRTT1NJMRAwDgYDVQQDEwdTT1NJIENBMB4XDTA2MTEwMjA4NTAwMFoXDTI2MTAyODA4NTAwMFowLjELMAkGA1UEBhMCREsxDTALBgNVBAoTBFNPU0kxEDAOBgNVBAMTB1NPU0kgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCPkuU7NNxasHO04GcOes2jUGkbER7TPuBpViDprkzcMoBg/zk+vCk4M8WaLTkmmAEbFUvvtYpq46oB5zvdHlPhUDMiHA9t+59oHTb16RYW2/es9q3iNZxm1nfMFeJqPfwhuVSl0IxmvWjUV3j4slW+fXa0FPIEQsdAITM9dQp8qY7fxBQbxMAckVI5BYYOpUDiGvZE3m97pii/uSUlUludXLPNqlmJLg1XNg/VXn1jWnOOdJqVYax7h4Y/YrPCwpqz8875xtLbPAKXCE6JoqimmjEtGANJ6j3PEZgGufrV2CROm4mdSkdrpFfTSqESL/8V1LtZgt05Gbz81cnGSKVPAgMBAAGjIzAhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBBQUAA4IBAQBCTtOX5UQBZL/ZpCiF2n8uJokuh54fG1stooEozn9+rw+xfohfcoWNQ1Eoegq3odWf5lobjsVDe4TPBiYbg7cSFIFCY5LtMaLNdyIyy9/0w1otidNs3hCT2yVXyYb75p0iog58SSSsmP5cznOsqjbpgO9/e13i2o8S5ApPLTi24GB56r6OJLvZMhSWtnN3vBdLLsAWCm7dZQqhXxq6KvElK9Ly+MI3tPhaHzxc3tQs4vaQtWmd68gGntwYpYXIh435OANBuHwunO5JvLbKuEFhnaIVGldOTLsh+nXovNpZmfJ/cRbFsOxV5IQKwMnmPPYjnfyqQMk3TsIyvJMe6F6Q";

    public PKITestCA(Properties properties) throws Exception {
    }

    public X509Certificate getRootCertificate() {
        return CertificateParser.asCertificate(XmlUtil.fromBase64(ROOTCERT));
    }

    public boolean isValid(X509Certificate certificate) throws PKIException {
        if(certificate.getNotAfter().getTime() < System.currentTimeMillis()) {
            return false; // Certificate is expired
        } else if(certificate.getNotBefore().getTime() > System.currentTimeMillis()) {
            return false; // Certificate is not yet valid
        }
        if (!isIssuerOf(certificate, getRootCertificate())) {
            throw new PKIException("Certificate not issued by PKITestCA");
        }
        return true;
    }

    public CertificateStatus getCertificateStatus(X509Certificate certificate) throws PKIException {
        return new CertificateStatus(isValid(certificate), new Date());
    }

    private boolean isIssuerOf(X509Certificate certificate, X509Certificate verifyAgainst) throws PKIException {
        try {
            certificate.verify(verifyAgainst.getPublicKey());
            return true; // NOPMD
        } catch (InvalidKeyException e) {
            return false; // NOPMD
        } catch (CertificateException e) {
            throw new PKIException("Failed to establish issuer of");
        } catch (NoSuchAlgorithmException e) {
            throw new PKIException("Failed to establish issuer of");
        } catch (NoSuchProviderException e) {
            throw new PKIException("Failed to establish issuer of");
        } catch (SignatureException e) {
            return false;
        }
    }

    public X509Certificate getFederationCertificate(FederationCertificateReference reference) {
        return null;
    }
}