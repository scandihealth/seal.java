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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/pki/OCESUtil.java $
 * $Id: OCESUtil.java 20807 2014-12-17 12:53:48Z ChristianGasser $
 */
package dk.sosi.seal.pki;

import org.bouncycastle.asn1.*;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Properties;

/**
 * @author $LastChangedBy: ChristianGasser $ $LastChangedDate: 2014-12-17 13:53:48 +0100 (Wed, 17 Dec 2014) $
 * @version $Revision: 20807 $
 */
public class OCESUtil {

    static URI retrieveIntermediateCertificateURI(X509Certificate certificate) throws PKIException {
        try {
            byte[] b1_3_6_1_5_5_7_1_1 = certificate.getExtensionValue("1.3.6.1.5.5.7.1.1");
            if (b1_3_6_1_5_5_7_1_1 == null) {
                throw new PKIException("Invalid certificate - Authority Information Access (1.3.6.1.5.5.7.1.1) not found.");
            }

            ASN1InputStream is1_3_6_1_5_5_7_1_1 = new ASN1InputStream(b1_3_6_1_5_5_7_1_1);

            DEROctetString osAuthorityInformationAccess = (DEROctetString) is1_3_6_1_5_5_7_1_1.readObject();
            ASN1InputStream osAuthorityInformationAccessValue = new ASN1InputStream(
                    osAuthorityInformationAccess.getOctets());

            ASN1Sequence seqAuthorityInformationAccessValue = (ASN1Sequence) osAuthorityInformationAccessValue.readObject();

            if (seqAuthorityInformationAccessValue.size() < 2) {
                throw new PKIException("Invalid certificate - CA Issuers (1.3.6.1.5.5.7.48.2) not found under Authority Information Access.");
            }

            ASN1Sequence seq1_3_6_1_5_5_7_48_2 = (ASN1Sequence) seqAuthorityInformationAccessValue.getObjectAt(1);
            ASN1Encodable seq1_3_6_1_5_5_7_48_2Value = seq1_3_6_1_5_5_7_48_2.getObjectAt(1);

            DEROctetString osAlternativeName = (DEROctetString) ASN1TaggedObject.getInstance(seq1_3_6_1_5_5_7_48_2Value).getObject();

            return new URI(new String(osAlternativeName.getOctets()));
        } catch (IOException ex) {
            throw new PKIException(ex);
        } catch (URISyntaxException ex) {
            throw new PKIException(ex);
        }
    }

    static boolean isProbableOCES1Certificate(X509Certificate certificate) {
        return certificate.getIssuerX500Principal().getName().indexOf("TDC OCES") != -1;
    }

    static boolean isProbableOCES2Certificate(X509Certificate certificate) {
        return certificate.getIssuerX500Principal().getName().indexOf("TRUST2408") != -1;
    }

    static boolean isProbableIntermediateOrRootCertificate(X509Certificate certificate) {
        return isProbableOCES2Certificate(certificate) && certificate.getIssuerX500Principal().getName().indexOf("Primary") != -1;
    }

    static boolean isIssuerOf(X509Certificate certificate, X509Certificate verifyAgainst) throws PKIException {
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

    @Deprecated
    // Not used
    public static String getPropertyNotNull(String propertyName, Properties props) {
        String value = props.getProperty(propertyName);
        if (value == null) {
            throw new IllegalArgumentException("Property '" + propertyName + "' is not defined.");
        }
        return value;
    }
}
