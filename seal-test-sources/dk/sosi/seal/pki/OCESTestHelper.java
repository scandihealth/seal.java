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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/pki/OCESTestHelper.java $
 * $Id: OCESTestHelper.java 15447 2014-08-12 13:26:46Z ChristianGasser $
 */
package dk.sosi.seal.pki;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.SignatureUtil;
import dk.sosi.seal.xml.XmlUtil;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Date;

public class OCESTestHelper {

    /* pp */static final String CA_DN = "cn=SOSI CA,o=SOSI,c=DK";
    private final static String MODULUS = "AI+S5Ts03Fqwc7TgZw56zaNQaRsRHtM+4GlWIOmuTNwygGD/OT68KTgzxZotOSaYARsVS++1imrjqgHnO90eU+FQMyIcD237n2gdNvXpFhbb96z2reI1nGbWd8wV4mo9/CG5VKXQjGa9aNRXePiyVb59drQU8gRCx0AhMz11Cnypjt/EFBvEwByRUjkFhg6lQOIa9kTeb3umKL+5JSVSW51cs82qWYkuDVc2D9VefWNac450mpVhrHuHhj9is8LCmrPzzvnG0ts8ApcITomiqKaaMS0YA0nqPc8RmAa5+tXYJE6biZ1KR2ukV9NKoRIv/xXUu1mC3TkZvPzVycZIpU8=";
    private static int nextSerialNumber = 1000001;
    private final static String PRIVATE_EXP = "RFnKh8VComoeq52pcltEStudLiWYZzkn3P4D7Tvtm2bvdz4KIrOxa/A5woyFCLqUzC/3Vsc2fmykIwPSnBI0HK/xp+tz7Qg9e3NtFuVAfuF5p/5ICck8DDlODvrcL3gS8HsqsUX3kXHa1jxOexdreqSAPns6PI0ODpm/qyJtO6tGm0b4O69MIDLbDnaDb5ZXmmBD2+R22S9efaH4XZVsmQaBVPPDX9bJCXVysyjRQvSxTjGRh9neqhWwO/8ssZ4ihdbJ4OzUkHDPxRX/3S+P+6A4V890ita7Ige8in+HdNfCQB3bNvDSyB9iOWabAw4MlePH1JoGQKSkshWK8g2NAQ==";

    public static X509V3CertificateGenerator createTemplateCertificateGenerator(String dn, String email, PublicKey publicKey, boolean addCDP, PublicKey rootCertificateKey) throws CertificateParsingException, InvalidKeyException {
        X509V3CertificateGenerator cg = new X509V3CertificateGenerator();
        cg.setIssuerDN(new X509Name(true, X509Name.DefaultLookUp, CA_DN));
        cg.setSubjectDN(new X509Name(true, X509Name.DefaultLookUp, dn));
        cg.setSerialNumber(new BigInteger("" + nextSerialNumber++));
        cg.setSignatureAlgorithm("SHA1withRSA"); // RSA with SHA1
        cg.setPublicKey(publicKey);

        cg.setNotBefore(new Date());
        cg.setNotAfter(new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000L));

        cg.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.dataEncipherment | KeyUsage.keyEncipherment | KeyUsage.keyAgreement));
        if(email != null) {
            cg.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.rfc822Name, email)));
        }
        // Uncommented unnecessary extensions
        //cg.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(rootCertificateKey));
        //cg.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(publicKey));

        if(addCDP) {
            DistributionPoint dp = new DistributionPoint(getDistributionPointName(1), null, null);
            cg.addExtension(X509Extensions.CRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[] { dp }));
        }
        return cg;
    }

    private static PrivateKey generatePrivateKey() {
        try {
            KeyFactory fac = KeyFactory.getInstance("RSA", SignatureUtil.getCryptoProvider(SignatureUtil.setupCryptoProviderForJVM(), SOSIFactory.PROPERTYNAME_SOSI_CRYPTOPROVIDER_RSA));
            RSAPrivateKeySpec spec = new RSAPrivateKeySpec(new BigInteger(XmlUtil.fromBase64(MODULUS)), new BigInteger(XmlUtil.fromBase64(PRIVATE_EXP)));
            return fac.generatePrivate(spec);
        } catch (NoSuchAlgorithmException e) {
            throw new PKIException(e);
        } catch (NoSuchProviderException e) {
            throw new PKIException(e);
        } catch (InvalidKeySpecException e) {
            throw new PKIException(e);
        }
    }

    private static DistributionPointName getDistributionPointName(int crlNumber) {
        return new DistributionPointName(DistributionPointName.FULL_NAME, new GeneralName(new X509Name(true, X509Name.DefaultLookUp, getPartCRLDN(crlNumber))));
    }

    private static String getPartCRLDN(int crlNumber) {
        return "cn=CRL" + crlNumber + "," + CA_DN;
    }

    public static X509Certificate issueCertificate(String dn, String email, PublicKey certificatePublicKey, PublicKey issuerPublicKey) throws PKIException {
        try {
            X509V3CertificateGenerator cg = OCESTestHelper.createTemplateCertificateGenerator(dn, email, certificatePublicKey, true, issuerPublicKey);
            return cg.generate(generatePrivateKey());
        } catch (InvalidKeyException e) {
            throw new PKIException(e);
        } catch (SecurityException e) {
            throw new PKIException(e);
        } catch (SignatureException e) {
            throw new PKIException(e);
        } catch (CertificateParsingException e) {
            throw new PKIException(e);
        } catch (CertificateEncodingException e) {
            throw new PKIException(e);
        } catch (IllegalStateException e) {
            throw new PKIException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new PKIException(e);
        }
    }

    public static X509Certificate issueCertificate(String dn, String email, PublicKey publicKey, PublicKey issuerPublicKey, Date notBefore, Date notAfter) throws PKIException {
        try {
            X509V3CertificateGenerator cg = OCESTestHelper.createTemplateCertificateGenerator(dn, email, publicKey, true, issuerPublicKey);
            cg.setNotAfter(notAfter);
            cg.setNotBefore(notBefore);
            return cg.generate(generatePrivateKey());
        } catch (InvalidKeyException e) {
            throw new PKIException(e);
        } catch (SecurityException e) {
            throw new PKIException(e);
        } catch (SignatureException e) {
            throw new PKIException(e);
        } catch (CertificateParsingException e) {
            throw new PKIException(e);
        } catch (CertificateEncodingException e) {
            throw new PKIException(e);
        } catch (IllegalStateException e) {
            throw new PKIException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new PKIException(e);
        }
    }

    public static X509Certificate issueCertificateWithoutCDP(String dn, String email, PublicKey publicKey, PublicKey issuerPublicKey) throws PKIException {
        try {
            X509V3CertificateGenerator cg = OCESTestHelper.createTemplateCertificateGenerator(dn, email, publicKey, false, issuerPublicKey);
            return cg.generate(generatePrivateKey());
        } catch (InvalidKeyException e) {
            throw new PKIException(e);
        } catch (SecurityException e) {
            throw new PKIException(e);
        } catch (SignatureException e) {
            throw new PKIException(e);
        } catch (CertificateParsingException e) {
            throw new PKIException(e);
        } catch (CertificateEncodingException e) {
            throw new PKIException(e);
        } catch (IllegalStateException e) {
            throw new PKIException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new PKIException(e);
        }
    }

}