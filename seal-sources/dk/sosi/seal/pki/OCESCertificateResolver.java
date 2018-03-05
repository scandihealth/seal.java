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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/pki/OCESCertificateResolver.java $
 * $Id: OCESCertificateResolver.java 20816 2014-12-18 10:15:53Z ChristianGasser $
 */
package dk.sosi.seal.pki;

import dk.sosi.seal.pki.impl.intermediate.IntermediateCertificateStoreAdapter;

import java.security.cert.X509Certificate;

/**
 * @author $LastChangedBy: ChristianGasser $ $LastChangedDate: 2014-12-18 11:15:53 +0100 (Thu, 18 Dec 2014) $
 * @version $Revision: 20816 $
 */
public class OCESCertificateResolver implements CertificateResolver {

    private IntermediateCertificateCache cache;

    public OCESCertificateResolver(IntermediateCertificateCache intermediateCertificateCache) {
        this.cache = intermediateCertificateCache;
    }

    public OCESCertificateResolver(CertificateCache certificateCache) {
        this.cache = new IntermediateCertificateStoreAdapter(certificateCache);
    }

    public X509Certificate getIssuingCertificate(X509Certificate certificate) {
        if (certificate == null) {
            throw new IllegalArgumentException("'certificate' must not be null");
        }
        if (OCESUtil.isProbableOCES1Certificate(certificate)) {
            if (OCESUtil.isIssuerOf(certificate, OCESCertificationAuthority.OCES_1_ROOT_CERTIFICATE)) {
                throw constructOCES1PKIException(certificate);
            } else if (OCESUtil.isIssuerOf(certificate, OCESTestCertificationAuthority.OCES_1_TEST_ROOT_CERTIFICATE)) {
                throw constructOCES1PKIException(certificate);
            } else {
                throw constructPKIException(certificate);
            }
        } else if (OCESUtil.isProbableOCES2Certificate(certificate)) {
            if (OCESUtil.isProbableIntermediateOrRootCertificate(certificate)) {
                if (OCESUtil.isIssuerOf(certificate, OCESCertificationAuthority.OCES_2_ROOT_CERTIFICATE)) {
                    return OCESCertificationAuthority.OCES_2_ROOT_CERTIFICATE;
                } else if (OCESUtil.isIssuerOf(certificate, OCESTestCertificationAuthority.OCES_2_TEST_ROOT_CERTIFICATE)) {
                    return OCESTestCertificationAuthority.OCES_2_TEST_ROOT_CERTIFICATE;
                } else {
                    throw constructPKIException(certificate);
                }
            } else {
                X509Certificate intermediateCertificate = cache.getCertificate(OCESUtil.retrieveIntermediateCertificateURI(certificate));
                if (OCESUtil.isIssuerOf(certificate, intermediateCertificate)) {
                    return intermediateCertificate;
                } else {
                    throw constructPKIException(certificate);
                }
            }
        } else {
            throw constructPKIException(certificate);
        }
    }

    private PKIException constructPKIException(X509Certificate certificate) {
        return new PKIException("Unable to resolve issuing certificate with DN: " + certificate.getIssuerX500Principal().getName());
    }

    private PKIException constructOCES1PKIException(X509Certificate certificate) {
        return new PKIException("The supplied certificate issued by: '" + certificate.getIssuerX500Principal().getName() + "' is an OCES1 certificate which is no longer supported") ;
    }


}
