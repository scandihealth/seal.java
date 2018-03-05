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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/pki/AbstractOCESCertificationAuthority.java $
 * $Id: AbstractOCESCertificationAuthority.java 34587 2017-11-22 10:44:21Z ChristianGasser $
 */
package dk.sosi.seal.pki;

import java.security.cert.X509Certificate;

/**
 * Abstract implementation of the CertificationAuthority interface.
 *
 * @author ads@lakeside.dk
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 34587 $
 * @since 2.0
 */
public abstract class AbstractOCESCertificationAuthority implements CertificationAuthority {

    private final CertificateStatusChecker certificateStatusChecker;
    private final IntermediateCertificateCache intermediateCertificateCache;
    private final FederationCertificateResolver federationCertificateResolver;
    private final AuditEventHandler eventHandler;

    protected AbstractOCESCertificationAuthority(SOSIConfiguration configuration,
                                                 CertificateStatusChecker certificateStatusChecker, IntermediateCertificateCache intermediateCertificateCache, FederationCertificateResolver federationCertificateResolver) {
        configuration.verify();
        if (certificateStatusChecker == null) throw new IllegalArgumentException("'certificateStatusChecker' cannot be null");
        if (intermediateCertificateCache == null) throw new IllegalArgumentException("'intermediateCertificateCache' cannot be null");

        this.eventHandler = configuration.getAuditEventHandler();

        this.certificateStatusChecker = certificateStatusChecker;
        this.intermediateCertificateCache = intermediateCertificateCache;
        this.federationCertificateResolver = federationCertificateResolver;
    }

    public final boolean isValid(X509Certificate certificate) throws PKIException {
        return getCertificateStatus(certificate).isValid();
    }

    public CertificateStatus getCertificateStatus(final X509Certificate cert) throws PKIException {
        CertificateStatus certificateStatus;
        if (checkDates(cert)) {
            if (OCESUtil.isProbableOCES1Certificate(cert) && OCESUtil.isIssuerOf(cert, getOCES1RootCertificate())) {
                throw new PKIException("The supplied certificate with DN '" + new DistinguishedName(cert.getSubjectX500Principal()) + "' is an OCES1 certificate. OCES1 certificates are no longer supported.");
            }
            if (!(OCESUtil.isProbableOCES2Certificate(cert) && OCESUtil.isIssuerOf(cert, getAndValidateIntermediateCertificate(cert)))) {
                throw new PKIException("The supplied certificate  with DN '" + new DistinguishedName(cert.getSubjectX500Principal()) + "' is not a " + getCertificationAuthorityName() + " certificate");
            }
            certificateStatus = checkRevocation(cert);
        } else {
            certificateStatus = new CertificateStatus(false, null);
        }
        auditLogCertificationStatus(certificateStatus, cert);
        return certificateStatus;
    }

    private void auditLogCertificationStatus(CertificateStatus certificateStatus, Object certificate) {
        if (certificateStatus.isValid()) {
            eventHandler.onInformationalAuditingEvent(AuditEventHandler.EVENT_TYPE_INFO_CERTIFICATE_VALIDATED, new Object[]{certificate});
        } else {
            eventHandler.onErrorAuditingEvent(AuditEventHandler.EVENT_TYPE_ERROR_VALIDATING_CERTIFICATE, new Object[]{certificate});
        }
    }

    protected abstract X509Certificate getOCES1RootCertificate();

    protected abstract X509Certificate getOCES2RootCertificate();

    protected abstract String getCertificationAuthorityName();

    // visible for unit-testing
    /*pp*/ boolean checkDates(X509Certificate certificate) {
        if (certificate.getNotAfter().getTime() < System.currentTimeMillis()) {
            return false; // Certificate is expired
        } else if (certificate.getNotBefore().getTime() > System.currentTimeMillis()) {
            return false; // Certificate is not yet valid
        }
        return true;
    }

    // visible for unit-testing
    /* pp */ X509Certificate getAndValidateIntermediateCertificate(X509Certificate certificate) throws PKIException {
        X509Certificate intermediateCertificate = intermediateCertificateCache.getCertificate(OCESUtil.retrieveIntermediateCertificateURI(certificate));

        if (!checkDates(intermediateCertificate)) {
            throw new PKIException("Intermediate certificate not valid in time");
        }
        if (!OCESUtil.isIssuerOf(intermediateCertificate, getOCES2RootCertificate())) {
            throw new PKIException("Intermediate certificate not issued by " + getCertificationAuthorityName() + " root certificate");
        }
        if (!checkRevocation(intermediateCertificate).isValid()) {
            throw new PKIException("Intermediate certificate is revoked");
        }
        return intermediateCertificate;
    }

    private CertificateStatus checkRevocation(X509Certificate certificate) {
        try {
            return certificateStatusChecker.getRevocationStatus(certificate);
        } catch (PKIException e) {
            eventHandler.onWarningAuditingEvent(e.getMessage(), null);
            throw e;
        }
    }

    public X509Certificate getFederationCertificate(FederationCertificateReference reference) {
        return federationCertificateResolver.getFederationCertificate(reference);
    }

}