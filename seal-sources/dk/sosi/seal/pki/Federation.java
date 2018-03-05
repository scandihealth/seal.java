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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/pki/Federation.java $
 * $Id: Federation.java 20816 2014-12-18 10:15:53Z ChristianGasser $
 */
package dk.sosi.seal.pki;

import dk.sosi.seal.pki.impl.PropertiesSOSIConfiguration;

import java.security.cert.X509Certificate;
import java.util.Properties;

/**
 * Representation of a federation, identified by a certification authority and the identity of the STS.
 * 
 * @author thomas@signaturgruppen.dk
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 20816 $
 * @since 1.0
 */
public abstract class Federation {

	private final CertificationAuthority certificationAuthority;

	private final AuditEventHandler eventHandler;
    private final Properties properties;

    /**
     * Construct an instance of <code>Federation</code>
     *
     * @param certificationAuthority the CA used in the federation
     */
    protected Federation(Properties properties, CertificationAuthority certificationAuthority) {
        this.certificationAuthority = certificationAuthority;
        this.properties = properties;
        this.eventHandler = new PropertiesSOSIConfiguration(properties).getAuditEventHandler();
        eventHandler.onInformationalAuditingEvent(
                AuditEventHandler.EVENT_TYPE_INFO_FEDERATION_INITIALIZED,
                new Object[]{this}
        );
    }

    /**
     * Construct an instance of <code>Federation</code>
     *
     * @param certificationAuthority
     *            the CA used in the federation
     * @param stsSubjectSerialNumber
     *            subject serial number used in the certificates issued to the STS.
     * @deprecated use {@link #Federation(java.util.Properties, CertificationAuthority)}
     */
    @Deprecated
    protected Federation(Properties properties, CertificationAuthority certificationAuthority, String stsSubjectSerialNumber) {
        this(properties, certificationAuthority);
    }

    public X509Certificate getFederationCertificate(FederationCertificateReference reference) {
        return certificationAuthority.getFederationCertificate(reference);
    }

	/**
	 * Returns the certification authority used in the federation.
	 */
	public CertificationAuthority getCertificationAuthority() {
		return certificationAuthority;
	}

	/**
	 * Return the subject serial number used in STS company certificates.
     *
     * @deprecated
	 */
	@Deprecated
    public final String getSTSSubjectSerialNumber() {
		throw new UnsupportedOperationException("Federation is no longer bound to a single STS subject serial number");
	}

	/**
	 * Returns <code>true</code> if the passed certificate is a valid certificate issued to the STS of the federation and <code>false</code>
	 * otherwise.
	 * 
	 * @param certificate
	 *            the certificate to check.
	 */
    public boolean isValidSTSCertificate(X509Certificate certificate) {
        if (!subjectDistinguishedNameMatches(new DistinguishedName(certificate.getSubjectX500Principal()))) {
            eventHandler.onErrorAuditingEvent(
                    AuditEventHandler.EVENT_TYPE_ERROR_VALIDATING_STS_CERTIFICATE,
                    new Object[]{certificate}
            );
            return false; // NOPMD
        }

        return getCertificationAuthority().isValid(certificate);
    }

    /**
     * Returns <code>true</code> if the passed subjectDistinguishedName matches an STS of the federation and <code>false</code>
     * otherwise.
     *
     * @param subjectDistinguishedName
     *            the subjectDistinguishedName to check.
     */
    protected abstract boolean subjectDistinguishedNameMatches(DistinguishedName subjectDistinguishedName);

	/**
	 * Returns <code>true</code> if the passed certificate is a valid certificate issued by the CA of the federation and <code>false</code>
	 * otherwise.
	 * 
	 * @param certificate
	 *            the certificate to check.
	 */
	public boolean isValidCertificate(X509Certificate certificate) {
		return getCertificationAuthority().isValid(certificate);
    }

    /**
     * Returns a combined result containing the result of a corresponding <link>isValidCertificate</link> call and the timestamp
     * for the revocation check involved.
     *
     * @param certificate to be checked.
     * @return the combined result.
     */
    public CertificateStatus getCertificateStatus(X509Certificate certificate) {
        return getCertificationAuthority().getCertificateStatus(certificate);
    }

    public Properties getProperties() {
		return new Properties(properties);
	}
}
