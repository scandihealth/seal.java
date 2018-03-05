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
 * $HeadURL$
 * $Id$
 */

package dk.sosi.seal.pki;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class CertificateInfo {

    private static final Pattern PATTERN = Pattern.compile("SubjectDN=\\{([^\\{}]+)\\},IssuerDN=\\{([^\\{}]+)},CertSerial=\\{([^\\{}]+)}");

    private final DistinguishedName subjectDN;
    private final DistinguishedName issuerDN;
    private final BigInteger certificateSerial;

    public CertificateInfo(X509Certificate certificate) {
        if (certificate == null) {
            throw new IllegalArgumentException("certificate must not be null!");
        }
        subjectDN = new DistinguishedName(certificate.getSubjectX500Principal());
        issuerDN = new DistinguishedName(certificate.getIssuerX500Principal());
        certificateSerial = certificate.getSerialNumber();
    }

    public static CertificateInfo fromString(String certInfoString) {
        if (certInfoString == null) {
            throw new IllegalArgumentException("certInfoString must not be null!");
        }
        Matcher matcher = PATTERN.matcher(certInfoString);
        if (!matcher.matches()) {
           throw new IllegalArgumentException("certInfoString does not represent a CertificateInfo, certInfoString was '"
           + certInfoString + "'");
        }
        return new CertificateInfo(matcher.group(1), matcher.group(2), matcher.group(3));
    }

    public static boolean isProbableCertificateInfoString(String candidate) {
        return candidate != null && PATTERN.matcher(candidate).matches();
    }

    private CertificateInfo(String subjectDNString, String issuerDNString, String certificateSerialString) {
        this.subjectDN = new DistinguishedName(subjectDNString);
        this.issuerDN = new DistinguishedName(issuerDNString);
        this.certificateSerial = new BigInteger(certificateSerialString);
    }

    public DistinguishedName getSubjectDN() {
        return subjectDN;
    }

    public DistinguishedName getIssuerDN() {
        return issuerDN;
    }

    public BigInteger getCertificateSerialNumber() {
        return certificateSerial;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder("SubjectDN={");
        builder.append(subjectDN);
        builder.append("},IssuerDN={");
        builder.append(issuerDN);
        builder.append("},CertSerial={");
        builder.append(certificateSerial.toString());
        builder.append("}");
        return builder.toString();
    }

}
