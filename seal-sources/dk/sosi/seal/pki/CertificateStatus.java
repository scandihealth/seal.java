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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/pki/CertificateStatus.java $
 * $Id: CertificateStatus.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.pki;

import java.util.Date;

/**
 * A class representing a certificate's status
 *
 * @author ht@arosii.dk
 * @since 2.0
 */
public class CertificateStatus {

    private final boolean isValid;
    private final Date timestamp;

    public CertificateStatus(final boolean isValid, final Date timestamp) {
        this.isValid = isValid;
        this.timestamp = timestamp;
    }

    /**
     * Returns the certificate's validation status
     *
     * @return whether the certificate is valid in time, issued by the correct CertificationAuthority and not revoked
     * (if revocation check is employed)
     */
    public boolean isValid() {
        return isValid;
    }

    /**
     * Returns the time for the certificate status
     *
     * @return the date for when the certificate had the status. Eg. when CRL-based revocation checks are employed, this
     * could be the date for the CRLs last update
     */
    public Date getTimestamp() {
        return timestamp;
    }
}
