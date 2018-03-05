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

import java.security.cert.X509Certificate;

public class FederationCertificateReference {

    @Deprecated
    public static final String OCES1_VERSION = "OCES1";
    public static final String OCES2_VERSION = "OCES2";

    private final String ocesVersion;
    private final String subjectSerialNumber;
    private final String serialNumber;

    public FederationCertificateReference(X509Certificate certificate) {
        if (certificate == null) {
            throw new IllegalArgumentException("certificate cannot be null");
        }
        if (OCESUtil.isProbableOCES1Certificate(certificate)) {
            throw new IllegalArgumentException("supplied certificate is an OCES1 certificate which is no longer supported: " + certificate);
        } else if (OCESUtil.isProbableOCES2Certificate(certificate)) {
            ocesVersion = OCES2_VERSION;
        } else {
            throw new IllegalArgumentException("supplied certificate is not a valid OCES certificate: " + certificate);
        }
        subjectSerialNumber = new DistinguishedName(certificate.getSubjectX500Principal()).getSubjectSerialNumber();
        serialNumber = String.valueOf(certificate.getSerialNumber());
    }

    public FederationCertificateReference(String rawString) {
        if (rawString == null || rawString.length() == 0) {
            throw new IllegalArgumentException("rawstring cannot be null or empty");
        }
        String[] parts = rawString.split(",");
        if (parts.length != 3) {
            throw new IllegalArgumentException("rawstring must be be formatted as '<OCESVersion>, <SubjectSerialNumber>,<CertificateSerialNumber>");
        }
        ocesVersion = parts[0];
        subjectSerialNumber = parts[1];
        serialNumber = parts[2];
    }

    public String getOcesVersion() {
        return ocesVersion;
    }

    public String getSubjectSerialNumber() {
        return subjectSerialNumber;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public String toString() {
        return ocesVersion + ',' + subjectSerialNumber + ',' + serialNumber;
    }
}
