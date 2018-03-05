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
package dk.sosi.seal.xml;

import dk.sosi.seal.model.ModelException;
import dk.sosi.seal.model.SignatureUtil;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Helper class, with the purpose of parsing certificates
 *
 * @author ksr@lakeside.dk
 * @author $LastChangedBy: chg@lakeside.dk $
 * @since 1.0
 */
public class CertificateParser {
    /**
     * Convert a byte array to an X509 certificate
     *
     * @param value
     *            The byte array to convert
     * @return The X509 certificate
     * @throws dk.sosi.seal.model.ModelException
     *             if conversion fails
     */
    public static X509Certificate asCertificate(byte[] value) {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(value);
        try {
            String provider = SignatureUtil.getCryptoProvider(null, "X.509"); // forces BouncyCastle to be set as x509 provider
            CertificateFactory factory = CertificateFactory.getInstance("X.509", provider);
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
}
