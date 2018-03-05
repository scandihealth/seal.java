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
package dk.sosi.seal.pki.internal.remote;

import dk.sosi.seal.pki.PKIException;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;

import java.io.IOException;

/**
 * This is a remote source of certificates.
 * Certificates are fetched by Http
 * Note that the fetching is separated from the parsing
 *
 * @author ksr@lakeside.dk
 * @author $LastChangedBy: ksr@lakeside.dk $
 * @since 2.1
 */
public class HttpCertificateLoader implements RemoteCertificateLoader {
    private final static int DEFAULT_CONNECT_TIMEOUT = 3000;
    private final static int DEFAULT_READ_TIMEOUT = 3000;

    private static final int HTTP_RESPONSE_OK = 200;

    private int connectTimeout;
    private int readTimeout;

    public HttpCertificateLoader() {
        this.connectTimeout = DEFAULT_CONNECT_TIMEOUT;
        this.readTimeout = DEFAULT_READ_TIMEOUT;
    }

    /**
     * Download certificate from a remote location.
     *
     * @param uri
     *            The URI of the intermediate certificate.
     * @return The downloaded certificate.
     * @throws dk.sosi.seal.pki.PKIException
     *             Thrown if anything goes wrong.
     */
    public byte[] loadCertificate(String uri) {
        GetMethod getMethod = new GetMethod(uri);

        HttpClient httpclient = new HttpClient();
        httpclient.getHttpConnectionManager().getParams().setConnectionTimeout(connectTimeout);
        httpclient.getHttpConnectionManager().getParams().setSoTimeout(readTimeout);

        try {
            final int responseCode = httpclient.executeMethod(getMethod);
            if (responseCode != HTTP_RESPONSE_OK) {
                throw new PKIException("Intermediate certificate could not be found. Statuscode = " + responseCode + ". Responsebody: " + getMethod.getResponseBodyAsString());
            }
            return getMethod.getResponseBody();
        } catch (IOException ioe) {
            throw new PKIException("Intermediate certificate could not be found at " + uri, ioe);
        }
    }
}
