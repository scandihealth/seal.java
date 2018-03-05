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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/pki/CRLCertificateStatusChecker.java $
 * $Id: CRLCertificateStatusChecker.java 15447 2014-08-12 13:26:46Z ChristianGasser $
 */
package dk.sosi.seal.pki;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.X509Extension;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.*;
import java.util.Date;
import java.util.Map;
import java.util.Set;

/**
 * The semantic for the interval setting in the properties:
 * <p/>
 * NEVER: never download any CRL.
 * ALWAYS: on each check download the corresponding CRL.
 * <p/>
 * The STRICT value governs whether the isValid should throw an
 * exception when no CRL could be downloaded or found.
 * <p/>
 * If the policy adheres that the CRL should be downloaded
 * but it could not, the cache entry will be invalidated
 * and the check will be performed as if no CRL was found.
 * This behavior relates to the STRICT setting.
 *
 * @author ht@arosii.dk
 * @since 2.0
 */
public class CRLCertificateStatusChecker implements CertificateStatusChecker {

    /**
     * A constant for never checking for CRL updates
     */
    public static final int NEVER = -1;
    /**
     * A constant for always checking for CRL updates
     */
    public static final int ALWAYS = 0;

    /**
     * Check results including this timestamp, should be regarded as artificial
     */
    public static final Date INVALID_TIMESTAMP = new Date(0);

    /**
     * The strictness of the check, see class javadoc
     */
    protected final boolean strict;

    /**
     * The check interval for the revocation lists
     */
    protected final long interval;

    /**
     * The used cache
     */
    private final CRLCache cache;

    /**
     * Used for CRL verification.
     */
    private final CertificateResolver certificateResolver;

    /**
     * Default http connect timeout in ms for retrieving CRL
     */
    private final static int DEFAULT_CONNECT_TIMEOUT = 3000;

    /**
     * Default http read timeout in ms for retrieving CRL
     */
    private final static int DEFAULT_READ_TIMEOUT = 3000;

    /**
     * http connect timeout in ms for retrieving CRL
     */
    private int connectTimeout = DEFAULT_CONNECT_TIMEOUT;

    /**
     * http read timeout in ms for retrieving CRL
     */
    private int readTimeout = DEFAULT_READ_TIMEOUT;

    /**
     * Time to live for a CRL. A CRL must satisfy:
     *   CRL.getNextUpdate() + ttl > now
     * before it can be used.
     *
     * ttl == NEVER means that the check is disregarded.
     */
    private final int ttl;

    private static final Log log = LogFactory.getLog(CRLCertificateStatusChecker.class);

    /**
     * Creates a new <code>CRLCertificateStatusChecker</code> with the supplied
     * cache, interval and strictness.
     *
     * @param cache    the used cache.
     * @param interval the interval in seconds, see NEVER and ALWAYS for special values.
     * @param strict   see class javadoc for semantic.
     * @param ttl specifies a CRL's extra time to live
     * @param certificateResolver the resolver for finding the issuer certificate used for CRL verification
     */
    public CRLCertificateStatusChecker(final CRLCache cache,
                                       final int interval,
                                       final boolean strict,
                                       final int ttl,
                                       final CertificateResolver certificateResolver) {

        if (cache == null) throw new IllegalArgumentException("'cache' must not be null");
        if (certificateResolver == null) throw new IllegalArgumentException("'certificateResolver' must not be null");
        if (interval < -1) throw new IllegalArgumentException("Illegal interval");

        this.cache = cache;
        this.strict = strict;
        this.interval = calcInterval(interval);
        this.certificateResolver = certificateResolver;
        this.ttl = ttl;
    }

    private int calcInterval(int interval) {
        if (interval == ALWAYS || interval == NEVER) {
            return interval;
        } else {
            return interval * 1000;
        }
    }

    public void setConnectTimeout(int connectTimeout) {
        if (connectTimeout <= 0) {
            throw new IllegalArgumentException("'connectTimeout' must be positive");
        }
        this.connectTimeout = connectTimeout;
    }

    public void setReadTimeout(int readTimeout) {
        if (readTimeout <= 0) {
            throw new IllegalArgumentException("'readTimeout' must be positive");
        }
        this.readTimeout = readTimeout;
    }


    /**
     * Checks if the certificate supplied is revoked. The check is performed
     * against the CRL downloaded from the URL found in the certificate.
     * <p/>
     * The CRL is conditionally downloaded depending on the settings.
     * <p/>
     * If the certificate is null, a negative result is returned with invalid
     * timestamp.
     *
     * @param cert the certificate to check.
     * @return the result of the check including the timestamp for CRL.
     */
    public CertificateStatus getRevocationStatus(final X509Certificate cert) {
        if (cert == null) {
            throw new IllegalArgumentException("'cert' must not be null");
        }

        final String url = getCRLUrlFromCertificate(cert);
        if (url == null) {
            return check(null, cert);
        }
        final CRLCache.CRLInfo crlInfo = cache.get(url);

        // If the CRL was not found in the cache
        if (crlInfo == null) {
            return check(checkCRL(url, createNew(url), cert), cert);
        }

        return check(checkCRL(url, checkAndUpdate(url, crlInfo), cert), cert);
    }

    /**
     * No measures are taken to ensure, that the same CRL is not downloaded by
     * multiple threads simultaneously. The cache does however ensure consistency.
     *
     * @param url     the CRL endpoint
     * @param crlInfo the old crlInfo if such exists otherwise null
     * @return the crlInfo, which might be updated.
     */
    private CRLCache.CRLInfo checkAndUpdate(String url, final CRLCache.CRLInfo crlInfo) {
        final boolean update;
        if (interval == NEVER) {
            update = false;
        } else if (crlInfo == null) {
            log.debug("CRL download triggered by having no existing CRL.");
            update = true;
        } else if (interval == ALWAYS) {
            log.debug("CRL download triggered by ALWAYS.");
            update = true;
        } else if (!hasTTL(crlInfo.getCrl())) {
            update = true;
            log.debug("CRL download triggered by ttl.");
        } else {
            update = System.currentTimeMillis() - crlInfo.getCreated() > interval;
            if (update) log.debug("CRL download triggered interval.");
        }

        if (update) {
            try {
                return cache.update(url, load(url, crlInfo));
            } catch (Throwable t) {
                log.error("While trying to download " + url + " <" + t.toString() + "> occurred.");
                return cache.update(url, (CRLCache.CRLInfo) null);
            }
        }
        return crlInfo;
    }

    private CRLCache.CRLInfo checkCRL(String url, CRLCache.CRLInfo crlInfo, X509Certificate cert) {
        if (crlInfo instanceof UncheckedCRLInfo) {
            if (isValidCRL(crlInfo.getCrl(), cert)) {
                return cache.update(url, new CRLCache.CRLInfo(crlInfo)); // now it is no longer unchecked
            } else {
                // invalidate the cache entry for the invalid CRL, subsequent checks will try to
                // download a new CRL
                cache.update(url, (CRLCache.CRLInfo) null);
                // We could return null, but if the behavior for checking against an unchecked CRL
                // changes, this will be nice to have.
                return crlInfo;
            }
        } else {
            // do nothing if it is already checked
            return crlInfo;
        }
    }

    /**
     * Just a subclass of CRLInfo to indicate the checked status.
     */
    protected static class UncheckedCRLInfo extends CRLCache.CRLInfo {
        public UncheckedCRLInfo(final X509CRL crl, final long lastModified) {
            super(crl, lastModified);
        }
    }

    /**
     * Performs the conditional download of the CRL. One can supply other means
     * to retrieve a CRL, but the timestamp in the CRLInfo should be updated
     * according to the same semantics.
     *
     * @param url     the location of the CRL.
     * @param crlInfo the previous CRL together with associate timestamps
     * @return the new CRL together the updated timestamps, or the previous CRL with the timestamps updated.
     * @throws IOException in case the download fails.
     */
    protected CRLCache.CRLInfo load(final String url, final CRLCache.CRLInfo crlInfo) throws IOException {
        return downloadCRL(url, crlInfo);
    }

    private CRLCache.CRLInfo createNew(final String url) {
        return checkAndUpdate(url, null);
    }

    /**
     * Updates all known CRL entries in the cache.
     * <p/>
     * Should not be used lightly since all registered CRL are downloaded.
     */
    protected void updateAll() {
        final Set<Map.Entry<String, CRLCache.CRLInfo>> entries = cache.entries();
        for (Map.Entry<String, CRLCache.CRLInfo> entry : entries) {
            createNew(entry.getKey());
        }
    }

    /**
     * Check the certificate against the revocation list. If the CRLInfo
     * is unchecked, the CRLinfo is disregarded.
     *
     * Having no CRLInfo in the strict case will throw an exception, while
     * in the non-strict case nothing is revoked. The timestamp will however be
     * invalid.
     * @param info the revocation list; this also contains information about the check status. See <link>UncheckedCRLInfo</link>
     * @param cert the certificate being checked.
     * @return the status of the check including the boolean answer and the timestamp for the implicated CRL.
     */
    protected CertificateStatus check(CRLCache.CRLInfo info, X509Certificate cert) {
        if (info == null || info instanceof UncheckedCRLInfo) {
            if (strict) {
                throw new IllegalStateException("Unable to check certificate revocation. CRL was " + getCRLUrlFromCertificate(cert));
            } else {
                return nonStrictCaseWithoutCRL();
            }
        }
        return new CertificateStatus(! info.getCrl().isRevoked(cert), info.getCrl().getThisUpdate());
    }

    private CertificateStatus nonStrictCaseWithoutCRL() {
        return new CertificateStatus(true, INVALID_TIMESTAMP);
    }

    /**
     * Retrieves the CRL URL from the certificate.
     *
     * @param cert the certificate
     * @return the first found CRL URL in the certificate or <code>null</code> if no such URL was found.
     */
    private static String getCRLUrlFromCertificate(final X509Certificate cert) {
        final byte[] extensionValue = cert.getExtensionValue(X509Extension.cRLDistributionPoints.getId());

        // In case no such extension exists
        if (extensionValue == null) {
            return null;
        }

        final DEROctetString oct;
        final ASN1Sequence seq;
        try {
            oct = (DEROctetString) new ASN1InputStream(new ByteArrayInputStream(extensionValue)).readObject();
            seq = (ASN1Sequence) new ASN1InputStream(oct.getOctets()).readObject();
        } catch (IOException e) {
            return null;
        }

        // Special error handling if no full_name was found or if no URI was found
        final CRLDistPoint distPoint = CRLDistPoint.getInstance(seq);
        for (final DistributionPoint distributionPoint : distPoint.getDistributionPoints()) {

            if (distributionPoint.getDistributionPoint().getType() == DistributionPointName.FULL_NAME) {

                for (final GeneralName name : ((GeneralNames) distributionPoint.getDistributionPoint().getName()).getNames()) {
                    if (name.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        return DERIA5String.getInstance(name.getName().toASN1Primitive()).getString();
                    }
                }

            }
        }

        return null;
    }

    /*Visible for testing*/
    CRLCache.CRLInfo downloadCRL(String url, CRLCache.CRLInfo old) throws IOException {
        final CRLCache.CRLInfo crlInfo = downloadCRL(new URL(url), old);

        if (crlInfo == null && old == null) {
            throw new IllegalStateException("CRL could not be downloaded");
        }

        if (crlInfo == null) {
            // not modified, but checked
            if (old instanceof UncheckedCRLInfo)
                return new UncheckedCRLInfo(old.getCrl(), old.getLastModified());
            else
                return new CRLCache.CRLInfo(old.getCrl(), old.getLastModified());
        } else {
            return crlInfo;
        }

    }

    /**
     * Download the CRL from the url, but do a If-Modified-Since request
     * based on the CRLInfo
     *
     * @param url the location of the crl
     * @param crlInfo the date used for the request
     * @return the newly downloaded crl with corresponding timestamp or null if
     *         nothing was downloaded.
     *
     * @throws IOException in case something went wrong
     */
    private CRLCache.CRLInfo downloadCRL(URL url, CRLCache.CRLInfo crlInfo) throws IOException {
        X509CRL x509CRL = crlInfo == null ? null : crlInfo.getCrl();
        long lastModified = crlInfo == null ? -1 : crlInfo.getLastModified();
        final URLConnection conn = url.openConnection();
        conn.setConnectTimeout(connectTimeout);
        conn.setReadTimeout(readTimeout);
        if (lastModified != 0) {
            conn.setIfModifiedSince(lastModified);
        }
        conn.connect();
        if (conn instanceof HttpURLConnection) {
            // Last-Modified header not (always) set when HTTP status is 304
            if (HttpURLConnection.HTTP_NOT_MODIFIED != ((HttpURLConnection) conn).getResponseCode()) {
                lastModified = conn.getLastModified();
                x509CRL = generateCrl(conn.getInputStream());
            }
        } else if (lastModified != conn.getLastModified()) {
            lastModified = conn.getLastModified();
            x509CRL = generateCrl(conn.getInputStream());
        }
        if (x509CRL == null) {
            return null;
        }

        // always new
        if (crlInfo == null || lastModified != crlInfo.getLastModified())
            return new UncheckedCRLInfo(x509CRL, lastModified);
        else
            return new CRLCache.CRLInfo(x509CRL, lastModified); // if nothing changed
    }

    private static X509CRL generateCrl(InputStream in) {
        try {
            final CertificateFactory certificatefactory = CertificateFactory.getInstance("X.509");
            return (X509CRL) certificatefactory.generateCRL(in);
        } catch (CertificateException e) {
            throw new PKIException(e);
        } catch (CRLException e) {
            throw new PKIException(e);
        } finally {
            closeStream(in);
        }
    }


    private static void closeStream(InputStream in) {
        if (in != null) {
            try {
                in.close();
            } catch (IOException e) {
                //ignore
            }
        }
    }


    protected boolean verify(X509CRL crl, X509Certificate cert) {
        try {
            crl.verify(certificateResolver.getIssuingCertificate(cert).getPublicKey());
        } catch(Exception e) {
            log.error("CRL verification failed.", e);
            return false;
        }
        return true;
    }

    private boolean isValidCRL(X509CRL crl, X509Certificate cert) {
        return verify(crl, cert) && notPartitioned(crl) && hasTTL(crl);
    }

    protected boolean notPartitioned(X509CRL crl) {
        boolean notPartitioned = !crl.getCriticalExtensionOIDs().contains(X509Extension.issuingDistributionPoint.getId());
        if (!notPartitioned) log.error("CRL is partitioned, which is not supported.");
        return notPartitioned;
    }

    protected boolean hasTTL(X509CRL crl) {
        if (ttl == NEVER) return true;

        long now = System.currentTimeMillis();
        boolean result = crl.getNextUpdate().getTime() + ttl > now;
        if (!result) log.error("The CRL is not live, the next update timestamp was: " + crl.getNextUpdate());
        return result;
    }

}
