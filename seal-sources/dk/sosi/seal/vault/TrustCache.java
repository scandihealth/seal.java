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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/vault/TrustCache.java $
 * $Id: TrustCache.java 20818 2014-12-18 11:26:29Z ChristianGasser $
 */
package dk.sosi.seal.vault;

import java.util.Date;
import java.util.Hashtable;

/**
 * A cache to keep track of when certificate trust has been established.
 * 
 * @author thomas@signaturgruppen.dk
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 20818 $
 * @since 1.0
 */
@Deprecated
public class TrustCache {
    private long timeToLiveMillis;

    // If this hashtables memory consumption becomes an issue, use LinkedHashMap (not thread safe) with suitable
    // overriding of removeEldestEntry.
    private Hashtable<String, Date> digestToLastCheckDate = new Hashtable<String, Date>();

    /**
     * Construct a cache to keep track on when trust was last established for given certificates.
     * 
     * @param timeToLiveMillis
     *            how long a trust establishement should be remembered.
     */
    public TrustCache(long timeToLiveMillis) {
        super();
        this.timeToLiveMillis = timeToLiveMillis;
    }

    /**
     * Add trust establishment
     * 
     * @param digest
     *            digest of the certificate to which trust was established
     */
    public void trustEstablished(String digest) {
        digestToLastCheckDate.put(digest, new Date());
    }

    /**
     * Return <code>true</code> if trust was established within the TTL, <code>false</code> otherwise.
     * 
     * @param digest
     *            digest to check
     */
    public boolean wasTrustEstablishedRecently(String digest) {
        if(!digestToLastCheckDate.containsKey(digest)) {
            return false; // NOPMD
        }
        Date lastCheck = digestToLastCheckDate.get(digest);
        return lastCheck.getTime() + timeToLiveMillis > System.currentTimeMillis();
    }

}
