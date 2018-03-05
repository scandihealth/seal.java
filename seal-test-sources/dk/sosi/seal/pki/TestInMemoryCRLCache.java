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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/pki/TestInMemoryCRLCache.java $
 * $Id: TestInMemoryCRLCache.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.pki;

import junit.framework.TestCase;

import java.security.cert.X509CRL;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @author $LastChangedBy: chg@lakeside.dk $ $LastChangedDate: 2011-09-02 12:33:55 +0200 (Fri, 02 Sep 2011) $
 * @version $Revision: 8697 $
 */
public class TestInMemoryCRLCache extends TestCase {

    public void testCacheUpdate() throws Exception {
        InMemoryCRLCache cache = new InMemoryCRLCache();

        String KEY = "hey";
        CRLCache.CRLInfo crlInfo = new CRLCache.CRLInfo(null, System.currentTimeMillis());

        try {
            cache.update(null, crlInfo);
            fail("IllegalArgumentException expected");
        } catch (IllegalArgumentException e) {
            // OK
        }

        cache.update(KEY, crlInfo);

        assertEquals(cache.get(KEY).getLastModified(), crlInfo.getLastModified());

        cache.update(KEY, (X509CRL) null);

        assertNull(cache.get(KEY));

        cache.update(KEY, crlInfo);
        cache.update(KEY, (CRLCache.CRLInfo) null);

        assertNull(cache.get(KEY));

        cache.update(KEY, crlInfo);
        cache.update(KEY + "2", crlInfo);
        cache.update(KEY + "3", crlInfo);
        Set<Map.Entry<String, CRLCache.CRLInfo>> entries = cache.entries();
        assertEquals(entries.size(), 3);

        Set<String> keys = new HashSet<String>();
        for (Map.Entry<String, CRLCache.CRLInfo> entry : entries) {
            keys.add(entry.getKey());
        }

        assertTrue(keys.contains(KEY));
        assertTrue(keys.contains(KEY + "2"));
        assertTrue(keys.contains(KEY + "3"));
    }

}
