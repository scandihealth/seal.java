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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/pki/TestFederation.java $
 * $Id: TestFederation.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.pki;

import junit.framework.TestCase;

import java.util.Properties;

public class TestFederation extends TestCase {

    public void testFederationProperties() {
        Properties prop = new Properties();
        prop.setProperty("my.test", "test.me");
        prop.setProperty("hurry.now", "now.done");

        Federation federation = new MockFederation(prop);

        assertNotSame("Different instance", prop, federation.getProperties());
        assertEquals("Element 1", "test.me", federation.getProperties().getProperty("my.test"));
        assertEquals("Element 2", "now.done", federation.getProperties().getProperty("hurry.now"));
        // Don't assert size of properties. size is based on actual number of elements.
        // The constructor takes a properties object, but uses it as default values
        // and they are not included in the size() operation.
        // assertEquals("Number of elements", 2, federation.getProperties().size());
    }
}
