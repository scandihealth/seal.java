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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/xml/TestDebugErrorHandler.java $
 * $Id: TestDebugErrorHandler.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.xml;

import dk.sosi.seal.pki.testobjects.PrintStreamAdapter;
import junit.framework.TestCase;
import org.xml.sax.SAXParseException;

public class TestDebugErrorHandler extends TestCase {
    private static final SAXParseException EXCEPTION = new SAXParseException("Hov hov, hva nu", "PubID", "SysID", 1000,
            2000);
    private PrintStreamAdapter err;

    private PrintStreamAdapter out;

    public void testErrorWithErrorsAndWarnings() {
        try {
            DebugErrorHandler debugErrorHandler = new DebugErrorHandler(true);
            debugErrorHandler.error(EXCEPTION);

            fail();
        } catch (SAXParseException ex) {
            assertOut("Error:(SysID: 1.000, 2.000): Hov hov, hva nu");
            assertSame(EXCEPTION, ex);
        }
    }

    public void testErrorWithOutErrorsAndWarnings() throws SAXParseException {
        try {
            DebugErrorHandler debugErrorHandler = new DebugErrorHandler(false);

            debugErrorHandler.error(EXCEPTION);
        } catch (SAXParseException ex) {
            assertOut("");
            assertSame(EXCEPTION, ex);
        }
    }

    public void testFatalErrorWithErrorsAndWarnings() {
        try {
            DebugErrorHandler debugErrorHandler = new DebugErrorHandler(true);
            debugErrorHandler.fatalError(EXCEPTION);

            fail();
        } catch (SAXParseException ex) {
            assertOut("Fatal:(SysID: 1.000, 2.000): Hov hov, hva nu");
            assertSame(EXCEPTION, ex);
        }
    }

    public void testFatalErrorWithOutErrorsAndWarnings() throws SAXParseException {
        try {
            DebugErrorHandler debugErrorHandler = new DebugErrorHandler(false);

            debugErrorHandler.fatalError(EXCEPTION);
        } catch (SAXParseException ex) {
            assertOut("");
            assertSame(EXCEPTION, ex);
        }
    }

    public void testWarningWithErrorsAndWarnings() {
        DebugErrorHandler debugErrorHandler = new DebugErrorHandler(true);

        debugErrorHandler.warning(EXCEPTION);

        assertOut("Warn:(SysID: 1.000, 2.000): Hov hov, hva nu");
    }

    public void testWarningWithOutErrorsAndWarnings() {
        DebugErrorHandler debugErrorHandler = new DebugErrorHandler(false);

        debugErrorHandler.warning(EXCEPTION);

        assertOut("");
    }

    protected void setUp() throws Exception {
        System.setOut(out = new PrintStreamAdapter());
        System.setErr(err = new PrintStreamAdapter());
    }

    private void assertOut(String string) {
        assertEquals(string, out.sb.toString());
        assertEquals("", err.sb.toString());
    }
}