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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/xml/DebugErrorHandler.java $
 * $Id: DebugErrorHandler.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.xml;

import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

import java.text.MessageFormat;
import java.util.Locale;

/**
 * ErrorHandler realization where you can configure the handler a little more flexible.
 * 
 * @author ${user}
 * @author $$LastChangedBy: chg@lakeside.dk $$
 * @version $$Revision: 8697 $$
 * @since 1.3
 */
public class DebugErrorHandler extends DefaultHandler {
    private MessageFormat message;
    private final boolean showWarnings;

    public DebugErrorHandler(boolean showErrorsAndWarnings) {
        super();
        this.showWarnings = showErrorsAndWarnings;
        message = new MessageFormat("({0}: {1}, {2}): {3}", new Locale("da"));
    }

    private void print(String lvl, SAXParseException x) {
        String msg = message.format(new Object[] { x.getSystemId(), new Integer(x.getLineNumber()),
                new Integer(x.getColumnNumber()), x.getMessage() });
        System.out.println(lvl + ":" + msg);
    }

    public void warning(SAXParseException x) {
        if(showWarnings) {
            print("Warn", x);
        }
    }

    public void error(SAXParseException x) throws SAXParseException {
        if(showWarnings) {
            print("Error", x);
        }
        throw x;
    }

    public void fatalError(SAXParseException x) throws SAXParseException {
        if(showWarnings) {
            print("Fatal", x);
        }
        throw x;
    }
}