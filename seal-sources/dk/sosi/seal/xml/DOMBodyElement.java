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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/xml/DOMBodyElement.java $
 * $Id: DOMBodyElement.java 8699 2011-09-02 10:45:06Z chg@lakeside.dk $
 */
package dk.sosi.seal.xml;

import org.apache.axis.encoding.SerializationContext;
import org.apache.axis.message.SOAPBodyElement;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * @author kkj
 * @author $LastChangedBy: chg@lakeside.dk $
 * @version 1.0 Jul 13, 2006
 * @since 1.0
 */
@Deprecated
public class DOMBodyElement extends SOAPBodyElement {

	private static final long serialVersionUID = -4623089013580663866L;

	private Element soapBodyElement;

    public DOMBodyElement(Element soapBodyElement) {
        super(soapBodyElement);
        this.soapBodyElement = soapBodyElement;
    }

    protected void outputImpl(SerializationContext contxt) throws Exception {
        NodeList headerElements = soapBodyElement.getChildNodes();
        for (int i = 0; i < headerElements.getLength(); i++) {
            contxt.writeDOMElement((Element)headerElements.item(i));
        }
    }
}
