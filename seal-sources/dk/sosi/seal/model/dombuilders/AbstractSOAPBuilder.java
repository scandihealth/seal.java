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

package dk.sosi.seal.model.dombuilders;

import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.model.constants.SOAPTags;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public abstract class AbstractSOAPBuilder<T> extends AbstractDOMBuilder<T>{

    @Override
    protected Element createRoot(Document doc) {
        return doc.createElementNS(NameSpaces.SOAP_SCHEMA, SOAPTags.ENVELOPE_PREFIXED);
    }

    /**
     * Method called by {@link #createDocument()}.<br />
     * Override this method to control the creation of the root <code>Element</code>.<br />
     * The default implementation adds <i>soapenv:Envelope</i> element and invokes the {@link #addRootAttributes(org.w3c.dom.Element)} method.
     *
     *
     * @param doc
     *            The <code>Document</code> container instance.
     * @param root
     */
    @Override
    protected void appendToRoot(Document doc, Element root) {
        appendHeader(doc, root);
        appendBody(doc, root);
    }

    /**
     * Method called by {@link #appendBody(org.w3c.dom.Document, org.w3c.dom.Element)}.<br />
     * Use this method to add the actual contents to the body element.
     *
     * @param doc
     *            The <code>Document</code> container instance.
     * @param body
     *            The body <code>Element</code> instance.
     */
    protected abstract void addBodyContent(Document doc, Element body);

    /**
     * Method called by {@link #appendHeader(org.w3c.dom.Document, org.w3c.dom.Element)}.<br />
     * Use this method to add the actual contens to the header element.
     *
     * @param doc
     *            The <code>Document</code> container instance.
     * @param header
     *            The header <code>Element</code> instance.
     */
    protected abstract void addHeaderContent(Document doc, Element header);

    /**
     * Method called by {@link #createDocument()}.<br />
     * Override this method to control the creation of the body <code>Element</code>.<br />
     * The default implementation adds <i>soapenv:Body</i> element.
     *
     * @param doc
     *            The <code>Document</code> container instance.
     * @param envelope
     *            The root <code>Element</code> instance.
     */
    protected void appendBody(Document doc, Element envelope) {
        Element body = doc.createElementNS(NameSpaces.SOAP_SCHEMA, SOAPTags.BODY_PREFIXED);
        envelope.appendChild(body);
        addBodyContent(doc, body);
    }

    /**
     * Method called by {@link #createDocument()}.<br />
     * Override this method to control the creation of the header <code>Element</code>.<br />
     * The default implementation adds <i>soapenv:Header</i> element.
     *
     * @param doc
     *            The <code>Document</code> container instance.
     * @param envelope
     *            The root <code>Element</code> instance.
     */
    protected void appendHeader(Document doc, Element envelope) {
        Element header = doc.createElementNS(NameSpaces.SOAP_SCHEMA, SOAPTags.HEADER_PREFIXED);
        envelope.appendChild(header);
        addHeaderContent(doc, header);
    }
}
