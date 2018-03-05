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

import dk.sosi.seal.model.ModelException;
import dk.sosi.seal.model.UserIDCard;
import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.model.constants.WSSETags;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public abstract class IDCardOIOWSTrustRequestDOMBuilder<T extends IDCardOIOWSTrustRequestDOMBuilder> extends OIOWSTrustRequestDOMBuilder<T> {

    protected UserIDCard idCard;
    protected boolean placeIDCardInSOAPHeader;

    /**
     * <b>Mandatory</b>: Set the <code>UserIDCard</code> to be exchanged
     *
     * @param idCard
     *            The UserIDCard.
     * @return The <code>IDCardOIOWSTrustRequestDOMBuilder</code> instance.
     */
    public T setUserIDCard(UserIDCard idCard) {
        this.idCard = idCard;
        return (T) this;
    }

    public T requireIDCardInSOAPHeader() {
        placeIDCardInSOAPHeader = true;
        return (T) this;
    }

    @Override
    protected void validateBeforeBuild() throws ModelException {
        super.validateBeforeBuild();
        validate("idcard", idCard);
    }

    @Override
    protected void addExtraNamespaceDeclarations(Element envelope) {
        super.addExtraNamespaceDeclarations(envelope);
        if(placeIDCardInSOAPHeader) {
            envelope.setAttributeNS(NameSpaces.XMLNS_SCHEMA, NameSpaces.NS_XMLNS + ":" + NameSpaces.NS_WSSE, NameSpaces.WSSE_SCHEMA);
        }
    }

    @Override
    protected void addExtraHeaders(Document doc, Element header) {
        super.addExtraHeaders(doc, header);
        if(placeIDCardInSOAPHeader) {
            final Element security = doc.createElementNS(NameSpaces.WSSE_SCHEMA, WSSETags.SECURITY_PREFIXED);
            header.appendChild(security);
            addIdCard(doc, security);
        }
    }

    @Override
    protected void addActAsTokens(Document doc, Element actAs) {
        if(placeIDCardInSOAPHeader) {
            addSecurityTokenReferenceToIDCard(doc, actAs);
        } else {
            addIdCard(doc, actAs);
        }
    }

    private void addIdCard(Document doc, Element parent) {
        final Element idCardElement = idCard.serialize2DOMDocument(null, doc);
        parent.appendChild(idCardElement);
    }

}
