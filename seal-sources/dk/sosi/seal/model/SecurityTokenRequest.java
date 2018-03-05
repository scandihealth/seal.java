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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/SecurityTokenRequest.java $
 * $Id: SecurityTokenRequest.java 20824 2014-12-18 15:00:40Z ChristianGasser $
 */
package dk.sosi.seal.model;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.constants.MedcomAttributes;
import dk.sosi.seal.model.dombuilders.SecurityTokenRequestDOMBuilder;
import dk.sosi.seal.pki.SignatureProvider;
import org.w3c.dom.Document;

/**
 * Model class for SOSI SecurityToken request.
 * 
 * @author Peter Buus
 * @since 1.0
 */
public class SecurityTokenRequest extends Message {

    /**
     * Constructs a <code>Request</code> model element
     * 
     * @param dgwsVersion
     *            The DGWS version this message adheres to
     * @param factory
     *            the factory that is creating this request
     */
    public SecurityTokenRequest(String dgwsVersion, SOSIFactory factory) {
        super(dgwsVersion, factory);
        // cpr is optional
        validator.remove(MedcomAttributes.USER_CIVIL_REGISTRATION_NUMBER);
    }

    // ================================
    // Overridden methods
    // ================================
    public void setFlowID(String flowID) throws ModelException {
        throw new ModelException("Method not applicable for SecurityTokenRequest");
    }

    /**
     * Generates a new XML document using the given request message.
     */
    protected Document regenerateDOM(Document doc, SignatureProvider signatureProvider) {
        return new SecurityTokenRequestDOMBuilder(doc, this, signatureProvider).buildDOMDocument();
    }

    /**
     * @see Object#equals(java.lang.Object)
     */
    public boolean equals(Object obj) {

        return obj == this || obj != null && obj.getClass() == getClass() && (getCreationDate().getTime() / 1000 == ((Message)obj).getCreationDate().getTime() / 1000) && ((getIDCard() == null && ((Message)obj).getIDCard() == null) || (getIDCard() != null && getIDCard().equals(((Message)obj).getIDCard())));
    }

    /**
     * @see Object#hashCode()
     */
    public int hashCode() { // NOPMD

        return super.hashCode();
    }

}
