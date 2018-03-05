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

package dk.sosi.seal.model;

import dk.sosi.seal.model.constants.*;
import dk.sosi.seal.vault.EmptyCredentialVault;
import dk.sosi.seal.xml.CertificateParser;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.cert.X509Certificate;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class OIOWSTrustMessage extends AbstractDOMInfoExtractor {

    public OIOWSTrustMessage(Document doc) {
        super(doc);
    }

    /**
     * Retrieve the action part of the SOAP header.
     *
     * <pre>
     *   &lt;soap:Header&gt;
     *     &lt;wsa:Action&gt;http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue&lt;/wsa:Action&gt;
     *     ...
     *   &lt;/soap:Header&gt;
     * </pre>
     *
     * @return The action value
     */
    public String getAction() {
        return safeGetTagTextContent(SOAPTags.envelope, SOAPTags.header, WSATags.action);
    }

    /**
     * Retrieve the MessageID part of the SOAP header.
     *
     * <pre>
     *   &lt;soap:Header&gt;
     *     ...
     *     &lt;wsa:MessageID&gt;urn:uuid:99999777-0000-0000&lt;/wsa:MessageID&gt;
     *     ...
     *   &lt;/soap:Header&gt;
     * </pre>
     *
     * @return The message id.
     */
    public String getMessageID() {
        return safeGetTagTextContent(SOAPTags.envelope, SOAPTags.header, WSATags.messageID);
    }

    /**
     * Gets the signing certificate
     *
     * @return Returns the certificate contained in the XML signature or <code>null</code> if the OIOWSTrust message was not signed
     */
    public X509Certificate getSigningCertificate() {
        Element certificateElm = getTag(SOAPTags.envelope, SOAPTags.header, WSSETags.security, DSTags.signature, DSTags.keyInfo, DSTags.x509Data, DSTags.x509Certificate);
        if (certificateElm == null) {
            return null;
        } else {
            return CertificateParser.asCertificate(XmlUtil.fromBase64(certificateElm.getTextContent()));
        }
    }

    /**
     * Checks the signature on the <code>OIOWSTrustMessage</code> - no trust-checks are performed.
     *
     * @throws ModelException
     *             Thrown if the message is unsigned or the signature on the <code>OIOWSTrustMessage</code> is invalid.
     */
    public void validateSignature() {
        LibertySignatureValidator validator = new LibertySignatureValidator(new EmptyCredentialVault(), dom);
        configureSignatureValidator(validator);
        validator.validateSignature();
    }

    protected void configureSignatureValidator(LibertySignatureValidator validator) {
    }

}
