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
import dk.sosi.seal.modelbuilders.ModelBuildException;
import dk.sosi.seal.pki.SignatureProviderFactory;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.Date;
import java.util.LinkedList;
import java.util.List;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class LibertyMessageDOMEnhancer {
    protected final Document document;

    private final CredentialVault credentialVault;
    private final boolean ensureLibertyFrameworkHeader;

    private String wsAddressingMessageID;
    private String wsAddressingAction;
    private String wsAddressingTo;
    private String wsAddressingRelatesTo;

    public LibertyMessageDOMEnhancer(CredentialVault credentialVault, Document document, boolean ensureLibertyFrameworkHeader) {
        this.credentialVault = credentialVault;
        this.document = document;
        this.ensureLibertyFrameworkHeader = ensureLibertyFrameworkHeader;
    }

    /**
     * Optional - generated otherwise, overwrites existing
     *
     * @param wsAddressingMessageID
     */
    public void setWSAddressingMessageID(String wsAddressingMessageID) {
        if (isNullOrEmpty(wsAddressingMessageID)) {
            throw new IllegalArgumentException("'wsAddressingMessageID' cannot be null or empty");
        }
        this.wsAddressingMessageID = wsAddressingMessageID;
    }

    /**
     * Required if not already present
     *
     * @param wsAddressingAction
     */
    public void setWSAddressingAction(String wsAddressingAction) {
        if (isNullOrEmpty(wsAddressingAction)) {
            throw new IllegalArgumentException("'wsAddressingAction' cannot be null or empty");
        }
        this.wsAddressingAction = wsAddressingAction;
    }

    /**
     * Optional
     *
     * @param wsAddressingTo
     */
    public void setWSAddressingTo(String wsAddressingTo) {
        if (isNullOrEmpty(wsAddressingTo)) {
            throw new IllegalArgumentException("'wsAddressingTo' cannot be null or empty");
        }
        this.wsAddressingTo = wsAddressingTo;
    }

    /**
     * Optional
     *
     * @param wsAddressingRelatesTo
     */
    public void setWSAddressingRelatesTo(String wsAddressingRelatesTo) {
        if (isNullOrEmpty(wsAddressingRelatesTo)) {
            throw new IllegalArgumentException("'wsAddressingRelatesTo' cannot be null or empty");
        }
        this.wsAddressingRelatesTo = wsAddressingRelatesTo;
    }

    public void enhanceAndSign() {
        final Element header = XmlUtil.getFirstChildElementNS(document.getDocumentElement(), NameSpaces.SOAP_SCHEMA, SOAPTags.HEADER_UNPREFIXED);

        checkBeforeEnhancing(header);
        ensureNameSpaceDeclarations(document);

        String messageIDWsuId = ensureWSAddressingMessageIDHeader(header);
        String actionWsuId = ensureWSAddressingActionHeader(header);
        String toWsuId = null;
        String relatesToWsuId = null;
        String sbfWsuID = null;

        if (wsAddressingTo != null || hasWsAddressingHeader(header, WSATags.to)) toWsuId = ensureWSAddressingTo(header);
        if (wsAddressingRelatesTo != null || hasWsAddressingHeader(header, WSATags.relatesTo)) relatesToWsuId = ensureWSAddressingRelatesTo(header);
        if (ensureLibertyFrameworkHeader) sbfWsuID = ensureLibertyFrameworkHeader(header);

        Element securityHeader = addWSSecurityHeader(header);
        String securityWsuId = ensureIdAttribute(securityHeader, "security");
        String timestampWsuID = addWsuTimestamp(securityHeader);
        String bodyWsuId = ensureIdAttributeInBody(document);

        final List<SignatureConfiguration.Reference> references = new LinkedList<SignatureConfiguration.Reference>();
        references.add(new SignatureConfiguration.Reference(messageIDWsuId, SignatureConfiguration.Type.DIRECT_REFERENCE_NOT_ENVELOPED));
        references.add(new SignatureConfiguration.Reference(actionWsuId, SignatureConfiguration.Type.DIRECT_REFERENCE_NOT_ENVELOPED));
        if (toWsuId != null) references.add(new SignatureConfiguration.Reference(toWsuId, SignatureConfiguration.Type.DIRECT_REFERENCE_NOT_ENVELOPED));
        if (relatesToWsuId != null) references.add(new SignatureConfiguration.Reference(relatesToWsuId, SignatureConfiguration.Type.DIRECT_REFERENCE_NOT_ENVELOPED));
        if (sbfWsuID != null) references.add(new SignatureConfiguration.Reference(sbfWsuID, SignatureConfiguration.Type.DIRECT_REFERENCE_NOT_ENVELOPED));
        references.add(new SignatureConfiguration.Reference(timestampWsuID, SignatureConfiguration.Type.DIRECT_REFERENCE_NOT_ENVELOPED));
        references.add(new SignatureConfiguration.Reference(bodyWsuId, SignatureConfiguration.Type.DIRECT_REFERENCE_NOT_ENVELOPED));

        addTokenToSecurityHeader(securityHeader, references);

        final SignatureConfiguration config = getSignatureConfiguration(securityWsuId, references);
        SignatureUtil.sign(SignatureProviderFactory.fromCredentialVault(credentialVault), document, config);
    }

    protected void checkBeforeEnhancing(Element header) {
    }

    protected void addTokenToSecurityHeader(Element securityHeader, List<SignatureConfiguration.Reference> references) {
    }

    //To be able to override for unit-test purposes
    protected SignatureConfiguration getSignatureConfiguration(String securityWsuId, List<SignatureConfiguration.Reference> references) {
        return new SignatureConfiguration(references.toArray(new SignatureConfiguration.Reference[references.size()]), securityWsuId, null);
    }

    private void ensureNameSpaceDeclarations(Document document) {
        final Element root = document.getDocumentElement();
        //TODO Fail if namespace declaration with same prefix but different URI exists?
        root.setAttributeNS(NameSpaces.XMLNS_SCHEMA, NameSpaces.NS_XMLNS + ":" + NameSpaces.NS_WSA, NameSpaces.WSA_1_0_SCHEMA);
        root.setAttributeNS(NameSpaces.XMLNS_SCHEMA, NameSpaces.NS_XMLNS + ":" + NameSpaces.NS_WSU, NameSpaces.WSU_SCHEMA);
        if (ensureLibertyFrameworkHeader) {
            root.setAttributeNS(NameSpaces.XMLNS_SCHEMA, NameSpaces.NS_XMLNS + ":" + NameSpaces.NS_SBF, NameSpaces.LIBERTY_SBF_SCHEMA);
            root.setAttributeNS(NameSpaces.XMLNS_SCHEMA, NameSpaces.NS_XMLNS + ":" + NameSpaces.NS_SBFPROFILE, NameSpaces.LIBERTY_SBF_PROFILE_SCHEMA);
        }
        root.setAttributeNS(NameSpaces.XMLNS_SCHEMA, NameSpaces.NS_XMLNS + ":" + NameSpaces.NS_SAML, NameSpaces.SAML2ASSERTION_SCHEMA);
        root.setAttributeNS(NameSpaces.XMLNS_SCHEMA, NameSpaces.NS_XMLNS + ":" + NameSpaces.NS_DS, NameSpaces.DSIG_SCHEMA);
        root.setAttributeNS(NameSpaces.XMLNS_SCHEMA, NameSpaces.NS_XMLNS + ":" + NameSpaces.NS_WSSE, NameSpaces.WSSE_SCHEMA);
    }

    private String ensureWSAddressingMessageIDHeader(Element header) {
        String value;
        boolean overwrite;
        if (wsAddressingMessageID != null) {
            value = wsAddressingMessageID;
            overwrite = true;
        } else {
            value = XmlUtil.generateUUID();
            overwrite = false;
        }
        return ensureElement(header, WSATags.messageID, value, overwrite, "messageID");
    }

    private String ensureWSAddressingActionHeader(Element header) {
        final boolean overwrite = wsAddressingAction != null;
        return ensureElement(header, WSATags.action, wsAddressingAction, overwrite, "action");
    }

    private String ensureWSAddressingTo(Element header) {
        final boolean overwrite = wsAddressingTo != null;
        return ensureElement(header, WSATags.to, wsAddressingTo, overwrite, "to");
    }

    private String ensureWSAddressingRelatesTo(Element header) {
        final boolean overwrite = wsAddressingRelatesTo != null;
        return ensureElement(header, WSATags.relatesTo, wsAddressingRelatesTo, overwrite, "relatesTo");
    }

    private String ensureLibertyFrameworkHeader(Element header) {
        Element framework = XmlUtil.getFirstChildElementNS(header, NameSpaces.LIBERTY_SBF_SCHEMA, LibertyTags.FRAMEWORK);
        if (framework == null) {
            framework = document.createElementNS(NameSpaces.LIBERTY_SBF_SCHEMA, LibertyTags.FRAMEWORK_PREFIXED);
            header.appendChild(framework);
        }
        framework.setAttributeNS(null, LibertyAttributes.VERSION, LibertyValues.VERSION);
        framework.setAttributeNS(NameSpaces.LIBERTY_SBF_PROFILE_SCHEMA, LibertyAttributes.PROFILE_PREFIXED, LibertyValues.PROFILE);
        return ensureIdAttribute(framework, "sbf");
    }

    private String ensureIdAttributeInBody(Document document) {
        final Element body = XmlUtil.getFirstChildElementNS(document.getDocumentElement(), NameSpaces.SOAP_SCHEMA, SOAPTags.BODY_UNPREFIXED);
        return ensureIdAttribute(body, "body");
    }

    protected String ensureIdAttribute(Element element, String value) {
        final String id = element.getAttributeNS(NameSpaces.WSU_SCHEMA, WSUAttributes.ID_UNPREFIXED);
        if (isNullOrEmpty(id)) {
            element.setAttributeNS(NameSpaces.WSU_SCHEMA, WSUAttributes.ID_PREFIXED, value);
            return value;
        } else {
            return id;
        }
    }

    private String ensureElement(Element parent, Tag tag, String value, boolean overwriteValue, String idValue) {
        Element child = XmlUtil.getFirstChildElementNS(parent, tag.getNS(), tag.getTagName());
        if (child == null) {
            if (isNullOrEmpty(value)) {
                throw new ModelBuildException("Required element '" + tag.getTagName() + "' in namespace '" + tag.getNS() + "' not present in document. " +
                                                      "Failed to set it as no value has been provided for it.");
            }
            child = document.createElementNS(tag.getNS(), tag.getPrefix() + ":" + tag.getTagName());
            child.setTextContent(value);
            parent.appendChild(child);
        } else if (overwriteValue) {
            child.setTextContent(value);
        }
        return ensureIdAttribute(child, idValue);
    }

    private boolean hasWsAddressingHeader(Element header, WSATags tag) {
        return XmlUtil.getFirstChildElementNS(header, NameSpaces.WSA_1_0_SCHEMA, tag.getTagName()) != null;
    }

    private String addWsuTimestamp(Element securityHeader) {
        final Element timestamp = document.createElementNS(NameSpaces.WSU_SCHEMA, WSUTags.TIMESTAMP_PREFIXED);
        securityHeader.appendChild(timestamp);
        final Element created = document.createElementNS(NameSpaces.WSU_SCHEMA, WSUTags.CREATED_PREFIXED);
        //TODO allow to set created time explicitly?
        created.setTextContent(XmlUtil.toXMLTimeStamp(new Date(), true));
        timestamp.appendChild(created);
        return ensureIdAttribute(timestamp, "ts");
    }

    private Element addWSSecurityHeader(Element header) {
        final Element securityHeader = document.createElementNS(NameSpaces.WSSE_SCHEMA, WSSETags.SECURITY_PREFIXED);
        securityHeader.setAttributeNS(null, WSSEAttributes.MUST_UNDERSTAND, "1");
        header.appendChild(securityHeader);
        return securityHeader;
    }

    private boolean isNullOrEmpty(String string) {
        return string == null || string.equals("");
    }

}
