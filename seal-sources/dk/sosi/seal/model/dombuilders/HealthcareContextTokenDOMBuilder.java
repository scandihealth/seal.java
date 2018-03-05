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
import dk.sosi.seal.model.constants.HealthcareSAMLAttributes;
import dk.sosi.seal.model.constants.SAMLAttributes;
import dk.sosi.seal.model.constants.SAMLTags;
import dk.sosi.seal.model.constants.SAMLValues;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.HashMap;
import java.util.Map;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class HealthcareContextTokenDOMBuilder extends AbstractSAMLBuilder<HealthcareContextTokenDOMBuilder, Document> {

    private String subjectNameID;
    private String subjectNameIDFormat;

    private Map<String, String> attributes = new HashMap<String, String>();

    public HealthcareContextTokenDOMBuilder setAttribute(String attributeName, String attributeValue) {
        checkEmpty(attributeName, "attributeName");
        checkEmpty(attributeValue, "attributeValue for '" + attributeName + "'");
        attributes.put(attributeName, attributeValue);
        return this;
    }

    public HealthcareContextTokenDOMBuilder setUserAuthorizationCode(String userAuthorizationCode) {
        return setAttribute(HealthcareSAMLAttributes.USER_AUTHORIZATION_CODE, userAuthorizationCode);
    }

    public HealthcareContextTokenDOMBuilder setUserEducationCode(String userEducationCode) {
        return setAttribute(HealthcareSAMLAttributes.USER_EDUCATION_CODE, userEducationCode);
    }

    public HealthcareContextTokenDOMBuilder setITSystemName(String itSystemName) {
        return setAttribute(HealthcareSAMLAttributes.IT_SYSTEM_NAME, itSystemName);
    }

    public HealthcareContextTokenDOMBuilder setUserGivenName(String userGivenName) {
        return setAttribute(HealthcareSAMLAttributes.USER_GIVEN_NAME, userGivenName);
    }

    public HealthcareContextTokenDOMBuilder setUserSurName(String userSurName) {
        return setAttribute(HealthcareSAMLAttributes.USER_SUR_NAME, userSurName);
    }

    public HealthcareContextTokenDOMBuilder setSubjectNameID(String subjectNameID) {
        this.subjectNameID = subjectNameID;
        return this;
    }

    public HealthcareContextTokenDOMBuilder setSubjectNameIDFormat(String subjectNameIDFormat) {
        this.subjectNameIDFormat = subjectNameIDFormat;
        return this;
    }

    @Override
    public Document build() throws ModelException {
        return createDocument();
    }

    @Override
    protected void validateBeforeBuild() throws ModelException {
        super.validateBeforeBuild();
        validate("subjectNameID", subjectNameID);
        validate("subjectNameIDFormat", subjectNameIDFormat);
    }

    @Override
    protected void appendToRoot(Document doc, Element root) {
        super.appendToRoot(doc, root);
        root.appendChild(createSubject());
        Element attributeStatement = createAttributeStatement();
        if (attributeStatement != null) {
            root.appendChild(attributeStatement);
        }
    }

    private Element createSubject() {
        Element subjectElm = createElement(SAMLTags.subject);

        Element nameIdElm = createElement(SAMLTags.nameID);
        nameIdElm.setAttributeNS(null, SAMLAttributes.FORMAT, subjectNameIDFormat);
        nameIdElm.setTextContent(subjectNameID);
        subjectElm.appendChild(nameIdElm);

        Element subjectConfirmationElm = createElement(SAMLTags.subjectConfirmation);
        subjectConfirmationElm.setAttributeNS(null, SAMLAttributes.METHOD, SAMLValues.CONFIRMATION_METHOD_SENDER_VOUCHES);
        subjectElm.appendChild(subjectConfirmationElm);

        return subjectElm;
    }

    private Element createAttributeStatement() {
        if (attributes.isEmpty()) {
            return null;
        }

        Element attributeStatementElm = createElement(SAMLTags.attributeStatement);
        for (String attributeName : attributes.keySet()) {
            Element attributeElm = createAttributeElement(attributeName, null, attributes.get(attributeName));
            attributeStatementElm.appendChild(attributeElm);
        }

        return attributeStatementElm;
    }

    private void checkEmpty(String parameter, String errorMsg) {
        if (parameter == null || parameter.trim().length() == 0) {
            throw new IllegalArgumentException(errorMsg + " cannot be null or empty");
        }
    }

}
