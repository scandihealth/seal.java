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

import dk.sosi.seal.model.constants.HealthcareSAMLAttributes;
import dk.sosi.seal.modelbuilders.ModelBuildException;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Schema;
import javax.xml.validation.Validator;
import java.io.IOException;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class HealthcareContextToken extends AbstractSAMLToken {

    private static Schema schema;

    public HealthcareContextToken(Element dom) {
        super(dom);
        validateSchema(dom);
    }

    /**
     * Extract the <code>dk:healthcare:saml:attribute:UserAuthorizationCode</code> value from the DOM.<br />
     *
     * <pre>
     *  &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
     *                     Name="dk:healthcare:saml:attribute:UserAuthorizationCode"&gt;
     *      &lt;saml:AttributeValue xsi:type="xs:string"&gt;004PT&lt;/saml:AttributeValue&gt;
     *  &lt;/saml:Attribute&gt;
     * </pre>
     *
     * @return The value of the <code>dk:healthcare:saml:attribute:UserAuthorizationCode</code> tag.
     */
    public String getAuthorizationCode() {
        return getAttribute(HealthcareSAMLAttributes.USER_AUTHORIZATION_CODE);
    }

    /**
     * Extract the <code>dk:healthcare:saml::attribute:UserEducationCode</code> value from the DOM.<br />
     *
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="dk:healthcare:saml:attribute:UserEducationCode"&gt;
     *       &lt;saml:AttributeValue xsi:type="xs:string"&gt;7170;/saml:AttributeValue&gt;
     *     &lt;/saml:Attribute&gt;
     * </pre>
     *
     * @return The value of the <code>dk:healthcare:saml::attribute:UserEducationCode</code> tag.
     */
    public String getUserEducationCode() {
        return getAttribute(HealthcareSAMLAttributes.USER_EDUCATION_CODE);
    }

    /**
     * Extract the <code>dk:healthcare:saml:attribute:ITSystemName</code> value from the DOM.<br />
     *
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="dk:healthcare:saml:attribute:ITSystemName"&gt;
     *       &lt;saml:AttributeValue xsi:type="xs:string"&gt;Harmoni;/saml:AttributeValue&gt;
     *     &lt;/saml:Attribute&gt;
     * </pre>
     *
     * @return The value of the <code>dk:healthcare:saml:attribute:ITSystemName</code> tag.
     */
    public String getITSystemName() {
        return getAttribute(HealthcareSAMLAttributes.IT_SYSTEM_NAME);
    }

    /**
     * Extract the <code>dk:healthcare:saml:attribute:UserGivenName</code> value from the DOM.<br />
     *
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="dk:healthcare:saml:attribute:UserGivenName"&gt;
     *       &lt;saml:AttributeValue xsi:type="xs:string"&gt;Holger;/saml:AttributeValue&gt;
     *     &lt;/saml:Attribute&gt;
     * </pre>
     *
     * @return The value of the <code>dk:healthcare:saml::attribute:UserGivenName</code> tag.
     */
    public String getUserGivenName() {
        return getAttribute(HealthcareSAMLAttributes.USER_GIVEN_NAME);
    }

    /**
     * Extract the <code>dk:healthcare:saml:attribute:UserSurName</code> value from the DOM.<br />
     *
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="dk:healthcare:saml:attribute:UserSurName"&gt;
     *       &lt;saml:AttributeValue xsi:type="xs:string"&gt;Larsen;/saml:AttributeValue&gt;
     *     &lt;/saml:Attribute&gt;
     * </pre>
     *
     * @return The value of the <code>dk:healthcare:saml::attribute:UserSurName</code> tag.
     */
    public String getUserSurName() {
        return getAttribute(HealthcareSAMLAttributes.USER_SUR_NAME);
    }


    private void validateSchema(Node node) {
        try {
            final Validator validator = getSchema().newValidator();
            validator.validate(new DOMSource(node));
        } catch (SAXException e) {
            throw new ModelBuildException("Error validating HealthcareContextToken", e);
        } catch (IOException e) {
            throw new ModelBuildException("Error validating HealthcareContextToken", e);
        }
    }

    private static synchronized Schema getSchema() throws SAXException {
        if (schema == null) {
            schema = SchemaUtil.loadSchema("/oiosaml/standard-saml.xsd");
        }
        return schema;
    }


}
