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

import dk.sosi.seal.model.constants.DSTags;
import dk.sosi.seal.model.constants.HealthcareSAMLAttributes;
import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.modelbuilders.ModelBuildException;
import dk.sosi.seal.pki.Federation;
import dk.sosi.seal.xml.XmlUtil;
import org.apache.commons.codec.binary.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Schema;
import javax.xml.validation.Validator;
import java.io.*;
import java.util.Properties;
import java.util.zip.Deflater;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * The <code>IdentityToken</code> is a smaller ID representation than the regular <code>IDCard</code>.<br />
 * The <code>IdentityToken</code> was introduced to allow transfering identity information within the limited constraints of an URL.<br />
 * <br />
 * Currently Internet Explorer 6/7/8/9 sets the limit for the URL representation to < 2000 characters.<br />
 * Any part of an URL beyound 2000 characters will be cut off.<br />
 * <br />
 * All operations related to constructing, wrappring, etc. of the <code>IdentityToken</code> should be done through the <code>IDWSHFactory</code>.
 * 
 * @author ads
 * @since 2.1
 */
public class IdentityToken extends AbstractOIOSAMLToken {

    private static final String UTF8 = "UTF-8";
    private static final int BOM = 65279;

    private static Schema schema;

    /**
     * Constructor for the <code>IdentityToken</code> class.
     * 
     * @param dom
     *            DOM representation of the <code>IdentityToken</code> object.
     */
    public IdentityToken(Element dom) {
        super(dom);
        validateSchema(dom);
    }

    /**
     * Constructor for the <code>IdentityToken</code> class.
     * 
     * @param urlString
     *            URL <code>String</code> representation of the <code>IdentityToken</code>.
     * @param federation
     *            The federation used to check trust for the <code>IdentityToken</code>.
     * @throws ModelException
     *             Thrown if the conversion from the URL <code>String</code> to an <code>IdentityToken</code> object fails.
     */
    /* pp */IdentityToken(String urlString, Federation federation) throws ModelException, UnsupportedEncodingException {
        super(init(urlString).getDocumentElement());
        validateSignature(federation);
        validateTimestamp();
    }

    private static Document init(String urlString) throws UnsupportedEncodingException {
        byte[] unbased = Base64.decodeBase64(urlString);
        byte[] uncompressed = decompress(unbased);
        String string = new String(uncompressed, UTF8);

        // Strip eventual ByteOrderMark character
        if (string.charAt(0) == BOM) {
            string = string.substring(1);
        }

        Document doc = XmlUtil.readXml(new Properties(), string, false);
        validateSchema(doc);
        return doc;
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
     * Extract the <code>dk:gov:saml:attribute:ITSystemName</code> value from the DOM.<br />
     *
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="dk:gov:saml:attribute:ITSystemName"&gt;
     *       &lt;saml:AttributeValue xsi:type="xs:string"&gt;Harmoni/EMS&lt;/saml:AttributeValue&gt;
     *     &lt;/saml:Attribute&gt;
     * </pre>
     *
     * @return The value of the <code>dk:healthcare:saml:attribute:ITSystemName</code> tag.
     */
    public String getITSystemName() {
        return getAttribute(HealthcareSAMLAttributes.IT_SYSTEM_NAME);
    }

    /**
     * Extract the <code>dk:gov:saml:attribute:UserEducationCode</code> value from the DOM.<br />
     *
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="dk:gov:saml:attribute:UserEducationCode"&gt;
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
     * Creates an <code>IdentityTokenURLBuilder</code> used for converting the <code>IdentityToken</code> into a URL.<br />
     * See {@link IdentityTokenURLBuilder} for more usage information.
     * 
     * @return <code>IdentityTokenURLBuilder</code> instance used for constructing the final URL <code>String</code>.
     * @throws ModelException
     *             Thrown if the conversion fails.
     */
    public IdentityTokenURLBuilder createURLBuilder() throws ModelException {
        return new IdentityTokenURLBuilder(XmlUtil.node2String(dom));
    }

    /**
     * Invoke this method to verify the validity of the <code>IdentityToken</code> against the {@link #getNotBefore()} and {@link #getNotOnOrAfter()} values.<br />
     * 
     * @throws ModelException
     *             Thrown if the <code>IdentityToken</code> is invalid.
     *
     * @deprecated Use {@link @validateTimestamp()} instead
     */
    @Deprecated
    public void validate() throws ModelException {
        validateTimestamp();
    }

    /**
     * Checks the signature on the Identity Token.
     * 
     * An invocation of this method possibly involves retrieving the certificate used to sign the token from OCES operators LDAP
     * 
     * @param federation
     *            The federation used to check trust for the <code>IdentityToken</code>.
     */
    public void validateSignature(Federation federation) {
        final Node elmSignature = dom.getElementsByTagNameNS(NameSpaces.DSIG_SCHEMA, DSTags.SIGNATURE).item(0);
        if(!SignatureUtil.validate(elmSignature, federation, null, true)) {
            throw new ModelException("Signature on IdentityToken is invalid");
        }
    }

    private static byte[] decompress(byte[] data) {
        byte[] buffer = new byte[1024];
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            BufferedInputStream bis = new BufferedInputStream(new GZIPInputStream(new ByteArrayInputStream(data)));

            int bytesRead;
            while ((bytesRead = bis.read(buffer)) != -1) {
                bos.write(buffer, 0, bytesRead);
            }

            return bos.toByteArray();
        } catch (IOException e) {
            throw new ModelException("Error during deflating", e);
        }
    }

    private static synchronized Schema getSchema() throws SAXException {
        if (schema == null) {
            schema = SchemaUtil.loadSchema("/idwsh/idt/saml.xsd");
        }
        return schema;
    }

    private static void validateSchema(Node node) {
        try {
            final Validator validator = getSchema().newValidator();
            validator.validate(new DOMSource(node));
        } catch (SAXException e) {
            throw new ModelBuildException("Error validating IdentityToken", e);
        } catch (IOException e) {
            throw new ModelBuildException("Error validating IdentityToken", e);
        }
    }

    /**
     * Helper class used for converting the <code>IdentityToken</code> into a <code>String</code> valid for usage in an URL.<br />
     * The <code>IdentityToken</code> is first deflated using the <code>java.util.zip.Deflater</code> (see {@link Deflater}).<br />
     * After deflation, the result is converted into a URL safe BASE64 encoded <code>String</code>.
     */
    public class IdentityTokenURLBuilder {

        private String xml;

        /* pp */IdentityTokenURLBuilder(String xml) {
            this.xml = xml;
        }

        /**
         * Converts the <code>IdentityToken</code> to a <code>String</code> valid for usage in an URL.
         * 
         * @return The encoded <code>IdentityToken</code>.
         */
        public String encode() {
            byte[] zipped = compress(xml);
            return Base64.encodeBase64URLSafeString(zipped);
        }

        private byte[] compress(String data) {
            try {
                ByteArrayOutputStream bos = new ByteArrayOutputStream(data.length());

                BufferedOutputStream out = new BufferedOutputStream(new GZIPOutputStream(bos));
                out.write(data.getBytes(UTF8));
                out.close();

                return bos.toByteArray();
            } catch (IOException e) {
                throw new ModelException("Error during deflating", e);
            }
        }
    }
}