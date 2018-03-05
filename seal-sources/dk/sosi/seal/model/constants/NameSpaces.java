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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/constants/NameSpaces.java $
 * $Id: NameSpaces.java 34001 2017-02-22 09:51:47Z ChristianGasser $
 */
package dk.sosi.seal.model.constants;

import java.util.HashMap;
import java.util.Map;

/**
 * Class containing namespace declarations.
 * 
 * @author Jan
 * @author $Author: ChristianGasser $
 * @since 1.0
 */
public final class NameSpaces { // NOPMD
    public static final String SOSI_SCHEMA = "http://www.sosi.dk/sosi/2006/04/sosi-1.0.xsd";
    public static final String WSU_SCHEMA = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    public static final String WSSE_SCHEMA = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    public static final String WSSE_1_1_SCHEMA = "http://docs.oasis-open.org/wss/oasis-wsswssecurity-secext-1.1.xsd";
    public static final String MEDCOM_SCHEMA = "http://www.medcom.dk/dgws/2006/04/dgws-1.0.xsd";
    public static final String XMLSCHEMAINSTANCE_SCHEMA = "http://www.w3.org/2001/XMLSchema-instance";
    public static final String SAML2ASSERTION_SCHEMA = "urn:oasis:names:tc:SAML:2.0:assertion";
    public static final String SAML2PROTOCOL_SCHEMA = "urn:oasis:names:tc:SAML:2.0:protocol";
    public static final String DSIG_SCHEMA = "http://www.w3.org/2000/09/xmldsig#";
    public static final String SOAP_SCHEMA = "http://schemas.xmlsoap.org/soap/envelope/";
    public static final String XSD_SCHEMA = "http://www.w3.org/2001/XMLSchema";
    public static final String WST_SCHEMA = "http://schemas.xmlsoap.org/ws/2005/02/trust";
    public static final String WST_1_3_SCHEMA = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
    public static final String WST_1_4_SCHEMA = "http://docs.oasis-open.org/ws-sx/ws-trust/200802";
    public static final String WSA_SCHEMA = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
    public static final String WSA_1_0_SCHEMA = "http://www.w3.org/2005/08/addressing";
    public static final String WSP_SCHEMA = "http://schemas.xmlsoap.org/ws/2004/09/policy";
    public static final String XMLNS_SCHEMA = "http://www.w3.org/2000/xmlns/";
    public static final String LIBERTY_SBF_SCHEMA = "urn:liberty:sb";
    public static final String LIBERTY_SBF_PROFILE_SCHEMA = "urn:liberty:sb:profile";
    public static final String LIBERTY_DISCOVERY_SCHEMA = "urn:liberty:disco:2006-08";
    public static final String LIBERTY_SECURITY_SCHEMA = "urn:liberty:security:2006-08";
    public static final String WSF_AUTH_SCHEMA = "http://docs.oasis-open.org/wsfed/authorization/200706";
    public static final String NS_SAML = "saml";
    public static final String NS_SAMLP = "samlp";
    public static final String NS_SOAP = "soapenv";
    public static final String NS_XMLNS = "xmlns";
    public static final String NS_WSU = "wsu";
    public static final String NS_WSSE = "wsse";
    public static final String NS_WSSE_1_1 = "wsse11";
    public static final String NS_XSI = "xsi";
    public static final String NS_XSD = "xsd";
    public static final String NS_XS = "xs";
    public static final String NS_SOSI = "sosi";
    public static final String NS_DS = "ds";
    public static final String NS_WST = "wst";
    public static final String NS_WST14 = "wst14";
    public static final String NS_WSA = "wsa";
    public static final String NS_WSP = "wsp";
    public static final String NS_MEDCOM = "medcom";
    public static final String NS_SBF = "sbf";
    public static final String NS_SBFPROFILE = "sbfprofile";
    public static final String NS_LIB_DISCO = "disco";
    public static final String NS_LIB_SEC = "sec";
    public static final String NS_WSF_AUTH = "auth";
    @Deprecated
    public static final String XMLNS_URI = "http://www.w3.org/2000/xmlns/";

    /**
     * A Map of (name->URI) of all the namespaces that should be declared in SOSI compliant documents.
     */
    public static final Map<String, String> SOSI_NAMESPACES;
    static {
        SOSI_NAMESPACES = new HashMap<String, String>();
        SOSI_NAMESPACES.put(NS_SOAP, NameSpaces.SOAP_SCHEMA);
        SOSI_NAMESPACES.put(NS_DS, NameSpaces.DSIG_SCHEMA);
        SOSI_NAMESPACES.put(NS_SAML, NameSpaces.SAML2ASSERTION_SCHEMA);
        SOSI_NAMESPACES.put(NS_XSI, NameSpaces.XMLSCHEMAINSTANCE_SCHEMA);
        SOSI_NAMESPACES.put(NS_MEDCOM, NameSpaces.MEDCOM_SCHEMA);
        SOSI_NAMESPACES.put(NS_WSSE, NameSpaces.WSSE_SCHEMA);
        SOSI_NAMESPACES.put(NS_WST, NameSpaces.WST_SCHEMA);
        SOSI_NAMESPACES.put(NS_WSA, NameSpaces.WSA_SCHEMA);
        SOSI_NAMESPACES.put(NS_WSU, NameSpaces.WSU_SCHEMA);
        SOSI_NAMESPACES.put(NS_SOSI, NameSpaces.SOSI_SCHEMA);
        SOSI_NAMESPACES.put(NS_XSD, NameSpaces.XSD_SCHEMA);
    }

    /**
     * A Map of (name->URI) of all the namespaces that should be declared in SOSI compliant fault documents.
     */
    public static final Map<String, String> SOSI_FAULT_NAMESPACES;
    static {
        SOSI_FAULT_NAMESPACES = new HashMap<String, String>();
        SOSI_FAULT_NAMESPACES.put(NS_SOAP, NameSpaces.SOAP_SCHEMA);
        SOSI_FAULT_NAMESPACES.put(NS_MEDCOM, NameSpaces.MEDCOM_SCHEMA);
        SOSI_FAULT_NAMESPACES.put(NS_WSSE, NameSpaces.WSSE_SCHEMA);
        SOSI_FAULT_NAMESPACES.put(NS_WSU, NameSpaces.WSU_SCHEMA);
    }

}
