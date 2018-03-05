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

package dk.sosi.seal.model.constants;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public interface OIOSAMLAttributes {

    String COMMON_NAME = "urn:oid:2.5.4.3";
    String CPR_NUMBER = "dk:gov:saml:attribute:CprNumberIdentifier";
    String CVR_NUMBER = "dk:gov:saml:attribute:CvrNumberIdentifier";
    String RID_NUMBER = "dk:gov:saml:attribute:RidNumberIdentifier";
    String EMAIL = "urn:oid:0.9.2342.19200300.100.1.3";
    String ORGANIZATION_NAME = "urn:oid:2.5.4.10";
    String SURNAME = "urn:oid:2.5.4.4";
    String USER_CERTIFICATE = "urn:oid:1.3.6.1.4.1.1466.115.121.1.8";
    String CERTIFICATE_ISSUER = "urn:oid:2.5.29.29";
    String IS_YOUTH_CERT = "dk:gov:saml:attribute:IsYouthCert";
    String ASSURANCE_LEVEL = "dk:gov:saml:attribute:AssuranceLevel";
    String SPEC_VERSION = "dk:gov:saml:attribute:SpecVer";
    String CERTIFICATE_SERIAL = "urn:oid:2.5.4.5";
    String UID = "urn:oid:0.9.2342.19200300.100.1.1";
    String DISCOVERY_EPR = "urn:liberty:disco:2006-08:DiscoveryEPR";

    String SURNAME_FRIENDLY = "surName";
    String COMMON_NAME_FRIENDLY = "CommonName";
    String EMAIL_FRIENDLY = "email";
    String ORGANIZATION_NAME_FRIENDLY = "organizationName";
    String CERTIFICATE_SERIAL_FRIENDLY = "serialNumber";
    String UID_FRIENDLY = "Uid";
}
