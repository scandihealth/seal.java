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
package dk.sosi.seal.pki.internal.remote;

import com.unboundid.ldap.sdk.*;
import dk.sosi.seal.pki.PKIException;

import java.util.ArrayList;
import java.util.List;

/**
 * This is a remote source of certificates.
 * Note that the fetching is separated from the parsing
 *
 * @author ksr@lakeside.dk
 * @author $LastChangedBy: ksr@lakeside.dk $
 * @since 2.1
 */
public class LdapCertificateLoader implements RemoteCertificateLoader {
    private static final String SERIAL_NUMBER_ATTRIBUTE = "serialNumber";
    private static final String USER_CERTIFICATE_ATTRIBUTE = "userCertificate;binary";

    private final String hostName;
    private final int portNumber;

    public LdapCertificateLoader(String hostName, int portNumber) {
        this.hostName = hostName;
        this.portNumber = portNumber;
    }

    public byte[] loadCertificate(String uri) {
        try {
            return bySubjectSerialNumber(uri);
        } catch (LDAPException e) {
            throw new PKIException(e);
        }
    }

    public byte[] bySubjectSerialNumber(String serialNumber) throws LDAPException {
        LDAPConnection conn = connect();
        try {
            SearchResultEntry entry = conn.searchForEntry("c=DK", SearchScope.SUB, "serialNumber=" + serialNumber, USER_CERTIFICATE_ATTRIBUTE);
            if (entry == null) {
                throw new PKIException("No entry found at " + serialNumber);
            }
            Attribute userCertAtt = entry.getAttribute(USER_CERTIFICATE_ATTRIBUTE);
            if (userCertAtt == null) {
                throw new PKIException("No certificate found at " + serialNumber);
            }
            byte[][] valueByteArrays = userCertAtt.getValueByteArrays();
            return valueByteArrays[0];
        } finally {
            conn.close();
        }
    }


    public String findSubjectSerialNumber(String baseDn, String filter) throws LDAPException {
        String[] tmp = findSubjectSerialNumbers(baseDn, filter);
        if (tmp.length > 1) {
            throw new PKIException("Multiple entries found for baseDn={" + baseDn + "} filter={"+ filter + "}");
        }
        return tmp[0];
    }

    public String[] findSubjectSerialNumbers(String baseDn, String filter) throws LDAPException {
        LDAPConnection conn = connect();
        try {
            SearchResult entries = conn.search(baseDn, SearchScope.SUB, filter, SERIAL_NUMBER_ATTRIBUTE);
            if (entries.getEntryCount() == 0) {
                throw new PKIException("No entry found for baseDn={" + baseDn + "} filter={"+ filter + "}");
            }
            List<String> res = new ArrayList<String>();
            for (SearchResultEntry entry : entries.getSearchEntries()) {
                res.add(entry.getAttribute(SERIAL_NUMBER_ATTRIBUTE).getValue());
            }
            return res.toArray(new String[res.size()]);
        } finally {
            conn.close();
        }
    }

    private LDAPConnection connect() throws LDAPException {
        LDAPConnection conn = new LDAPConnection();
        conn.connect(hostName, portNumber);
        return conn;
    }
}
