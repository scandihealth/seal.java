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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/pki/DistinguishedName.java $
 * $Id: DistinguishedName.java 21017 2015-02-20 11:01:47Z ChristianGasser $
 */

package dk.sosi.seal.pki;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import java.util.*;

/**
 * <p>
 * Abstraction of X500 names, i.e. sequences of relative DNS
 * </p>
 *
 * @author thomas@signaturgruppen.dk
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 21017 $
 * @since 1.0
 */
public class DistinguishedName {

    private static final String COMMONNAME = "CN";

    private static final String COUNTRY = "C";

    private static final Map<String, String> oidNameToCanonicalOidName = new HashMap<String, String>();

    private static final String ORGANIZATION = "O";

    private static final String ORGANIZATIONALUNIT = "OU";

    private static final String SERIALNUMBER = "SERIALNUMBER";

    private static final String STATE = "ST";

    private static final Map<String, String> oidMap = new HashMap<String, String>();

    static {
        oidMap.put("2.5.4.5", SERIALNUMBER);

        oidNameToCanonicalOidName.put(COMMONNAME, COMMONNAME);
        oidNameToCanonicalOidName.put("COMMONNAME", COMMONNAME);

        oidNameToCanonicalOidName.put(ORGANIZATIONALUNIT, ORGANIZATIONALUNIT);

        oidNameToCanonicalOidName.put(ORGANIZATION, ORGANIZATION);

        oidNameToCanonicalOidName.put(SERIALNUMBER, SERIALNUMBER);
        oidNameToCanonicalOidName.put("SERIAL", SERIALNUMBER);
        oidNameToCanonicalOidName.put("SN", SERIALNUMBER);

        oidNameToCanonicalOidName.put(COUNTRY, COUNTRY);

        oidNameToCanonicalOidName.put(STATE, STATE);
    }

    private final String distinguishedName;

    private final Map<String, Set<String>> oidToValue = new HashMap<String, Set<String>>();

    /**
     * Construct an instance of <code>DistinguishedName</code>
     *
     * @param distinguishedName string representation of DN
     * @throws PKIException if DN parsing fails
     */
    public DistinguishedName(String distinguishedName) throws PKIException {
        this.distinguishedName = distinguishedName;
        parse();
    }

    /**
     * Construct an instance of <code>DistinguishedName</code>
     *
     * @param principal the X500Principal to extract the DN for
     * @throws PKIException if DN parsing fails
     */
    public DistinguishedName(X500Principal principal) throws PKIException {
        // Use X500Principal.RFC1779 format, since X500Principal.RFC2253 doesn't
        // handle danish special characters correctly in OCES certificates
        this.distinguishedName = principal.getName(X500Principal.RFC1779, oidMap);
        parse();
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof DistinguishedName)) {
            return false; // NOPMD
        }
        DistinguishedName other = (DistinguishedName) obj;
        return other.oidToValue.equals(this.oidToValue);
    }

    public String getCommonName() {
        return getSingleValueByKey(COMMONNAME);
    }

    public String getCountry() {
        return getSingleValueByKey(COUNTRY);
    }

    public String getOrganization() {
        return getSingleValueByKey(ORGANIZATION);
    }

    public String getOrganizationalUnit() {
        return getSingleValueByKey(ORGANIZATIONALUNIT);
    }

    public Set<String> getOrganizationalUnits() {
        return getMultiValueByKey(ORGANIZATIONALUNIT);
    }

    public String getSubjectSerialNumber() {
        return getSingleValueByKey(SERIALNUMBER);
    }

    @Override
    public int hashCode() {
        return oidToValue.hashCode();
    }

    @Override
    public String toString() {
        return distinguishedName;
    }

    private void addRDN(String name, String value) {
        String attr = oidNameToCanonicalOidName.get(name);
        if (oidToValue.containsKey(attr)) {
            oidToValue.get(attr).add(value);
        } else {
            HashSet<String> values = new HashSet<String>();
            values.add(value);
            oidToValue.put(attr, values);
        }
    }

    private Set<String> getMultiValueByKey(String key) {
        Set<String> val = oidToValue.get(key);
        if (val == null) {
            return null; // NOPMD
        }
        return val;
    }

    private String getSingleValueByKey(String key) {
        Set<String> val = oidToValue.get(key);
        if (val == null) {
            return null; // NOPMD
        }
        return val.iterator().next();
    }

    private void parse() {
        try {
            LdapName ldapName = new LdapName(distinguishedName);
            for (Rdn rdn : ldapName.getRdns()) {
                parseRDN(rdn);
            }
        } catch (NamingException e) {
            throw new PKIException(e);
        }

    }

    private void parseRDN(Rdn rdn) throws NamingException {
        Attributes attributes = rdn.toAttributes();
        for (Attribute attribute : Collections.list(attributes.getAll())) {
            String name = attribute.getID();
            String value = (String) attribute.get();
            String canonicalName = oidNameToCanonicalOidName.get(name.toUpperCase());
            if (canonicalName != null) {
                addRDN(canonicalName, value);
            } else {
                throw new PKIException("Failed to parse DN: Unknown attribute: " + name);
            }

        }
    }

}