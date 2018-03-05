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
package dk.sosi.seal.pki.impl;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.ModelException;
import dk.sosi.seal.pki.AuditEventHandler;
import dk.sosi.seal.pki.SOSIConfiguration;

import java.util.Properties;

/**
 * Default implementation based on a java.util.Properties
 */
public class PropertiesSOSIConfiguration implements SOSIConfiguration {
    private final Properties properties;
    private final Properties defaultValues;

    public static SOSIConfiguration createWithDefaultOcesProperties(Properties properties) {
        final Properties defaults = new Properties();
        defaults.put(SOSIFactory.PROPERTYNAME_SOSI_LDAP_CERTIFICATE_HOST_OCES2, "crtdir.certifikat.dk");
        defaults.put(SOSIFactory.PROPERTYNAME_SOSI_LDAP_CERTIFICATE_PORT_OCES2, "389");
        return new PropertiesSOSIConfiguration(properties, defaults);
    }

    public static SOSIConfiguration createWithDefaultOcesTestProperties(Properties properties) {
        final Properties defaults = new Properties();
        defaults.put(SOSIFactory.PROPERTYNAME_SOSI_LDAP_CERTIFICATE_HOST_OCES2, "crtdir.pp.certifikat.dk");
        defaults.put(SOSIFactory.PROPERTYNAME_SOSI_LDAP_CERTIFICATE_PORT_OCES2, "389");
        return new PropertiesSOSIConfiguration(properties, defaults);
    }

    public PropertiesSOSIConfiguration(Properties props) {
        this(props, new Properties());
    }

    public PropertiesSOSIConfiguration(Properties props, Properties defaults) {
        this.properties = props;
        this.defaultValues = defaults;
    }

    public void verify() {
        if (getProperty("sosi:certificate.checker") != null) {
            throw new RuntimeException("sosi:certificate.checker - no longer supported");
        }
    }

    public String getLdapCertificateHostOCES1() {
        throw new UnsupportedOperationException("OCES1 is no longer supported");
    }

    public int getLdapCertificatePortOCES1() {
        throw new UnsupportedOperationException("OCES1 is no longer supported");
    }

    public String getLdapCertificateHostOCES2() {
        return getPropertyOrFail(SOSIFactory.PROPERTYNAME_SOSI_LDAP_CERTIFICATE_HOST_OCES2);
    }

    public int getLdapCertificatePortOCES2() {
        return Integer.valueOf(getPropertyOrFail(SOSIFactory.PROPERTYNAME_SOSI_LDAP_CERTIFICATE_PORT_OCES2));
    }

    public AuditEventHandler getAuditEventHandler() {
        String className = properties.getProperty(
                SOSIFactory.PROPERTYNAME_SOSI_FEDERATION_AUDITHANDLER,
                SOSIFactory.SOSI_DEFAULT_AUDIT_EVENT_HANDLER);
        if(className == null) {
            return null; //NOPMD
        }
        try {
            return (AuditEventHandler) Class.forName(className).newInstance();
        } catch (SecurityException e) {
            throw new ModelException("Failed to construct audit handler", e);
        } catch (ClassNotFoundException e) {
            throw new ModelException("Failed to construct audit handler", e);
        } catch (IllegalArgumentException e) {
            throw new ModelException("Failed to construct audit handler", e);
        } catch (InstantiationException e) {
            throw new ModelException("Failed to construct audit handler", e);
        } catch (IllegalAccessException e) {
            throw new ModelException("Failed to construct audit handler", e);
        }
    }

    public String getProperty(String name) {
        if (properties.containsKey(name)) {
            return properties.getProperty(name);
        } else {
            return defaultValues.getProperty(name);
        }
    }

    private String getPropertyOrFail(String name) {
        String value = getProperty(name);
        if (value == null) {
            throw new IllegalArgumentException("Property '" + name + "' is not defined.");
        } else {
            return value;
        }
    }
}
