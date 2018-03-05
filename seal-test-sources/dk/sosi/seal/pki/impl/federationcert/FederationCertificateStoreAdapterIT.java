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

package dk.sosi.seal.pki.impl.federationcert;

import dk.sosi.seal.pki.FederationCertificateReference;
import dk.sosi.seal.pki.PKIException;
import dk.sosi.seal.pki.SOSIConfiguration;
import dk.sosi.seal.pki.impl.HashMapCertificateCache;
import dk.sosi.seal.pki.impl.PropertiesSOSIConfiguration;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.cert.X509Certificate;

import static junit.framework.Assert.assertEquals;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class FederationCertificateStoreAdapterIT {

    private FederationCertificateStoreAdapter adapter;

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Before
    public void setUp() throws Exception {
        final SOSIConfiguration sosiConfiguration = PropertiesSOSIConfiguration.createWithDefaultOcesTestProperties(System.getProperties());
        adapter = new FederationCertificateStoreAdapter(sosiConfiguration, new HashMapCertificateCache());
    }

    @After
    public void tearDown() throws Exception {
        adapter = null;
    }

    @Test
    public void testInvalidOCES1Reference() {
        expectedEx.expect(PKIException.class);
        expectedEx.expectMessage("OCES-version OCES1 is not supported.");

        final FederationCertificateReference reference = new FederationCertificateReference("OCES1,CVR:55832218-UID:1163447368627,1077430095");
        adapter.getFederationCertificate(reference);
    }

    @Test
    // Reference for 'DanID Test (gyldig)' certificate on https://www.nets-danid.dk/produkter/for_tjenesteudbydere/nemid_tjenesteudbyder/nemid_tjenesteudbyder_support/testcertifikater/oces_2/
    // expires 24/3/2017
    public void testOces2TestCertificateReference() {
        final FederationCertificateReference reference = new FederationCertificateReference("OCES2,CVR:30808460-FID:94731315,1478017734");
        final X509Certificate certificate = adapter.getFederationCertificate(reference);
        assertEquals(1478017734, certificate.getSerialNumber().intValue());

    }

    @Test
    public void testOces2TestCertificateReferenceWithWrongSerialnumber() {
        expectedEx.expect(PKIException.class);
        expectedEx.expectMessage("Certificate lookup for reference 'OCES2,CVR:30808460-FID:94731315,1111' failed. Got certificate with serialnumber '1478017734'");

        final FederationCertificateReference reference = new FederationCertificateReference("OCES2,CVR:30808460-FID:94731315,1111");
        adapter.getFederationCertificate(reference);

    }

    @Test
    public void testOces2ProductionCertificateReference() {
        final SOSIConfiguration sosiConfiguration = PropertiesSOSIConfiguration.createWithDefaultOcesProperties(System.getProperties());
        FederationCertificateStoreAdapter productionAdapter = new FederationCertificateStoreAdapter(sosiConfiguration, new HashMapCertificateCache());

        // Reference for 'NETS DENMARK A/S - TU-Support signering'
        final FederationCertificateReference reference = new FederationCertificateReference("OCES2,CVR:20016175-UID:45867513,1402205222");
        final X509Certificate certificate = productionAdapter.getFederationCertificate(reference);
        assertEquals(1402205222, certificate.getSerialNumber().intValue());

    }

    @Test
    public void testOces2ProductionCertificateReferenceWithTestConfiguration() {
        expectedEx.expect(PKIException.class);
        expectedEx.expectMessage("No entry found at CVR:20016175-UID:45867513");

        // Reference for 'NETS DENMARK A/S - TU-Support signering'
        final FederationCertificateReference reference = new FederationCertificateReference("OCES2,CVR:20016175-UID:45867513,1402205222");
        adapter.getFederationCertificate(reference);

    }

}
