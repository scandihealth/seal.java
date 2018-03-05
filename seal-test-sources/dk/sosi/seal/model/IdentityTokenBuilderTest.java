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

import dk.sosi.seal.model.constants.SubjectIdentifierTypeValues;
import dk.sosi.seal.pki.SOSITestFederation;
import dk.sosi.seal.xml.XmlUtil;
import org.jdom.Attribute;
import org.jdom.Element;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.w3c.dom.Document;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import static junit.framework.Assert.fail;

public class IdentityTokenBuilderTest extends AbstractModelTest {

    @Rule
     public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testBuilder() throws Exception {
        IdentityTokenBuilder itb = createBuilder();
        itb.requireCertificateAsReference();

        Document identityTokenDoc = itb.build().getDOM();
        String xml = XmlUtil.node2String(identityTokenDoc);

        new XMLValidator() {

            @Override
            protected boolean assertAttributeValues(Element element, Attribute attribute, String expectedValue, String actualValue) {
                if("Conditions".equals(element.getName()) && "NotBefore".equals(attribute.getName())) {
                    expectedValue = XmlUtil.getDateFormat(true).format(notBefore);
                } else if("Conditions".equals(element.getName()) && "NotOnOrAfter".equals(attribute.getName())) {
                    expectedValue = XmlUtil.getDateFormat(true).format(notOnOrAfter);
                }
                return super.assertAttributeValues(element, attribute, expectedValue, actualValue);
            }

            @Override
            protected boolean ignore(String tag, String attribute) {
                if("Assertion".equals(tag) && "IssueInstant".equals(attribute)) {
                    return true; // Ignore this one, as it is generated based on NOW.
                }
                if("Assertion".equals(tag) && "ID".equals(attribute)) {
                    return true; // Ignore this one, as it is a generated UUID.
                }
                if("Reference".equals(tag) && "URI".equals(attribute)) {
                    return true; // Ignore this one, as it is a generated UUID.
                }
                if("AuthnStatement".equals(tag) && "AuthnInstant".equals(attribute)) {
                    return true; // Ignore this one, as it is generated based on NOW.
                }
                if("DigestValue".equals(tag)) {
                    return true; // Ignore this one, since it is generated based on contents
                }
                if("SignatureValue".equals(tag)) {
                    return true; // Ignore this one, since it is generated based on contents
                }

                return false;
            }
        }.assertXML(xml, "IDWS-H Identity Token.xml");
    }

    @Test(expected = ModelException.class)
    public void testCreatedVSExpired() {
        IdentityTokenBuilder itb = new IdentityTokenBuilder(sosiFactory.getCredentialVault());
        itb.setAudienceRestriction("http://fmk-online.dk");
        itb.setNotBefore(notOnOrAfter);
        itb.setNotOnOrAfter(notBefore);
        itb.setUserIdCard(createUserIDCard());
        itb.requireCertificateAsReference();
        itb.requireOrganizationName();
        itb.requireCvrNumberIdentifier();
        itb.requireCprNumber();
        itb.build();
    }

    @Test(expected = ModelException.class)
    public void testInvalidCVRType() {
        IdentityTokenBuilder itb = new IdentityTokenBuilder(sosiFactory.getCredentialVault());
        itb.setAudienceRestriction("http://fmk-online.dk");
        itb.setNotBefore(notOnOrAfter);
        itb.setNotOnOrAfter(notBefore);
        itb.setUserIdCard(createUserIDCard(SubjectIdentifierTypeValues.CPR_NUMBER));
        itb.requireCertificateAsReference();
        itb.requireOrganizationName();
        itb.requireCvrNumberIdentifier();
        itb.requireCprNumber();
        itb.build();
    }

    @Test
    public void testValitityProblems() throws Exception {
        IdentityTokenBuilder itb = createBuilder();
        modifyAttributValue(itb, "audienceRestriction", null, true);
        modifyAttributValue(itb, "issuer", null, true);
        modifyAttributValue(itb, "notBefore", null, true);
        modifyAttributValue(itb, "notOnOrAfter", null, true);
        modifyAttributValue(itb, "userIdCard", null, true);

        modifyAttributValue(itb, "audienceRestriction", "", true);
        modifyAttributValue(itb, "issuer", "", true);

        modifyAttributValue(itb, "audienceRestriction", " ", true);
        modifyAttributValue(itb, "issuer", " ", true);

        modifyAttributValue(itb, "audienceRestriction", "     ", true);
        modifyAttributValue(itb, "issuer", "     ", true);

        modifyAttributValue(itb, "audienceRestriction", "     a", false);
        modifyAttributValue(itb, "issuer", "     a", false);
    }

    @Ignore("Disabled since the identity token contained in the urlstring is signed by an expired Test-STS certificate")
    @Test
    public void testConstructFromURLGeneratedBySealDotNet() {
        expectedException.expect(ModelException.class);
        expectedException.expectMessage("OIOSAML token no longer valid - now:");

        IdentityTokenBuilder.constructFromURLString("H4sIAAAAAAAEAOy9B2AcSZYlJi9tynt_SvVK1-B0oQiAYBMk2JBAEOzBiM3mkuwdaUcjKasqgcplVmVdZhZAzO2dvPfee--999577733ujudTif33_8_XGZkAWz2zkrayZ4hgKrIHz9-fB8_Ih432aJ8dNw0ed0W1TI9e_rZR7__7mT26exg__72-YPzve392V62nU12drZ3z6e7-5_uTHYmWf5RetY06_xs2bTZsv3so72d3d3tnYfbO5--2T14tPvw0d6Dn_oo_cm8bggsfT3e-Sh9tyiXzaN3zWcfzdt29eju3aurq_HVvXFVX9zd29nZvft7f_H89XSeLzLTFth99tG6Xj6qsqZoHi2zRd48aqePXh9_8fwRAX2UGdQ_OpKxMFr10ZvT12_ov8d3_Q8fz5pHr4uLZdau6zw9m3320Zcnp6_tJ6bX2RCGO3d3Ht6lNrOmuPjxjyy4fHa2PK_4z5NsWS2LaVYWP8iA1Rd5O69m6XF5UdVFO18MDn13B4C383fTbSLy8sc_Su-G6N4SUoBi3WTbzTzbNcBe5ed5nS-nefrVq7PPPvrx2800v_qmzpbNeVUvmvDP90MoX17mZbXKZ9uNI_rd94Q4QKy7fSyfFhd5034dyvlUEyg_mZXr_OgHRV384H776ie--vyn6_OfuC73rnd2P7n3ev2i-owx8BvzB5bm8meHX-z0yhs_dV7kp5P83ezdT5W_6O6LX_Tdn5qc3v_i9Nnvna_f_l4vmk9fT5_cfb338hf91N29N5_8Pj94u7Oefefuq_VPVBdfHez_PnfPFvP22cGzkydnJ-c7-9_99smrl6cnv9fv81PPns3ufvKd1eL422eT_bPP99-un1ar6598cLl--RN7p9WbH_yis4u3O7_X7kl2d3L_4G729MlZ-7B9cPJ0cv6Tx9_-vV9Mfqp4N__0-d75i5_OfvL8wfSnH-y9_cwOx8MfQ_q98msMj8ULXxfLC_roI_PdCxLhI4jd7ujkJ189un__4N7e3u7B9ldnTx_t7n56b3__wb1PDz7dezDa3XnwYH_n00_39rkr8675Q2gYIKEq4PV68tP5tNW_8NLZ0_QZcUXWDiuT3fEuf1LMts-56aP1slnl04KmZPbR0a55DlSlCNiwx5NqeV7gXahSYbvN2mu6eDSvylleb1fn22-ZSkPwnmZtFtD3_XWVoaCblU2E3YzI4Nedr3RA1GJW4OsmfVG1T3IicT5kNKjBl8sv6-PzNq-7bfZ2Ht2_91OGTMfrWQHRekUiVxdT6T745khpc754u10ty2KZj2dvFUPbpvN3AO1uB30Lv50vX7dZmy_yZZvyn0O2cJ-H5b9I4Nr8naGN_9FJSQaNVMbRRps3fTRFO_r4976_89CiHwET-S74zA7B4NLS0CfrNh_8In1WE5VmJfPMZx816xq_0Kzxn4x2MSM074_3x_vy8U2ix2Mi-PjUCN-E2k0t0UznrGXSd03xqL1eUXfvyEWgr5YXzrkobvYutgueqSmZtpfkoFRLQ6WgG0sn8-kNlDipFotqOUyMe_-vJ8aXqxlNOhmrWZ5-g4ShToqyS5Od8cPx3r39vfHuQ8Ln3s7OeBf___8AlRbFcsxD-j0zIhcRrGnH02rxNUklVJm9fXRRXbK7y8Pi7-CWr2t0-jwnt-lnhTDfJGHu_SyQ4DVZYAoi_l8_9qe_1zZQ2CYUfhaocLKqX6wXk7w-m5FGhkfy_36K9BymGwnS-cCzQPqNCfWO_p8AAAD__11mF9O2DgAA", new SOSITestFederation(System.getProperties()));
    }

    private void modifyAttributValue(IdentityTokenBuilder itb, String attribute, String value, boolean shouldFail) throws Exception {
        Field var = getField(attribute);
        var.setAccessible(true);

        Method smethod = getMethod("set" + Character.toUpperCase(attribute.charAt(0)) + attribute.substring(1), var.getType());

        Object oldVal = var.get(itb);
        smethod.invoke(itb, new Object[] { value });

        try {
            itb.build();
            if(shouldFail) {
                fail("Setting " + attribute + " to " + (value == null ? "null" :"\"" + value + "\"") + " was expected to fail.");
            }
        } catch (ModelException ex) {
            if(!shouldFail) {
                ex.printStackTrace();
                fail("Setting " + attribute + " to " + (value == null ? "null" :"\"" + value + "\"") + " was NOT expected to fail.");
            }
        }

        smethod.invoke(itb, oldVal);
    }

    private Field getField(String name) throws NoSuchFieldException {
        Class clazz = IdentityTokenBuilder.class;
        Field field = null;
        // Since Class#getDeclaredField does not return members declared in superclasses ....
        do {
            try {
                field = clazz.getDeclaredField(name);
            } catch (NoSuchFieldException e) {/* ignore */}
            clazz = clazz.getSuperclass();
        } while (clazz != null);
        return field;
    }

    private Method getMethod(String name, Class<?> type) throws NoSuchMethodException {
        Class clazz = IdentityTokenBuilder.class;
        Method method = null;
        // Since Class#getDeclaredMethod does not return members declared in superclasses ....
        do {
            try {
                method = clazz.getDeclaredMethod(name, type);
            } catch (NoSuchMethodException e) {/* ignore */}
            clazz = clazz.getSuperclass();
        } while (clazz != null);
        return method;
    }
}