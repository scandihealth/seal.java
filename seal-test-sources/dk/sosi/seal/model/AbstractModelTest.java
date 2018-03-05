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

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.constants.SubjectIdentifierTypeValues;
import dk.sosi.seal.pki.*;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.vault.GenericCredentialVault;
import org.junit.BeforeClass;
import org.w3c.dom.Element;

import java.util.Calendar;
import java.util.Date;
import java.util.Properties;

public abstract class AbstractModelTest {

    protected static GenericCredentialVault credentialVault;
    protected static final String EXPECTED_ASSURANCELEVEL = "3";
    protected static final String EXPECTED_AUTHORIZATIONCODE = "004PT";
    protected static final String EXPECTED_COMMONNAME = "Jens Sundbye Poulsen";
    protected static final String EXPECTED_CPR = "2702681273";
    protected static final String EXPECTED_CVR = "20688092";
    protected static final String EXPECTED_EMAIL = "jens@email.dk";
    protected static final String EXPECTED_GIVENNAME = "Jens Sundbye";
    protected static final String EXPECTED_ISSUER = "http://pan.certifikat.dk/sts/services/SecurityTokenService";
    protected static final String EXPECTED_ITSYSTEMNAME = "Harmoni/EMS";
    protected static final String EXPECTED_OCCUPATION = "overlæge";
    protected static final String EXPECTED_ORGANIZATION = "Lægehuset på bakken";
    protected static final String EXPECTED_SPECVERSION = "DK-SAML-2.0";
    protected static final String EXPECTED_SURNAME = "Poulsen";

    protected static final String EXPECTED_USEREDUCATIONCODE = "7170";
    protected static SOSIFactory sosiFactory;

    protected static final Date notBefore = d(-10);
    protected static final Date notOnOrAfter = d(10);

    @BeforeClass
    public static void setupAbstract() {
        credentialVault = CredentialVaultTestUtil.getCredentialVaultCertInLdap();
        sosiFactory = new SOSIFactory(getMockFederation(), credentialVault, System.getProperties());
    }

    /**
     * Creates a signed <code>UserIDCard</code>.<br />
     * This is usually done by the STS, but for use in unittests, we emulate the STS here.
     * 
     * @return A signed <code>UserIDCard</code>.
     */
    protected static UserIDCard createSignedIdCard() {
        UserIDCard userIdCard = createUserIDCard();
        final SecurityTokenRequest tokenRequest = sosiFactory.createNewSecurityTokenRequest();
        tokenRequest.setIDCard(userIdCard);
        userIdCard.sign(tokenRequest.serialize2DOMDocument(), sosiFactory.getSignatureProvider());
        return userIdCard;
    }

    /**
     * Creates a <code>UserIDCard</code> based on the following information.<br />
     * <table border="1">
     * <tr>
     * <td>CVR#</td>
     * <td>20688092</td>
     * </tr>
     * <tr>
     * <td>Organization</td>
     * <td>Lægehuset på bakken</td>
     * </tr>
     * <tr>
     * <td>CPR#</td>
     * <td>2702681273</td>
     * </tr>
     * <tr>
     * <td>Given name</td>
     * <td>Jens Sundbye</td>
     * </tr>
     * <tr>
     * <td>Surname</td>
     * <td>Poulsen</td>
     * </tr>
     * <tr>
     * <td>E-mail</td>
     * <td>jens@email.dk</td>
     * </tr>
     * <tr>
     * <td>Occupation</td>
     * <td>overlæge</td>
     * </tr>
     * <tr>
     * <td>Role</td>
     * <td>doctor</td>
     * </tr>
     * <tr>
     * <td>AuthorizationCode</td>
     * <td>004PT</td>
     * </tr>
     * </table>
     * 
     * @return New <code>UserIDCard</code> instance.
     */
    protected static UserIDCard createUserIDCard() {
        return createUserIDCard(SubjectIdentifierTypeValues.CVR_NUMBER);
    }

    /**
     * Creates a <code>UserIDCard</code> based on the following information.<br />
     * <table border="1">
     * <tr>
     * <td>CVR#</td>
     * <td>20688092</td>
     * </tr>
     * <tr>
     * <td>Organization</td>
     * <td>Lægehuset på bakken</td>
     * </tr>
     * <tr>
     * <td>CPR#</td>
     * <td>2702681273</td>
     * </tr>
     * <tr>
     * <td>Given name</td>
     * <td>Jens Sundbye</td>
     * </tr>
     * <tr>
     * <td>Surname</td>
     * <td>Poulsen</td>
     * </tr>
     * <tr>
     * <td>E-mail</td>
     * <td>jens@email.dk</td>
     * </tr>
     * <tr>
     * <td>Occupation</td>
     * <td>overlæge</td>
     * </tr>
     * <tr>
     * <td>Role</td>
     * <td>doctor</td>
     * </tr>
     * <tr>
     * <td>AuthorizationCode</td>
     * <td>004PT</td>
     * </tr>
     * </table>
     * 
     * @param careProviderType
     *            Type of identication of the care provider.
     * @return New <code>UserIDCard</code> instance.
     */
    protected static UserIDCard createUserIDCard(String careProviderType) {
        CareProvider careProvider = new CareProvider(careProviderType, EXPECTED_CVR, EXPECTED_ORGANIZATION);
        UserInfo userInfo = new UserInfo(EXPECTED_CPR, EXPECTED_GIVENNAME, EXPECTED_SURNAME, EXPECTED_EMAIL, EXPECTED_OCCUPATION, EXPECTED_USEREDUCATIONCODE, EXPECTED_AUTHORIZATIONCODE);
        UserIDCard idcard = sosiFactory.createNewUserIDCard(EXPECTED_ITSYSTEMNAME, userInfo, careProvider, AuthenticationLevel.MOCES_TRUSTED_USER, null, null, null, "hans@dampf.dk");
        return new UserIDCard(idcard, "newIssuer");
    }

    protected static Date d(int minutesFromNow) {
        Calendar now = Calendar.getInstance();
        now.set(Calendar.MILLISECOND, 0);

        return new Date(now.getTimeInMillis() + (minutesFromNow * 60 * 1000));
    }

    /**
     * Creates a new <code>Date</code> based on the input parameters.
     * 
     * @param year
     *            The year value.
     * @param month
     *            The month (1 based) value.
     * @param date
     *            The date value.
     * @param hour
     *            The 24h clock value.
     * @param minute
     *            The minute value.
     * @param second
     *            The second value.
     * @return The constructed <code>Date</code> object.
     */
    protected static Date d(int year, int month, int date, int hour, int minute, int second) {
        Calendar cal = Calendar.getInstance();
        cal.set(Calendar.YEAR, year);
        cal.set(Calendar.MONTH, month - 1);
        cal.set(Calendar.DATE, date);
        cal.set(Calendar.HOUR_OF_DAY, hour);
        cal.set(Calendar.MINUTE, minute);
        cal.set(Calendar.SECOND, second);
        cal.set(Calendar.MILLISECOND, 0);
        return cal.getTime();
    }

    /**
     * Creates a <code>Federation</code> for test purposes.
     * 
     * @return A test <code>Federation</code> instance.
     */
    protected static Federation getMockFederation() {
        Properties properties = System.getProperties();
        final CertificationAuthority ca = CertificationAuthorityFactory.create(properties, CertificationAuthorityFactory.OCES_SYSTEMTEST_CA,
                new NaiveCertificateStatusChecker(properties), CredentialVaultTestUtil.getCertificateCacheForVocesCredentialVaultCertInLdap());
        return new MockFederation(properties, ca, "CVR:30808460-UID:25351738");
    }

    protected IdentityTokenBuilder createBuilder() {
        UserIDCard uidc = createUserIDCard();

        IdentityTokenBuilder itb = new IdentityTokenBuilder(sosiFactory.getCredentialVault());
        itb.setAudienceRestriction("http://fmk-online.dk");
        itb.setNotBefore(notBefore);
        itb.setNotOnOrAfter(notOnOrAfter);
        itb.setUserIdCard(uidc);
        itb.requireOrganizationName();
        itb.requireCvrNumberIdentifier();
        itb.requireCprNumber();
        itb.requireITSystemName();
        itb.requireUserAuthorizationCode();
        itb.requireUserEducationCode();
        itb.setIssuer("http://pan.certifikat.dk/sts/services/SecurityTokenService");
        return itb;
    }

    public static class TestDOMInfoExtractor extends AbstractDOMInfoExtractor {

        public TestDOMInfoExtractor(Element dom) {
            super(dom);
        }
    }
}