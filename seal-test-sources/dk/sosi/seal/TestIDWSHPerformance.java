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

package dk.sosi.seal;

import dk.sosi.seal.model.*;
import dk.sosi.seal.model.dombuilders.IdentityTokenRequestDOMBuilder;
import dk.sosi.seal.model.dombuilders.IdentityTokenResponseDOMBuilder;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;

import java.util.Date;

public class TestIDWSHPerformance extends AbstractModelTest {

    private static final String ADDRESSING_TO = "http://pan.certifikat.dk/sts/services/SecurityTokenService";

    private static final String AUDIENCE = "http://fmk-online.dk";
    private static IDWSHFactory IDWSH_FACTORY;
    private static final int ITERATIONS = Integer.getInteger("dk.sosi.seal.responsetimedivider", 1).intValue();
    private static final Date NOT_BEFORE = d(-1);
    private static final Date NOT_ON_OR_AFTER = d(2);
    private static UserIDCard SIGNED_ID_CARD;

    @BeforeClass
    public static void initStatics() {
        IDWSH_FACTORY = new IDWSHFactory(getMockFederation(), sosiFactory.getCredentialVault());
        SIGNED_ID_CARD = createSignedIdCard();
    }

    private static Document createTestRequestDOM() {
        IdentityTokenRequestDOMBuilder b = IDWSH_FACTORY.createIdentityTokenRequestDOMBuilder();
        b.setAudience(AUDIENCE);
        b.setUserIDCard(SIGNED_ID_CARD);
        b.setWSAddressingTo(ADDRESSING_TO);
        return b.build();
    }

    private IdentityToken clientIdentityToken;
    private Document clientIdentityTokenRequestDOM;
    private IdentityTokenResponse clientIdentityTokenResponse;
    private String clientURL;
    private IdentityTokenRequest serverIdentityTokenRequest;
    private Document serverIdentityTokenResponseDOM;

    @Before
    public void initBase() {
        clientIdentityTokenRequestDOM = createTestRequestDOM();
        serverIdentityTokenRequest = createIdentityTokenRequestFromDOM(clientIdentityTokenRequestDOM);
        serverIdentityTokenResponseDOM = createIdentityTokenResponseDOMFromRequest(serverIdentityTokenRequest);
        clientIdentityTokenResponse = IDWSH_FACTORY.createIdentityTokenResponseModelBuilder().build(serverIdentityTokenResponseDOM);
        clientIdentityToken = clientIdentityTokenResponse.getIdentityToken();
        clientURL = clientIdentityToken.createURLBuilder().encode();
    }

    @Test
    public void buildIdentityTokenResponse() {
        for (int i = 0; i < ITERATIONS; i++) {
            IDWSH_FACTORY.createIdentityTokenResponseModelBuilder().build(serverIdentityTokenResponseDOM);
        }
    }

    @Test
    public void buildIdentityTokenRequest() {
        for (int i = 0; i < ITERATIONS; i++) {
            createIdentityTokenRequestFromDOM(clientIdentityTokenRequestDOM);
        }
    }

    @Test
    public void buildIdentityTokenRequestDOM() {
        for (int i = 0; i < ITERATIONS; i++) {
            createTestRequestDOM();
        }
    }

    @Test
    public void buildIdentityTokenResponseDOM() {
        for (int i = 0; i < ITERATIONS; i++) {
            createIdentityTokenResponseDOMFromRequest(serverIdentityTokenRequest);
        }
    }

    @Test
    public void extractIdentityToken() {
        for (int i = 0; i < ITERATIONS; i++) {
            clientIdentityTokenResponse.getIdentityToken();
        }
    }

    @Test
    public void buildIdentityTokenURL() {
        for (int i = 0; i < ITERATIONS; i++) {
            clientIdentityToken.createURLBuilder().encode();
        }
    }

    @Test
    public void buildIdentityTokenFromURL() {
        for (int i = 0; i < ITERATIONS; i++) {
            convertURLtoIdentityToken(clientURL);
        }
    }

    private IdentityToken convertURLtoIdentityToken(String url) {
        return IDWSH_FACTORY.createIdentityTokenFromURL(url);
    }

    private IdentityTokenBuilder createIdentityTokenBuilder(IdentityTokenRequest request) {
        IdentityTokenBuilder itb = IDWSH_FACTORY.createIdentityTokenBuilder();
        itb.setAudienceRestriction(request.getAudience());
        itb.requireCertificateAsReference();
        itb.setNotBefore(NOT_BEFORE);
        itb.setNotOnOrAfter(NOT_ON_OR_AFTER);
        itb.setUserIdCard((UserIDCard)request.getIDCard());
        itb.requireCprNumber();
        itb.requireUserAuthorizationCode();
        itb.setIssuer("http://pan.certifikat.dk/sts/services/SecurityTokenService");
        return itb;
    }

    private IdentityTokenRequest createIdentityTokenRequestFromDOM(Document sIdentityTokenRequestDOM) {
        return IDWSH_FACTORY.createIdentityTokenRequestModelBuilder().buildModel(sIdentityTokenRequestDOM);
    }

    private Document createIdentityTokenResponseDOMFromRequest(IdentityTokenRequest request) {
        IdentityTokenResponseDOMBuilder b = IDWSH_FACTORY.createIdentityTokenResponseDOMBuilder();
        b.setContext(request.getContext());
        b.setIdentityToken(createIdentityTokenBuilder(request).build());
        b.setRelatesTo(request.getMessageID());

        return b.build();
    }
}