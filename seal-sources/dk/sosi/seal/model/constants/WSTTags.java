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

public enum WSTTags implements Tag {
    requestSecurityToken("RequestSecurityToken"),
    requestSecurityTokenResponseCollection("RequestSecurityTokenResponseCollection"),
    requestSecurityTokenResponse("RequestSecurityTokenResponse"),
    lifetime("Lifetime"),
    tokenType("TokenType"),
    requestedSecurityToken("RequestedSecurityToken"),
    claims("Claims");

    public static final String REQUEST_SECURITY_TOKEN_RESPONSE_COLLECTION_PREFIXED = NameSpaces.NS_WST + ":RequestSecurityTokenResponseCollection";
    public static final String REQUEST_SECURITY_TOKEN_RESPONSE_PREFIXED = NameSpaces.NS_WST + ":RequestSecurityTokenResponse";
    public static final String TOKEN_TYPE_PREFIXED = NameSpaces.NS_WST + ":TokenType";
    public static final String REQUEST_SECURITY_TOKEN_PREFIXED = NameSpaces.NS_WST + ":RequestedSecurityToken";
    public static final String LIFETIME_PREFIXED = NameSpaces.NS_WST + ":Lifetime";
    public static final String REQUESTED_ATTACHED_REFERENCE_PREFIXED = NameSpaces.NS_WST + ":RequestedAttachedReference";
    public static final String REQUESTED_UNATTACHED_REFERENCE_PREFIXED = NameSpaces.NS_WST + ":RequestedUnattachedReference";

    private final String tag;

    private WSTTags(String tag) {
        this.tag = tag;
    }

    public String getNS() {
        return NameSpaces.WST_1_3_SCHEMA;
    }

    public String getTagName() {
        return tag;
    }

    public String getPrefix() {
        return NameSpaces.NS_WST;
    }
}
