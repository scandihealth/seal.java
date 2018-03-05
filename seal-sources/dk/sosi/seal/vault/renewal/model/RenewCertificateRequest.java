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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/vault/renewal/model/RenewCertificateRequest.java $
 * $Id: RenewCertificateRequest.java 20818 2014-12-18 11:26:29Z ChristianGasser $
 */

package dk.sosi.seal.vault.renewal.model;

/**
 * Model of the ws renew certificate request.
 * 
 * @author thomas@signaturgruppen.dk
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 20818 $
 * @since 1.0
 */
@Deprecated
public class RenewCertificateRequest extends Request {
	private Argument referenceNumber;

	private Argument authorizationCode;

	private Argument certificateRequest;

	/**
	 * Constructs a request model object
	 * @param referenceNumber
	 * 		the reference number
	 * @param authorizationCode
	 * 		the authorization code
	 * @param certificateRequest
	 * 		the DER encoded certificate request (PKCS#10)
	 */
	public RenewCertificateRequest(String referenceNumber, String authorizationCode,
			byte[] certificateRequest) {
		super();
		this.referenceNumber = new Argument("string", String.class, referenceNumber);
		this.authorizationCode = new Argument("string0", String.class, authorizationCode);
		this.certificateRequest = new Argument("bytes", byte[].class, certificateRequest);
		addMethodArgument(this.referenceNumber);
		addMethodArgument(this.authorizationCode);
		addMethodArgument(this.certificateRequest);
	}

	/**
	 * @see dk.sosi.seal.vault.renewal.model.Message#messageName()
	 */
	public String messageName() {
		return "renewCertificate";
	}

	/**
	 * Returns the authorization code
	 * @return The authorization code
	 */
	public String getAuthorizationCode() {
		return (String) authorizationCode.getValue();
	}

	/**
	 * Returns the certificate request
	 * @return The certificate request as a <code>byte</code> array.
	 */
	public byte[] getCertificateRequest() {
		return (byte[]) certificateRequest.getValue();
	}

	/**
	 * Returns the reference number
	 * @return The reference number.
	 */
	public String getReferenceNumber() {
		return (String) referenceNumber.getValue();
	}

}
