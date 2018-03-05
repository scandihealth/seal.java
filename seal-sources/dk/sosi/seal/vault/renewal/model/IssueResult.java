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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/vault/renewal/model/IssueResult.java $
 * $Id: IssueResult.java 20818 2014-12-18 11:26:29Z ChristianGasser $
 */

package dk.sosi.seal.vault.renewal.model;

/**
 * Model of a the result of a TDC ws renewal invocation.
 * 
 * @author thomas@signaturgruppen.dk
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 20818 $
 * @since 1.0
 */
@Deprecated
public class IssueResult extends Response { //NOPMD

	private byte[] issuedUserCertificate;
	private byte[] rootCertificate;
	private int statusCode;
	private String statusText;

	/**
	 * @see dk.sosi.seal.vault.renewal.model.Message#messageName()
	 */
	public String messageName() {
		return "renewCertificateResponse";
	}

	/**
	 * Returns the issued user certificate
	 */
	public byte[] getIssuedUserCertificate() {
		return issuedUserCertificate;
	}

	/**
	 * Sets the issued user certificate
	 * @param issuedUserCertificate
	 */
	public void setIssuedUserCertificate(byte[] issuedUserCertificate) {
		this.issuedUserCertificate = issuedUserCertificate;
	}

	/**
	 * Returns the CA certificate of the issuer
	 * @return The certificate as a <code>byte</code> array.
	 */
	public byte[] getRootCertificate() {
		return rootCertificate;
	}

	/**
	 * Sets the CA certificate of the issuer
	 * @param rootCertificate
	 */
	public void setRootCertificate(byte[] rootCertificate) {
		this.rootCertificate = rootCertificate;
	}

	/**
	 * Returns the status code
	 * @return The status code.
	 */
	public int getStatusCode() {
		return statusCode;
	}

	/**
	 * Sets the status code
	 * @param statusCode
	 */
	public void setStatusCode(int statusCode) {
		this.statusCode = statusCode;
	}

	/**
	 * Returns the status text message
	 * @return The status text.
	 */
	public String getStatusText() {
		return statusText;
	}

	/**
	 * Sets the status text message
	 * @param statusText
	 */
	public void setStatusText(String statusText) {
		this.statusText = statusText;
	}

}
