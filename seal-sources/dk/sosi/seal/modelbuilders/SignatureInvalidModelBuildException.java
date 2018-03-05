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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/modelbuilders/SignatureInvalidModelBuildException.java $
 * $Id: SignatureInvalidModelBuildException.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */

package dk.sosi.seal.modelbuilders;


/**
 * Exception used to signal an invalid signature.
 *
 * @author sr
 * @author $LastChangedBy: chg@lakeside.dk $
 * @since 1.0
 */
public class SignatureInvalidModelBuildException extends ModelBuildException {

	private static final long serialVersionUID = -4612393949293371651L;

	private final String messageID;
	private final String flowID;
	private final String dgwsVersion;

	/**
	 * @param messageID
	 *            A message id.
	 * @param flowID
	 *            A flow id.
	 * @param dgwsVersion
	 *			  A dgwsVersion
	 * @see ModelBuildException#ModelBuildException(String)
	 */
	public SignatureInvalidModelBuildException(String message, String messageID, String flowID, String dgwsVersion) {
		super(message);
		this.messageID = messageID;
		this.flowID = flowID;
		this.dgwsVersion = dgwsVersion;
	}

	/**
	 * Returns the flowID.
	 */
	public String getFlowID() {

		return flowID;
	}

	/**
	 * Returns the messageID.
	 */
	public String getMessageID() {

		return messageID;
	}

	/**
	 * Returns the dgwsVersion.
	 */
	public String getDGWSVersion() {
		return dgwsVersion;
	}
}
