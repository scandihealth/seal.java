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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/Header.java $
 * $Id: Header.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.model;

import org.w3c.dom.Document;

import java.util.Date;

/**
 * The common superclass for <code>RequestHeader</code> and <code>RequestHeader</code>
 *
 * @author chg
 * @since 1.5.10
 */
public abstract class Header {

	private final Document doc;
	private final IDCard idCard;
	private final String messageID;
	private final Date creationDate;
	private final String dgwsVersion;
	private final String flowID;

	public Header(String dgwsVersion, Date creationDate, IDCard idCard, String messageID, String flowID, Document doc) {
		this.doc = doc;
		this.idCard = idCard;
		this.messageID = messageID;
		this.creationDate = creationDate;
		this.dgwsVersion = dgwsVersion;
		this.flowID = flowID;
	}

	public Document getDocument() {
		return doc;
	}

	public IDCard getIDCard() {
		return idCard;
	}

	public String getMessageID() {
		return messageID;
	}

	public Date getCreationDate() {
		return creationDate;
	}

	public String getDGWSVersion() {
		return dgwsVersion;
	}

	public String getFlowID() {
		return flowID;
	}

}
