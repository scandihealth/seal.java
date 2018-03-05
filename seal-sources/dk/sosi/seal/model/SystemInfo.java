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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/SystemInfo.java $
 * $Id: SystemInfo.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.model;

import java.io.Serializable;

/**
 * A class for embedding information about care provider and system name into an
 * ID card.
 *
 * @author kkj
 * @author $LastChangedBy: chg@lakeside.dk $
 * @since 1.0
 */
public class SystemInfo implements Serializable {

	private static final long serialVersionUID = -6798815792767831734L;

	private final CareProvider careProvider;
	private final String itSystemName;

	/**
	 * @param itSystemName
	 *            A human readable name of the IT system that is constructing
	 *            this ID card.
	 * @param careProvider
	 *            The organizational unit that the user is acting on behalf of
	 */
	public SystemInfo(CareProvider careProvider, String itSystemName) {
		ModelUtil.validateNotNull(careProvider, "Careprovider must be specified");
		ModelUtil.validateNotEmpty(itSystemName, "IT System Name must be specified");
		this.careProvider = careProvider;
		this.itSystemName = itSystemName;
	}

	/**
	 * Returns the organizational unit that the user is acting on behalf of.
	 */
	public CareProvider getCareProvider() {

		return careProvider;
	}

	/**
	 * Returns a human readable name of the IT system that is constructing a
	 * given ID card.
	 */
	public String getITSystemName() {

		return itSystemName;
	}

	// =============================
	// Overridden parts
	// =============================

	public boolean equals(Object obj) {

		return obj == this || obj != null && obj.getClass() == getClass() && obj.hashCode() == hashCode()
				&& itSystemName.equals(((SystemInfo) obj).getITSystemName()) && careProvider.equals(((SystemInfo) obj).getCareProvider());
	}

	public int hashCode() {

		return itSystemName.hashCode() ^ careProvider.hashCode();
	}
}
