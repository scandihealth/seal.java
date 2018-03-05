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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/CareProvider.java $
 * $Id: CareProvider.java 10349 2012-10-19 08:38:16Z ChristianGasser $
 */
package dk.sosi.seal.model;

import dk.sosi.seal.model.constants.SubjectIdentifierTypeValues;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

/**
 * A immutable dataholder for a "care provider", i.e. a organizational unit on
 * which health professionals are acting on behalf of. The care provider can be
 * identified in various ways, e.g. by a "yder nummer" or a "CVR number". How
 * the care provider is identified is passed as a "type code" in the
 * constructor. Valid types can be found as constants in this class.
 *
 * @author Jan Riis
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
public class CareProvider  implements Serializable {

	private static final long serialVersionUID = 633787373809073569L;

	private static final Set<String> allowedTypes;

	private final String type;
	private final String id;
	private final String orgName;

	static {
		allowedTypes = new HashSet<String>();
		allowedTypes.add(SubjectIdentifierTypeValues.CVR_NUMBER);
		allowedTypes.add(SubjectIdentifierTypeValues.SKS_CODE);
		allowedTypes.add(SubjectIdentifierTypeValues.Y_NUMBER);
		allowedTypes.add(SubjectIdentifierTypeValues.P_NUMBER);
	}

	/**
	 * Constructs a <code>Careprovider</code> instance.
	 *
	 * @param type
	 *            Type of identication of the care provider.
	 * @param id
	 *            The id of the care provider (e.g. "25450442" for a cvr number)
	 * @param orgName
	 *            A human readable name of the care provider organization.
	 */
	public CareProvider(String type, String id, String orgName) {
		super();
		ModelUtil.validateNotEmpty(type, "Type must be specified for care provider");
		if (! allowedTypes.contains(type)) {
			throw new ModelException("Type must be one of: " + allowedTypes);
		}
		ModelUtil.validateNotEmpty(id, "Id must be specified for care provider");
		ModelUtil.validateNotEmpty(orgName, "Organization Name must be specified for care provider");
		this.type = type;
		this.id = id;
		this.orgName = orgName;
	}

	/**
	 * Returns the type of identification. See constants on this class.
	 */
	public String getType() {

		return type;
	}

	/**
	 * Returns the ID.
	 */
	public String getID() {

		return id;
	}

	/**
	 * Returns a huan readable name for the oorganization.
	 */
	public String getOrgName() {

		return orgName;
	}

	// ====================================
	// Overridden methods
	// ====================================

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	public boolean equals(Object obj) {

		boolean result = obj == this || obj != null && obj.getClass() == getClass() && obj.hashCode() == hashCode();

		CareProvider other = (CareProvider) obj;
		return result && id.equals(other.getID()) && orgName.equals(other.getOrgName()) && type.equals(other.getType());
	}

	/**
	 * @see java.lang.Object#hashCode()
	 */
	public int hashCode() {

		return id.hashCode() ^ orgName.hashCode() ^ type.hashCode();
	}

}
