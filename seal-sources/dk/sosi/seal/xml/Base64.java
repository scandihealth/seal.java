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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/xml/Base64.java $
 * $Id: Base64.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */

package dk.sosi.seal.xml;

/**
 * This class provides encode/decode for RFC 2045 Base64 as defined by RFC 2045,
 * N. Freed and N. Borenstein. RFC 2045: Multipurpose Internet Mail Extensions
 * (MIME) Part One: Format of Internet Message Bodies. Reference 1996 Available
 * at: http://www.ietf.org/rfc/rfc2045.txt This class is used by XML Schema
 * binary format validation
 * 
 * This implementation does not encode/decode streaming data. You need the data
 * that you will encode/decode already on a byte arrray.
 * 
 * @author Jeffrey Rodriguez
 * @author Sandy Gao
 * @version $Id: Base64.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
@Deprecated
public final class Base64 { //NOPMD

	static private final int BASELENGTH = 128;

	static private final int LOOKUPLENGTH = 64;

	static private final int TWENTYFOURBITGROUP = 24;

	static private final int EIGHTBIT = 8;

	static private final int SIXTEENBIT = 16;

	static private final int FOURBYTE = 4;

	static private final int SIGN = -128;

	static private final char PAD = '=';

	static final private byte[] base64Alphabet = new byte[BASELENGTH];

	static final private char[] lookUpBase64Alphabet = new char[LOOKUPLENGTH];

	static {

		for (int i = 0; i < BASELENGTH; ++i) {
			base64Alphabet[i] = -1;
		}
		for (int i = 'Z'; i >= 'A'; i--) {
			base64Alphabet[i] = (byte) (i - 'A');
		}
		for (int i = 'z'; i >= 'a'; i--) {
			base64Alphabet[i] = (byte) (i - 'a' + 26);
		}

		for (int i = '9'; i >= '0'; i--) {
			base64Alphabet[i] = (byte) (i - '0' + 52);
		}

		base64Alphabet['+'] = 62;
		base64Alphabet['/'] = 63;

		for (int i = 0; i <= 25; i++)
			lookUpBase64Alphabet[i] = (char) ('A' + i);

		for (int i = 26, j = 0; i <= 51; i++, j++)
			lookUpBase64Alphabet[i] = (char) ('a' + j);

		for (int i = 52, j = 0; i <= 61; i++, j++)
			lookUpBase64Alphabet[i] = (char) ('0' + j);
		lookUpBase64Alphabet[62] = '+';
		lookUpBase64Alphabet[63] = '/';

	}

	private static boolean isWhiteSpace(char octect) {
		return (octect == 0x20 || octect == 0xd || octect == 0xa || octect == 0x9);
	}

	private static boolean isPad(char octect) {
		return (octect == PAD);
	}

	private static boolean isData(char octect) {
		return (octect < BASELENGTH && base64Alphabet[octect] != -1);
	}

	/**
	 * Encodes hex octects into Base64
	 * 
	 * @param binaryData
	 *            Array containing binaryData
	 * @return Encoded Base64 array
	 */
	public static String encode(byte[] binaryData) {
		if (binaryData == null || binaryData.length == 0)
			return null;

		int lengthDataBits = binaryData.length * EIGHTBIT;
		int fewerThan24bits = lengthDataBits % TWENTYFOURBITGROUP;
		int numberTriplets = lengthDataBits / TWENTYFOURBITGROUP;
		int numberQuartet = fewerThan24bits != 0 ? numberTriplets + 1
				: numberTriplets;
		char encodedData[] = null;

		encodedData = new char[numberQuartet * 4];

		byte k = 0, l = 0, b1 = 0, b2 = 0, b3 = 0;

		int encodedIndex = 0;
		int dataIndex = 0;

		for (int i = 0; i < numberTriplets; i++) {
			b1 = binaryData[dataIndex++];
			b2 = binaryData[dataIndex++];
			b3 = binaryData[dataIndex++];

			l = (byte) (b2 & 0x0f);
			k = (byte) (b1 & 0x03);

			byte val1 = ((b1 & SIGN) == 0) ? (byte) (b1 >> 2)
					: (byte) ((b1) >> 2 ^ 0xc0);

			byte val2 = ((b2 & SIGN) == 0) ? (byte) (b2 >> 4)
					: (byte) ((b2) >> 4 ^ 0xf0);
			byte val3 = ((b3 & SIGN) == 0) ? (byte) (b3 >> 6)
					: (byte) ((b3) >> 6 ^ 0xfc);

			encodedData[encodedIndex++] = lookUpBase64Alphabet[val1];
			encodedData[encodedIndex++] = lookUpBase64Alphabet[val2 | (k << 4)];
			encodedData[encodedIndex++] = lookUpBase64Alphabet[(l << 2) | val3];
			encodedData[encodedIndex++] = lookUpBase64Alphabet[b3 & 0x3f];
		}

		// form integral number of 6-bit groups
		if (fewerThan24bits == EIGHTBIT) {
			b1 = binaryData[dataIndex];
			k = (byte) (b1 & 0x03);
			byte val1 = ((b1 & SIGN) == 0) ? (byte) (b1 >> 2)
					: (byte) ((b1) >> 2 ^ 0xc0);
			encodedData[encodedIndex++] = lookUpBase64Alphabet[val1];
			encodedData[encodedIndex++] = lookUpBase64Alphabet[k << 4];
			encodedData[encodedIndex++] = PAD;
			encodedData[encodedIndex++] = PAD;
		} else if (fewerThan24bits == SIXTEENBIT) {
			b1 = binaryData[dataIndex];
			b2 = binaryData[dataIndex + 1];
			l = (byte) (b2 & 0x0f);
			k = (byte) (b1 & 0x03);

			byte val1 = ((b1 & SIGN) == 0) ? (byte) (b1 >> 2)
					: (byte) ((b1) >> 2 ^ 0xc0);
			byte val2 = ((b2 & SIGN) == 0) ? (byte) (b2 >> 4)
					: (byte) ((b2) >> 4 ^ 0xf0);

			encodedData[encodedIndex++] = lookUpBase64Alphabet[val1];
			encodedData[encodedIndex++] = lookUpBase64Alphabet[val2 | (k << 4)];
			encodedData[encodedIndex++] = lookUpBase64Alphabet[l << 2];
			encodedData[encodedIndex++] = PAD;
		}

		return new String(encodedData);
	}

	/**
	 * Decodes Base64 data into octects
	 * 
	 * @param encoded
	 *            string containing Base64 data
	 * @return Array containind decoded data.
	 */
	public static byte[] decode(String encoded) {

		if (encoded == null)
			return null;

		char[] base64Data = encoded.toCharArray();
		// remove white spaces
		int len = removeWhiteSpace(base64Data);

		if (len % FOURBYTE != 0) {
			return null;// should be divisible by four
		}

		int numberQuadruple = (len / FOURBYTE);

		if (numberQuadruple == 0)
			return new byte[0];

		byte decodedData[] = null;
		byte b1 = 0, b2 = 0, b3 = 0, b4 = 0;
		char d1 = 0, d2 = 0, d3 = 0, d4 = 0;

		int i = 0;
		int encodedIndex = 0;
		int dataIndex = 0;
		decodedData = new byte[(numberQuadruple) * 3];

		for (; i < numberQuadruple - 1; i++) {

			if (!isData((d1 = base64Data[dataIndex++]))
					|| !isData((d2 = base64Data[dataIndex++]))
					|| !isData((d3 = base64Data[dataIndex++]))
					|| !isData((d4 = base64Data[dataIndex++])))
				return null;// if found "no data" just return null

			b1 = base64Alphabet[d1];
			b2 = base64Alphabet[d2];
			b3 = base64Alphabet[d3];
			b4 = base64Alphabet[d4];

			decodedData[encodedIndex++] = (byte) (b1 << 2 | b2 >> 4);
			decodedData[encodedIndex++] = (byte) (((b2 & 0xf) << 4) | ((b3 >> 2) & 0xf));
			decodedData[encodedIndex++] = (byte) (b3 << 6 | b4);
		}

		if (!isData((d1 = base64Data[dataIndex++]))
				|| !isData((d2 = base64Data[dataIndex++]))) {
			return null;// if found "no data" just return null
		}

		b1 = base64Alphabet[d1];
		b2 = base64Alphabet[d2];

		d3 = base64Data[dataIndex++];
		d4 = base64Data[dataIndex++];
		if (!isData((d3)) || !isData((d4))) {// Check if they are PAD
												// characters
			if (isPad(d3) && isPad(d4)) { // Two PAD e.g. 3c[Pad][Pad]
				if ((b2 & 0xf) != 0)// last 4 bits should be zero
					return null;
				byte[] tmp = new byte[i * 3 + 1];
				System.arraycopy(decodedData, 0, tmp, 0, i * 3);
				tmp[encodedIndex] = (byte) (b1 << 2 | b2 >> 4);
				return tmp;
			} else if (!isPad(d3) && isPad(d4)) { // One PAD e.g. 3cQ[Pad]
				b3 = base64Alphabet[d3];
				if ((b3 & 0x3) != 0)// last 2 bits should be zero
					return null;
				byte[] tmp = new byte[i * 3 + 2];
				System.arraycopy(decodedData, 0, tmp, 0, i * 3);
				tmp[encodedIndex++] = (byte) (b1 << 2 | b2 >> 4);
				tmp[encodedIndex] = (byte) (((b2 & 0xf) << 4) | ((b3 >> 2) & 0xf));
				return tmp;
			} else {
				return null;// an error like "3c[Pad]r", "3cdX", "3cXd", "3cXX"
							// where X is non data
			}
		}

		// No PAD e.g 3cQl
		b3 = base64Alphabet[d3];
		b4 = base64Alphabet[d4];
		decodedData[encodedIndex++] = (byte) (b1 << 2 | b2 >> 4);
		decodedData[encodedIndex++] = (byte) (((b2 & 0xf) << 4) | ((b3 >> 2) & 0xf));
		decodedData[encodedIndex++] = (byte) (b3 << 6 | b4);

		return decodedData;
	}

	/**
	 * remove WhiteSpace from MIME containing encoded Base64 data.
	 * 
	 * @param data
	 *            the byte array of base64 data (with WS)
	 * @return the new length
	 */
	private static int removeWhiteSpace(char[] data) {
		// count characters that's not whitespace
		int newSize = 0;
		int len = data.length;
		for (int i = 0; i < len; i++) {
			if (!isWhiteSpace(data[i]))
				data[newSize++] = data[i];
		}
		return newSize;
	}
}
