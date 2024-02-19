import { UnsafeUtilities } from './unsafe-utilities';

const EMPTY_STRING = "";
const DEFAULT_SEPARATOR = ",";
const TEXT_ENCODER = UnsafeUtilities.executeUnsafe({
  unsafeFunction: () => new TextEncoder(),
});
const TEXT_DECODER = UnsafeUtilities.executeUnsafe({
  unsafeFunction: () => new TextDecoder(),
});

export class StringUtilities {

  /**
   * This method provides an empty string.
   * @returns An empty string.
   */
  public static getEmptyString(): string {
    return EMPTY_STRING;
  }

  /**
   * Checks if a text is of string type.
   * @param text Text that needs to be checked.
   * @returns True if the text is of type string. Otherwise false.
   */
  public static isString(text: any): boolean {
    return typeof text === "string";
  }

  /**
   * Checks if a text is empty.
   * @param text Text that needs to be checked.
   * @returns True if the text is empty. Otherwise false.
   */
  public static isEmpty(text: any): boolean {
    // anything other than string is also considered as empty string...
    return this.getEmptyString() === text || !this.isString(text);
  }

  /**
   * Checks if a text is 'undefined' or 'null'.
   * @param text Text that needs to be checked.
   * @returns True if the text is 'undefined' or 'null'. Otherwise false.
   */
  public static isUndefinedOrNull(text: any): boolean {
    // anything other than string is also considered as undefined...
    return text === undefined || text === null || !this.isString(text);
  }

  /**
   * Checks if a text is 'undefined', 'null' or an empty string.
   * @param text Text that needs to be checked.
   * @param shallTrim If true, text will be trimmed before length is checked. Default value is 'false'.
   * @returns True if the text is 'undefined', 'null' or an empty string. Otherwise returns false.
   */
  public static isUndefinedOrNullOrEmpty(text: any, shallTrim = false) {
    if (this.isUndefinedOrNull(text)) { return true; }
    if (shallTrim) { text = text.trim(); }

    return this.isEmpty(text);
  }

  /**
   * Returns default value if the text is 'undefined' or 'null'. Otherwise,
   * returns the original text.
   * @param text Text that needs to be checked.
   * @param defaultValue Default value that shall be returned if the text is 'undefined' or 'null'.
   * @returns Default value if text is 'undefined' or 'null'. Otherwise, returns the
   * original text.
   */
  public static getDefaultIfUndefinedOrNull(text: any, defaultValue: any = EMPTY_STRING): any {
    return this.isUndefinedOrNull(text) ? defaultValue : text;
  }

  /**
   * Returns default value if the text is 'undefined', 'null' or an empty string.
   * Otherwise, returns the original text.
   * @param text Text that needs to be checked.
   * @param defaultValue Default value that shall be returned if the text is 'undefined', 'null' or an empty string.
   * @param shallTrim If true, text will be trimmed before length is checked. Default value is 'false'.
   * @returns Default value if text is 'undefined', 'null' or an empty string. Otherwise, returns the
   * original text. The original text is trimmed if 'shallTrim' is set to true.
   */
  public static getDefaultIfUndefinedOrNullOrEmpty(text: any, defaultValue: any = EMPTY_STRING, shallTrim = false): any {
    if (this.isUndefinedOrNullOrEmpty(text, shallTrim)) { return defaultValue; }
    if (shallTrim) { text = text.trim(); }

    return text;
  }

  /**
   * Converts comma separated string value to an array of strings.
   * @param csv The comma (or any separator) separated string value
   * that shall be converted to an array of strings.
   * @param separator Separator to be used for string separation.
   * @returns An array containing string values.
   */
  public static toArrayFromCsv(csv: string, separator = DEFAULT_SEPARATOR): Array<string> {
    csv = this.getDefaultIfUndefinedOrNullOrEmpty(csv, this.getEmptyString(), true);

    if (this.isEmpty(csv)) { return []; }

    const splittedText = csv.split(separator);

    for (let i = 0; i < splittedText.length; ++i) {
      splittedText[i] = this.getDefaultIfUndefinedOrNullOrEmpty(splittedText[i], this.getEmptyString(), true);
    }

    return splittedText;
  }

  /**
   * Checks if a character is upper case.
   * @param character Character to be checked.
   * @returns Returns true if the character is upper case.
   * Otherwise returns false.
   */
  public static isUpperCaseCharacter(character: string): boolean {
    const characterCode = character.charCodeAt(0);

    return characterCode > 64 && characterCode < 91;
  }

  /**
   * Checks if a character is lower case.
   * @param character Character to be checked.
   * @returns Returns true if the character is lower case.
   * Otherwise returns false.
   */
  public static isLowerCaseCharacter(character: string): boolean {
    const characterCode = character.charCodeAt(0);

    return characterCode > 96 && characterCode < 123;
  }

  /**
   * Performs a very basic check to determine if the specified text is JSON.
   * @param text Text to be checked.
   * @returns Returns true if the text is JSON. Otherwise returns false.
   */
  public static isJson(text: string): boolean {
    const firstCharacter = text.charAt(0);
    const lastCharacter = text.charAt(text.length - 1);
    const isJson = (firstCharacter === '{' && lastCharacter === '}')
      || (firstCharacter === '[' && lastCharacter === ']');

    return isJson;
  }

  /**
   * Encodes a string into a sequence of bytes.
   * Note: This method returns undefined if TextEncoder
   * is not supported by the runtime environment.
   * @param text Text to encode.
   * @returns The resultant byte array.
   */
  public static getBytes(text: string): undefined | Uint8Array {
    // if text encoder is not supported...
    if (typeof TEXT_ENCODER === 'undefined') {
      // we shall return undefined...
      return undefined;
    }

    return TEXT_ENCODER.encode(text);
  }

  /**
   * Decodes a sequence of bytes into a string.
   * Note: This method returns an empty string if TextDecoder
   * is not supported by the runtime environment.
   * @param bytes Bytes to decode.
   * @returns The resultant string.
   */
  public static fromBytes(bytes: Uint8Array): string {
    // if text decoder is not supported...
    if (typeof TEXT_DECODER === 'undefined') {
      // we shall return an empty string...
      return this.getEmptyString();
    }

    return TEXT_DECODER.decode(bytes);
  }

  /**
   * Retrieves the number of bytes in a string.
   * Note: This method returns zero (0) if TextEncoder
   * is not supported by the runtime environment.
   * @param text Text to retrieve byte length.
   * @returns The length of the string in bytes.
   */
  public static getByteLength(text: string): number {
    const bytes = this.getBytes(text);

    return typeof bytes === 'undefined' ? 0 : bytes.byteLength;
  }

  /**
   * Truncates a string.
   * @param text Text to truncate.
   * @param length Truncated text length.
   * @returns The truncated text.
   */
  public static truncate(text: string, length: number): string {
    return text.substring(0, length);
  }

  /**
   * Truncates a string by byte length.
   * Note: This method returns the original text without truncating
   * if TextEncoder or TextDecoder is not supported by the runtime environment.
   * @param text Text to truncate.
   * @param byteLength Truncated text length in bytes.
   * @returns The truncated text.
   */
  public static truncateByByteLength(text: string, byteLength: number): string {
    const bytes = this.getBytes(text);

    if (typeof bytes === 'undefined') { return text; }

    const slicedByteArray = bytes.slice(0, byteLength);
    let truncatedString = this.fromBytes(slicedByteArray);

    if (this.isEmpty(truncatedString)) { return text; }

    // removing the last character to avoid corrupted character...
    truncatedString = truncatedString.substring(0, truncatedString.length - 1);

    return truncatedString;
  }
}
