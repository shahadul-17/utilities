const EMPTY_STRING = "";
const DEFAULT_SEPARATOR = ",";

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
   * @returns True if the text is 'undefined' or 'null'. Otherwise false.
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
  public static isJson(text: string) {
    const firstCharacter = text.charAt(0);
    const lastCharacter = text.charAt(text.length - 1);
    const isJson = (firstCharacter === '{' && lastCharacter === '}')
      || (firstCharacter === '[' && lastCharacter === ']');

    return isJson;
  }
}
