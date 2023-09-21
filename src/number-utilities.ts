import { StringUtilities } from "./string-utilities";

export class NumberUtilities {

  /**
   * Checks if a value is of number type.
   * @param value Value that needs to be checked.
   * @returns True if the value is of type number. Otherwise false.
   */
  public static isNumber(value: any): boolean {
    // if the type of the value is any of the following types,
    // we shall return false...
    if (["undefined", "boolean", "symbol", "object", "function"].includes(typeof value)) {
      return false;
    }

    // if the type of the value is string or big integer,
    // we shall convert the value to a number...
    if (StringUtilities.isString(value) || typeof value === "bigint") {
      value = Number(value);
    }

    return !isNaN(value);
  }

  public static getIntegerOrDefault(value: any, defaultValue: any = undefined): any {
    const valueAsNumber = this.getNumberOrDefault(value, defaultValue);

    if (valueAsNumber === defaultValue) { return defaultValue; }

    return parseInt(valueAsNumber);
  }

  public static getNumberOrDefault(value: any, defaultValue: any = undefined): any {
    // if the value is not a number, returns the default value...
    if (!this.isNumber(value)) { return defaultValue; }

    // otherwise, we shall convert the value to number and return that...
    return Number(value);
  }

  /**
   * Checks if a value is a positive number.
   * @param value Value that needs to be checked.
   * @returns True if the value is a positive number. Otherwise false.
   */
  public static isPositiveNumber(value: any): boolean {
    const valueAsNumber = this.getNumberOrDefault(value, undefined);

    if (typeof valueAsNumber === 'undefined') { return false; }

    return valueAsNumber > 0;
  }

  /**
   * Checks if a value is a negative number.
   * @param value Value that needs to be checked.
   * @returns True if the value is a negative number. Otherwise false.
   */
  public static isNegativeNumber(value: any): boolean {
    const valueAsNumber = this.getNumberOrDefault(value, undefined);

    if (typeof valueAsNumber === 'undefined') { return false; }

    return valueAsNumber < 0;
  }

  /**
   * Checks if a value is not zero.
   * @param value Value that needs to be checked.
   * @returns True if the value is not zero. Otherwise false.
   */
  public static isNonZeroNumber(value: any): boolean {
    const valueAsNumber = this.getNumberOrDefault(value, undefined);

    if (typeof valueAsNumber === 'undefined') { return false; }

    return valueAsNumber !== 0;
  }

  /**
   * This method ensures that any given value is atleast double digit.
   * It adds a leading zero if the provided value is single digit.
   * @param value Value that needs to be double digit.
   * @returns Double digit number.
   */
  public static ensureDoubleDigit(value: any): string {
    // gets the value as number if it is actually a number.
    // otherwise, returns undefined...
    let valueAsNumber = this.getNumberOrDefault(value, undefined);

    // if value (as number) is undefined, we'll return a default value...
    if (typeof valueAsNumber === 'undefined') { return '00'; }

    const isNegativeNumber = this.isNegativeNumber(valueAsNumber);

    // if the number is negative, we shall make it positive before any operation is performed...
    if (isNegativeNumber) { valueAsNumber = -valueAsNumber; }

    // if the value is less than 10, we shall add a leading zero...
    let doubleDigitValue = valueAsNumber < 10
      ? `0${valueAsNumber}` : `${valueAsNumber}`;

    // if the value was initially negative, we shall add the negative sign...
    if (isNegativeNumber) { doubleDigitValue = `-${doubleDigitValue}` }

    return doubleDigitValue;
  }
}
