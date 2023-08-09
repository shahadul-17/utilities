import { StringUtilities } from "./string-utilities";

export class NumberUtilities {

  /**
   * Checks if a value is of number type.
   * @param value Value that needs to be checked.
   * @returns True if the value is of type number. Otherwise false.
   */
  public static isNumber(value: any): boolean {
    return typeof value === "number" && !isNaN(value);
  }

  /**
   * Checks if a value is a positive number.
   * @param value Value that needs to be checked.
   * @returns True if the value is a positive number. Otherwise false.
   */
  public static isPositiveNumber(value: any): boolean {
    return this.isNumber(value) && value > 0;
  }

  /**
   * Checks if a value is a negative number.
   * @param value Value that needs to be checked.
   * @returns True if the value is a negative number. Otherwise false.
   */
  public static isNegativeNumber(value: any): boolean {
    return this.isNumber(value) && value < 0;
  }

  /**
   * Checks if a value is not zero.
   * @param value Value that needs to be checked.
   * @returns True if the value is not zero. Otherwise false.
   */
  public static isNonZeroNumber(value: any): boolean {
    return this.isNumber(value) && value !== 0;
  }

  /**
   * This method ensures that any given value is atleast double digit.
   * It adds a leading zero if the provided value is single digit.
   * @param value Value that needs to be double digit.
   * @returns Double digit number.
   */
  public static ensureDoubleDigit(value: any): string {
    let valueAsNumber: number = 0;

    // checks if the value is of type string...
    if (StringUtilities.isString(value)) {
      valueAsNumber = Number(value);

      // if the value is not actually a number, we'll return a default value...
      if (!this.isNumber(valueAsNumber)) { return '00'; }
    }
    // checks if the value is actually a number...
    else if (this.isNumber(value)) {
      valueAsNumber = value as number;
    }
    // otherwise, if the value is not actually a number, we'll return a default value...
    else { return '00'; }

    const isNegativeNumber = this.isNegativeNumber(valueAsNumber);

    // if the number is negative, we shall make it positive before any operation is performed...
    if (isNegativeNumber) { valueAsNumber = -valueAsNumber; }

    // if the value is less than 10, we shall add a leading zero...
    let doubleDigitValue: string = valueAsNumber < 10
      ? `0${valueAsNumber}` : `${valueAsNumber}`;

    // if the value was initially negative, we shall add the negative sign...
    if (isNegativeNumber) { doubleDigitValue = `-${doubleDigitValue}` }

    return doubleDigitValue;
  }
}
