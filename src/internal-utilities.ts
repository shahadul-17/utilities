export class InternalUtilities {

  /**
   * Checks if provided value is actually an object.
   * @param value Value that shall be checked.
   * @returns True if the value is an object. Otherwise returns false.
   */
  public static isObject(value: any): boolean {
    return typeof value === "object" && value !== null && !Array.isArray(value);
  }
}
