import { StringUtilities } from "./string-utilities";

type SanitizationOptions = {
  data: any,
  shallDeepSanitize?: boolean,
  propertiesToRename?: Record<string, string>,
  propertiesToRemove?: Array<string>,
};

type CloningOptions = {
  data: any,
  shallDeepSanitize?: boolean,
  propertiesToRename?: Record<string, string>,
  propertiesToRemove?: Array<string>,
};

export class ObjectUtilities {

  /**
   * Checks if provided value is actually an object.
   * @param value Value that shall be checked.
   * @returns True if the value is an object. Otherwise returns false.
   */
  public static isObject(value: any): boolean {
    return typeof value === "object" && value !== null && !Array.isArray(value);
  }

  private static sanitizeObject(options: SanitizationOptions): any {
    let sanitizedData: Record<string, any> = Object.create(null);
    const propertyNames = Object.getOwnPropertyNames(options.data);

    if (propertyNames.length === 0) { return sanitizedData; }

    // prepares sanitized data object...
    for (const propertyName of propertyNames) {
      let propertyValue = options.data[propertyName];

      if (options.shallDeepSanitize === true) {
        propertyValue = this.sanitize({
          data: propertyValue,
          shallDeepSanitize: options.shallDeepSanitize,
          propertiesToRename: options.propertiesToRename,
          propertiesToRemove: options.propertiesToRemove,
        });
      }

      sanitizedData[propertyName] = propertyValue;
    }

    sanitizedData = this.removeProperties(sanitizedData, options.propertiesToRemove);
    sanitizedData = this.renameProperties(sanitizedData, options.propertiesToRename);

    return sanitizedData;
  }

  public static sanitizeObjects(options: SanitizationOptions) {
    const temporaryOptions: SanitizationOptions = {
      data: undefined,
      shallDeepSanitize: options.shallDeepSanitize,
      propertiesToRemove: options.propertiesToRemove,
      propertiesToRename: options.propertiesToRename,
    };
    const sanitizedObjects = new Array(options.data.length);

    for (let i = 0; i < options.data.length; ++i) {
      // changing the data on each iteration...
      temporaryOptions.data = options.data[i];
      // cloning the object...
      sanitizedObjects[i] = this.sanitize(temporaryOptions);
    }

    return sanitizedObjects;
  }

  public static sanitize(options: SanitizationOptions): any {
    if (!this.isObject(options)) { return options.data; }
    if (Array.isArray(options.data)) { return this.sanitizeObjects(options); }
    if (this.isObject(options.data)) { return this.sanitizeObject(options); }

    return options.data;
  }

  private static cloneObject(options: CloningOptions): any {
    const dataAsJson = JSON.stringify(options.data);
    let clonedObject = JSON.parse(dataAsJson);
    clonedObject = this.removeProperties(clonedObject, options.propertiesToRemove);
    clonedObject = this.renameProperties(clonedObject, options.propertiesToRename);

    return clonedObject;
  }

  private static cloneObjects(options: CloningOptions): any {
    const temporaryOptions: CloningOptions = {
      data: undefined,
      propertiesToRemove: options.propertiesToRemove,
      propertiesToRename: options.propertiesToRename,
    };
    const clonedObjects = new Array(options.data.length);

    for (let i = 0; i < options.data.length; ++i) {
      // changing the data on each iteration...
      temporaryOptions.data = options.data[i];
      // cloning the object...
      clonedObjects[i] = this.clone(temporaryOptions);
    }

    return clonedObjects;
  }

  public static clone(options: CloningOptions): any {
    if (!this.isObject(options)) { return options.data; }

    // performs data sanitization before cloning...
    options.data = this.sanitize({
      data: options.data,
      shallDeepSanitize: options.shallDeepSanitize,
    });

    if (Array.isArray(options.data)) { return this.cloneObjects(options); }
    if (this.isObject(options.data)) { return this.cloneObject(options); }

    return options.data;
  }

  public static removeProperties(value: any,
    propertiesToRemove: undefined | Array<string>): any {
    if (!this.isObject(value) || !Array.isArray(propertiesToRemove) || !propertiesToRemove.length) { return value; }

    const propertyNames = Object.keys(value);
    const propertyNameCount = propertyNames.length;

    for (let i = 0; i < propertyNameCount; ++i) {
      const propertyName = propertyNames[i];

      // if property needs to be removed...
      if (propertiesToRemove.includes(propertyName)) {
        delete value[propertyName];
      }
    }

    return value;
  }

  public static renameProperties(value: any,
    propertiesToRename: undefined | Record<string, string>): any {
    if (!this.isObject(value) || !this.isObject(propertiesToRename)) { return value; }

    const propertyNames = Object.keys(value);
    const propertyNameCount = propertyNames.length;

    for (let i = 0; i < propertyNameCount; ++i) {
      const propertyName = propertyNames[i];
      const propertyValue = value[propertyName];

      let newPropertyName = propertiesToRename![propertyName];
      newPropertyName = StringUtilities.getDefaultIfUndefinedOrNullOrEmpty(
        newPropertyName, StringUtilities.getEmptyString(), true);

      if (StringUtilities.isEmpty(newPropertyName)) { continue; }

      // if the new property name is not empty, it means the field needs to be renamed...
      value[newPropertyName] = propertyValue;
      // deletes the previous property...
      delete value[propertyName];
    }

    return value;
  }
}
