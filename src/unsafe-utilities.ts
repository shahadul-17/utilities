import { InternalUtilities } from './internal-utilities';

type UnsafeFunction = (argument?: any) => any | Promise<any>;
type UnsafeExecutionErrorCallback = (error: Error) => void | Promise<void>;

type UnsafeExecutionOptions = {
  unsafeFunction: UnsafeFunction,
  unsafeFunctionArgument?: any,
  defaultValue?: any,
  errorCallback?: UnsafeExecutionErrorCallback,
};

export class UnsafeUtilities {

  public static executeUnsafe(options: UnsafeExecutionOptions): any {
    if (!InternalUtilities.isObject(options)) {
      console.warn('Unsafe execution options not provided.');

      return undefined;
    }

    if (typeof options!.unsafeFunction !== 'function') {
      console.warn('Invalid unsafe function provided.');

      return options!.defaultValue;
    }

    try {
      return options!.unsafeFunction(options!.unsafeFunctionArgument);
    } catch (error) {
      if (typeof options!.errorCallback === 'function') {
        try {
          options!.errorCallback(error as Error);
        } catch { }
      }
    }

    return options!.defaultValue;
  }

  public static async executeUnsafeAsync(options: UnsafeExecutionOptions): Promise<any> {
    if (!InternalUtilities.isObject(options)) {
      console.warn('Unsafe execution options not provided.');

      return undefined;
    }

    if (typeof options!.unsafeFunction !== 'function') {
      console.warn('Invalid unsafe function provided.');

      return options!.defaultValue;
    }

    try {
      return await options!.unsafeFunction(options!.unsafeFunctionArgument);
    } catch (error) {
      if (typeof options!.errorCallback === 'function') {
        try {
          await options!.errorCallback(error as Error);
        } catch { }
      }
    }

    return options!.defaultValue;
  }
}
