import { ObjectUtilities } from './object-utilities';

type UnsafeFunction = (argument?: any) => any | Promise<any>;

type UnsafeExecutionOptions = {
  unsafeFunction: UnsafeFunction,
  unsafeFunctionArgument?: any,
  defaultValue?: any,
};

export class UnsafeUtilities {

  public static executeUnsafe(options: UnsafeExecutionOptions): any {
    if (!ObjectUtilities.isObject(options)) {
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
      console.error('An error occurred while executing the unsafe function.', error);
    }

    return options!.defaultValue;
  }

  public static async executeUnsafeAsync(options: UnsafeExecutionOptions): Promise<any> {
    if (!ObjectUtilities.isObject(options)) {
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
      console.error('An error occurred while executing the unsafe function.', error);
    }

    return options!.defaultValue;
  }
}
