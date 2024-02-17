import { IMap, Map, } from "@shahadul-17/collections";
import { StringUtilities } from "./string-utilities";
import { ObjectUtilities } from "./object-utilities";
import { UnsafeUtilities } from './unsafe-utilities';

const ARGUMENT_NAME_PREFIX = "--";

export class ArgumentsParser {

  private static readonly argumentsMap: IMap<string, string>
    = this.populateArgumentsMap(UnsafeUtilities.executeUnsafe({
      unsafeFunction: () => process.argv,
      defaultValue: [],
    }));

  /**
   * Populates a map containing arguments.
   * @param args Arguments that shall be used to populate map.
   * @returns Returns a map containing arguments.
   */
  private static populateArgumentsMap(args: Array<string>): IMap<string, string> {
    const argumentsMap: IMap<string, string> = new Map<string, string>();

    for (let i = 2; i < args.length; ++i) {
      const argument = args[i];

      if (!argument.startsWith(ARGUMENT_NAME_PREFIX)) { continue; }

      ++i;    // i points to the next index...

      const argumentName = argument.substring(2);
      const argumentValue = args[i];        // next argument is the value...

      argumentsMap.set(argumentName, argumentValue);
    }

    return argumentsMap;
  }

  /**
   * Retrieves command-line argument value by name.
   * @param argumentName Command-line argument name.
   * @param defaultValue Default value is returned if
   * the specified argument is not available.
   * @returns Command-line argument value.
   */
  public static getArgument(argumentName: string, defaultValue = StringUtilities.getEmptyString()): string {
    const argumentValue = this.argumentsMap.get(argumentName);

    return StringUtilities.getDefaultIfUndefinedOrNull(argumentValue, defaultValue);
  }

  public static toObject(): Record<string, string> {
    const entries = this.argumentsMap.entries();
    const argumentsAsObject: Record<string, string> = ObjectUtilities.getEmptyObject(true);

    for (const { key, value, } of entries) {
      argumentsAsObject[key] = value;
    }

    return argumentsAsObject;
  }

  public static toMap(): IMap<string, string> {
    const entries = this.argumentsMap.entries();
    const argumentsAsMap: IMap<string, string> = new Map<string, string>();

    for (const { key, value, } of entries) {
      argumentsAsMap.set(key, value);
    }

    return argumentsAsMap;
  }
}
