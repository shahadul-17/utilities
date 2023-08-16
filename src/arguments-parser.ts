import { IMap, Map, } from "@shahadul-17/collections";
import { StringUtilities } from "./string-utilities";

const ARGUMENT_NAME_PREFIX = "--";

export class ArgumentsParser {

  private static readonly argumentsMap: IMap<string, string>
    = this.populateArgumentsMap(process.argv);

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
   * @returns Command-line argument value.
   */
  public static getArgument(argumentName: string): string {
    const argumentValue = this.argumentsMap.get(argumentName);

    return StringUtilities.getDefaultIfUndefinedOrNull(argumentValue);
  }

  public static getArguments(): Record<string, string> {
    const entries = this.argumentsMap.entries();
    const _arguments: Record<string, string> = Object.create(null);

    for (const { key, value, } of entries) {
      _arguments[key] = value;
    }

    return _arguments;
  }
}
