import { StringUtilities } from "./string-utilities";

const ARGUMENT_NAME_PREFIX = "--";

export class ArgumentsParser {

  private static readonly argumentsMap: Record<string, string>
    = this.populateArgumentsMap(process.argv);

  /**
   * Populates a map containing arguments.
   * @param args Arguments that shall be used to populate map.
   * @returns Returns a map containing arguments.
   */
  private static populateArgumentsMap(args: Array<string>): Record<string, string> {
    const argumentsMap: Record<string, string> = Object.create(null);

    for (let i = 2; i < args.length; ++i) {
      const argument = args[i];

      if (!argument.startsWith(ARGUMENT_NAME_PREFIX)) { continue; }

      ++i;    // i points to the next index...

      const argumentName = argument.substring(2);
      const argumentValue = args[i];        // next argument is the value...

      argumentsMap[argumentName] = argumentValue;
    }

    return argumentsMap;
  }

  /**
   * Retrieves command-line argument value by name.
   * @param argumentName Command-line argument name.
   * @returns Command-line argument value.
   */
  public static getArgument(argumentName: string): string {
    return StringUtilities.getDefaultIfUndefinedOrNull(this.argumentsMap[argumentName]);
  }
}
