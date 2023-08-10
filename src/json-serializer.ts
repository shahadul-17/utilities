import { ObjectUtilities } from "./object-utilities";

const DEFAULT_JSON = "{}";

type SerializationOptions = {
  shallDeepSanitize?: boolean,
  spaces?: number,
  propertiesToRename?: Record<string, string>,
  propertiesToRemove?: Array<string>,
};

export class JsonSerializer {

  public static serialize(value: any, options?: SerializationOptions): string {
    const sanitizedValue = ObjectUtilities.sanitize({
      data: value,
      shallDeepSanitize: options?.shallDeepSanitize,
      propertiesToRemove: options?.propertiesToRemove,
      propertiesToRename: options?.propertiesToRename,
    });

    if (typeof sanitizedValue === "undefined" || sanitizedValue === null) { return DEFAULT_JSON; }

    return JSON.stringify(sanitizedValue, undefined, options?.spaces);
  }

  public static deserialize<Type>(json: string): Type {
    return JSON.parse(json);
  }
}
