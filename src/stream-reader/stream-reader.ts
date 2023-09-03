import { IStreamReader } from "./stream-reader.i";
import { JsonSerializer } from "../json-serializer";
import { StringUtilities } from "../string-utilities";

const DEFAULT_LINE_DELIMITER = "\n";
const DEFAULT_CONTENT_ENCODING = "utf-8";

export class StreamReader implements IStreamReader {

  private lineDelimiter: string = DEFAULT_LINE_DELIMITER;
  private content: string = StringUtilities.getEmptyString();

  getLineDelimiter(): string {
    return this.lineDelimiter;
  }

  setLineDelimiter(lineDelimiter: string): void {
    this.lineDelimiter = StringUtilities.getDefaultIfUndefinedOrNullOrEmpty(
      lineDelimiter, DEFAULT_LINE_DELIMITER, false);
  }

  append(chunk: string | Buffer, encoding?: BufferEncoding): void {
    let chunkAsString = StringUtilities.getEmptyString();

    if (chunk instanceof Buffer) {
      encoding = StringUtilities.getDefaultIfUndefinedOrNullOrEmpty(encoding, DEFAULT_CONTENT_ENCODING, true);
      chunkAsString = chunk.toString(encoding);
    } else if (StringUtilities.isString(chunk)) {
      chunkAsString = chunk;
    }

    if (StringUtilities.isEmpty(chunkAsString)) { return; }

    this.content += chunkAsString;
  }

  readLine(): string {
    const indexOfNewLine = this.content.indexOf(this.lineDelimiter);

    if (indexOfNewLine === -1) { return StringUtilities.getEmptyString(); }

    const line = this.content.substring(0, indexOfNewLine);
    this.content = this.content.substring(indexOfNewLine + this.lineDelimiter.length);

    return line;
  }

  readObject<Type>(): undefined | Type {
    let line = this.readLine();
    line = StringUtilities.getDefaultIfUndefinedOrNullOrEmpty(
      line, StringUtilities.getEmptyString(), true);

    if (StringUtilities.isEmpty(line) || !StringUtilities.isJson(line)) { return undefined; }

    try {
      return JsonSerializer.deserialize<Type>(line);
    } catch { return undefined; }
  }
}
