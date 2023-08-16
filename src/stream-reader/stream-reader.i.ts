export interface IStreamReader {
  getLineDelimiter(): string;
  setLineDelimiter(lineDelimiter: string): void;
  append(chunk: string | Buffer, encoding?: BufferEncoding): void;
  readLine(): string;
  readObject<Type>(): undefined | Type;
}
