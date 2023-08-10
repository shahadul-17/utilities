import path from "path";
import fileSystem from "fs";
import asyncFileSystem from "fs/promises";
import { Stream } from "stream";
import { JsonSerializer } from "./json-serializer";
import { ObjectUtilities } from "./object-utilities";
import { StringUtilities } from "./string-utilities";

const UNWANTED_FILE_NAME_CHARACTERS_PATTERN = "[/\\?%*:|\"<>!]";

type WritableData = string | Buffer | NodeJS.ArrayBufferView
  | Stream | Iterable<string | NodeJS.ArrayBufferView>
  | AsyncIterable<string | NodeJS.ArrayBufferView>;

export class FileUtilities {

  public static join(...paths: Array<string>): string {
    const joinedPath = path.join(...paths);
    const absolutePath = path.resolve(joinedPath);
    // cannot use this.extractDirectoryPath(absolutePath) because
    // join() method is used there...
    const directoryPath = path.dirname(absolutePath);
    const fileName = this.extractFileName(absolutePath);
    const sanitizedFileName = this.removeUnwantedFileNameCharacters(fileName);

    return path.join(directoryPath, sanitizedFileName);
  }

  public static toAbsolutePath(...paths: Array<string>): string {
    return this.join(...paths);
  }

  public static async deleteFileAsync(...filePaths: Array<string>): Promise<boolean> {
    const filePath = this.join(...filePaths);

    try {
      await asyncFileSystem.unlink(filePath);
    } catch (error) {
      console.warn(`An error occurred while deleting the file, '${filePath}'.`, error);

      return false;
    }

    return true;
  }

  public static exists(itemType: "symbolicLink" | "file" | "directory" | "any" = "any",
    ...paths: Array<string>): boolean {
    const path = this.join(...paths);
    const doesExist = fileSystem.existsSync(path);

    // checks if item type is anything other than "symbolicLink", "file" or "directory"...
    if (!doesExist || !["symbolicLink", "file", "directory"].includes(itemType)) { return doesExist; }

    let fileInformation;

    try {
      fileInformation = fileSystem.lstatSync(path);
    } catch (error) {
      console.warn(`An error occurred while collecting information for file, '${path}'.`, error);

      return false;
    }

    if (itemType === "symbolicLink") { return fileInformation.isSymbolicLink(); }
    if (itemType === "file") { return fileInformation.isFile(); }

    return fileInformation.isDirectory();
  }

  public static async getAllPathsAsync(
    itemType: "symbolicLink" | "file" | "directory" | "any" = "any",
    pattern?: string,
    shallPerformRecursiveSearch = false,
    ...directoryPaths: Array<string>): Promise<Array<string>> {
    const directoryPath = this.join(...directoryPaths);

    // if the directory path belongs to a file, we shall return an empty array...
    if (this.exists("file", directoryPath)) { return []; }

    pattern = StringUtilities.getDefaultIfUndefinedOrNullOrEmpty(pattern, StringUtilities.getEmptyString(), true);

    const regularExpression = StringUtilities.isEmpty(pattern) ? undefined : new RegExp(pattern!, "i");
    const paths = await asyncFileSystem.readdir(directoryPath);
    const filteredPaths: Array<string> = [];

    for (let i = 0; i < paths.length; ++i) {
      const path = this.join(directoryPath, paths[i]);

      // if a pattern is provided, we shall check if the path matches the pattern...
      if (typeof regularExpression !== "undefined" && !regularExpression.test(path)) { continue; }
      // if the item type is "file" but the path does not belong to a file, we shall continue...
      if (!this.exists(itemType, path)) { continue; }

      // otherwise, we shall add the path to the filtered paths...
      filteredPaths.push(path);

      // if we don't need to perform recursive search, we shall continue...
      if (shallPerformRecursiveSearch !== true) { continue; }

      // we shall perform recursive search...
      const subdirectoryPaths = await this.getAllPathsAsync(itemType, pattern, shallPerformRecursiveSearch, path);

      // adding all the subdirectory paths...
      filteredPaths.push(...subdirectoryPaths);
    }

    return filteredPaths;
  }

  public static async createDirectoryIfDoesNotExistAsync(
    ...directoryPaths: Array<string>): Promise<void> {
    const directoryPath = this.join(...directoryPaths);

    if (this.exists("any", directoryPath)) { return; }

    await asyncFileSystem.mkdir(directoryPath, { recursive: true, });
  }

  public static async createFileAsync(...filePaths: Array<string>): Promise<void> {
    const filePath = this.join(...filePaths);

    if (this.exists("any", filePath)) { return; }

    await this.writeAsync("", false, filePath);
  }

  public static extractDirectoryPath(...paths: Array<string>): string {
    const joinedPath = this.join(...paths);

    return path.dirname(joinedPath);
  }

  public static extractFileName(filePath: string, fileExtension?: string): string {
    return path.basename(filePath, fileExtension);
  }

  public static extractFileNameWithoutExtension(filePath: string): string {
    const fileExtension = this.extractExtension(filePath);
    const fileNameWithoutExtension = this.extractFileName(filePath, fileExtension);

    return fileNameWithoutExtension;
  }

  public static extractExtension(filePath: string): string {
    return path.extname(filePath);
  }

  /**
   * Removes unwanted characters from file name.
   * @param fileName File name to be sanitized.
   * @param replacementCharacter Placeholder character for unwanted characters. Default value is '_'.
   * @returns Sanitized file name that does not contain any unwanted characters.
   */
  public static removeUnwantedFileNameCharacters(
    fileName: string, replacementCharacter = "_"): string {
    const sanitizedPath = fileName
      .replace(new RegExp(UNWANTED_FILE_NAME_CHARACTERS_PATTERN, "g"), replacementCharacter)
      .replace(new RegExp(`${replacementCharacter}+`, "g"), replacementCharacter);

    return sanitizedPath;
  }

  public static async readAsync(...paths: Array<string>): Promise<Buffer> {
    const filePath = this.join(...paths);
    const buffer = await asyncFileSystem.readFile(filePath);

    return buffer;
  }

  public static async readTextAsync(encoding: BufferEncoding, ...paths: Array<string>): Promise<string> {
    const buffer = await this.readAsync(...paths);
    const text = buffer.toString(encoding);

    return text;
  }

  public static async readJsonAsync<Type>(encoding: BufferEncoding,
    ...paths: Array<string>): Promise<Type> {
    const jsonContent = await this.readTextAsync(encoding, ...paths);

    return JsonSerializer.deserialize<Type>(jsonContent);
  }

  public static async writeAsync(data: WritableData,
    shallOverwrite: boolean = false, ...filePaths: Array<string>): Promise<void> {
    const filePath = this.join(...filePaths);
    const directoryPath = this.extractDirectoryPath(filePath);

    // creates directory if does not exist...
    await this.createDirectoryIfDoesNotExistAsync(directoryPath);
    await asyncFileSystem.writeFile(filePath, data, { flag: shallOverwrite === true ? "w" : "a", });
  }

  public static async writeJsonAsync(data: any,
    shallOverwrite: boolean = false, ...filePaths: Array<string>): Promise<void> {
    // if the data is not an array nor an object...
    if (!Array.isArray(data) && !ObjectUtilities.isObject(data)) {
      data = ObjectUtilities.getEmptyObject(false);
    }

    const json = JsonSerializer.serialize(data);

    await this.writeAsync(json, shallOverwrite, ...filePaths);
  }
}
