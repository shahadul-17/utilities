import path from "path";
import fileSystem from "fs";
import asyncFileSystem from "fs/promises";
import { Stream } from "stream";

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

  public static exists(itemType: 'file' | 'directory' | 'any' = 'any',
    ...paths: Array<string>): boolean {
    const path = this.join(...paths);
    const doesExist = fileSystem.existsSync(path);

    // checks if item type is anything other than 'file' or 'directory'...
    if (!doesExist || !['file', 'directory'].includes(itemType)) { return doesExist; }

    let fileInformation;

    try {
      fileInformation = fileSystem.lstatSync(path);
    } catch (error) {
      console.warn(`An error occurred while collecting information for file, '${path}'.`, error);

      return false;
    }

    if (itemType === 'file') { return fileInformation.isFile(); }

    return fileInformation.isDirectory();
  }

  public static async createDirectoryIfDoesNotExistAsync(
    ...directoryPaths: Array<string>): Promise<void> {
    const directoryPath = this.join(...directoryPaths);

    if (this.exists('any', directoryPath)) { return; }

    await asyncFileSystem.mkdir(directoryPath, { recursive: true, });
  }

  public static async createFileAsync(...filePaths: Array<string>): Promise<void> {
    const filePath = this.join(...filePaths);

    if (this.exists('any', filePath)) { return; }

    await this.writeAsync('', false, filePath);
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
    fileName: string, replacementCharacter = '_'): string {
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

  public static async writeAsync(data: WritableData,
    shallOverwrite: boolean = false, ...filePaths: Array<string>): Promise<void> {
    const filePath = this.join(...filePaths);
    const directoryPath = this.extractDirectoryPath(filePath);

    // creates directory if does not exist...
    await this.createDirectoryIfDoesNotExistAsync(directoryPath);
    await asyncFileSystem.writeFile(filePath, data, { flag: shallOverwrite === true ? 'w' : 'a', });
  }
}
