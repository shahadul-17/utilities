import cryptography from "crypto";
import { RandomGenerator } from "@shahadul-17/random-generator";
import { StringUtilities } from "./string-utilities";

const INTEGER_SIZE_IN_BYTES = 4;
const EMPTY_BUFFER = Buffer.from([]);

const DEFAULT_HASH_ENCODING = "base64url";
const DEFAULT_HASH_ALGORITHM = "SHA512";
const DEFAULT_KEYED_HASH_ENCODING = "base64url";
const DEFAULT_KEYED_HASH_ALGORITHM = "HMACSHA512";

const AES_SALT_LENGTH = 64;
const AES_KEY_LENGTH = 128;
const AES_SALT_ENCODING = "ascii";
const AES_AUTHENTICATION_TAG_LENGTH = 16;
const AES_ADDITIONAL_AUTHENTICATED_DATA_AS_STRING =
  "2591a4f1a5f006fb1b62bb2318f47c020c517131016256e0ef859e073d075338b02d5173614b94c66d04b9f0b7f3e96cb9afbbd6808c5ccecfe5fe95a822db42";
const AES_ADDITIONAL_AUTHENTICATED_DATA = Buffer.from(AES_ADDITIONAL_AUTHENTICATED_DATA_AS_STRING, "ascii");
const AES_KEY_AND_INITIALIZATION_VECTOR_DERIVATION_HASH_ENCODING = "hex";
const AES_KEY_AND_INITIALIZATION_VECTOR_DERIVATION_HASH_ALGORITHM = "SHA512";
const AES_KEY_AND_INITIALIZATION_VECTOR_DERIVED_DATA_ENCODING = "ascii";

const DEFAULT_HYBRID_ENCRYPTION_SYMMETRIC_KEY_ENCODING = "ascii";
const DEFAULT_HYBRID_ENCRYPTION_SYMMETRIC_KEYED_ENCRYPTION_ALGORITHM = "AESGCM256";
const DEFAULT_HYBRID_ENCRYPTION_ASYMMETRIC_KEYED_ENCRYPTION_ALGORITHM = "RSA4096";

const DEFAULT_PLAINTEXT_ENCRYPTION_ENCODING = "utf-8";
const DEFAULT_CIPHERTEXT_ENCRYPTION_ENCODING = "base64url";

type Encoding = "ascii" | "utf-8" | "hex" | "base16" | "base64" | "base64url";
type HashAlgorithm = "SHA160" | "SHA256" | "SHA384" | "SHA512";
type KeyedHashAlgorithm = "HMACSHA160" | "HMACSHA256" | "HMACSHA384" | "HMACSHA512";
type EncryptionAlgorithm = "AESCBC128" | "AESCBC192" | "AESCBC256"
  | "AESECB128" | "AESECB192" | "AESECB256"
  | "AESCCM128" | "AESCCM192" | "AESCCM256"
  | "AESGCM128" | "AESGCM192" | "AESGCM256"
  | "AESOCB128" | "AESOCB192" | "AESOCB256"
  | "AESCTR128" | "AESCTR192" | "AESCTR256"
  | "AESOFB128" | "AESOFB192" | "AESOFB256"
  | "RSA1024" | "RSA2048" | "RSA4096";
type DerivationResult = {
  key: Buffer,
  initializationVector: Buffer,
};
type EncryptionAlgorithmInformation = {
  isSymmetricKeyedEncryptionAlgorithm: boolean,
  shallSetAdditionalAuthenticatedData: boolean,
  algorithm: string,
  keyLengthInBytes: number,
  initializationVectorLengthInBytes: number,
};
type AsymmetricKeyPair = {
  publicKey: string,
  privateKey: string,
};

export class CryptographicUtilities {

  public static async computeHashAsync(message: string | Buffer, encoding?: null | Encoding,
    algorithm?: HashAlgorithm): Promise<string | Buffer> {
    // if the message is not an instance of Buffer class and
    // it is also not a string...
    if (!(message instanceof Buffer) && !StringUtilities.isString(message)) {
      // we shall set the empty string as message...
      message = StringUtilities.getEmptyString();
    }

    // NOTE: IF ENCODING IS NULL, WE SHALL RETURN THE RAW BUFFER...
    // BUT IF ENCODING IS UNDEFINED, WE SHALL USE THE DEFAULT ENCODING...
    const hashEncoding = await this.validateEncodingAsync(encoding, DEFAULT_HASH_ENCODING);
    const hashAlgorithm = await this.validateHashAlgorithmAsync(algorithm, DEFAULT_HASH_ALGORITHM);
    let hashGenerator = cryptography.createHash(hashAlgorithm);
    hashGenerator = hashGenerator.update(message);
    const hash = hashGenerator.digest();

    // if encoding is undefined, null or empty string, we shall return the raw buffer...
    if (StringUtilities.isUndefinedOrNullOrEmpty(hashEncoding, true)) { return hash; }

    // otherwise we shall perform appropriate encoding...
    return hash.toString(hashEncoding as any);
  }

  public static async isHashMatchedAsync(message: string, preComputedHash: string,
    encoding?: null | Encoding, algorithm?: HashAlgorithm): Promise<boolean> {
    const hash = await this.computeHashAsync(message, encoding, algorithm);

    return hash === preComputedHash;
  }

  public static async computeKeyedHashAsync(message: string | Buffer, key: string,
    encoding?: null | Encoding, algorithm?: KeyedHashAlgorithm): Promise<string | Buffer> {
    // if the message is not an instance of Buffer class and
    // it is also not a string...
    if (!(message instanceof Buffer) && !StringUtilities.isString(message)) {
      // we shall set the empty string as message...
      message = StringUtilities.getEmptyString();
    }

    // if key is not provided...
    if (!StringUtilities.isString(key)) {
      // we shall set empty string as the key...
      key = StringUtilities.getEmptyString();
    }

    // NOTE: IF ENCODING IS NULL, WE SHALL RETURN THE RAW BUFFER...
    // BUT IF ENCODING IS UNDEFINED, WE SHALL USE THE DEFAULT ENCODING...
    const hashEncoding = await this.validateEncodingAsync(encoding, DEFAULT_KEYED_HASH_ENCODING);
    const hashAlgorithm = await this.validateKeyedHashAlgorithmAsync(algorithm, DEFAULT_KEYED_HASH_ALGORITHM);
    let hashGenerator = cryptography.createHmac(hashAlgorithm, key);
    hashGenerator = hashGenerator.update(message);
    const hash = hashGenerator.digest();

    // if encoding is undefined, null or empty string, we shall return the raw buffer...
    if (StringUtilities.isUndefinedOrNullOrEmpty(hashEncoding, true)) { return hash; }

    // otherwise we shall perform appropriate encoding...
    return hash.toString(hashEncoding as any);
  }

  public static async isKeyedHashMatchedAsync(message: string, key: string,
    preComputedHash: string,
    encoding: Encoding = DEFAULT_KEYED_HASH_ENCODING,
    algorithm: KeyedHashAlgorithm = DEFAULT_KEYED_HASH_ALGORITHM): Promise<boolean> {
    const hash = await this.computeKeyedHashAsync(message, key, encoding, algorithm);

    return hash === preComputedHash;
  }

  public static async generateKeyAsync(algorithm: EncryptionAlgorithm): Promise<string> {
    const algorithmInformation = await this.validateEncryptionAlgorithmAsync(algorithm);

    if (algorithmInformation.isSymmetricKeyedEncryptionAlgorithm) {
      const key = await this.generateSymmetricKeyAsync(algorithmInformation);

      return key;
    }

    throw new Error("Unsupported symmetric keyed encryption algorithm provided.");
  }

  public static async generateKeyPairAsync(algorithm: EncryptionAlgorithm): Promise<AsymmetricKeyPair> {
    const algorithmInformation = await this.validateEncryptionAlgorithmAsync(algorithm);

    // if the algorithm is not symmetric keyed encryption algorithm...
    if (!algorithmInformation.isSymmetricKeyedEncryptionAlgorithm) {
      // we shall generate RSA key pair...
      const keyPair = await this.generateAsymmetricKeyPairAsync(algorithmInformation);

      return keyPair;
    }

    // otherwise, we shall throw error...
    throw new Error("Unsupported asymmetric keyed encryption algorithm provided.");
  }

  public static async encryptAsync(
    plaintext: string | Buffer,
    encryptionKey: string,
    algorithm: EncryptionAlgorithm,
    plaintextEncoding?: Encoding,
    ciphertextEncoding?: null | Encoding): Promise<string | Buffer> {
    const algorithmInformation = await this.validateEncryptionAlgorithmAsync(algorithm);
    const plaintextAsBuffer = await this.validatePlaintextAsync(plaintext, algorithmInformation, plaintextEncoding);
    // NOTE: IF ENCODING IS NULL, WE SHALL RETURN THE RAW BUFFER...
    // BUT IF ENCODING IS UNDEFINED, WE SHALL USE THE DEFAULT ENCODING...
    const _ciphertextEncoding = await this.validateEncodingAsync(ciphertextEncoding, DEFAULT_CIPHERTEXT_ENCRYPTION_ENCODING);

    // if encryption key is not a string...
    if (!StringUtilities.isString(encryptionKey)) {
      // we shall set an empty string...
      encryptionKey = StringUtilities.getEmptyString();
    }

    // if the algorithm is a symmetric keyed encryption algorithm...
    if (algorithmInformation.isSymmetricKeyedEncryptionAlgorithm) {
      const ciphertext = await this.encryptUsingAesAsync(plaintextAsBuffer,
        encryptionKey, algorithmInformation, _ciphertextEncoding);

      return ciphertext;
    }

    // otherwise, for asymmetric keyed encryption algorithm...
    if (algorithmInformation.algorithm === "rsa") {
      // if encryption key is not provided...
      if (StringUtilities.isEmpty(encryptionKey)) {
        throw new Error("Invalid asymmetric encryption key provided.");
      }

      const ciphertext = await this.encryptUsingRsaAsync(plaintextAsBuffer,
        encryptionKey, algorithmInformation, _ciphertextEncoding);

      return ciphertext;
    }

    throw new Error("Unsupported encryption algorithm provided.");
  }

  public static async decryptAsync(
    ciphertext: string | Buffer,
    decryptionKey: string,
    algorithm: EncryptionAlgorithm,
    ciphertextEncoding?: Encoding,
    plaintextEncoding?: null | Encoding): Promise<string | Buffer> {
    const algorithmInformation = await this.validateEncryptionAlgorithmAsync(algorithm);
    const ciphertextAsBuffer = await this.validateCiphertextAsync(ciphertext, algorithmInformation, ciphertextEncoding);
    // NOTE: IF ENCODING IS NULL, WE SHALL RETURN THE RAW BUFFER...
    // BUT IF ENCODING IS UNDEFINED, WE SHALL USE THE DEFAULT ENCODING...
    const _plaintextEncoding = await this.validateEncodingAsync(plaintextEncoding, DEFAULT_PLAINTEXT_ENCRYPTION_ENCODING);

    // if decryption key is not a string...
    if (!StringUtilities.isString(decryptionKey)) {
      // we shall set an empty string...
      decryptionKey = StringUtilities.getEmptyString();
    }

    // if the algorithm is a symmetric keyed encryption algorithm...
    if (algorithmInformation.isSymmetricKeyedEncryptionAlgorithm) {
      const plaintext = await this.decryptUsingAesAsync(ciphertextAsBuffer, decryptionKey,
        algorithmInformation, _plaintextEncoding);

      return plaintext;
    }

    // otherwise, for asymmetric keyed encryption algorithm...
    if (algorithmInformation.algorithm === "rsa") {
      // if decryption key is not provided...
      if (StringUtilities.isEmpty(decryptionKey)) {
        throw new Error("Invalid asymmetric decryption key provided.");
      }

      const plaintext = await this.decryptUsingRsaAsync(ciphertextAsBuffer,
        decryptionKey, algorithmInformation, _plaintextEncoding);

      return plaintext;
    }

    throw new Error("Unsupported encryption algorithm provided.");
  }

  public static async encryptHybridAsync(
    plaintext: string | Buffer,
    asymmetricEncryptionKey: string,
    asymmetricKeyedEncryptionAlgorithm?: EncryptionAlgorithm,
    symmetricKeyedEncryptionAlgorithm?: EncryptionAlgorithm,
    plaintextEncoding?: Encoding,
    ciphertextEncoding?: null | Encoding,
    symmetricKey?: string): Promise<string | Buffer> {
    try {
      await this.validateEncryptionAlgorithmAsync(asymmetricKeyedEncryptionAlgorithm as any);
    } catch {
      asymmetricKeyedEncryptionAlgorithm = DEFAULT_HYBRID_ENCRYPTION_ASYMMETRIC_KEYED_ENCRYPTION_ALGORITHM;
    }

    if (StringUtilities.isUndefinedOrNullOrEmpty(asymmetricEncryptionKey, true)) {
      throw new Error("Invalid asymmetric encryption key provided.");
    }

    try {
      await this.validateEncryptionAlgorithmAsync(symmetricKeyedEncryptionAlgorithm as any);
    } catch {
      symmetricKeyedEncryptionAlgorithm = DEFAULT_HYBRID_ENCRYPTION_SYMMETRIC_KEYED_ENCRYPTION_ALGORITHM;
    }

    let _plaintextEncoding = await this.validateEncodingAsync(plaintextEncoding, DEFAULT_PLAINTEXT_ENCRYPTION_ENCODING);

    // if no encoding is provided, we shall set to default value...
    if (StringUtilities.isUndefinedOrNullOrEmpty(_plaintextEncoding, true)) {
      _plaintextEncoding = DEFAULT_PLAINTEXT_ENCRYPTION_ENCODING;
    }

    const _ciphertextEncoding = await this.validateEncodingAsync(ciphertextEncoding, DEFAULT_CIPHERTEXT_ENCRYPTION_ENCODING);

    // if symmetric key is not provided...
    if (!StringUtilities.isString(symmetricKey)) {
      // we shall generate a new one...
      symmetricKey = await this.generateKeyAsync(symmetricKeyedEncryptionAlgorithm as any);
    }

    // first we shall encrypt the plaintext using symmetric keyed encryption algorithm...
    const encryptedPlaintext = await this.encryptAsync(plaintext, symmetricKey!,
      symmetricKeyedEncryptionAlgorithm as any, _plaintextEncoding as any, null) as Buffer;
    // now we shall encrypt the symmetric key using asymmetric keyed encryption algorithm...
    const encryptedSymmetricKey = await this.encryptAsync(symmetricKey!, asymmetricEncryptionKey,
      asymmetricKeyedEncryptionAlgorithm as any, DEFAULT_HYBRID_ENCRYPTION_SYMMETRIC_KEY_ENCODING, null) as Buffer;
    const encryptedSymmetricKeyLengthAsBuffer = Buffer.allocUnsafe(INTEGER_SIZE_IN_BYTES);
    encryptedSymmetricKeyLengthAsBuffer.writeInt32LE(encryptedSymmetricKey.length);
    const ciphertextAsBuffer = Buffer.concat([
      encryptedSymmetricKeyLengthAsBuffer,
      encryptedSymmetricKey,
      encryptedPlaintext,
    ]);

    // if encoding is undefined, null or empty string, we shall return the raw buffer...
    if (StringUtilities.isUndefinedOrNullOrEmpty(_ciphertextEncoding, true)) { return ciphertextAsBuffer; }

    return ciphertextAsBuffer.toString(_ciphertextEncoding as any);
  }

  public static async decryptHybridAsync(
    ciphertext: string | Buffer,
    asymmetricDecryptionKey: string,
    asymmetricKeyedEncryptionAlgorithm?: EncryptionAlgorithm,
    symmetricKeyedEncryptionAlgorithm?: EncryptionAlgorithm,
    ciphertextEncoding?: Encoding,
    plaintextEncoding?: null | Encoding): Promise<string | Buffer> {
    try {
      await this.validateEncryptionAlgorithmAsync(asymmetricKeyedEncryptionAlgorithm as any);
    } catch {
      asymmetricKeyedEncryptionAlgorithm = DEFAULT_HYBRID_ENCRYPTION_ASYMMETRIC_KEYED_ENCRYPTION_ALGORITHM;
    }

    if (StringUtilities.isUndefinedOrNullOrEmpty(asymmetricDecryptionKey, true)) {
      throw new Error("Invalid asymmetric decryption key provided.");
    }

    try {
      await this.validateEncryptionAlgorithmAsync(symmetricKeyedEncryptionAlgorithm as any);
    } catch {
      symmetricKeyedEncryptionAlgorithm = DEFAULT_HYBRID_ENCRYPTION_SYMMETRIC_KEYED_ENCRYPTION_ALGORITHM;
    }

    let _ciphertextEncoding = await this.validateEncodingAsync(ciphertextEncoding, DEFAULT_CIPHERTEXT_ENCRYPTION_ENCODING);

    // if no encoding is provided, we shall set to default value...
    if (StringUtilities.isUndefinedOrNullOrEmpty(_ciphertextEncoding, true)) {
      _ciphertextEncoding = DEFAULT_CIPHERTEXT_ENCRYPTION_ENCODING;
    }

    const _plaintextEncoding = await this.validateEncodingAsync(plaintextEncoding, DEFAULT_PLAINTEXT_ENCRYPTION_ENCODING);
    let totalBytesReadFromCiphertextAsBuffer = 0;
    // converts the ciphertext to buffer if needed...
    let ciphertextAsBuffer = ciphertext instanceof Buffer
      ? ciphertext
      : Buffer.from(ciphertext, _ciphertextEncoding as any);
    const encryptedSymmetricKeyLengthAsBuffer = ciphertextAsBuffer.subarray(0, INTEGER_SIZE_IN_BYTES);
    const encryptedSymmetricKeyLength = encryptedSymmetricKeyLengthAsBuffer.readInt32LE(0);
    totalBytesReadFromCiphertextAsBuffer += encryptedSymmetricKeyLengthAsBuffer.length;
    const encryptedSymmetricKeyAsBuffer = ciphertextAsBuffer.subarray(totalBytesReadFromCiphertextAsBuffer,
      totalBytesReadFromCiphertextAsBuffer + encryptedSymmetricKeyLength);
    totalBytesReadFromCiphertextAsBuffer += encryptedSymmetricKeyAsBuffer.length;
    // now we'll need to process the rest of the bytes...
    ciphertextAsBuffer = ciphertextAsBuffer.subarray(totalBytesReadFromCiphertextAsBuffer);
    // now we shall decrypt the symmetric key...
    const symmetricKey = await this.decryptAsync(encryptedSymmetricKeyAsBuffer, asymmetricDecryptionKey,
      asymmetricKeyedEncryptionAlgorithm as any, undefined, DEFAULT_HYBRID_ENCRYPTION_SYMMETRIC_KEY_ENCODING) as string;
    // finally we will decrypt the ciphertext using symmetric keyed encryption algorithm...
    const decryptedCiphertext = await this.decryptAsync(ciphertextAsBuffer, symmetricKey,
      symmetricKeyedEncryptionAlgorithm as any, undefined, null) as Buffer;

    // if encoding is undefined, null or empty string, we shall return the raw buffer...
    if (StringUtilities.isUndefinedOrNullOrEmpty(_plaintextEncoding, true)) { return decryptedCiphertext; }

    return decryptedCiphertext.toString(_plaintextEncoding as any);
  }

  private static async generateSaltAsync(): Promise<string> {
    let arbitraryNumberAsString = `${(Date.now() % 8192)}`;

    // arbitrary number could be of odd length...
    if (arbitraryNumberAsString.length % 2 != 0) {
      arbitraryNumberAsString += RandomGenerator.generateCharacter();
    }

    const randomStringLength = (AES_SALT_LENGTH - arbitraryNumberAsString.length) / 2;
    const randomStringA = RandomGenerator.generateString(randomStringLength);
    const randomStringB = RandomGenerator.generateString(randomStringLength);
    const salt = `${randomStringA}${arbitraryNumberAsString}${randomStringB}`;

    return salt;
  }

  private static async deriveKeyAndInitializationVectorAsync(
    key: string, salt: string, keyLengthInBytes: number,
    initializationVectorLengthInBytes: number): Promise<DerivationResult> {
    const derivedData = await this.computeHashAsync(`${salt}.${key}`,
      AES_KEY_AND_INITIALIZATION_VECTOR_DERIVATION_HASH_ENCODING,
      AES_KEY_AND_INITIALIZATION_VECTOR_DERIVATION_HASH_ALGORITHM) as string;
    const derivedDataAsBuffer = Buffer.from(derivedData, AES_KEY_AND_INITIALIZATION_VECTOR_DERIVED_DATA_ENCODING);
    const keyAsBuffer = derivedDataAsBuffer.subarray(0, keyLengthInBytes);
    const initializationVectorAsBuffer = derivedDataAsBuffer.subarray(keyAsBuffer.length,
      keyAsBuffer.length + initializationVectorLengthInBytes);
    const keyAndInitializationVector: DerivationResult = Object.create(null);
    keyAndInitializationVector.key = keyAsBuffer;
    keyAndInitializationVector.initializationVector = initializationVectorAsBuffer;

    return keyAndInitializationVector;
  }

  private static async setAdditionalAuthenticatedDataAsync(cryptographicServiceProvider: any,
    information: EncryptionAlgorithmInformation): Promise<void> {
    if (!information.shallSetAdditionalAuthenticatedData
      || typeof cryptographicServiceProvider?.setAAD !== "function") { return; }

    try {
      cryptographicServiceProvider.setAAD(AES_ADDITIONAL_AUTHENTICATED_DATA, {
        plaintextLength: AES_ADDITIONAL_AUTHENTICATED_DATA.length,
      });
    } catch { }
  }

  private static async getAuthenticationTagAsync(cryptographicServiceProvider: any): Promise<Buffer> {
    let authenticationTag = EMPTY_BUFFER;

    if (typeof cryptographicServiceProvider?.getAuthTag !== "function") { return authenticationTag; }

    try {
      authenticationTag = cryptographicServiceProvider.getAuthTag();
    } catch { }

    return authenticationTag;
  }

  private static async setAuthenticationTagAsync(authenticationTag: Buffer,
    cryptographicServiceProvider: any): Promise<void> {
    if (typeof cryptographicServiceProvider?.setAuthTag !== "function") { return; }

    try {
      cryptographicServiceProvider.setAuthTag(authenticationTag);
    } catch { }
  }

  private static async generateSymmetricKeyAsync(
    algorithmInformation: EncryptionAlgorithmInformation): Promise<string> {
    const key = RandomGenerator.generateString(AES_KEY_LENGTH);

    return key;
  }

  private static async encryptUsingAesAsync(
    plaintext: Buffer,
    encryptionKey: string,
    algorithmInformation: EncryptionAlgorithmInformation,
    ciphertextEncoding?: string): Promise<string | Buffer> {
    const salt = await this.generateSaltAsync();
    const saltAsBuffer = Buffer.from(salt, AES_SALT_ENCODING);
    const { key, initializationVector, } = await this.deriveKeyAndInitializationVectorAsync(
      encryptionKey, salt, algorithmInformation.keyLengthInBytes,
      algorithmInformation.initializationVectorLengthInBytes);
    const internalCipherOptions: any = {
      authTagLength: AES_AUTHENTICATION_TAG_LENGTH,
    };
    const cipher = cryptography.createCipheriv(algorithmInformation.algorithm, key,
      initializationVector, internalCipherOptions);

    // sets additional authenticated data if supported...
    await this.setAdditionalAuthenticatedDataAsync(cipher, algorithmInformation);

    const bufferList = [
      saltAsBuffer,                         // index 0
      EMPTY_BUFFER,                         // index 1
      EMPTY_BUFFER,                         // index 2
      cipher.update(plaintext),             // index 3
      cipher.final(),                       // index 4
    ];

    // retrieves the authentication tag...
    const authenticationTag = await this.getAuthenticationTagAsync(cipher);
    const authenticationTagLengthAsBuffer = Buffer.allocUnsafe(INTEGER_SIZE_IN_BYTES);
    authenticationTagLengthAsBuffer.writeInt32LE(authenticationTag.length);
    bufferList[1] = authenticationTagLengthAsBuffer;
    bufferList[2] = authenticationTag;
    const ciphertextAsBuffer = Buffer.concat(bufferList);

    // if encoding is undefined, null or empty string, we shall return the raw buffer...
    if (StringUtilities.isUndefinedOrNullOrEmpty(ciphertextEncoding, true)) { return ciphertextAsBuffer; }

    return ciphertextAsBuffer.toString(ciphertextEncoding as any);
  }

  private static async decryptUsingAesAsync(
    ciphertext: Buffer,
    decryptionKey: string,
    algorithmInformation: EncryptionAlgorithmInformation,
    plaintextEncoding?: string): Promise<string | Buffer> {
    let totalBytesReadFromCiphertextAsBuffer = 0;
    const saltAsBuffer = ciphertext.subarray(0, AES_SALT_LENGTH);
    const salt = saltAsBuffer.toString(AES_SALT_ENCODING);
    // keeping track of the number of bytes read from the buffer...
    totalBytesReadFromCiphertextAsBuffer += saltAsBuffer.length;
    // extracting authentication tag length...
    const authenticationTagLengthAsBuffer = ciphertext.subarray(
      totalBytesReadFromCiphertextAsBuffer,
      totalBytesReadFromCiphertextAsBuffer + INTEGER_SIZE_IN_BYTES);
    // keeping track of the number of bytes read from the buffer...
    totalBytesReadFromCiphertextAsBuffer += authenticationTagLengthAsBuffer.length;
    // converts 4 bytes buffer into an integer number...
    const authenticationTagLength = authenticationTagLengthAsBuffer.readInt32LE(0);
    // derives key and initialization vector...
    const { key, initializationVector, } = await this.deriveKeyAndInitializationVectorAsync(
      decryptionKey, salt, algorithmInformation.keyLengthInBytes,
      algorithmInformation.initializationVectorLengthInBytes);
    const internalCipherOptions: any = {
      authTagLength: AES_AUTHENTICATION_TAG_LENGTH,
    };
    const decipher = cryptography.createDecipheriv(algorithmInformation.algorithm,
      key, initializationVector, internalCipherOptions);

    // sets additional authenticated data if supported...
    await this.setAdditionalAuthenticatedDataAsync(decipher, algorithmInformation);

    // if authentication tag length is not zero...
    if (authenticationTagLength > 0) {
      // we shall read the authentication tag...
      const authenticationTag = ciphertext.subarray(
        totalBytesReadFromCiphertextAsBuffer,
        totalBytesReadFromCiphertextAsBuffer + authenticationTagLength);
      // keeping track of the number of bytes read from the buffer...
      totalBytesReadFromCiphertextAsBuffer += authenticationTag.length;

      // sets the authentication tag if supported...
      await this.setAuthenticationTagAsync(authenticationTag, decipher);
    }

    // now we'll need to process the rest of the bytes...
    ciphertext = ciphertext.subarray(totalBytesReadFromCiphertextAsBuffer);
    // now we shall concatenate the buffers...
    const plaintextAsBuffer = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);

    // if encoding is undefined, null or empty string, we shall return the raw buffer...
    if (StringUtilities.isUndefinedOrNullOrEmpty(plaintextEncoding, true)) { return plaintextAsBuffer; }

    return plaintextAsBuffer.toString(plaintextEncoding as any);
  }

  private static generateRsaKeyPairAsync(algorithmInformation: EncryptionAlgorithmInformation): Promise<AsymmetricKeyPair> {
    return new Promise<AsymmetricKeyPair>((resolve, reject) => {
      const rsaKeyPairOptions: cryptography.RSAKeyPairOptions<"pem", "pem"> = {
        // modulus length is in bits...
        modulusLength: algorithmInformation.keyLengthInBytes * 8,
        publicKeyEncoding: {
          type: "pkcs1",
          format: "pem",
        },
        privateKeyEncoding: {
          type: "pkcs8",
          format: "pem",
          // cipher: "aes-256-cbc",
          // passphrase: "b8ab#4zf9hc44f2@2b573e7324142fe6b0d!dbe$",
        },
      };

      cryptography.generateKeyPair(algorithmInformation.algorithm as any, rsaKeyPairOptions,
        (error: null | Error, publicKey: string, privateKey: string) => {
          if (error) { return reject(error); }

          resolve({
            publicKey: publicKey,
            privateKey: privateKey,
          });
        });
    });
  };

  private static generateAsymmetricKeyPairAsync(algorithmInformation: EncryptionAlgorithmInformation): Promise<AsymmetricKeyPair> {
    if (algorithmInformation.algorithm === "rsa") {
      return this.generateRsaKeyPairAsync(algorithmInformation);
    }

    // otherwise, we shall throw error...
    throw new Error("Unsupported asymmetric keyed encryption algorithm provided.");
  }

  private static async encryptUsingRsaAsync(
    plaintext: Buffer,
    encryptionKey: string,
    algorithmInformation: EncryptionAlgorithmInformation,
    ciphertextEncoding?: string): Promise<string | Buffer> {
    const ciphertextAsBuffer = cryptography.publicEncrypt(encryptionKey, plaintext);

    // if encoding is undefined, null or empty string, we shall return the raw buffer...
    if (StringUtilities.isUndefinedOrNullOrEmpty(ciphertextEncoding, true)) { return ciphertextAsBuffer; }

    return ciphertextAsBuffer.toString(ciphertextEncoding as any);
  }

  private static async decryptUsingRsaAsync(
    ciphertext: Buffer,
    decryptionKey: string,
    algorithmInformation: EncryptionAlgorithmInformation,
    plaintextEncoding?: string): Promise<string | Buffer> {
    const plaintextAsBuffer = cryptography.privateDecrypt({
      key: decryptionKey,
      padding: cryptography.constants.RSA_PKCS1_OAEP_PADDING,
      // oaepHash: "sha256",
      // passphrase: "b8ab#4zf9hc44f2@2b573e7324142fe6b0d!dbe$",
    }, ciphertext);

    // if encoding is undefined, null or empty string, we shall return the raw buffer...
    if (StringUtilities.isUndefinedOrNullOrEmpty(plaintextEncoding, true)) { return plaintextAsBuffer; }

    return plaintextAsBuffer.toString(plaintextEncoding as any);
  }

  private static async validateEncodingAsync(encoding: undefined | null | Encoding,
    defaultEncoding: undefined | Encoding): Promise<undefined | string> {
    switch (encoding) {
      // if encoding is null...
      case null:
        // we shall return undefined...
        return undefined;
      case "ascii":
      case "utf-8":
      case "base64":
      case "base64url":
      case "hex":
        return encoding;
      case "base16":
        return "hex";
      default:
        // first we shall sanitize the default encoding...
        let _defaultEncoding = StringUtilities.getDefaultIfUndefinedOrNullOrEmpty(
          defaultEncoding, StringUtilities.getEmptyString(), true);

        // if default encoding is provided...
        if (!StringUtilities.isEmpty(_defaultEncoding)) {
          // we shall validate the default encoding...
          _defaultEncoding = await this.validateEncodingAsync(_defaultEncoding, undefined);

          return _defaultEncoding;
        }

        // otherwise, we shall throw an exception...
        throw new Error("Invalid encoding provided.");
    }
  }

  private static async validateHashAlgorithmAsync(algorithm: undefined | HashAlgorithm,
    defaultAlgorithm: undefined | HashAlgorithm): Promise<string> {
    switch (algorithm) {
      case "SHA160":
        return "sha1";
      case "SHA256":
        return "sha256";
      case "SHA384":
        return "sha384";
      case "SHA512":
        return "sha512";
      default:
        // first we shall sanitize the default algorithm...
        let _defaultAlgorithm = StringUtilities.getDefaultIfUndefinedOrNullOrEmpty(
          defaultAlgorithm, StringUtilities.getEmptyString(), true);

        // if default algorithm is provided...
        if (!StringUtilities.isEmpty(_defaultAlgorithm)) {
          // we shall validate the default algorithm...
          _defaultAlgorithm = await this.validateHashAlgorithmAsync(_defaultAlgorithm, undefined);

          return _defaultAlgorithm;
        }

        // otherwise, we shall throw an exception...
        throw new Error("Invalid hash algorithm provided.");
    }
  }

  private static async validateKeyedHashAlgorithmAsync(
    algorithm: undefined | KeyedHashAlgorithm,
    defaultAlgorithm: undefined | KeyedHashAlgorithm): Promise<string> {
    switch (algorithm) {
      case "HMACSHA160":
        return "sha1";
      case "HMACSHA256":
        return "sha256";
      case "HMACSHA384":
        return "sha384";
      case "HMACSHA512":
        return "sha512";
      default:
        // first we shall sanitize the default algorithm...
        let _defaultAlgorithm = StringUtilities.getDefaultIfUndefinedOrNullOrEmpty(
          defaultAlgorithm, StringUtilities.getEmptyString(), true);

        // if default algorithm is provided...
        if (!StringUtilities.isEmpty(_defaultAlgorithm)) {
          // we shall validate the default algorithm...
          _defaultAlgorithm = await this.validateKeyedHashAlgorithmAsync(_defaultAlgorithm, undefined);

          return _defaultAlgorithm;
        }

        // otherwise, we shall throw an exception...
        throw new Error("Invalid keyed hash algorithm provided.");
    }
  }

  private static async validateEncryptionAlgorithmAsync(algorithm: EncryptionAlgorithm)
    : Promise<EncryptionAlgorithmInformation> {
    const information: EncryptionAlgorithmInformation = Object.create(null);

    switch (algorithm) {
      case "AESCBC128":
        information.algorithm = "aes-128-cbc";
        information.keyLengthInBytes = 16;
        information.initializationVectorLengthInBytes = 16;
        information.isSymmetricKeyedEncryptionAlgorithm = true;
        information.shallSetAdditionalAuthenticatedData = false;

        break;
      case "AESCBC192":
        information.algorithm = "aes-192-cbc";
        information.keyLengthInBytes = 24;
        information.initializationVectorLengthInBytes = 16;
        information.isSymmetricKeyedEncryptionAlgorithm = true;
        information.shallSetAdditionalAuthenticatedData = false;

        break;
      case "AESCBC256":
        information.algorithm = "aes-256-cbc";
        information.keyLengthInBytes = 32;
        information.initializationVectorLengthInBytes = 16;
        information.isSymmetricKeyedEncryptionAlgorithm = true;
        information.shallSetAdditionalAuthenticatedData = false;

        break;
      case "AESECB128":
        information.algorithm = "aes-128-ecb";
        information.keyLengthInBytes = 16;
        information.initializationVectorLengthInBytes = 0;
        information.isSymmetricKeyedEncryptionAlgorithm = true;
        information.shallSetAdditionalAuthenticatedData = false;

        break;
      case "AESECB192":
        information.algorithm = "aes-192-ecb";
        information.keyLengthInBytes = 24;
        information.initializationVectorLengthInBytes = 0;
        information.isSymmetricKeyedEncryptionAlgorithm = true;
        information.shallSetAdditionalAuthenticatedData = false;

        break;
      case "AESECB256":
        information.algorithm = "aes-256-ecb";
        information.keyLengthInBytes = 32;
        information.initializationVectorLengthInBytes = 0;
        information.isSymmetricKeyedEncryptionAlgorithm = true;
        information.shallSetAdditionalAuthenticatedData = false;

        break;
      case "AESCCM128":
        information.algorithm = "aes-128-ccm";
        information.keyLengthInBytes = 16;
        information.initializationVectorLengthInBytes = 12;
        information.isSymmetricKeyedEncryptionAlgorithm = true;
        information.shallSetAdditionalAuthenticatedData = false;

        break;
      case "AESCCM192":
        information.algorithm = "aes-192-ccm";
        information.keyLengthInBytes = 24;
        information.initializationVectorLengthInBytes = 12;
        information.isSymmetricKeyedEncryptionAlgorithm = true;
        information.shallSetAdditionalAuthenticatedData = false;

        break;
      case "AESCCM256":
        information.algorithm = "aes-256-ccm";
        information.keyLengthInBytes = 32;
        information.initializationVectorLengthInBytes = 12;
        information.isSymmetricKeyedEncryptionAlgorithm = true;
        information.shallSetAdditionalAuthenticatedData = false;

        break;
      case "AESGCM128":
        information.algorithm = "aes-128-gcm";
        information.keyLengthInBytes = 16;
        information.initializationVectorLengthInBytes = 16;
        information.isSymmetricKeyedEncryptionAlgorithm = true;
        information.shallSetAdditionalAuthenticatedData = true;

        break;
      case "AESGCM192":
        information.algorithm = "aes-192-gcm";
        information.keyLengthInBytes = 24;
        information.initializationVectorLengthInBytes = 16;
        information.isSymmetricKeyedEncryptionAlgorithm = true;
        information.shallSetAdditionalAuthenticatedData = true;

        break;
      case "AESGCM256":
        information.algorithm = "aes-256-gcm";
        information.keyLengthInBytes = 32;
        information.initializationVectorLengthInBytes = 16;
        information.isSymmetricKeyedEncryptionAlgorithm = true;
        information.shallSetAdditionalAuthenticatedData = true;

        break;
      case "AESOCB128":
        information.algorithm = "aes-128-ocb";
        information.keyLengthInBytes = 16;
        information.initializationVectorLengthInBytes = 12;
        information.isSymmetricKeyedEncryptionAlgorithm = true;
        information.shallSetAdditionalAuthenticatedData = true;

        break;
      case "AESOCB192":
        information.algorithm = "aes-192-ocb";
        information.keyLengthInBytes = 24;
        information.initializationVectorLengthInBytes = 12;
        information.isSymmetricKeyedEncryptionAlgorithm = true;
        information.shallSetAdditionalAuthenticatedData = true;

        break;
      case "AESOCB256":
        information.algorithm = "aes-256-ocb";
        information.keyLengthInBytes = 32;
        information.initializationVectorLengthInBytes = 12;
        information.isSymmetricKeyedEncryptionAlgorithm = true;
        information.shallSetAdditionalAuthenticatedData = true;

        break;
      case "AESCTR128":
        information.algorithm = "aes-128-ctr";
        information.keyLengthInBytes = 16;
        information.initializationVectorLengthInBytes = 16;
        information.isSymmetricKeyedEncryptionAlgorithm = true;
        information.shallSetAdditionalAuthenticatedData = false;

        break;
      case "AESCTR192":
        information.algorithm = "aes-192-ctr";
        information.keyLengthInBytes = 24;
        information.initializationVectorLengthInBytes = 16;
        information.isSymmetricKeyedEncryptionAlgorithm = true;
        information.shallSetAdditionalAuthenticatedData = false;

        break;
      case "AESCTR256":
        information.algorithm = "aes-256-ctr";
        information.keyLengthInBytes = 32;
        information.initializationVectorLengthInBytes = 16;
        information.isSymmetricKeyedEncryptionAlgorithm = true;
        information.shallSetAdditionalAuthenticatedData = false;

        break;
      case "AESOFB128":
        information.algorithm = "aes-128-ofb";
        information.keyLengthInBytes = 16;
        information.initializationVectorLengthInBytes = 16;
        information.isSymmetricKeyedEncryptionAlgorithm = true;
        information.shallSetAdditionalAuthenticatedData = false;

        break;
      case "AESOFB192":
        information.algorithm = "aes-192-ofb";
        information.keyLengthInBytes = 24;
        information.initializationVectorLengthInBytes = 16;
        information.isSymmetricKeyedEncryptionAlgorithm = true;
        information.shallSetAdditionalAuthenticatedData = false;

        break;
      case "AESOFB256":
        information.algorithm = "aes-256-ofb";
        information.keyLengthInBytes = 32;
        information.initializationVectorLengthInBytes = 16;
        information.isSymmetricKeyedEncryptionAlgorithm = true;
        information.shallSetAdditionalAuthenticatedData = false;

        break;
      case "RSA1024":
        information.algorithm = "rsa";
        information.keyLengthInBytes = 128;    // 1024 bits...
        information.initializationVectorLengthInBytes = 0;
        information.isSymmetricKeyedEncryptionAlgorithm = false;
        information.shallSetAdditionalAuthenticatedData = false;

        break;
      case "RSA2048":
        information.algorithm = "rsa";
        information.keyLengthInBytes = 256;     // 2048 bits...
        information.initializationVectorLengthInBytes = 0;
        information.isSymmetricKeyedEncryptionAlgorithm = false;
        information.shallSetAdditionalAuthenticatedData = false;

        break;
      case "RSA4096":
        information.algorithm = "rsa";
        information.keyLengthInBytes = 512;     // 4096 bits...
        information.initializationVectorLengthInBytes = 0;
        information.isSymmetricKeyedEncryptionAlgorithm = false;
        information.shallSetAdditionalAuthenticatedData = false;

        break;
      default:
        throw new Error("Invalid symmetric keyed encryption algorithm provided.");
    }

    return information;
  }

  private static async validatePlaintextAsync(
    plaintext: string | Buffer,
    algorithmInformation: EncryptionAlgorithmInformation,
    plaintextEncoding?: Encoding): Promise<Buffer> {
    // if plaintext is already a buffer, we shall return the plaintext as-is...
    if (plaintext instanceof Buffer) { return plaintext; }

    let encoding: any = await this.validateEncodingAsync(plaintextEncoding, DEFAULT_PLAINTEXT_ENCRYPTION_ENCODING);

    // if encoding is null...
    if (StringUtilities.isUndefinedOrNullOrEmpty(encoding, true)) {
      // we shall set the default plaintext encoding...
      encoding = DEFAULT_PLAINTEXT_ENCRYPTION_ENCODING;
    }

    // if plaintext is not a string...
    if (!StringUtilities.isString(plaintext)) {
      // we shall set empty string to the plaintext...
      plaintext = StringUtilities.getEmptyString();
    }

    const plaintextAsBuffer = Buffer.from(plaintext, encoding);

    return plaintextAsBuffer;
  }

  private static async validateCiphertextAsync(
    ciphertext: string | Buffer,
    algorithmInformation: EncryptionAlgorithmInformation,
    ciphertextEncoding?: Encoding): Promise<Buffer> {
    // if ciphertext is already a buffer, we shall return the ciphertext as-is...
    if (ciphertext instanceof Buffer) { return ciphertext; }
    // if ciphertext is not provided...
    if (!StringUtilities.isString(ciphertext)) {
      throw new Error("Invalid ciphertext provided.");
    }

    let encoding: any = await this.validateEncodingAsync(ciphertextEncoding, DEFAULT_CIPHERTEXT_ENCRYPTION_ENCODING);

    // if encoding is null...
    if (StringUtilities.isUndefinedOrNullOrEmpty(encoding, true)) {
      // we shall set the default ciphertext encoding...
      encoding = DEFAULT_CIPHERTEXT_ENCRYPTION_ENCODING;
    }

    const ciphertextAsBuffer = Buffer.from(ciphertext, encoding);

    return ciphertextAsBuffer;
  }
}
