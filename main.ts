import { createResponse } from "create-response";
import { TextEncoder } from "encoding";
import { crypto } from "crypto";
import { logger } from "log";

// define the username and password field in your POST request
// this script only requires the username and password field.
const UNAME = "uname";
const PASSWD = "passwd";

export async function responseProvider(request: EW.ResponseProviderRequest) {
  // There is a limit on the max-body size of 16KB
  const maxBodyLength = 16384;
  var hex = "";

  // make sure we're not trying to read a body where content-length is > 16KB.
  // The promise will fail if we try to do so.
  // For now just ignore the check if body is too large.
  if (parseInt(request.getHeader("content-length")[0], 10) < maxBodyLength) {
    // read the body to completion which returns a promise of a json object
    // if anything goes wrong, just set it to null
    const myBody = await request.json().catch(() => null);

    // make sure we have the field UNAME and PASSWD, doesn't make any sense to continue if the don't exist
    // according to the No More Leaks description password field should be at least 2 chars long.
    // using short circuiting to bypass check if myBody == null
    if (
      myBody &&
      myBody[UNAME] &&
      myBody[PASSWD] &&
      myBody[PASSWD].length > 1
    ) {
      // from the request body we only need the username and password field
      // No More Leaks requires a lowercase use username and UTF-8 format with Normalization Form C (NFC)
      // https://www.unicode.org/reports/tr15/
      //
      // uname: normalisation@test.nl
      // passwd: ümláût
      // Hash: 35383e4c63b157472d939ca98fac0da3fdc468c7641d7fc70411348b9b6e98a2
      //
      // so first lowercase our username and then normalize to NFC. (optional)
      // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/normalize
      const normalizedUnamePasswd =
        myBody[UNAME].toLowerCase().normalize("NFC") +
        myBody[PASSWD].normalize("NFC");

      // create a string digest from our input string using SHA-256
      hex = await generateDigest("SHA-256", normalizedUnamePasswd);

      // when using DataStream for EdgeWorkers you can track the number successful of events
      logger.info("SHA-256 hash created from username+password combination");

      // return some nice JSON object with the response
      return createResponse(
        200,
        { "Content-Type": ["application/json"] },
        JSON.stringify({ key: hex })
      );
    } else {
      logger.error("Something wrong with the request body");
      return createResponse(500, {}, "Something wrong with the provided body");
    }
  } else {
    logger.error("Body too large");
    return createResponse(500, {}, "Body too large");
  }
}

/**
 * Generates the digest from a string using the provided algorithm
 * @param {('SHA-1'|'SHA-256'|'SHA-384'|'SHA-512')} algorithm - The algorithm to use, must be one of the following options ["SHA-1", "SHA-256", "SHA-384","SHA-512"]
 * @param {string} stringToDigest - a string to digest
 * @returns {string} returns the string value of the digest
 */
async function generateDigest(
  algorithm: string,
  stringToDigest: string
): Promise<string> {
  // first convert the input string into a stream of UTF-8 bytes (Uint8Array)
  // Uint8Array is a TypedArray so an array-like object that stores 8-bit unsigned integers (bytes).
  // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray
  // length of the array should be the exact same size as the length of the string.
  // https://techdocs.akamai.com/edgeworkers/docs/encoding
  const msgUint8 = new TextEncoder().encode(stringToDigest);

  // A digest is a short fixed-length value derived from some variable-length input.
  // Generate a digest of the given data using SHA256, response will be an Arraybuffer promise.
  // Arraybuffer serves as a raw binary data storage.
  const hashBuffer = await crypto.subtle.digest(algorithm, msgUint8);

  // convert the digest generate arraybuffer to a Uint8Array TypedArray
  // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray
  const walkable = Array.from(new Uint8Array(hashBuffer));

  // walk through the array, convert to string and put into single var
  return walkable.map((b) => b.toString(16).padStart(2, "0")).join("");
}
