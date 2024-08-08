/*
 *
 * Algorithms (Updated)
 *
 */

const algorithms = require('bindings')('multihashing.node');

module.exports = {

  /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
  'allium': algorithms.allium,

  /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
  'blake': algorithms.blake,

  /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
  'blake2s': algorithms.blake2s,

  /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
  'c11': algorithms.c11,

    /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
     'curvehash': algorithms.curvehash,

  /**
   * @param header {Buffer} Equihash header hash
   * @param solution {Buffer} Equihash solution hash
   * @param personalization {number} Personalization string
   * @param equihash_n {number} Equihash "N" value
   * @param equihash_k {number} Equihash "K" value
   * @returns {boolean} True if valid, otherwise false.
   */
  'equihash': algorithms.equihash,

  /**
   * @param headerHashBuf {Buffer} 32-byte header hash
   * @param nonceBuf {Buffer} 8-byte nonce value (64-bits)
   * @param blockHeight {number} Block height integer
   * @param mixHashBuf {Buffer} Mix hash for verification
   * @param hashOutBuf {Buffer} Hash result output Buffer
   * @returns {boolean} True if valid, otherwise false.
   */
   'evrprogpow': algorithms.evrprogpow,

  /**
   * @param headerHashBuf {Buffer} 32-byte header hash
   * @param nonceBuf {Buffer} 8-byte nonce value (64-bits)
   * @param blockHeight {number} Block height integer
   * @param mixHashBuf {Buffer} Mix hash for verification
   * @param hashOutBuf {Buffer} Hash result output Buffer
   * @returns {boolean} True if valid, otherwise false.
   */
  'firopow': algorithms.firopow,

  /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
  'fugue': algorithms.fugue,

  /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
  'ghostrider': algorithms.ghostrider,

  /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
  'groestl': algorithms.groestl,

    /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
  'groestlmyriad': algorithms.groestlmyriad,
  'myr-gr': algorithms.groestlmyriad,

  /**
   * @param headerHashBuf {Buffer} 32-byte header hash
   * @param nonceBuf {Buffer} 8-byte nonce value (64-bits)
   * @param blockHeight {number} Block height integer
   * @param mixHashBuf {Buffer} Mix hash for verification
   * @param hashOutBuf {Buffer} Hash result output Buffer
   * @returns {boolean} True if valid, otherwise false.
   */
  'kawpow': algorithms.kawpow,

  /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
  'keccak': algorithms.keccak,

  /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
  'lyra2re': algorithms.lyra2re,

  /**
   * @param headerHashBuf {Buffer} 32-byte header hash
   * @param nonceBuf {Buffer} 8-byte nonce value (64-bits)
   * @param blockHeight {number} Block height integer
   * @param mixHashBuf {Buffer} Mix hash for verification
   * @param hashOutBuf {Buffer} Hash result output Buffer
   * @returns {boolean} True if valid, otherwise false.
   */
  'meowpow': algorithms.meowpow,


  /**
   * @param headerHashBuf {Buffer} 32-byte header hash
   * @param nonceBuf {Buffer} 8-byte nonce value (64-bits)
   * @param blockHeight {number} Block height integer
   * @param mixHashBuf {Buffer} Mix hash for verification
   * @param hashOutBuf {Buffer} Hash result output Buffer
   * @returns {boolean} True if valid, otherwise false.
   */
  'meraki': algorithms.meraki,

  /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
  'minotaur': algorithms.minotaur,

  /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
  'minotaurx': algorithms.minotaurx,

  /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
  'nist5': algorithms.nist5,

  /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
  'quark': algorithms.quark,

  /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
  'qubit': algorithms.qubit,

  /**
   * @param input {Buffer} Initial buffer to hash
   * @param nValue {Buffer} nValue to pass to scrypt algorithm
   * @param rValue {Buffer} rValue to pass to scrypt algorithm
   * @returns {Buffer} Hashing result
   */
  'scrypt': algorithms.scrypt,

  /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
  'sha256d': algorithms.sha256d,

  /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
  'sha512256d': algorithms.sha512256d,

  /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
  'skein': algorithms.skein,

  /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
  'verthash': algorithms.verthash,

  /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
  'x11': algorithms.x11,

  /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
  'x13': algorithms.x13,

  /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
  'x15': algorithms.x15,

  /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
  'x16r': algorithms.x16r,

  /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
  'x16rt': algorithms.x16rt,

  /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
  'x16rv2': algorithms.x16rv2,
  /**
   * @param input {Buffer} Initial buffer to hash
   * @returns {Buffer} Hashing result
   */
   'x17': algorithms.x17,
  }
