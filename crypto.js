const crypto = require('crypto')
const fs = require('fs')
const randbytes = require('randbytes')

class PasswordHashUtil {
  constructor (opt) {
    this.random_state = new Date().getTime() + process.pid
    this.itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
  }

  /**
   * hash user pass
   * @param password
   * @returns {Promise}
   * @constructor
   */
  HashPassword (password) {
    return new Promise((resolve, reject) => {
      this.get_random_bytes(6)
        .then(data => {
          let hash = this.crypt_private(password, this._gensalt_private(data))
          // # Returning '*' on error is safe here, but would _not_ be safe
          // # in a crypt(3)-like function used _both_ for generating new
          // # hashes and for validating passwords against existing hashes.
          if (hash.length !== 34) {
            hash = '*'
          }
          resolve(hash)
        })
    })
  }

  /**
   * check user pass
   * @param password
   * @param stored_hash
   * @returns {boolean}
   */
  CheckPassword (password, stored_hash) {
    let hash = this.crypt_private(password, stored_hash)
    return hash === stored_hash
  }

  /**
   * generate random code according to /dev/urandom
   * @param count
   */
  get_random_bytes (count) {
    return new Promise((resolve, reject) => {
        let randomSource = require('randbytes').urandom.getInstance()
        randomSource.getRandomBytes(count, (buff) => {
          resolve(buff.toString())
        })
      }
    )
  }

  /**
   *
   * @param password
   * @param setting
   * @returns {string}
   */
  crypt_private (password, setting) {
    let output = '*0'
    if (setting.substring(0, 2) === output) output = '*1'
    if (setting.substring(0, 3) !== '$H$') return output

    let count_log2 = this.itoa64.indexOf(setting[3])
    let count = 1 << count_log2

    let salt = setting.substring(4, 12)
    let hash = this._processMD5(salt, password)
    do {
      hash = this._processMD5(hash, password)
    } while (--count)

    output = setting.substring(0, 12)
    output += this._encode64(hash, 16)

    return output
  }

  /**
   * hash password by binary encode and digest binary
   * @param salt
   * @param secret
   * @returns {Array}
   * @private
   */
  _processMD5 (salt, secret) {
    return crypto.createHash('md5').update(salt + secret, 'binary').digest('binary')
  }

  /**
   * encode input according to hash count
   * @param input
   * @param count
   * @returns {string}
   * @private
   */
  _encode64 (input, count) {
    let output = ''
    let i = 0

    do {
      let value = this._processAscii(input[i++][0])
      output += this.itoa64[value & 0x3f]
      if (i < count) {
        value |= this._processAscii(input[i][0]) << 8
      }

      output += this.itoa64[(value >> 6) & 0x3f]

      if (i++ >= count) break
      if (i < count) {
        value |= this._processAscii(input[i][0]) << 16
      }

      output += this.itoa64[(value >> 12) & 0x3f]

      if (i++ >= count) break

      output += this.itoa64[(value >> 18) & 0x3f]
    } while (i < count)

    return output
  }

  /**
   * ascii encode
   * @param str
   * @returns {Number}
   * @private
   */
  _processAscii (str) {
    return str.charCodeAt()
  }

  /**
   * generate hash salt
   * @param input
   * @returns {string}
   * @private
   */
  _gensalt_private (input) {
    let output = '$H$'
    output += this.itoa64[13]
    output += this._encode64(input, 6)
    return output
  }
}

module.exports = PasswordHashUtil
