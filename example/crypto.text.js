'use strict'
const PasswordHashUtil = require('../crypto')

let passwordUtil = new PasswordHashUtil()

// 生成密码
passwordUtil
  .HashPassword('password')
  .then((user_pass) => console.log(user_pass))
  .catch(err => console.log(err))

// 验证密码
passwordUtil
  .CheckPassword('user_pass', 'user_hash_pass')
  .then(result => console.log(result))
  .catch(err => console.log(err))
