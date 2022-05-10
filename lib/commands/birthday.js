const BaseCommand = require('../base-command.js')
const log = require('../utils/log-shim')

class Birthday extends BaseCommand {
  static name = 'birthday'
  static description = 'Birthday, deprecated'
  static ignoreImplicitWorkspace = true
  static isShellout = true

  async exec () {
    log.warn('birthday', 'birthday is deprecated, and will be removed in a future version.')
    this.npm.config.set('yes', true)
    return this.npm.exec('exec', ['@npmcli/npm-birthday'])
  }
}

module.exports = Birthday
