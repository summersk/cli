const Arborist = require('@npmcli/arborist')
const auditReport = require('npm-audit-report')
const chalk = require('chalk')
const crypto = require('crypto')
const fetch = require('npm-registry-fetch')
const localeCompare = require('@isaacs/string-locale-compare')('en')
const npa = require('npm-package-arg')
const pacote = require('pacote')
// const pickManifest = require('npm-pick-manifest')

const ArboristWorkspaceCmd = require('../arborist-cmd.js')
const auditError = require('../utils/audit-error.js')
const {
  registry: { default: defaultRegistry },
} = require('../utils/config/definitions.js')
// const log = require('../utils/log-shim.js')
const reifyFinish = require('../utils/reify-finish.js')

const validateSignature = async ({ message, signature, publicKey }) => {
  const verifier = crypto.createVerify('SHA256')
  verifier.write(message)
  verifier.end()
  return verifier.verify(publicKey, signature, 'base64')
}

class VerifySignatures {
  constructor (tree, filterSet, npm, opts) {
    this.tree = tree
    this.filterSet = filterSet
    this.npm = npm
    this.opts = opts
    this.edges = new Set()
    this.keys = new Map()
    this.invalid = new Set()
    this.missing = new Set()
    this.verified = 0
    this.output = []
    this.exitCode = 0
  }

  async run () {
    const start = process.hrtime.bigint()

    // Find all deps in tree
    const nodes = this.tree.inventory.values()
    this.getEdges(nodes, 'edgesOut')
    const edges = Array.from(this.edges)

    // QUESTION: Do we need to get the registry host from the resolved url to handle proxies?
    // Prefetch and cache public keys from used registries
    const registries = this.findAllRegistryUrls(edges, this.npm.flatOptions)
    for (const registry of registries) {
      const keys = await this.getKeys({ registry })
      if (keys) {
        this.keys.set(registry, keys)
      }
    }

    await Promise.all(edges.map((edge) => this.getVerifiedInfo(edge)))

    // Sort alphabetically
    const invalid = Array.from(this.invalid).sort((a, b) => localeCompare(a.name, b.name))
    const missing = Array.from(this.missing).sort((a, b) => localeCompare(a.name, b.name))

    const verified = invalid.length === 0 && missing.length === 0

    if (!verified) {
      this.exitCode = 1
    }

    const end = process.hrtime.bigint()
    const elapsed = end - start

    if (this.npm.config.get('json')) {
      this.appendOutput(this.makeJSON({ invalid, missing }))
    } else {
      const timing = `audited ${edges.length} packages in ${Math.floor(Number(elapsed) / 1e9)}s`
      const verifiedPrefix = verified ? 'verified signatures, ' : ''
      this.appendOutput(`${verifiedPrefix}${timing}\n`)

      if (this.verified && !verified) {
        this.appendOutput(`${this.verified} ${chalk.bold('verified')} packages\n`)
      }

      if (missing.length) {
        const msg = missing.length === 1 ?
          `package has a ${chalk.bold(chalk.magenta('missing'))} registry signature` :
          `packages have ${chalk.bold(chalk.magenta('missing'))} registry signatures`
        this.appendOutput(
          `${missing.length} ${msg} but the registry is ` +
          `providing signing keys${this.npm.config.get('missing') ? ':\n' : ''}`
        )
        // TODO: This might not be the right option for this
        if (this.npm.config.get('missing')) {
          this.appendOutput(this.humanOutput(missing))
        } else {
          this.appendOutput(`  run \`npm audit signatures --missing\` for details`)
        }
      }

      if (invalid.length) {
        const msg = invalid.length === 1 ?
          `package has an ${chalk.bold(chalk.red('invalid'))} registry signature` :
          `packages have ${chalk.bold(chalk.red('invalid'))} registry signatures`
        this.appendOutput(
          `${missing.length ? '\n' : ''}${invalid.length} ${msg}:\n`
        )
        this.appendOutput(this.humanOutput(invalid))
        const plural = invalid.length === 1 ? '' : 's'
        this.appendOutput(
          `\nSomeone might have tampered with the package${plural} ` +
          `since being published on the registry (monster-in-the-middle attack)!\n`
        )
      }
    }
  }

  findAllRegistryUrls (edges, opts) {
    return Array.from(edges.reduce((p, edge) => {
      let alias = false
      try {
        alias = npa(edge.spec).subSpec
      } catch (err) {
      }
      const spec = npa(alias ? alias.name : edge.name)
      p.add(fetch.pickRegistry(spec, opts))
      return p
    }, new Set()))
  }

  appendOutput (...args) {
    this.output.push(...args.flat())
  }

  report () {
    return { report: this.output.join('\n'), exitCode: this.exitCode }
  }

  getEdges (nodes, type) {
    // when no nodes are provided then it should only read direct deps
    // from the root node and its workspaces direct dependencies
    if (!nodes) {
      this.getEdgesOut(this.tree)
      this.getWorkspacesEdges()
      return
    }

    for (const node of nodes) {
      type === 'edgesOut'
        ? this.getEdgesOut(node)
        : this.getEdgesIn(node)
    }
  }

  getEdgesIn (node) {
    for (const edge of node.edgesIn) {
      this.trackEdge(edge)
    }
  }

  getEdgesOut (node) {
    for (const edge of node.edgesOut.values()) {
      this.trackEdge(edge)
    }
  }

  trackEdge (edge) {
    const filteredOut =
      edge.from
        && this.filterSet
        && this.filterSet.size > 0
        && !this.filterSet.has(edge.from.target)

    if (filteredOut) {
      return
    }

    this.edges.add(edge)
  }

  getWorkspacesEdges () {
    for (const edge of this.tree.edgesOut.values()) {
      const workspace = edge
        && edge.to
        && edge.to.target
        && edge.to.target.isWorkspace

      if (workspace) {
        this.getEdgesOut(edge.to.target)
      }
    }
  }

  // TODO: Remove this once we can get time from pacote.manifest
  async getPackument (spec) {
    const packument = await pacote.packument(spec, {
      ...this.npm.flatOptions,
      fullMetadata: this.npm.config.get('long'),
      preferOffline: true,
    })
    return packument
  }

  async getKeys ({ registry }) {
    return await fetch.json('/-/npm/v1/keys', {
      ...this.npm.flatOptions,
      registry,
    }).then(({ keys }) => keys.map((key) => {
      key.pemKey = `-----BEGIN PUBLIC KEY-----\n${key.key}\n-----END PUBLIC KEY-----`
      return key
    })).catch(err => {
      if (err.code === 'E404') {
        return null
      } else {
        throw err
      }
    })
  }

  async getVerifiedInfo (edge) {
    let alias = false
    try {
      alias = npa(edge.spec).subSpec
    } catch (err) {
    }
    const spec = npa(alias ? alias.name : edge.name)
    const node = edge.to || edge
    const { path, location } = node
    const { version } = node.package || {}

    // Skip packages that don't have a installed version, e.g. optonal dependencies
    if (!version) {
      return
    }

    const type = edge.optional ? 'optionalDependencies'
      : edge.bundled ? 'bundledDependencies'
      : edge.peer ? 'peerDependencies'
      : edge.dev ? 'devDependencies'
      : 'dependencies'

    for (const omitType of this.npm.config.get('omit')) {
      if (node[omitType]) {
        return
      }
    }

    // Skip potentially optional packages that are not on disk, as these could
    // be omitted during install (e.g. via `--only=prod`)
    if (edge.error === 'MISSING' && type !== 'dependencies') {
      return
    }

    // Skip if the package is not in a registry, e.g. local workspace package
    try {
      if (!npa(`${edge.name}@${edge.spec}`).registry) {
        return null
      }
    } catch (err) {
      return null
    }

    try {
      const name = alias ? edge.spec.replace('npm', edge.name) : edge.name
      // QUESTION: Is name@version the right way to get the manifest?
      const manifest = await pacote.manifest(`${name}@${version}`, this.npm.flatOptions)
      const registry = fetch.pickRegistry(spec, this.npm.flatOptions)

      const { _integrity: integrity, _signatures } = manifest
      const message = `${name}@${version}:${integrity}`
      const signatures = _signatures || []

      // TODO: Get version created time from manifest
      //
      // const packument = await this.getPackument(spec)
      // const versionCreated = packument.time && packument.time[version]
      const keys = this.keys.get(registry) || []
      const validKeys = keys.filter((publicKey) => {
        if (!publicKey.expires) {
          return true
        }
        // return Date.parse(versionCreated) < Date.parse(publicKey.expires)
        return Date.parse(publicKey.expires) > Date.now()
      })

      // Currently we only care about missing signatures on registries that provide a public key
      // We could make this configurable in the future with a strict/paranoid mode
      if (!signatures.length && validKeys.length) {
        this.missing.add({
          name,
          path,
          version,
          location,
          registry,
        })

        return
      }

      await Promise.all(signatures.map(async (signature) => {
        const publicKey = keys.filter(key => key.keyid === signature.keyid)[0]
        const validPublicKey = validKeys.filter(key => key.keyid === signature.keyid)[0]

        if (!publicKey && !validPublicKey) {
          throw new Error(
            `${name} has a signature with keyid: ${signature.keyid} ` +
            `but not corresponding public key can be found on ${registry}-/npm/v1/keys`
          )
        } else if (publicKey && !validPublicKey) {
          throw new Error(
            `${name} has a signature with keyid: ${signature.keyid} ` +
            `but the corresponding public key on ${registry}-/npm/v1/keys has expired ` +
            `(${publicKey.expires})`
          )
        }

        const valid = await validateSignature({
          message,
          signature: signature.sig,
          publicKey: validPublicKey.pemKey,
        })

        if (!valid) {
          this.invalid.add({
            name,
            path,
            type,
            version,
            location,
            registry,
            integrity,
            signature: signature.sig,
            keyid: signature.keyid,
          })
        } else {
          this.verified++
        }
      }))
    } catch (err) {
      // QUESTION: Is this the right way to handle these errors?
      //
      // silently catch and ignore ETARGET, E403 &
      // E404 errors, deps are just skipped
      if (!(
        err.code === 'ETARGET' ||
        err.code === 'E403' ||
        err.code === 'E404')
      ) {
        throw err
      }
    }
  }

  humanOutput (list) {
    const uniquePackages = Array.from(list.reduce((set, v) => {
      let nameVersion = `${v.name}@${v.version}`
      if (this.npm.color) {
        nameVersion = chalk.red(nameVersion)
      }
      const registry = v.registry
      const suffix = registry !== defaultRegistry ? ` (${registry})` : ''
      set.add(`${nameVersion}${suffix}`)
      return set
    }, new Set()))

    return uniquePackages.join('\n')
  }

  makeJSON ({ invalid, missing }) {
    const out = {}
    invalid.forEach(dep => {
      const {
        name,
        version,
        path,
        registry,
        integrity,
        signature,
        keyid,
      } = dep
      out.invalid = out.invalid || {}
      out.invalid[name] = {
        version,
        location: path,
        registry,
        signature,
        integrity,
        keyid,
      }
    })
    missing.forEach(dep => {
      const {
        name,
        version,
        path,
        registry,
      } = dep
      out.missing = out.invalid || {}
      out.missing[name] = {
        version,
        location: path,
        registry,
      }
    })
    return JSON.stringify(out, null, 2)
  }
}

class Audit extends ArboristWorkspaceCmd {
  static description = 'Run a security audit'
  static name = 'audit'
  static params = [
    'audit-level',
    'dry-run',
    'force',
    'json',
    'package-lock-only',
    'omit',
    'foreground-scripts',
    'ignore-scripts',
    ...super.params,
  ]

  static usage = ['[fix]']

  async completion (opts) {
    const argv = opts.conf.argv.remain

    if (argv.length === 2) {
      return ['fix']
    }

    switch (argv[2]) {
      case 'fix':
        return []
      default:
        throw new Error(argv[2] + ' not recognized')
    }
  }

  async exec (args) {
    if (args[0] === 'signatures') {
      await this.auditSignatures()
    } else {
      await this.auditAdvisories(args)
    }
  }

  async auditAdvisories (args) {
    const reporter = this.npm.config.get('json') ? 'json' : 'detail'
    const opts = {
      ...this.npm.flatOptions,
      audit: true,
      path: this.npm.prefix,
      reporter,
      workspaces: this.workspaceNames,
    }

    const arb = new Arborist(opts)
    const fix = args[0] === 'fix'
    await arb.audit({ fix })
    if (fix) {
      await reifyFinish(this.npm, arb)
    } else {
      // will throw if there's an error, because this is an audit command
      auditError(this.npm, arb.auditReport)
      const result = auditReport(arb.auditReport, opts)
      process.exitCode = process.exitCode || result.exitCode
      this.npm.output(result.report)
    }
  }

  async auditSignatures () {
    const reporter = this.npm.config.get('json') ? 'json' : 'detail'
    const opts = {
      ...this.npm.flatOptions,
      path: this.npm.prefix,
      reporter,
      workspaces: this.workspaceNames,
    }

    const arb = new Arborist(opts)
    const tree = await arb.loadActual()
    let filterSet = new Set()
    if (opts.workspaces && opts.workspaces.length) {
      filterSet =
        arb.workspaceDependencySet(
          tree,
          opts.workspaces,
          this.npm.flatOptions.includeWorkspaceRoot
        )
    } else if (!this.npm.flatOptions.workspacesEnabled) {
      filterSet =
        arb.excludeWorkspacesDependencySet(tree)
    }

    const verify = new VerifySignatures(tree, filterSet, this.npm, { ...opts })
    await verify.run()
    const result = verify.report()
    process.exitCode = process.exitCode || result.exitCode
    this.npm.output(result.report)
  }
}

module.exports = Audit
