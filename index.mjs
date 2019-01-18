import forge from 'node-forge'
import path from 'path'
import util from 'util'
import cp from 'child_process'
import _fs from 'fs'

var exec = util.promisify(cp.exec)

// not using fs.promise because we're supporting Node 8
var fs = {}
for (let [name, method] of Object.entries(_fs)) {
	if (typeof method === 'function')
		fs[name] = util.promisify(method)
}


const defaultOptions = {
	days: 365,
	keySize: 1024,
	algorithm: 'sha256',
}

const caExtensions = [{
	name: 'basicConstraints',
	cA: true
}, {
	name: 'keyUsage',
	keyCertSign: true,
	digitalSignature: true,
	nonRepudiation: true,
	keyEncipherment: true,
	dataEncipherment: true
}]

const defaultSubject = {
	commonName: 'Test',
	countryName: 'Test',
	stateOrProvinceName: 'Test',
	localityName: 'Test',
	organizationName: 'Test',
	organizationalUnitName: 'Test',
	emailAddress: 'test@example.com'
}

function toNameValue(obj = {}) {
	return Object.keys(obj).map(key => ({
		name: key,
		value: obj[key]
	}))
}

function toPositiveHex(hexString) {
	var mostSiginficativeHexAsInt = parseInt(hexString[0], 16)
	if (mostSiginficativeHexAsInt < 8) return hexString
	mostSiginficativeHexAsInt -= 8
	return mostSiginficativeHexAsInt.toString() + hexString.substring(1)
}

function getAlgorithm(options) {
	var algo = forge.md[options.algorithm]
	if (!algo)
		algo = forge.md[defaultOptions.algorithm]
	return algo.create()
}

async function ensureDirectory(directory) {
	try {
		await fs.stat(directory)
	} catch(err) {
		await fs.mkdir(directory)
	}
}


// https://manuals.gfi.com/en/kerio/connect/content/server-configuration/ssl-certificates/adding-trusted-root-certificates-to-the-server-1605.html
export class CertStore {

	static _processArg(input) {
		if (typeof input === 'string') {
			input = {crtPath: input}
		}
		var {name, serialNumber} = input
		var crtPath = input.crtPath || input.path
		//var hash = input.thumbPrint || input.hash
		//if (hash) hash = hash.toLowerCase()
		if (name) {
			if (name.endsWith('.crt') && name.endsWith('.cer'))
				var filename = name.slice(0, -4)
			else if (name.endsWith('.cert'))
				var filename = name.slice(0, -5)
			else
				var filename = name
		} else {
			var filename = path.parse(crtPath).base
		}
		var output = {
			crtPath,
			filename,
			serialNumber,
			//hash,
			cert: input.cert || input.data,
		}
		return output
	}

	static async install(arg) {
		arg = this._processArg(arg)
		switch (process.platform) {
			case 'win32':
				if (arg.crtPath) {
					await exec(`certutil -addstore -user -f root "${arg.crtPath}"`)
				} else if (arg.cert) {
					var tempPath = `temp-${Date.now()}-${Math.random()}.crt`
					await fs.writeFile(tempPath, arg.cert)
					await exec(`certutil -addstore -user -f root "${tempPath}"`)
					await fs.unlink(tempPath)
				} else {
					throw new Error('path to or contents of the certificate has to be defined.')
				}
				return
			case 'darwin':
				console.warn('selfsigned-ca: CertStore.install() not yet implemented on this platform')
				return // TODO
			default:
				// copy crt file to
				await ensureDirectory(`/usr/share/ca-certificates/extra/`)
				await fs.writeFile(`/usr/share/ca-certificates/extra/${arg.filename}`, arg.cert)
				await exec('update-ca-certificates')
				//await exec('sudo update-ca-certificates')
				return
		}
	}

	static async isInstalled(arg) {
		arg = this._processArg(arg)
		switch (process.platform) {
			case 'win32':
				try {
					//await exec(`certutil -verifystore -user root ${arg.serialNumber}`)
					let {stdout} = await exec(`certutil -verifystore -user root ${arg.serialNumber}`)
					console.log(stdout)
					//return stdout.toLowerCase().includes(arg.hash)
					return true
				} catch(err) {
					return false
				}
			case 'darwin':
				console.warn('selfsigned-ca: CertStore.isInstalled() not yet implemented on this platform')
				return // TODO
			default:
				return !!(await this._findLinuxCert(arg))
		}
	}

	static async delete() {
		switch (process.platform) {
			case 'win32':
				console.warn('selfsigned-ca: CertStore.delete() not yet implemented on this platform')
				return // TODO
			case 'darwin':
				console.warn('selfsigned-ca: CertStore.delete() not yet implemented on this platform')
				return // TODO
			default:
				var filepath = await this._findLinuxCert(arg)
				if (filepath) await fs.unlink(filepath)
				return false
		}
	}

	// Only works on linux (ubuntu, debian).
	// Finds certificate in /usr/share/ca-certificates/extra/ by its serial number.
	// Returns path to the certificate if found, otherwise undefined.
	static async _findLinuxCert(arg) {
		let filenames = await fs.readdir(`/usr/share/ca-certificates/extra/`)
		for (let filename of filenames) {
			let filepath = `/usr/share/ca-certificates/extra/${filename}`
			let pem = (await fs.readFile(filepath)).toString()
			let cert = forge.pki.certificateFromPem(pem)
			if (arg.serialNumber === cert.serialNumber) return filepath
		}
	}

}


export class Cert {

	constructor(crtPath, keyPath) {
		if (crtPath !== undefined)
			this.handleNameAndPath(crtPath, keyPath)
	}

	handleNameAndPath(crtPath, keyPath) {
		var {dir, base, ext, name} = path.parse(crtPath)
		if (ext !== '.crt' && ext !== '.cer' && ext !== '.cert') {
			name = base
			ext = '.crt'
		}
		this.name = name
		this.crtPath = path.join(dir, name + ext)
		this.keyPath = keyPath || path.join(dir, name + '.key')
	}

	generatePems() {
		if (this.keys) {
			this.private = forge.pki.privateKeyToPem(this.keys.privateKey)
			this.public  = forge.pki.publicKeyToPem(this.keys.publicKey)
		}
		if (this.certificate) {
			this.cert    = forge.pki.certificateToPem(this.certificate)
		}
		return this
	}

	async load() {
		var [cert, key] = await Promise.all([
			fs.readFile(this.crtPath),
			fs.readFile(this.keyPath)
		])
		this.cert = cert
		this.key  = key
	}

	async save() {
		await Promise.all([
			Promise.all([
				ensureDirectory(path.dirname(this.crtPath)),
				fs.writeFile(this.crtPath, this.cert),
			]),
			Promise.all([
				ensureDirectory(path.dirname(this.keyPath)),
				fs.writeFile(this.keyPath, this.key)
			])
		])
	}

	async install() {
		await this.save()
		await CertStore.install(this)
	}

	async isInstalled() {
		try {
			if (!this.certificate) await this.load()
			return await CertStore.isInstalled(this)
		} catch(err) {
			console.error(err)
			return false
		}
	}

	////////////////////////////

	init() {
		var options = Object.assign({}, defaultOptions, this.options)

		this.keys        = forge.pki.rsa.generateKeyPair({bits: options.keySize, workers: -1})
		this.certificate = forge.pki.createCertificate()

		if (options.serialNumber === undefined)
			options.serialNumber = toPositiveHex(forge.util.bytesToHex(forge.random.getBytesSync(9)))

		this.certificate.publicKey    = this.keys.publicKey
		this.certificate.serialNumber = String(options.serialNumber)

		this.certificate.validity.notBefore = new Date()
		this.certificate.validity.notAfter  = new Date()
		this.certificate.validity.notAfter.setDate(this.certificate.validity.notBefore.getDate() + options.days)
	}

	async createRootCa(options = {}) {
		this.options = options
		this.init()
		// All cert data we've got from user or we use defaults.
		var subject    = toNameValue(options.subject || defaultSubject)
		var issuer     = toNameValue(options.issuer || options.subject || defaultSubject)
		var extensions = [...caExtensions, ...(options.extensions || [])]
		// Inflate the cert with acquired data.
		this.certificate.setSubject(subject)
		this.certificate.setIssuer(issuer)
		this.certificate.setExtensions(extensions)
		// Finalize creating the cert and convert it to string PEM format.
		this.certificate.sign(this.privateKey, getAlgorithm(options))
		return this.generatePems()
	}

	// second argument caCert is optional and can be used if the certificate is to be signed
	// by another certificate. Root CA in this case.
	async create(options = {}, caCert) {
		// options argument can be replaced by commonName string (in most cases 'localhost')
		if (typeof options === 'string')
			options = {subject: {commonName: options}}
		this.options = options
		this.init()
		// Add subject info (commonName of the domain). Use issuer info from CA cert.
		var subject    = toNameValue(options.subject || defaultSubject)
		var issuer     = caCert ? caCert.certificate.subject.attributes : subject
		var extensions = options.extensions || []
		// Inflate the cert with acquired data.
		this.certificate.setIssuer(issuer)
		this.certificate.setSubject(subject)
		this.certificate.setExtensions(extensions)
		// Finalize creating the cert and convert it to string PEM format.
		this.certificate.sign(caCert ? caCert.privateKey : this.privateKey, getAlgorithm(options))
		return this.generatePems()
	}

	////////////////////////////

	get serialNumber() {
		return this.certificate && this.certificate.serialNumber
	}

	get thumbPrint() {
		if (this._thumbPrint) return this._thumbPrint
		var asn = forge.pki.certificateToAsn1(this.certificate)
		var derBytes = forge.asn1.toDer(asn).getBytes()
		this._thumbPrint = forge.md.sha1.create().update(derBytes).digest().toHex()
		return this._thumbPrint
	}

	get hash() {
		return this.thumbPrint
	}

	////////////////////////////

	// Alias for 'key' because HTTPS module accepts objects with {cert, key} props.
	get private() {return this.key}
	set private(key) {this.key = key}

	////////////////////////////

	get privateKey() {
		if (this.keys) return this.keys.privateKey
		if (this._privateKey === undefined)
			this._privateKey = forge.pki.privateKeyFromPem(this.private)
		return this._privateKey
	}

	get publicKey() {
		if (this.keys) return this.keys.publicKey
		if (this._publicKey === undefined)
			this._publicKey = forge.pki.publicKeyFromPem(this.public)
		return this._publicKey
	}

	get certificate() {
		if (this._certificate) return this._certificate
		if (this.cert) return this._certificate = forge.pki.certificateFromPem(this.cert)
	}
	
	set privateKey(privateKey)   {this._privateKey  = privateKey}
	set publicKey(publicKey)     {this._publicKey   = publicKey}
	set certificate(certificate) {this._certificate = certificate}

}

export function createRootCa(...args) {
	// name is optional and only needed if certs are stored to/loaded from fs.
	var [options, name] = args.reverse()
	var cert = new Cert(name)
	return cert.createRootCa(options)
}

export function create(...args) {
	// name is optional and only needed if certs are stored to/loaded from fs.
	var [caCert, options, name] = args.reverse()
	var cert = new Cert(name)
	return cert.create(options, caCert)
}
