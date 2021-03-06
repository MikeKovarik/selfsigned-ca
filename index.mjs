import forge from 'node-forge'
import path from 'path'
import util from 'util'
import _fs from 'fs'
import rootstore from 'cert-store'


// not using fs.promise because we're supporting Node 8.
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
		await rootstore.install(this)
	}

	async isInstalled() {
		if (!this.certificate) await this.load()
		return await rootstore.isInstalled(this)
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

	_applyOptions(options = {}) {
		// options argument can be replaced by commonName string (in most cases 'localhost')
		if (typeof options === 'string')
			this.options = {subject: {commonName: options}}
		else
			this.options = options
	}

	createRootCa(options) {
		this._applyOptions(options)
		this.init()
		// All cert data we've got from user or we use defaults.
		var subject    = toNameValue(this.options.subject || defaultSubject)
		var issuer     = toNameValue(this.options.issuer || this.options.subject || defaultSubject)
		var extensions = [...caExtensions, ...(this.options.extensions || [])]
		// Inflate the cert with acquired data.
		this.certificate.setSubject(subject)
		this.certificate.setIssuer(issuer)
		this.certificate.setExtensions(extensions)
		// Finalize creating the cert and convert it to string PEM format.
		this.certificate.sign(this.privateKey, getAlgorithm(this.options))
		return this.generatePems()
	}

	// second argument caCert is optional and can be used if the certificate is to be signed
	// by another certificate. Root CA in this case.
	create(options, caCert) {
		this._applyOptions(options)
		this.init()
		// Add subject info (commonName of the domain). Use issuer info from CA cert.
		var subject    = toNameValue(this.options.subject || defaultSubject)
		var issuer     = caCert ? caCert.certificate.subject.attributes : subject
		var extensions = this.options.extensions || []
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
