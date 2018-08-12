(function (global, factory) {
	typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports, require('node-forge'), require('path'), require('fs')) :
	typeof define === 'function' && define.amd ? define(['exports', 'node-forge', 'path', 'fs'], factory) :
	(factory((global['selfsigned-ca'] = {}),global['node-forge'],global.path,global.fs));
}(this, (function (exports,forge,path,_fs) { 'use strict';

	forge = forge && forge.hasOwnProperty('default') ? forge['default'] : forge;
	path = path && path.hasOwnProperty('default') ? path['default'] : path;
	_fs = _fs && _fs.hasOwnProperty('default') ? _fs['default'] : _fs;

	var fs = _fs.promises;


	const defaultOptions = {
		days: 365,
		keySize: 1024,
		algorithm: 'sha256',
	};

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
	}];

	const defaultSubject = {
		commonName: 'Test',
		countryName: 'Test',
		stateOrProvinceName: 'Test',
		localityName: 'Test',
		organizationName: 'Test',
		organizationalUnitName: 'Test',
		emailAddress: 'test@example.com'
	};

	function toNameValue(obj = {}) {
		return Object.keys(obj).map(key => ({
			name: key,
			value: obj[key]
		}))
	}

	function toPositiveHex(hexString) {
		var mostSiginficativeHexAsInt = parseInt(hexString[0], 16);
		if (mostSiginficativeHexAsInt < 8) return hexString
		mostSiginficativeHexAsInt -= 8;
		return mostSiginficativeHexAsInt.toString() + hexString.substring(1)
	}

	function getAlgorithm(options) {
		var algo = forge.md[options.algorithm];
		if (!algo)
			algo = forge.md[defaultOptions.algorithm];
		return algo.create()
	}

	function exec(command) {
		var cp = require('child_process');
		return new Promise((resolve, reject) => {
			cp.exec(command, (error, stdout, stderr) => {
				if (error || stderr)
					reject(error || stderr);
				else
					resolve(stdout);
			});
		})
	}

	async function ensureDirectory(directory) {
		try {
			await fs.stat(directory);
		} catch(err) {
			await fs.mkdir(directory);
		}
	}


	class CertDescriptor {

		constructor(name, dir = './cert') {
			this.name = name;
			this.dir = dir;
			this.crtPath = path.join(this.dir, this.name + '.crt');
			this.keyPath = path.join(this.dir, this.name + '.key');
		}

		generatePems() {
			if (this.keys) {
				this.private = forge.pki.privateKeyToPem(this.keys.privateKey);
				this.public  = forge.pki.publicKeyToPem(this.keys.publicKey);
			}
			if (this.certificate) {
				this.cert    = forge.pki.certificateToPem(this.certificate);
			}
			return this
		}

		async load() {
			this.cert = await fs.readFile(this.crtPath);
			this.key  = await fs.readFile(this.keyPath);
		}

		async save() {
			await ensureDirectory(this.dir);
			await fs.writeFile(this.crtPath, this.cert);
			await fs.writeFile(this.keyPath, this.key);
		}

		async install() {
			switch (process.platform) {
				case 'win32':
					await this.save();
					await exec(`certutil -addstore -user -f root "${this.crtPath}"`);
				case 'darwin':
					return // TODO
				default:
					// copy crt file to
					await ensureDirectory(`/usr/share/ca-certificates/extra/`);
					await fs.writeFile(`/usr/share/ca-certificates/extra/${this.name}.crt`, this.cert);
					//return exec('sudo update-ca-certificates')
			}
		}

		async isInstalled() {
			if (!this.certificate)
				await this.load();
			try {
				switch (process.platform) {
					case 'win32':
						var result = await exec(`certutil -verifystore -user root ${this.serialNumber}`);
						return result.includes(this.thumbPrint)
					case 'darwin':
						return // TODO
					default:
						return // TODO
				}
			} catch(err) {
				return false
			}
		}

		////////////////////////////

		init() {
			var options = Object.assign({}, defaultOptions, this.options);

			this.keys        = forge.pki.rsa.generateKeyPair({bits: options.keySize, workers: -1});
			this.certificate = forge.pki.createCertificate();

			if (options.serialNumber === undefined)
				options.serialNumber = toPositiveHex(forge.util.bytesToHex(forge.random.getBytesSync(9)));

			this.certificate.publicKey    = this.keys.publicKey;
			this.certificate.serialNumber = String(options.serialNumber);

			this.certificate.validity.notBefore = new Date();
			this.certificate.validity.notAfter  = new Date();
			this.certificate.validity.notAfter.setDate(this.certificate.validity.notBefore.getDate() + options.days);
		}

		async createRootCa(options = {}) {
			this.options = options;
			this.init();
			// All cert data we've got from user or we use defaults.
			var subject    = toNameValue(options.subject || defaultSubject);
			var issuer     = toNameValue(options.issuer || options.subject || defaultSubject);
			var extensions = [...caExtensions, ...(options.extensions || [])];
			// Inflate the cert with acquired data.
			this.certificate.setSubject(subject);
			this.certificate.setIssuer(issuer);
			this.certificate.setExtensions(extensions);
			// Finalize creating the cert and convert it to string PEM format.
			this.certificate.sign(this.privateKey, getAlgorithm(options));
			return this.generatePems()
		}

		// second argument caCert is optional and can be used if the certificate is to be signed
		// by another certificate. Root CA in this case.
		async create(options = {}, caCert) {
			// options argument can be replaced by commonName string (in most cases 'localhost')
			if (typeof options === 'string')
				options = {subject: {commonName: options}};
			this.options = options;
			this.init();
			// Add subject info (commonName of the domain). Use issuer info from CA cert.
			var subject    = toNameValue(options.subject || defaultSubject);
			var issuer     = caCert ? caCert.certificate.subject.attributes : subject;
			var extensions = options.extensions || [];
			// Inflate the cert with acquired data.
			this.certificate.setIssuer(issuer);
			this.certificate.setSubject(subject);
			this.certificate.setExtensions(extensions);
			// Finalize creating the cert and convert it to string PEM format.
			this.certificate.sign(caCert ? caCert.privateKey : this.privateKey, getAlgorithm(options));
			return this.generatePems()
		}

		////////////////////////////

		get serialNumber() {
			return this.certificate && this.certificate.serialNumber
		}

		get thumbPrint() {
			if (this._thumbPrint) return this._thumbPrint
			var asn = forge.pki.certificateToAsn1(this.certificate);
			var derBytes = forge.asn1.toDer(asn).getBytes();
			this._thumbPrint = forge.md.sha1.create().update(derBytes).digest().toHex();
			return this._thumbPrint
		}

		////////////////////////////

		// Alias for 'key' because HTTPS module accepts objects with {cert, key} props.
		get private() {return this.key}
		set private(key) {this.key = key;}

		////////////////////////////

		get privateKey() {
			if (this.keys) return this.keys.privateKey
			if (this._privateKey === undefined)
				this._privateKey = forge.pki.privateKeyFromPem(this.private);
			return this._privateKey
		}

		get publicKey() {
			if (this.keys) return this.keys.publicKey
			if (this._publicKey === undefined)
				this._publicKey = forge.pki.publicKeyFromPem(this.public);
			return this._publicKey
		}

		get certificate() {
			if (this._certificate) return this._certificate
			if (this.cert) return this._certificate = forge.pki.certificateFromPem(this.cert)
		}
		
		set privateKey(privateKey)   {this._privateKey  = privateKey;}
		set publicKey(publicKey)     {this._publicKey   = publicKey;}
		set certificate(certificate) {this._certificate = certificate;}

	}

	function createRootCa(options) {
		var cert  = new CertDescriptor();
		return cert.createRootCa(options)
	}

	function create(options, caCert) {
		var cert  = new CertDescriptor();
		return cert.create(options, caCert)
	}

	exports.CertDescriptor = CertDescriptor;
	exports.createRootCa = createRootCa;
	exports.create = create;

	Object.defineProperty(exports, '__esModule', { value: true });

})));
