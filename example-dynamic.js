var https = require('https')
//var {Cert} = require('selfsigned-ca')
var {Cert} = require('./index.js')
var os = require('os')
var dns = require('dns')
var util = require('util')
var path = require('path')
dns.lookup = util.promisify(dns.lookup)


main()

async function main() {
	var certs = await loadOrCreateCerts()
	console.log('CERTIFICATES READY')
	var server = https.createServer(certs, (req, res) => {
		res.writeHead(200)
		res.end('hello world\n')
	})
	server.listen(443, () => console.log('HTTPS server listening on port 433'))
}

async function loadOrCreateCerts() {

	// Single ROOT CA for the user.
	var rootCaCert = new Cert('testsrv.root-ca')
	// Create new certificate for each IP from which the server is hosted.
	var lanIp = (await dns.lookup(os.hostname())).address
	var serverCert = new Cert(`testsrv.localhost.${lanIp}`)

	var rootCaCertOptions = {
		days: 9999,
		algorithm: 'sha256',
		subject: {
			commonName: 'Test Server HTTP Server',
			organizationName: 'Mutiny',
		}
	}

	var serverCertOptions = {
		days: 9999,
		algorithm: 'sha256',
		subject: {
			commonName: lanIp,
		},
		extensions: [{
			name: 'subjectAltName',
			altNames: [
				{type: 2, value: 'localhost'}, // DNS
				{type: 7, ip: '127.0.0.1'}, // IP
				{type: 7, ip: lanIp}, // IP
			]
		}]
	}

	try {
		console.log('loading existing server certificate')
		await serverCert.load()
		console.log('loaded server cert')
	} catch(err) {
		console.log('loading server cert failed, creating new one')
		try {
			console.log('trying to load existing root CA certificate and use it for signing')
			await rootCaCert.load()
			console.log('root CA loaded')
			if (!await rootCaCert.isInstalled()) {
				console.log('installing root CA')
				await rootCaCert.install()
				console.log('root CA installed')
			}
		} catch(err) {
			// Couldn't load existing root CA certificate. Generate new one.
			console.log(`couldn't load existing CA cert, creating new one`)
			await rootCaCert.createRootCa(rootCaCertOptions)
			console.log('created root CA')
			await rootCaCert.save()
			console.log('saved root CA certificate at')
			console.log(path.join(process.cwd(), rootCaCert.crtPath))
			console.log(path.join(process.cwd(), rootCaCert.keyPath))
			try {
			// Install the newly created CA to device's keychain so that all server certificates
			// signed by the CA are automatically trusted and green.
			console.log('installing root CA')
			await rootCaCert.install()
			console.log('installed root CA')
			} catch(err) {
				console.log('root CA could not be installed & trusted on the device')
			}
		}
		console.log(`creating server certificate for ${lanIp}`)
		await serverCert.create(serverCertOptions, rootCaCert)
		console.log(`created server cert`)
		await serverCert.save()
		console.log('saved server certificate at')
		console.log(path.join(process.cwd(), serverCert.crtPath))
		console.log(path.join(process.cwd(), serverCert.keyPath))
	}

	return serverCert
}
