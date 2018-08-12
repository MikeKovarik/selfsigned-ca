var {create, CertDescriptor} = require('./index.js')
var os = require('os')
var dns = require('dns')
var util = require('util')
dns.lookup = util.promisify(dns.lookup)


//create('localhost').then(console.log).catch(console.error)


loadOrCreateCerts()
	.then(createHttpsServer)
	.then(() => console.log('certificates ready, server listening'))
	.catch(console.error)

async function loadOrCreateCerts() {
	var caName = 'anchora.root-ca'
	var lanIp = (await dns.lookup(os.hostname())).address
	var devName = `anchora.localhost.${lanIp}`

	var caCertOptions = {
		days: 9999,
		algorithm: 'sha256',
		subject: {
			commonName: 'Anchora HTTP Server',
			organizationName: 'Mutiny',
		}
	}

	var devCertOptions = {
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

	var caCert  = new CertDescriptor(caName)
	var devCert = new CertDescriptor(devName)

	try {
		console.log('loading existing dev certificate')
		await devCert.load()
		console.log('loaded dev cert')
	} catch(err) {
		console.log('loading dev cert failed, creating new one')
		try {
			// Try to load and use existing CA certificate for signing.
			console.log('loading root CA certificate')
			await caCert.load()
			console.log('root CA loaded')
			if (!await caCert.isInstalled()) {
				console.log('installing root CA')
				await caCert.install()
				console.log('root CA installed')
			}
		} catch(err) {
			console.log(`couldn't load existing CA cert, creating new one`)
			// Couldn't load existing root CA certificate. Generate new one.
			await caCert.createRootCa(caCertOptions)
			console.log('created root CA')
			await caCert.save()
			// Install the newly created CA to device's keychain so that all dev certificates
			// signed by the CA are automatically trusted and green.
			console.log('installing root CA')
			await caCert.install()
			console.log('installed root CA')
		}
		console.log(`creating dev certificate for ${lanIp}`)
		await devCert.create(devCertOptions, caCert)
		console.log(`created dev cert`)
		await devCert.save()
	}

	return devCert
}

function createHttpsServer(devCert) {
	var https = require('https')
	var server = https.createServer(devCert, (req, res) => {
		res.writeHead(200)
		res.end('hello world\n')
	})
	server.listen(443)
}
