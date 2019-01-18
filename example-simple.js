var https = require('https')
var {create, createRootCa} = require('selfsigned-ca')


createCertificates()
	.then(createHttpsServer)
	.then(() => console.log('certificates ready, server listening'))
	.catch(console.error)

async function createCertificates() {

	var rootCaCertOptions = {
		subject: {
			commonName: 'My Trusted Certificate Authority',
		}
	}

	var serverCertOptions = {
		subject: {
			commonName: 'localhost',
		},
		extensions: [{
			name: 'subjectAltName',
			altNames: [
				{type: 2, value: 'localhost'}, // DNS
				{type: 7, ip: '127.0.0.1'}, // IP
			]
		}]
	}

	console.log('creating root CA cert')
	var rootCaCert = await createRootCa(rootCaCertOptions)
	console.log('CA certificate was just created, on installed. HTTPS connection will be untrusted by the browser')
	console.log('creating server certificate and signing it using CA cert')
	var serverCert = await create(serverCertOptions, rootCaCert)
	console.log('certifiactes ready')

	return serverCert
}

function createHttpsServer(serverCert) {
	var server = https.createServer(serverCert, (req, res) => {
		res.writeHead(200)
		res.end('hello world\n')
	})
	server.listen(443)
}
