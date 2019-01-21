var https = require('https')
//var {create, createRootCa} = require('selfsigned-ca')
var {create, createRootCa} = require('../index.js')


createCertificates()
	.then(createHttpsServer)
	.then(() => console.log('certificates ready, server listening'))
	.catch(console.error)

async function createCertificates() {

	var rootCaCertOptions = {
		subject: {
			commonName: 'My TEST Certificate Authority',
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
	var rootCaCert = createRootCa(rootCaCertOptions)
	console.log('CA certificate was just created, but not installed. HTTPS connection will be untrusted by the browser')
	console.log('creating server certificate and signing it using CA cert')
	var serverCert = create(serverCertOptions, rootCaCert)
	console.log('certifiactes ready')

	console.log('rootCaCert.serialNumber', rootCaCert.serialNumber)
	console.log('rootCaCert.thumbPrint', rootCaCert.thumbPrint)

	return serverCert
}

function createHttpsServer(serverCert) {
	var server = https.createServer(serverCert, (req, res) => {
		res.writeHead(200)
		res.end('hello world\n')
	})
	server.listen(443)
}
