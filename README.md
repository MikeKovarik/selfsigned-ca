# selfsigned-ca

🔑 Generate self-signed certificates, keys and Root CA for use in HTTPS servers.

## Installation

```js
npm install selfsigned-ca
```

## Usage

Following demo creates CA Root certificate and uses it to sign second certificate which is then used to start HTTPS server with. CA Root certificate is also installed to system's keychain so that all signed certs are automatically trusted. On a second run, the localhost certificate is loaded and used straight away or new one is generated and signed.

```js
var https = require('https')
var {Cert} = require('selfsigned-ca')

// Root CA certificate used to sign other certificates.
// argument(s) point to .crt and .key file paths - ./selfsigned.root-ca.crt & ./selfsigned.root-ca.key
var rootCaCert  = new Cert('selfsigned.root-ca')
// The certificate generated for use in the HTTP server. It is signed by the CA certificate.
// That way you can create any amount of certificates and they will be all trusted as long
// as the Root CA certificate is trusted (installed to device's keychain).
// argument(s) point to .crt and .key file paths - ./selfsigned.localhost.crt & ./selfsigned.localhost.key
var serverCert = new Cert(`selfsigned.localhost`)

serverCert.load()
  .catch(createCertificate)
  .then(startHttpsServer)
  .then(() => console.log('certificates ready, server listening'))
  .catch(console.error)

async function createCertificate() {
  try {
    // Try to load and use existing CA certificate for signing.
    console.log('loading root CA certificate')
    await loadRootCertificate()
  } catch(err) {
    console.log(`couldn't load existing CA cert, creating new one`)
    await createRootCertificate()
    console.log(`Root CA certificate created, stored and installed`)
  }
  console.log('creating server certificate')
  createServerCertificate()
  console.log('server certificate created & stored')
}

function startHttpsServer() {
  var server = https.createServer(serverCert, (req, res) => {
    res.writeHead(200)
    res.end('hello world\n')
  })
  server.listen(443)
}

async function loadRootCertificate() {
  await rootCaCert.load()
  if (!await rootCaCert.isInstalled()) {
    // Make sure the CA is installed to device's keychain so that all server certificates
    // signed by the CA are automatically trusted and green.
    await rootCaCert.install()
  }
}

async function createRootCertificate() {
  // Couldn't load existing root CA certificate. Generate new one.
  rootCaCert.createRootCa({
    subject: {
      commonName: 'My Trusted Certificate Authority',
    }
  })
  await rootCaCert.save()
  // Install the newly created CA to device's keychain so that all server certificates
  // signed by the CA are automatically trusted and green.
  await rootCaCert.install()
}

async function createServerCertificate() {
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
  serverCert.create(serverCertOptions, rootCaCert)
  await serverCert.save()
}

```

## License

MIT, Mike Kovařík, Mutiny.cz