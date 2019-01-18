var https = require('https')
//var {Cert} = require('selfsigned-ca')
var {CertStore} = require('./index.js')


main().catch(console.error)

async function main() {

	var result = await CertStore.isInstalled('./anchora.root-ca.crt')
	console.log('isInstalled()', result)

}
