var https = require('https')
//var {Cert} = require('selfsigned-ca')
var {Cert} = require('./index.js')


main().catch(console.error)

async function main() {

	var rootCaCert = new Cert('anchora.root-ca')

	await rootCaCert.load()
	console.log('root CA loaded')
	console.log('isInstalled()', await rootCaCert.isInstalled())

}
