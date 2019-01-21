var https = require('https')
//var {create, createRootCa} = require('selfsigned-ca')
var {createRootCa} = require('../index.js')


var rootCaCert = createRootCa('My Personal CA')

console.log('\n')
console.log(rootCaCert.cert)
console.log('serialNumber:', rootCaCert.serialNumber)
console.log('commonName:  ', rootCaCert.options.subject.commonName)