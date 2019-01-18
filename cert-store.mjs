import cp from 'child_process'


var exec = util.promisify(cp.exec)

// not using fs.promise because we're supporting Node 8.
var fs = {}
for (let [name, method] of Object.entries(_fs)) {
	if (typeof method === 'function')
		fs[name] = util.promisify(method)
}

// https://manuals.gfi.com/en/kerio/connect/content/server-configuration/ssl-certificates/adding-trusted-root-certificates-to-the-server-1605.html
export class CertStore {

	static _processArg(input) {
		if (typeof input === 'string') {
			input = {crtPath: input}
		}
		var {name, serialNumber} = input
		var crtPath = input.crtPath || input.path
		//var hash = input.thumbPrint || input.hash
		//if (hash) hash = hash.toLowerCase()
		if (name) {
			if (name.endsWith('.crt') && name.endsWith('.cer'))
				var filename = name.slice(0, -4)
			else if (name.endsWith('.cert'))
				var filename = name.slice(0, -5)
			else
				var filename = name
		} else {
			var filename = path.parse(crtPath).base
		}
		var output = {
			crtPath,
			filename,
			serialNumber,
			//hash,
			cert: input.cert || input.data,
		}
		return output
	}

	// Only works on linux (ubuntu, debian).
	// Finds certificate in /usr/share/ca-certificates/extra/ by its serial number.
	// Returns path to the certificate if found, otherwise undefined.
	static async _findLinuxCert(arg) {
		let filenames = await fs.readdir(`/usr/share/ca-certificates/extra/`)
		for (let filename of filenames) {
			let filepath = `/usr/share/ca-certificates/extra/${filename}`
			let pem = (await fs.readFile(filepath)).toString()
			let cert = forge.pki.certificateFromPem(pem)
			if (arg.serialNumber === cert.serialNumber) return filepath
		}
	}

	_readCertFromPem(filepath) {
	}

	static async install(arg) {
		arg = this._processArg(arg)
		switch (process.platform) {
			case 'win32':
				if (arg.crtPath) {
					await exec(`certutil -addstore -user -f root "${arg.crtPath}"`)
				} else if (arg.cert) {
					var tempPath = `temp-${Date.now()}-${Math.random()}.crt`
					await fs.writeFile(tempPath, arg.cert)
					await exec(`certutil -addstore -user -f root "${tempPath}"`)
					await fs.unlink(tempPath)
				} else {
					throw new Error('path to or contents of the certificate has to be defined.')
				}
				return
			case 'darwin':
				console.warn('selfsigned-ca: CertStore.install() not yet implemented on this platform')
				return // TODO
			default:
				// copy crt file to
				await ensureDirectory(`/usr/share/ca-certificates/extra/`)
				await fs.writeFile(`/usr/share/ca-certificates/extra/${arg.filename}`, arg.cert)
				await exec('update-ca-certificates')
				//await exec('sudo update-ca-certificates')
				return
		}
	}

	static async isInstalled(arg) {
		arg = this._processArg(arg)
		switch (process.platform) {
			case 'win32':
				try {
					//await exec(`certutil -verifystore -user root ${arg.serialNumber}`)
					let {stdout} = await exec(`certutil -verifystore -user root ${arg.serialNumber}`)
					console.log(stdout)
					//return stdout.toLowerCase().includes(arg.hash)
					return true
				} catch(err) {
					return false
				}
			case 'darwin':
				console.warn('selfsigned-ca: CertStore.isInstalled() not yet implemented on this platform')
				return // TODO
			default:
				return !!(await this._findLinuxCert(arg))
		}
	}

	static async delete() {
		switch (process.platform) {
			case 'win32':
				console.warn('selfsigned-ca: CertStore.delete() not yet implemented on this platform')
				return // TODO
			case 'darwin':
				console.warn('selfsigned-ca: CertStore.delete() not yet implemented on this platform')
				return // TODO
			default:
				var filepath = await this._findLinuxCert(arg)
				if (filepath) await fs.unlink(filepath)
				return false
		}
	}

}