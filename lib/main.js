const {Cc, Ci, Cr, Cu} = require('chrome');

var {setTimeout} = require('sdk/timers');

var self = require('sdk/self');

var HASHES = require('hardcoded-hashes/hashes.js');

var hex = require('asn1js/hex');
var asn1 = require('asn1js/asn1');

function CCIN(cName, ifaceName) {
	return Cc[cName].createInstance(Ci[ifaceName]);
}

function HCSChecker() {}
HCSChecker.prototype = {
	start: function() {
		var observerService = Cc['@mozilla.org/observer-service;1'].getService(Ci.nsIObserverService);
		observerService.addObserver(this, 'http-on-examine-response', false);
	},
	stop: function() {
		var observerService = Cc['@mozilla.org/observer-service;1'].getService(Ci.nsIObserverService);
		observerService.removeObserver(this, 'http-on-examine-response');
	},
	observe: function(aSubject, aTopic, aData) {
		if(aTopic === 'http-on-examine-response') {
			aSubject.QueryInterface(Ci.nsIHttpChannel);
			var uri = aSubject.URI;
			if(uri.scheme === 'https') {
				var win = this.getWindowForRequest(aSubject);
				if(win) {
					var hashes;
					var certificate = this.getCertificate(win);
					var loadedCertificate = !!certificate;
					var _this = this;
					if(loadedCertificate) {
						hashes = this.getHashesInCertificate(certificate) || this.getHardcodedHashes(aSubject, certificate);
					} else { // First request to a website.
						setTimeout(function() {
							certificate = _this.getCertificate(win);
							hashes = _this.getHashesInCertificate(certificate) || _this.getHardcodedHashes(aSubject, certificate);
							loadedCertificate = true;
						});
					}
					if(hashes || !loadedCertificate) {
						aSubject.QueryInterface(Ci.nsITraceableChannel);
						var newListener = new HCSChecker.TracingListener();
						newListener.originalListener = aSubject.setNewListener(newListener);
						newListener.checkResponse = function checkResponse(responseData, callback) {
							if(!loadedCertificate) {
								setTimeout(function() {
									checkResponse(responseData, callback);
								});
								return;
							}
							var isResponseValid = _this.isResponseValid(aSubject, hashes, responseData);
							callback(isResponseValid);
							if(!isResponseValid) {
								aSubject.cancel(Cr.NS_BINDING_ABORTED);
								_this.showSecurityError(aSubject, win);
							}
						};
					}
				}
			}
		}
	},
	isResponseValid: function(oHttp, hashes, responseData) {
		if(!hashes) return true;
		var path = oHttp.URI.path;
		if(!hashes.hasOwnProperty(path)) return true;
		var _this = this;
		return hashes[path].some(function(elm) {
			var [algo, hash] = elm.split('-');
			return _this.algorithmSupported(algo) && _this.computeHash(algo, responseData) === hash;
		});
	},
	algorithmSupported: function(algo) {
		return algo === 'sha256';
	},
	computeHash: function(algo, str) {
		var converter = CCIN('@mozilla.org/intl/scriptableunicodeconverter', 'nsIScriptableUnicodeConverter');
		converter.charset = 'UTF-8';
		var result = {};
		var data = converter.convertToByteArray(str, result);
		
		var ch = CCIN('@mozilla.org/security/hash;1', 'nsICryptoHash');
		ch.init(ch.SHA256);
		ch.update(data, data.length);
		var hash = ch.finish(false);
		function toHexString(charCode) {
			return ('0' + charCode.toString(16)).slice(-2);
		}
		return [toHexString(hash.charCodeAt(i)) for (i in hash)].join('');
	},
	getHardcodedHashes: function(oHttp, certificate) {
		var domain = oHttp.URI.prePath.replace(/^https?:\/\//, '');
		return HASHES[domain] && HASHES[domain][certificate.sha256Fingerprint];
	},
	getHashesInCertificate: function(certificate) {
		
		/**
		 * TODO: Find another way of extracting this information.
		 * The current method is a giant hack because:
		 * - `nsIASN1Object` is meant for displaying a certificate in UI, not for extracting information
		 * - we depend on strings meant for UI
		 * - on top of that, it doesn't expose extensions as `nsIASN1Sequence`s, thus we manually parse them
		 */
		
		var struc = certificate.ASN1Structure.QueryInterface(Ci.nsIASN1Sequence);
		
		var tbsCertificate = struc.ASN1Objects.queryElementAt(0, Ci.nsIASN1Sequence, tbsCertificate);
		
		var tbsCertificateEnumerator = tbsCertificate.ASN1Objects.enumerate();
		
		if(tbsCertificate.ASN1Objects.length >= 8) {
			for(var i = 0; tbsCertificateEnumerator.hasMoreElements(); i++) {
				var next = tbsCertificateEnumerator.getNext();
				if(i >= 7) {
					next.QueryInterface(Ci.nsIASN1Object);
					if(next.displayName === 'Extensions') {
						var extensions = next.QueryInterface(Ci.nsIASN1Sequence);
						
						var extensionsEnumerator = extensions.ASN1Objects.enumerate();
						
						while(extensionsEnumerator.hasMoreElements()) {
							var extension = extensionsEnumerator.getNext().QueryInterface(Ci.nsIASN1Object);
							
							if(extension.displayName === 'Object Identifier (2 5 29 66)') {
								var decoded = asn1.decode(hex.decode(extension.displayValue.split('Bits')[1].replace(/\s/g, '')));
								
								var hashes = {};
								
								decoded.sub.forEach(function(hashElm) {
									var path = hashElm.sub[0].content();
									if(!hashes[path]) {
										hashes[path] = [];
									}
									hashes[path].push(hashElm.sub[1].content());
								});
								
								return hashes;
							}
						}
					}
				}
			}
		}
	},
	getCertificate: function(win) {
		// Source: Certificate Watch
		
		var serverCert;

		var browser = this.getBrowserForWindow(win);
		if (!browser)
			return

		var securityUI = browser.securityUI;
		if (!securityUI)
			return;

		var sslStatusProvider = securityUI.QueryInterface(Ci.nsISSLStatusProvider);
		if (!sslStatusProvider)
			return;

		var sslStatus = sslStatusProvider.SSLStatus;
		if (!sslStatus)
			return;

		var sslStatusStruct = sslStatus.QueryInterface(Ci.nsISSLStatus);
		if (!sslStatusStruct)
			return;

		serverCert = sslStatusStruct.serverCert;
		if (!serverCert)
			return;
		
		return serverCert;
	},
	showSecurityError: function(oHttp, win) {
		if(win) {
			win.location = self.data.url('pages/securityError.html') + '?uri=' + encodeURIComponent(encodeURIComponent(oHttp.URI.spec));
		}
	},
	getWindowForRequest: function(request){
		// Source: http://stackoverflow.com/questions/10719606/is-it-possible-to-know-the-target-domwindow-for-an-httprequest
		if (request instanceof Ci.nsIRequest){
			try{
				if (request.notificationCallbacks){
					return request.notificationCallbacks
							.getInterface(Ci.nsILoadContext)
							.associatedWindow;
				}
			} catch(e) {}
			try{
				if (request.loadGroup && request.loadGroup.notificationCallbacks){
					return request.loadGroup.notificationCallbacks
							.getInterface(Ci.nsILoadContext)
							.associatedWindow;
				}
			} catch(e) {}
		}
		return null;
	},
	getBrowserForWindow: function(contentWindow) {
		if(contentWindow) {
			var aDOMWindow = contentWindow.top.QueryInterface(Ci.nsIInterfaceRequestor).getInterface(Ci.nsIWebNavigation).QueryInterface(Ci.nsIDocShellTreeItem).rootTreeItem.QueryInterface(Ci.nsIInterfaceRequestor).getInterface(Ci.nsIDOMWindow);
			var gBrowser = aDOMWindow.gBrowser; //this is the gBrowser object of the firefox window this tab is in
			var aTab = gBrowser._getTabForContentWindow(contentWindow.top); //this is the clickable tab xul element, the one found in the tab strip of the firefox window, aTab.linkedBrowser is same as browser var above //can stylize tab like aTab.style.backgroundColor = 'blue'; //can stylize the tab like aTab.style.fontColor = 'red';
			var browser = aTab.linkedBrowser; //this is the browser within the tab //this is what the example in the previous section gives
			return browser;
		}
	}
};

HCSChecker.TracingListener = function(hcschecker) {
	this.receivedData = [];
};
HCSChecker.TracingListener.prototype = {
	onStartRequest: function(request, context) {
		this.originalListener.onStartRequest(request, context);
	},
	onDataAvailable: function(request, context, inputStream, offset, count) {
		var binaryInputStream = CCIN('@mozilla.org/binaryinputstream;1',
				'nsIBinaryInputStream');
		var storageStream = CCIN('@mozilla.org/storagestream;1', 'nsIStorageStream');
		var binaryOutputStream = CCIN('@mozilla.org/binaryoutputstream;1',
				'nsIBinaryOutputStream');

		binaryInputStream.setInputStream(inputStream);
		storageStream.init(8192, count, null);
		binaryOutputStream.setOutputStream(storageStream.getOutputStream(0));

		// Copy received data as they come.
		var data = binaryInputStream.readBytes(count);
		this.receivedData.push(data);

		binaryOutputStream.writeBytes(data, count);

		this.originalListener.onDataAvailable(request, context,
			storageStream.newInputStream(0), offset, count);
	},
	onStopRequest: function(request, context, statusCode) {
		var responseData = this.receivedData.join('');
		var _this = this;
		this.checkResponse(responseData, function(isResponseValid) {
			if(isResponseValid) {
				_this.originalListener.onStopRequest(request, context, statusCode);
			}
		});
	}
};

var hcschecker = new HCSChecker();
hcschecker.start();