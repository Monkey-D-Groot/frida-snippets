from builtins import object

import frida, sys

a = dict()


def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        request_line = str(payload).split("\n")[0]
        if request_line not in a:
            print(payload)
            a[request_line] = 1
    else:
        print(message)


myviettel = """
Java.perform(function() {
    var String = Java.use("java.lang.String");
    var Arrays = Java.use("java.util.Arrays");
    var FormBody = Java.use('okhttp3.FormBody');
    var Buffer = Java.use('okio.Buffer');
    var Charset = Java.use('java.nio.charset.Charset');
    var CaptchaModel = Java.use('com.vttm.myviettel.model.CaptchaModel');
    var Thread = Java.use("java.lang.Thread");
    var Arrays = Java.use("java.util.Arrays");
    Java.use('okhttp3.internal.http.RealInterceptorChain').proceed.overload('okhttp3.Request', 'okhttp3.internal.connection.StreamAllocation', 'okhttp3.internal.http.HttpCodec', 'okhttp3.internal.connection.RealConnection').implementation = function(s1,s2,s3,s4) {
        try{
            var body = Java.cast(s1.body(),FormBody);
            var i;
            var queryString = "";
            for (i = 0; i < body.size(); i++) {
                queryString = queryString + body.name(i) + "=" + body.value(i) + "&";
            }
            if(s1.headers().toString().trim().length > 0){
                var dataPrint =  s1.method() + " " + s1.url() + "\\n" + s1.headers().toString() + "\\n" + queryString;
                send(dataPrint);
            }
        }
        catch(err){
            send(err);
        }
        return this.proceed(s1,s2,s3,s4);;
    }
});
"""
objection = """
setTimeout(function() {
	Java.perform(function () {
		console.log('');
		console.log('======');
		console.log('[#] Android Bypass for various Certificate Pinning methods [#]');
		console.log('======');


		var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
		var SSLContext = Java.use('javax.net.ssl.SSLContext');
	
		
		// TrustManager (Android < 7) //
		////////////////////////////////
		var TrustManager = Java.registerClass({
			// Implement a custom TrustManager
			name: 'dev.asd.test.TrustManager',
			implements: [X509TrustManager],
			methods: {
				checkClientTrusted: function (chain, authType) {},
				checkServerTrusted: function (chain, authType) {},
				getAcceptedIssuers: function () {return []; }
			}
		});
		// Prepare the TrustManager array to pass to SSLContext.init()
		var TrustManagers = [TrustManager.$new()];
		// Get a handle on the init() on the SSLContext class
		var SSLContext_init = SSLContext.init.overload(
			'[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
		try {
			// Override the init method, specifying the custom TrustManager
			SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
				console.log('[+] Bypassing Trustmanager (Android < 7) request');
				SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
			};
		} catch (err) {
			console.log('[-] TrustManager (Android < 7) pinner not found');
			//console.log(err);
		}

	 
	
		// OkHTTPv3 (quadruple bypass) //
		/////////////////////////////////
		try {
			// Bypass OkHTTPv3 {1}
			var okhttp3_Activity_1 = Java.use('okhttp3.CertificatePinner');    
			okhttp3_Activity_1.check.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
				console.log('[+] Bypassing OkHTTPv3 {1}: ' + a);
				return;
			};
		} catch (err) {
			console.log('[-] OkHTTPv3 {1} pinner not found');
			//console.log(err);
		}
		try {
			// Bypass OkHTTPv3 {2}
			// This method of CertificatePinner.check could be found in some old Android app
			var okhttp3_Activity_2 = Java.use('okhttp3.CertificatePinner');    
			okhttp3_Activity_2.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (a, b) {
				console.log('[+] Bypassing OkHTTPv3 {2}: ' + a);
				return;
			};
		} catch (err) {
			console.log('[-] OkHTTPv3 {2} pinner not found');
			//console.log(err);
		}
		try {
			// Bypass OkHTTPv3 {3}
			var okhttp3_Activity_3 = Java.use('okhttp3.CertificatePinner');    
			okhttp3_Activity_3.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (a, b) {
				console.log('[+] Bypassing OkHTTPv3 {3}: ' + a);
				return;
			};
		} catch(err) {
			console.log('[-] OkHTTPv3 {3} pinner not found');
			//console.log(err);
		}
		try {
			// Bypass OkHTTPv3 {4}
			var okhttp3_Activity_4 = Java.use('okhttp3.CertificatePinner');    
			okhttp3_Activity_4['check$okhttp'].implementation = function (a, b) {
				console.log('[+] Bypassing OkHTTPv3 {4}: ' + a);
			};
		} catch(err) {
			console.log('[-] OkHTTPv3 {4} pinner not found');
			//console.log(err);
		}

	
	
		// Trustkit (triple bypass) //
		//////////////////////////////
		try {
			// Bypass Trustkit {1}
			var trustkit_Activity_1 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
			trustkit_Activity_1.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (a, b) {
				console.log('[+] Bypassing Trustkit {1}: ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] Trustkit {1} pinner not found');
			//console.log(err);
		}
		try {
			// Bypass Trustkit {2}
			var trustkit_Activity_2 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
			trustkit_Activity_2.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (a, b) {
				console.log('[+] Bypassing Trustkit {2}: ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] Trustkit {2} pinner not found');
			//console.log(err);
		}
		try {
			// Bypass Trustkit {3}
			var trustkit_PinningTrustManager = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
			trustkit_PinningTrustManager.checkServerTrusted.implementation = function () {
				console.log('[+] Bypassing Trustkit {3}');
			};
		} catch (err) {
			console.log('[-] Trustkit {3} pinner not found');
			//console.log(err);
		}
		
	
	
  
		// TrustManagerImpl (Android > 7) //
		////////////////////////////////////
		try {
			var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
			TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
				console.log('[+] Bypassing TrustManagerImpl (Android > 7): ' + host);
				return untrustedChain;
			};   
		} catch (err) {
			console.log('[-] TrustManagerImpl (Android > 7) pinner not found');
			//console.log(err);
		}   
  
  
		
		// Appcelerator Titanium //
		///////////////////////////
		try {
			var appcelerator_PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
			appcelerator_PinningTrustManager.checkServerTrusted.implementation = function () {
				console.log('[+] Bypassing Appcelerator PinningTrustManager');
			};
		} catch (err) {
			console.log('[-] Appcelerator PinningTrustManager pinner not found');
			//console.log(err);
		}



		// OpenSSLSocketImpl Conscrypt //
		/////////////////////////////////
		try {
			var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
			OpenSSLSocketImpl.verifyCertificateChain.implementation = function (certRefs, JavaObject, authMethod) {
				console.log('[+] Bypassing OpenSSLSocketImpl Conscrypt');
			};
		} catch (err) {
			console.log('[-] OpenSSLSocketImpl Conscrypt pinner not found');
			//console.log(err);        
		}



		// OpenSSLEngineSocketImpl Conscrypt //
		///////////////////////////////////////
		try {
			var OpenSSLEngineSocketImpl_Activity = Java.use('com.android.org.conscrypt.OpenSSLEngineSocketImpl');
			OpenSSLSocketImpl_Activity.verifyCertificateChain.overload('[Ljava.lang.Long;', 'java.lang.String').implementation = function (a, b) {
				console.log('[+] Bypassing OpenSSLEngineSocketImpl Conscrypt: ' + b);
			};
		} catch (err) {
			console.log('[-] OpenSSLEngineSocketImpl Conscrypt pinner not found');
			//console.log(err);
		}



		// OpenSSLSocketImpl Apache Harmony //
		//////////////////////////////////////
		try {
			var OpenSSLSocketImpl_Harmony = Java.use('org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl');
			OpenSSLSocketImpl_Harmony.verifyCertificateChain.implementation = function (asn1DerEncodedCertificateChain, authMethod) {
				console.log('[+] Bypassing OpenSSLSocketImpl Apache Harmony');
			};
		} catch (err) {
			console.log('[-] OpenSSLSocketImpl Apache Harmony pinner not found');
			//console.log(err);      
		}



		// PhoneGap sslCertificateChecker (https://github.com/EddyVerbruggen/SSLCertificateChecker-PhoneGap-Plugin) //
		//////////////////////////////////////////////////////////////////////////////////////////////////////////////
		try {
			var phonegap_Activity = Java.use('nl.xservices.plugins.sslCertificateChecker');
			phonegap_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function (a, b, c) {
				console.log('[+] Bypassing PhoneGap sslCertificateChecker: ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] PhoneGap sslCertificateChecker pinner not found');
			//console.log(err);
		}



		// IBM MobileFirst pinTrustedCertificatePublicKey (double bypass) //
		////////////////////////////////////////////////////////////////////
		try {
			// Bypass IBM MobileFirst {1}
			var WLClient_Activity_1 = Java.use('com.worklight.wlclient.api.WLClient');
			WLClient_Activity_1.getInstance().pinTrustedCertificatePublicKey.overload('java.lang.String').implementation = function (cert) {
				console.log('[+] Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {1}: ' + cert);
				return;
			};
			} catch (err) {
			console.log('[-] IBM MobileFirst pinTrustedCertificatePublicKey {1} pinner not found');
			//console.log(err);
		}
		try {
			// Bypass IBM MobileFirst {2}
			var WLClient_Activity_2 = Java.use('com.worklight.wlclient.api.WLClient');
			WLClient_Activity_2.getInstance().pinTrustedCertificatePublicKey.overload('[Ljava.lang.String;').implementation = function (cert) {
				console.log('[+] Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {2}: ' + cert);
				return;
			};
		} catch (err) {
			console.log('[-] IBM MobileFirst pinTrustedCertificatePublicKey {2} pinner not found');
			//console.log(err);
		}



		// IBM WorkLight (ancestor of MobileFirst) HostNameVerifierWithCertificatePinning (quadruple bypass) //
		///////////////////////////////////////////////////////////////////////////////////////////////////////
		try {
			// Bypass IBM WorkLight {1}
			var worklight_Activity_1 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
			worklight_Activity_1.verify.overload('java.lang.String', 'javax.net.ssl.SSLSocket').implementation = function (a, b) {
				console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {1}: ' + a);                
				return;
			};
		} catch (err) {
			console.log('[-] IBM WorkLight HostNameVerifierWithCertificatePinning {1} pinner not found');
			//console.log(err);
		}
		try {
			// Bypass IBM WorkLight {2}
			var worklight_Activity_2 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
			worklight_Activity_2.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (a, b) {
				console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {2}: ' + a);
				return;
			};
		} catch (err) {
			console.log('[-] IBM WorkLight HostNameVerifierWithCertificatePinning {2} pinner not found');
			//console.log(err);
		}
		try {
			// Bypass IBM WorkLight {3}
			var worklight_Activity_3 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
			worklight_Activity_3.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;').implementation = function (a, b) {
				console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {3}: ' + a);
				return;
			};
		} catch (err) {
			console.log('[-] IBM WorkLight HostNameVerifierWithCertificatePinning {3} pinner not found');
			//console.log(err);
		}
		try {
			// Bypass IBM WorkLight {4}
			var worklight_Activity_4 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
			worklight_Activity_4.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (a, b) {
				console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {4}: ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] IBM WorkLight HostNameVerifierWithCertificatePinning {4} pinner not found');
			//console.log(err);
		}



		// Conscrypt CertPinManager //
		//////////////////////////////
		try {
			var conscrypt_CertPinManager_Activity = Java.use('com.android.org.conscrypt.CertPinManager');
			conscrypt_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
				console.log('[+] Bypassing Conscrypt CertPinManager: ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] Conscrypt CertPinManager pinner not found');
			//console.log(err);
		}



		// CWAC-Netsecurity (unofficial back-port pinner for Android<4.2) CertPinManager //
		///////////////////////////////////////////////////////////////////////////////////
		try {
			var cwac_CertPinManager_Activity = Java.use('com.commonsware.cwac.netsecurity.conscrypt.CertPinManager');
			cwac_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
				console.log('[+] Bypassing CWAC-Netsecurity CertPinManager: ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] CWAC-Netsecurity CertPinManager pinner not found');
			//console.log(err);
		}



		// Worklight Androidgap WLCertificatePinningPlugin //
		/////////////////////////////////////////////////////
		try {
			var androidgap_WLCertificatePinningPlugin_Activity = Java.use('com.worklight.androidgap.plugin.WLCertificatePinningPlugin');
			androidgap_WLCertificatePinningPlugin_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function (a, b, c) {
				console.log('[+] Bypassing Worklight Androidgap WLCertificatePinningPlugin: ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] Worklight Androidgap WLCertificatePinningPlugin pinner not found');
			//console.log(err);
		}



		// Netty FingerprintTrustManagerFactory //
		//////////////////////////////////////////
		try {
			var netty_FingerprintTrustManagerFactory = Java.use('io.netty.handler.ssl.util.FingerprintTrustManagerFactory');
			//NOTE: sometimes this below implementation could be useful 
			//var netty_FingerprintTrustManagerFactory = Java.use('org.jboss.netty.handler.ssl.util.FingerprintTrustManagerFactory');
			netty_FingerprintTrustManagerFactory.checkTrusted.implementation = function (type, chain) {
				console.log('[+] Bypassing Netty FingerprintTrustManagerFactory');
			};
		} catch (err) {
			console.log('[-] Netty FingerprintTrustManagerFactory pinner not found');
			//console.log(err);
		}



		// Squareup CertificatePinner [OkHTTP<v3] (double bypass) //
		////////////////////////////////////////////////////////////
		try {
			// Bypass Squareup CertificatePinner  {1}
			var Squareup_CertificatePinner_Activity_1 = Java.use('com.squareup.okhttp.CertificatePinner');
			Squareup_CertificatePinner_Activity_1.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (a, b) {
				console.log('[+] Bypassing Squareup CertificatePinner {1}: ' + a);
				return;
			};
		} catch (err) {
			console.log('[-] Squareup CertificatePinner {1} pinner not found');
			//console.log(err);
		}
		try {
			// Bypass Squareup CertificatePinner {2}
			var Squareup_CertificatePinner_Activity_2 = Java.use('com.squareup.okhttp.CertificatePinner');
			Squareup_CertificatePinner_Activity_2.check.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
				console.log('[+] Bypassing Squareup CertificatePinner {2}: ' + a);
				return;
			};
		} catch (err) {
			console.log('[-] Squareup CertificatePinner {2} pinner not found');
			//console.log(err);
		}



		// Squareup OkHostnameVerifier [OkHTTP v3] (double bypass) //
		/////////////////////////////////////////////////////////////
		try {
			// Bypass Squareup OkHostnameVerifier {1}
			var Squareup_OkHostnameVerifier_Activity_1 = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
			Squareup_OkHostnameVerifier_Activity_1.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (a, b) {
				console.log('[+] Bypassing Squareup OkHostnameVerifier {1}: ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] Squareup OkHostnameVerifier pinner not found');
			//console.log(err);
		}    
		try {
			// Bypass Squareup OkHostnameVerifier {2}
			var Squareup_OkHostnameVerifier_Activity_2 = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
			Squareup_OkHostnameVerifier_Activity_2.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (a, b) {
				console.log('[+] Bypassing Squareup OkHostnameVerifier {2}: ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] Squareup OkHostnameVerifier pinner not found');
			//console.log(err);
		}


		
		// Android WebViewClient (double bypass) //
		///////////////////////////////////////////
		try {
			// Bypass WebViewClient {1} (deprecated from Android 6)
			var AndroidWebViewClient_Activity_1 = Java.use('android.webkit.WebViewClient');
			AndroidWebViewClient_Activity_1.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function (obj1, obj2, obj3) {
				console.log('[+] Bypassing Android WebViewClient {1}');
			};
		} catch (err) {
			console.log('[-] Android WebViewClient {1} pinner not found');
			//console.log(err)
		}
		try {
			// Bypass WebViewClient {2}
			var AndroidWebViewClient_Activity_2 = Java.use('android.webkit.WebViewClient');
			AndroidWebViewClient_Activity_2.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function (obj1, obj2, obj3) {
				console.log('[+] Bypassing Android WebViewClient {2}');
			};
		} catch (err) {
			console.log('[-] Android WebViewClient {2} pinner not found');
			//console.log(err)
		}



		// Apache Cordova WebViewClient //
		//////////////////////////////////
		try {
			var CordovaWebViewClient_Activity = Java.use('org.apache.cordova.CordovaWebViewClient');
			CordovaWebViewClient_Activity.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function (obj1, obj2, obj3) {
				console.log('[+] Bypassing Apache Cordova WebViewClient');
				obj3.proceed();
			};
		} catch (err) {
			console.log('[-] Apache Cordova WebViewClient pinner not found');
			//console.log(err);
		}



		// Boye AbstractVerifier //
		///////////////////////////
		try {
			var boye_AbstractVerifier = Java.use('ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier');
			boye_AbstractVerifier.verify.implementation = function (host, ssl) {
				console.log('[+] Bypassing Boye AbstractVerifier: ' + host);
			};
		} catch (err) {
			console.log('[-] Boye AbstractVerifier pinner not found');
			//console.log(err);
		}

	 
	});
	
}, 0);
"""
v = """
Java.perform(function() {
    var Arrays = Java.use("java.util.Arrays");
    var Thread = Java.use("java.lang.Thread");
    var Request = Java.use("com.bplus.vtpay.model.request.Request");
    Java.use('f.f.a.x.b').a.overload('java.lang.String','java.lang.String','java.lang.String','int').implementation = function(s1,s2,s3,i) {
        try{
            send("Command " + s1);
            send("Encrypted " + s2);
            send("Signature " + s3);
        }
        catch(err){
            send(err);
        }
        return this.a(s1,s2,s3,i);
    }
    Java.use('f.f.a.x.b').b.overload('java.lang.String','java.lang.String','java.lang.Boolean').implementation = function(s1,s2,s3) {
        send("Encrypt");
        send("Data encrypt = " + s1);
        send("Pubkey = " + s2);
        return this.b(s1,s2,s3);
    }
    Java.use('f.f.a.x.b').a.overload('java.lang.String','java.lang.String','java.lang.Boolean').implementation = function(s1,s2,s3) {
        send("Decrypt");
        send("Data decrypt = " + s1);
        send("Privkey = " + s2);
        return this.a(s1,s2,s3);
    }
    Java.use('f.f.a.x.b').c.overload('java.lang.String','java.lang.String','java.lang.Boolean').implementation = function(s1,s2,s3) {
        send("Sign");
        send("Data sign = " + s1);
        send("Key  sign = " + s2);
        return this.c(s1,s2,s3);
    }
});
"""
m = """
Java.perform(function() {

    Java.use('com.RNRSA.RSA').encrypt64.overload('java.lang.String').implementation = function(s) {
        try{
            var ret = this.encrypt64(s);
            send("[Encrypt64 data RSA] cipher text: " + ret);
            send("[Encrypt64 data RSA] plain text: " + s);
        }
        catch(err){
            send(err);
        }
        return ret;
    }
    Java.use('com.RNRSA.RSA').encrypt.overload('java.lang.String').implementation = function(s) {
        try{
            var ret = this.encrypt(s);
            send("[Encrypt data RSA] cipher text: " + ret);
            send("[Encrypt data RSA] plain text: " + s);
        }
        catch(err){
            send(err);
        }
        return ret;
    }
    Java.use('com.mservice.utils.EncryptAES').encryptDecrypt.implementation = function(s1,s2,s3,s4) {
        try{
            send(s1 + " : " + s2 + " : " + s4);
            var ret = this.encryptDecrypt(s1,s2,s3,s4);
            send("[AES encrypt/decrypt]. S1 = " + s1);
            send("[AES encrypt/decrypt]. S2 = " + s2);
            send("[AES encrypt/decrypt]. S4 = " + s4);
            send("[AES encrypt/decrypt]. Result = " + ret);
        }
        catch(err){
            send(err);
        }
        return ret;
    }
    Java.use('com.RNRSA.RSA').decrypt.overload('java.lang.String').implementation = function(s) {
        try{
            var ret = this.decrypt(s);
            send("[Decrypt data RSA] cipher text: " + s);
            send("[Decrypt data RSA] plain text: " + ret);
        }
        catch(err){
            send(err);
        }
        return ret;
    }
    Java.use('com.RNRSA.RSA').decrypt64.overload('java.lang.String').implementation = function(s) {
        try{
            var ret = this.decrypt64(s);
            send("[Decrypt64 data RSA] cipher text: " + s);
            send("[Decrypt64 data RSA] plain text: " + ret);
        }
        catch(err){
            send(err);
        }
        return ret;
    }
    Java.use('com.mservice.nativemodules.common.emulator.EmulatorManager').isEmulator.implementation = function(s) {
        try{
            var ret = this.isEmulator(s);
            send("[Check emulator]: " + ret);
        }
        catch(err){
            send(err);
        }
        return false;
    }
});
"""
device = frida.get_device_manager().enumerate_devices()[-1]
# pid = device.spawn([""])
session = device.attach('')
script = session.create_script(objection)
script.on('message', on_message)
script.load()
sys.stdin.read()
