## Definition
The HTTP Host header:
- is a mandatory request header as of HTTP/1.1. 
- It specifies the domain name that the client wants to access. 

For example, when a user visits `https://portswigger.net/web-security`:
- their browser will compose a request containing a Host header as follows:
```http
GET /web-security HTTP/1.1
Host: portswigger.net
```

The purpose of the HTTP Host header is to:
- help identify which back-end component the client wants to communicate with.

If requests didn't contain Host headers, or if the Host header was malformed in some way:
- this could lead to issues when
	- routing incoming requests to the intended application

## Attacks
HTTP Host header attacks:
- exploit vulnerable websites 
	- that handle the value of the Host header in an unsafe way

If the server implicitly trusts the Host header, and fails to validate or escape it properly:
- an attacker may be able to:
	- use this input to inject harmful payloads that manipulate server-side behavior.

Attacks that involve injecting a payload directly into the Host header:
- are often known as "Host header injection" attacks.

## How arise
due to the flawed assumption that the header -->  is not user controllable. 
=>
This creates:
- implicit trust in the Host header 
- and results in inadequate validation or escaping of its value

Even if the Host header itself is handled more securely, depending on the configuration of the servers that deal with incoming requests:
- the Host can potentially be overridden by injecting other headers

Sometimes website owners:
- are unaware that these headers are supported by default
- and, as a result, they may not be treated with the same level of scrutiny.

In fact, many of these vulnerabilities arise:
- not because of insecure coding but because of insecure configuration of one or more components in the related infrastructure

These configuration issues can occur because:
- websites integrate third-party technologies into their architecture 
- without necessarily understanding the configuration options and their security implications

## How to test for vulnerabilities using the HTTP Host header


#### Host header authentication bypass
1. Send the `GET /` request that received a 200 response to Burp Repeater. Notice that you can change the Host header to an arbitrary value and still successfully access the home page.
2. Browse to `/robots.txt` and observe that there is an admin panel at `/admin`.
3. Try and browse to `/admin`. You do not have access, but notice the error message, which reveals that the panel can be accessed by local users.
4. Send the `GET /admin` request to Burp Repeater.
5. In Burp Repeater, change the Host header to `localhost` and send the request. Observe that you have now successfully accessed the admin panel, which provides the option to delete different users.
6. Change the request line to `GET /admin/delete?username=carlos` and send the request to delete `carlos` to solve the lab.

#### Web cache poisoning via ambiguous requests
1. Send the `GET /` request that received a 200 response to Burp Repeater and study the lab's behavior. 
	1. Observe that the website validates the Host header. 
	2. After tampering with it, you are unable to still access the home page.
	   
3. In the original response, notice the verbose caching headers, which tell you when you get a cache hit and how old the cached response is. 
	1. Add an arbitrary query parameter to your requests to serve as a cache buster, for example, `GET /?cb=123`. 
	2. You can simply change this parameter each time you want a fresh response from the back-end server.
	   
4. Notice that if you add a second Host header with an arbitrary value, this appears to be ignored when validating and routing your request. 
	1. Crucially, notice that the arbitrary value of your second Host header is reflected in an absolute URL used to import a script from `/resources/js/tracking.js`.
5. Remove the second Host header and send the request again using the same cache buster. 
	1. Notice that you still receive the same cached response containing your injected value.
6. Go to the exploit server and create a file at `/resources/js/tracking.js` containing the payload `alert(document.cookie)`. 
	1. Store the exploit and copy the domain name for your exploit server.
7. Back in Burp Repeater, add a second Host header containing your exploit server domain name. 
	1. The request should look something like this:
```
GET / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
```
1. Send the request a couple of times until you get a cache hit with your exploit server URL reflected in the response. 
	1. To simulate the victim, request the page in the browser using the same cache buster in the URL. 
	2. Make sure that the `alert()` fires.
2. In Burp Repeater, remove any cache busters and keep replaying the request until you have re-poisoned the cache. 
	1. The lab is solved when the victim visits the home page

#### Routing-based SSRF
2. Send the `GET /` request that received a 200 response to Burp Repeater.
3. In Burp Repeater, select the Host header value, right-click and select **Insert Collaborator payload** to replace it with a Collaborator domain name.
	1. Send the request.
	   
4. Go to the Collaborator tab and click **Poll now**. 
	1. You should see a couple of network interactions in the table, including an HTTP request. 
	2. This confirms that you are able to make the website's middleware issue requests to an arbitrary server.
	   
5. Send the `GET /` request to Burp Intruder.
6. Go to Burp Intruder and select the **Positions** tab.
7. Deselect **Update Host header to match target**.
8. Delete the value of the Host header and replace it with the following IP address, adding a payload position to the final octet:
   `Host: 192.168.0.§0§`
   
9. On the **Payloads** tab, select the payload type **Numbers**. Under **Payload settings**, enter the following values: from 0 to 255

1. Click **Start attack**. 
	1. A warning will inform you that the Host header does not match the specified target host. 
	2. As we've done this deliberately, you can ignore this message.
	   
2. When the attack finishes, click the **Status** column to sort the results. 
	1. Notice that a single request received a 302 response redirecting you to `/admin`. Send this request to Burp Repeater.
	   
3. In Burp Repeater, change the request line to `GET /admin` and send the request. 
	1. In the response, observe that you have successfully accessed the admin panel.
	   
4. Study the form for deleting users. 
	1. Notice that it will generate a `POST` request to `/admin/delete` with both a [CSRF](https://portswigger.net/web-security/csrf) token and `username` parameter. 
	2. You need to manually craft an equivalent request to delete `carlos`.
	   
5. Change the path in your request to `/admin/delete`. 
	1. Copy the CSRF token from the displayed response and add it as a query parameter to your request. 
	2. Also add a `username` parameter containing `carlos`. 
	3. The request line should now look like this but with a different CSRF token:
	   `GET /admin/delete?csrf=QCT5OmPeAAPnyTKyETt29LszLL7CbPop&username=carlos`
	   
6. Copy the session cookie from the `Set-Cookie` header in the displayed response and add it to your request.
7. Right-click on your request and select **Change request method**. 
	1. Burp will convert it to a `POST` request.
	   
8. Send the request to delete `carlos` and solve the lab.

#### SSRF via flawed request parsing
1. Send the `GET /` request that received a 200 response to Burp Repeater and study the lab's behavior. 
	1. Observe that the website validates the Host header and blocks any requests in which it has been modified.
2. Observe that you can also access the home page by supplying an absolute URL in the request line as follows:
   `GET https://YOUR-LAB-ID.web-security-academy.net/`
   
3. Notice that when you do this, modifying the Host header no longer causes your request to be blocked.
	1. Instead, you receive a timeout error. This suggests that the absolute URL is being validated instead of the Host header.
	   
4. Use Burp Collaborator to confirm that you can make the website's middleware issue requests to an arbitrary server in this way. 
	1. For example, the following request will trigger an HTTP request to your Collaborator server:
	   `GET https://YOUR-LAB-ID.web-security-academy.net/ Host: BURP-COLLABORATOR-SUBDOMAIN`
	   
5. Right-click and select **Insert Collaborator payload** to insert a Burp Collaborator subdomain where indicated in the request.
   
6. Send the request containing the absolute URL to Burp Intruder.
7. Go to Burp Intruder and select the **Positions** tab.
8. Deselect **Update Host header to match target**.
9. Use the Host header to scan the IP range `192.168.0.0/24` to identify the IP address of the admin interface. Send this request to Burp Repeater.
10. In Burp Repeater, append `/admin` to the absolute URL in the request line and send the request. 
	1. Observe that you now have access to the admin panel, including a form for deleting users.
11. Change the absolute URL in your request to point to `/admin/delete`. 
	1. Copy the [CSRF](https://portswigger.net/web-security/csrf) token from the displayed response and add it as a query parameter to your request. 
	2. Also add a `username` parameter containing `carlos`. 
	3. The request line should now look like this but with a different CSRF token:
	   `GET https://YOUR-LAB-ID.web-security-academy.net/admin/delete?csrf=QCT5OmPeAAPnyTKyETt29LszLL7CbPop&username=carlos`
	   
12. Copy the session cookie from the `Set-Cookie` header in the displayed response and add it to your request.
13. Right-click on your request and select "Change request method". Burp will convert it to a `POST` request.
14. Send the request to delete `carlos` and solve the lab.

#### Host validation bypass via connection state attack
1. Send the `GET /` request to Burp Repeater.
2. Make the following adjustments:
    - Change the path to `/admin`.
    - Change `Host` header to `192.168.0.1`.
    
3. Send the request. Observe that you are simply redirected to the homepage.
4. Duplicate the tab, then add both tabs to a new group.
5. Select the first tab and make the following adjustments:
    - Change the path back to `/`.
    - Change the `Host` header back to `YOUR-LAB-ID.h1-web-security-academy.net`.
        
6. Using the drop-down menu next to the **Send** button, change the send mode to **Send group in sequence (single connection)**.

7. Change the `Connection` header to `keep-alive`.
8. Send the sequence and check the responses. 
	1. Observe that the second request has successfully accessed the admin panel.
    
9. Study the response and observe that the admin panel contains an HTML form for deleting a given user. 
	1. Make a note of the following details:
	    - The action attribute (`/admin/delete`)
	    - The name of the input (`username`)
	    - The `csrf` token.
        
10. On the second tab in your group, use these details to replicate the request that would be issued when submitting the form. 
	1. The result should look something like this:
```html
POST /admin/delete HTTP/1.1
Host: 192.168.0.1
Cookie: _lab=YOUR-LAB-COOKIE; session=YOUR-SESSION-COOKIE
Content-Type: x-www-form-urlencoded
Content-Length: CORRECT

csrf=YOUR-CSRF-TOKEN&username=carlos
```

1. Send the requests in sequence down a single connection to solve the lab.

