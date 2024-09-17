## Definition
Cross-site request forgery (also known as CSRF):
allows an attacker to induce users to perform actions that they do not intend to perform

It allows an attacker to -->  partly circumvent the same origin policy

## How CSRF works
3 key conditions must be in place:
- **A relevant action.**
	- There is an action within the app that the attacker has a reason to induce. 
	- This might be:
		- a privileged action (such as modifying permissions for other users) 
		- or any action on user-specific data (such as changing the user's own pwd)
- **Cookie-based session handling.** 
	- Performing the action involves issuing one or more HTTP requests
	- and the app relies solely on session cookies to identify the user who has made the req. 
	- There is no other mechanism in place for:
		- tracking sessions or validating user requests.
- **No unpredictable request parameters.** 
	- The requests that perform the action do not contain any parameters 
		- whose values the attacker cannot determine or guess. 
	- For example, when causing a user to change their password:
		- the function is not vulnerable if an attacker needs to know the value of the existing password
		  
Suppose an app:
contains a function that lets the user change the email address on their account. 
When a user performs this action, they make an HTTP request like the following:

```http
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30
Cookie: session=yvthwsztyeQkAPzeQ5gHgTvlyxHfsAfE

email=wiener@normal-user.com
```
This meets the conditions required for CSRF:
- The action of changing the email address on a user's account is of interest to an attacker. 
  Following this action the attacker will typically be able to:
	  -  trigger a password reset 
	  - take full control of the user's account.
- The app uses a session cookie to identify which user issued the request. 
	- There are no other tokens or mechanisms in place to track user sessions.
- The attacker can easily determine the values of the request parameters that are needed to perform the action
=>
With these conditions in place,
the attacker can construct a web page containing the following HTML:

```html
<html>
    <body>
        <form action="https://vulnerable-website.com/email/change" method="POST">
            <input type="hidden" name="email" value="pwned@evil-user.net" />
        </form>
        <script>
            document.forms[0].submit();
        </script>
    </body>
</html>
```

If a victim user visits the attacker's web page, the following will happen:
- The attacker's page will trigger an HTTP request to the vulnerable website.
- If the user is logged in to the vulnerable website,
  =>
  their browser will automatically include their session cookie in the request
- The vulnerable website will process the request in the normal way, 
  treat it as having been made by the victim user, and change their email address

## How to construct a CSRF attack
Manually creating the HTML needed for a CSRF exploit can be cumbersome.
=>
The easiest way to construct a CSRF exploit is using the -->   [CSRF PoC generator](https://portswigger.net/burp/documentation/desktop/tools/engagement-tools/generate-csrf-poc) 
                                                    that is built into Burp Profess
=>
- Select a request anywhere in Burp that you want to test or exploit.
- From the right-click context menu, select Engagement tools > Generate CSRF PoC.
- Burp Suite will generate some HTML that will trigger the selected request 
  (minus cookies, which will be added automatically by the victim's browser).
- You can tweak various options in the CSRF PoC generator to fine-tune aspects of the attack. 
  You might need to do this in some unusual situations to deal with quirky features of requests.
- Copy the generated HTML into a web page, view it in a browser that is logged in to the vulnerable website,
	- test whether the intended request is issued successfully 
	- and the desired action occurs

### CSRF vulnerability with no defenses
- Open Burp's browser and log in to your account. 
  Submit the "Update email" form, and find the resulting request in your Proxy history.
- If you're using [Burp Suite Professional](https://portswigger.net/burp/pro), right-click on the request and select Engagement tools > Generate CSRF PoC. 
  Enable the option to include an auto-submit script (upper right corner) and click "Regenerate".
- Go to the exploit server, paste your exploit HTML into the "Body" section, and click "Store".
- To verify that the exploit works, try it on yourself by clicking "View exploit" and then check the resulting HTTP request and response.
- Change the email address in your exploit so that it doesn't match your own.
- Click "Deliver to victim" to solve the lab

## How to deliver a CSRF exploit
The delivery mechanisms for cross-site request forgery attacks:
 are essentially the same as for --> [[XSS#Reflected XSS]]
 =>
 the attacker will:
 - place the malicious HTML onto a website that they control
 - then induce victims to visit that website. 
 - This might be done by:
	 - feeding the user a link to the website, via an email or social media message. 
	 - Or if the attack is placed into a popular website (for example, in a user comment):
		 - they might just wait for users to visit the website

Note that some simple CSRF exploits:
employ the GET method and can be fully self-contained with a single URL on the vulnerable website
=>
In this situation:
- the attacker may not need to employ an external site
- he can directly feed victims a malicious URL on the vulnerable domain
=>
In the preceding example:
if the request to change email address can be performed with the GET method
=>
a self-contained attack would look like this:
`<img src="https://vulnerable-website.com/email/change?email=pwned@evil-user.net">`

## Common defences against CSRF
The most common defenses you'll encounter are as follows:
- **CSRF tokens** 
	- A CSRF token is a unique, secret, and unpredictable value 
	- that is generated by the server-side app and shared with the client. 
	- When attempting to perform a sensitive action, such as submitting a form:
		- the client must include the correct CSRF token in the request. 
	=>
		- This makes it very difficult for an attacker to construct a valid request on behalf of the victim.
    
- **SameSite cookies**  
	- browser security mechanism that:
		- determines when a website's cookies are included in requests originating from other websites
	- As requests to perform sensitive actions typically require:
		- an authenticated session cookie
		- the appropriate SameSite restrictions may prevent an attacker from triggering these actions cross-site. 
	- Since 2021, Chrome enforces `Lax` SameSite restrictions by default.
	  As this is the proposed standard, we expect other major browsers to adopt this behavior in future.
    
- **Referer-based validation** 
	- Some apps make use of the HTTP `Referer` header to attempt to defend vs CSRF attacks
	- normally by verifying that:
		- the request originated from the application's own domain. 
	- This is generally less effective than CSRF token validation

### Bypassing CSRF token validation
read [[CSRF#Common defences against CSRF]]
A common way to share CSRF tokens with the client is:
to include them as a hidden parameter in an HTML form, for example:

```html
<form name="change-email-form" action="/my-account/change-email" method="POST">
    <label>Email</label>
    <input required type="email" name="email" value="example@normal-website.com">
    <input required type="hidden" name="csrf" value="50FaWgdOhi9M9wyna8taR1k3ODOR8d6u">
    <button class='button' type='submit'> Update email </button>
</form>
```
Submitting this form results in the following request:
```http
POST /my-account/change-email HTTP/1.1
Host: normal-website.com
Content-Length: 70
Content-Type: application/x-www-form-urlencoded

csrf=50FaWgdOhi9M9wyna8taR1k3ODOR8d6u&email=example@normal-website.com
```
When implemented correctly, CSRF tokens:
- help protect against CSRF attacks 
	- by making it difficult for an attacker to construct a valid req on behalf of the victim.
		- As the attacker has no way of:
			- predicting the correct value for the CSRF token
			  =>
			  they won't be able to include it in the malicious request

#### Common flaws in CSRF token validation
CSRF vulnerabilities typically arise due to flawed validation of CSRF tokens.

##### Validation of CSRF token depends on request method
Some apps:
- correctly validate the token when the request uses the POST method 
- but skip the validation when the GET method is used.
=>
the attacker can:
- switch to the GET method to bypass the validation and deliver a CSRF attack:

```http
GET /email/change?email=pwned@evil-user.net HTTP/1.1
Host: vulnerable-website.com
Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm
```

###### CSRF where token validation depends on request method
- Open Burp's browser and log in to your account. 
  Submit the "Update email" form, and find the resulting request in your Proxy history.
- Send the request to Burp Repeater and observe that if you change the value of the `csrf` parameter then the request is rejected.
- Use "Change request method" on the context menu to convert it into a GET request and observe that the CSRF token is no longer verified
- In Burp professional right-click on the request, and from the context menu select Engagement tools > Generate CSRF PoC. 
  Enable the option to include an auto-submit script and click "Regenerate".
- Go to the exploit server, paste your exploit HTML into the "Body" section, and click "Store".
- To verify if the exploit will work, try it on yourself by clicking "View exploit" and checking the resulting HTTP request and response.
- Change the email address in your exploit so that it doesn't match your own.
- Store the exploit, then click "Deliver to victim" to solve the lab

##### Validation of CSRF token depends on token being present
Some apps:
- correctly validate the token when it is present 
- but skip the validation if the token is omitted.
=>
the attacker can:
- remove the entire parameter containing the token (not just its value) 
	- to bypass the validation and deliver a CSRF attack:
```http
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm

email=pwned@evil-user.net
```

###### CSRF where token validation depends on token being present
- Open Burp's browser and log in to your account. Submit the "Update email" form, and find the resulting request in your Proxy history.
- Send the request to Burp Repeater and observe that if you change the value of the `csrf` parameter then the request is rejected.
- Delete the `csrf` parameter entirely and observe that the request is now accepted.
- In Burp professional right-click on the request, and from the context menu select Engagement tools > Generate CSRF PoC. 
  Enable the option to include an auto-submit script and click "Regenerate".
- Go to the exploit server, paste your exploit HTML into the "Body" section, and click "Store".
- To verify if the exploit will work, try it on yourself by clicking "View exploit" and checking the resulting HTTP request and response.
- Change the email address in your exploit so that it doesn't match your own.
- Store the exploit, then click "Deliver to victim" to solve the lab

##### CSRF token is not tied to the user session
Some apps:
- do not validate that the token belongs to the same session as the user who is making the request.
- Instead, the app:
	- maintains a global pool of tokens that it has issued 
	- and accepts any token that appears in this pool.
=>
the attacker can:
- log in to the application using their own account
- obtain a valid token
- then feed that token to the victim user in their CSRF attack
###### CSRF where token is not tied to user session
This lab's email change functionality is vulnerable to CSRF. It uses tokens to try to prevent CSRF attacks, but they aren't integrated into the site's session handling system.

To solve the lab, use your exploit server to host an HTML page that uses a [CSRF attack](https://portswigger.net/web-security/csrf) to change the viewer's email address.

You have two accounts on the application that you can use to help design your attack. The credentials are as follows:
- `wiener:peter`
- `carlos:montoya`
=>
1. Open Burp's browser and log in to your account. Submit the "Update email" form, and intercept the resulting request.
2. Make a note of the value of the CSRF token, then drop the request.
3. Open a private/incognito browser window, log in to your other account, and send the update email request into Burp Repeater.
4. Observe that if you swap the CSRF token with the value from the other account, then the request is accepted.
5. Create and host a proof of concept exploit as described in the solution to the [CSRF vulnerability with no defenses](https://portswigger.net/web-security/csrf/lab-no-defenses) lab. Note that the CSRF tokens are single-use, so you'll need to include a fresh one.
6. Change the email address in your exploit so that it doesn't match your own.
7. Store the exploit, then click "Deliver to victim" to solve the lab

#### CSRF token is tied to a non-session cookie
In a variation on the preceding vulnerability, some apps do:
- tie the CSRF token to a cookie
- but not to the same cookie that is used to track sessions
This can easily occur when an application:
- employs 2 different frameworks:
	- one for session handling 
	- one for CSRF protection
	- which are not integrated together:

```http
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 68
Cookie: session=pSJYSScWKpmC60LpFOAHKixuFuM4uXWF; csrfKey=rZHCnSzEp8dbI6atzagGoSYyqJqTz5dv

csrf=RhV7yQDO0xcq9gLEah2WVbmuFqyOq7tY&email=wiener@normal-user.com
```

This situation is harder to exploit but is still vulnerable.
If the website contains any behavior that allows an attacker to set a cookie in a victim's browser
=>
then an attack is possible.

The attacker can:
- log in to the application using their own account
- obtain a valid token and associated cookie
- leverage the cookie-setting behavior to place their cookie into the victim's browser
- and feed their token to the victim in their CSRF attack

###### CSRF where token is tied to non-session cookie
1. Open Burp's browser and log in to your account. Submit the "Update email" form, and find the resulting request in your Proxy history.
2. Send the request to Burp Repeater and observe that changing the `session` cookie logs you out, but changing the `csrfKey` cookie merely results in the CSRF token being rejected. This suggests that the `csrfKey` cookie may not be strictly tied to the session.
3. Open a private/incognito browser window, log in to your other account, and send a fresh update email request into Burp Repeater.
4. Observe that if you swap the `csrfKey` cookie and `csrf` parameter from the first account to the second account, the request is accepted.
5. Close the Repeater tab and incognito browser.
6. Back in the original browser, perform a search, send the resulting request to Burp Repeater, and observe that the search term gets reflected in the Set-Cookie header. Since the search function has no CSRF protection, you can use this to inject cookies into the victim user's browser.
7. Create a URL that uses this vulnerability to inject your `csrfKey` cookie into the victim's browser:
   `/?search=test%0d%0aSet-Cookie:%20csrfKey=YOUR-KEY%3b%20SameSite=None`
8. Create and host a proof of concept exploit as described in the solution to the [CSRF vulnerability with no defenses](https://portswigger.net/web-security/csrf/lab-no-defenses) lab, ensuring that you include your CSRF token. The exploit should be created from the email change request.
9. Remove the auto-submit `<script>` block, and instead add the following code to inject the cookie:
   `<img src="https://YOUR-LAB-ID.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrfKey=YOUR-KEY%3b%20SameSite=None" onerror="document.forms[0].submit()">`
10. Change the email address in your exploit so that it doesn't match your own.
11. Store the exploit, then click "Deliver to victim" to solve the lab

#### CSRF token is simply duplicated in a cookie
In a further variation on the preceding vulnerability, some apps:
- do not maintain any server-side record of tokens that have been issued
- but instead duplicate each token within a cookie and a request parameter
=>
When the subsequent request is validated:
- the app simply verifies that:
  the token submitted in the req parameter matches the value submitted in the cookie

This is sometimes called -->  the "double submit" defense against CSRF


```http
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 68
Cookie: session=1DQGdzYbOJQzLP7460tfyiv3do7MjyPw; csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa

csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa&email=wiener@normal-user.com
```
In this situation, the attacker:
- can again perform a CSRF attack if the website contains any cookie setting functionality.
- he doesn't need to obtain a valid token of their own. 
- They simply invent a token (perhaps in the required format, if that is being checked),
- leverage the cookie-setting behavior to place their cookie into the victim's browser
- and feed their token to the victim in their CSRF attack

##### CSRF where token is duplicated in cookie
1. Open Burp's browser and log in to your account. 
   Submit the "Update email" form, and find the resulting request in your Proxy history.
2. Send the request to Burp Repeater and observe that the value of the `csrf` body parameter is simply being validated by comparing it with the `csrf` cookie.
3. Perform a search, send the resulting request to Burp Repeater, and observe that the search term gets reflected in the Set-Cookie header. Since the search function has no CSRF protection, you can use this to inject cookies into the victim user's browser.
4. Create a URL that uses this vulnerability to inject a fake `csrf` cookie into the victim's browser:
   `/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None`
5. =>
   Capture a new packet for changing email
6. In Burp professional right-click on the request, and from the context menu select Engagement tools > Generate CSRF PoC. 
   Enable the option to include an auto-submit script and click "Regenerate".
6. Change the `csrf` to a new fake value, like fake2 instead of fake![[Pasted image 20240912135657.png]]
7. Remove the auto-submit `<script>` block and instead add the following code to inject the cookie and submit the form: 
   `<img src="https://YOUR-LAB-ID.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrf=fake2%3b%20SameSite=None" onerror="document.forms[0].submit();"/>`
8. Go to the exploit server, paste your exploit HTML into the "Body" section
9. change the email and then click "Store".
10. To verify if the exploit will work, try it on yourself by clicking "View exploit" and checking the resulting HTTP request and response.
11. Change the email address in your exploit so that it doesn't match your own.
12. Store the exploit, then click "Deliver to victim" to solve the lab


### Bypassing SameSite cookie restrictions
read [[CSRF#Common defences against CSRF]]

SameSite is a:
browser security mechanism that -->   determines when a website's cookies are included in 
							     requests originating from other websites

#### Site in the context of SameSite cookies
In the context of SameSite cookie restrictions:
a site is defined as:
- the top-level domain (TLD) (like `.com` or `.net`) 
- plus 
- one additional level of the domain name.                 (This is often referred to as the TLD+1)

When determining whether a request is same-site or not:
the URL scheme -->  is also taken into consideration
=>
a link from `http://app.example.com` to `https://app.example.com` is treated as cross-site by most browsers

![[Pasted image 20240912140311.png|400]]

#### Difference between site and origin
![[Pasted image 20240912140431.png|400]]
The term "site":
is much less specific as it only accounts for the scheme and last part of the domain name
=>
This means that a cross-origin request can still be same-site, but not the other way around
![[Pasted image 20240912140733.png]]

This is an important distinction as it means that any:
vulnerability enabling arbitrary JS execution can be abused to:
- bypass site-based defenses on other domains belonging to the same site

#### How SameSite works
Before the SameSite mechanism was introduced:
browsers sent cookies -->  in every request to the domain that issued them
SameSite works by:
enabling browsers and website owners to -->  limit which cross-site requests, if any, 
                                        should include specific cookies.
This can help to reduce users' exposure to CSRF attacks

All major browsers currently support the following SameSite restriction levels:
- Strict
- Lax
- None
Developers can manually configure:
a restriction level for each cookie they set
=>
giving them more control over when these cookies are used

To do this, they just have to:
- include the `SameSite` attribute in the `Set-Cookie` response header, 
  along with their preferred value:
	`Set-Cookie: session=0F8tgdOhi9ynR1M9wa3ODa; SameSite=Strict`

##### Strict
If a cookie is set with `SameSite=Strict`:
browsers will not send it in any cross-site requests
=>
if the target site for the request:
does not match the site currently shown in the browser's address bar => it will not include 
															  the cookie
##### Lax
browsers will send the cookie in cross-site requests, 
but only if both of the following conditions are met:
- The request uses the `GET` method.
- The request resulted from a top-level navigation by the user, such as clicking on a link

##### None
this disables SameSite restrictions altogether, regardless of the browser.
=>
- browsers will send this cookie in all requests to the site that issued it
- even those that were triggered by completely unrelated third-party sites

When setting a cookie with `SameSite=None`:
- the website must also include the `Secure` attribute
- which ensures that the cookie is only sent in encrypted messages over HTTPS
- Otherwise, browsers will reject the cookie and it won't be set.

`Set-Cookie: trackingId=0F8tgdOhi9ynR1M9wa3ODa; SameSite=None; Secure`

##### Bypassing SameSite Lax restrictions using GET requests
Servers aren't always fussy if they receive a `GET` or `POST` req to a given endpoint.

As long as the request involves a top-level navigation:
- the browser will still include the victim's session cookie. 
- The following is one of the simplest approaches to launching such an attack:

```html
<script>
    document.location = 'https://vulnerable-website.com/account/transfer-payment?recipient=hacker&amount=1000000';
</script>
```
 Even if an ordinary GET request isn't allowed:
 some frameworks provide ways of overriding the method specified in the request line.
 For example, Symfony supports the `_method` parameter in forms, 
 which takes precedence over the normal method for routing purposes:
 ```html
<form action="https://vulnerable-website.com/account/transfer-payment" method="POST">
    <input type="hidden" name="_method" value="GET">
    <input type="hidden" name="recipient" value="hacker">
    <input type="hidden" name="amount" value="1000000">
</form>
```
<form action="https://vulnerable-website.com/account/transfer-payment" method="POST">
    <input type="hidden" name="_method" value="GET">
    <input type="hidden" name="recipient" value="hacker">
    <input type="hidden" name="amount" value="1000000">
</form>
Other frameworks support a variety of similar parameters

###### SameSite Lax bypass via method override
<span style="background:#fff88f">Study the change email function</span>
1. In Burp's browser, log in to your own account and change your email address.
2. In Burp, go to the **Proxy > HTTP history** tab.
3. Study the `POST /my-account/change-email` request and notice that this doesn't contain any unpredictable tokens, 
   so may be vulnerable to CSRF if you can bypass the SameSite cookie restrictions.

4. Look at the response to your `POST /login` request. 
   Notice that the website doesn't explicitly specify any SameSite restrictions when setting session cookies. 
   As a result, the browser will use the default `Lax` restriction level.

5. Recognize that this means the session cookie will be sent in cross-site `GET` requests, as long as they involve a top-level navigation.

 <span style="background:#fff88f">Bypass the SameSite restrictions</span>
1. Send the `POST /my-account/change-email` request to Burp Repeater.
2. In Burp Repeater, right-click on the request and select **Change request method**. 
   Burp automatically generates an equivalent `GET` request.

3. Send the request. Observe that the endpoint only allows `POST` requests.
4. Try overriding the method by adding the `_method` parameter to the query string:
   `GET /my-account/change-email?email=foo%40web-security-academy.net&_method=POST HTTP/1.1`
5. Send the request and observe that this seems to have been accepted by the server.
6. In the browser, 
   go to your account page and confirm that your email address has changed
   
<span style="background:#fff88f">Craft an exploit</span>
1. In the browser, go to the exploit server.
2. In the **Body** section, create an HTML/JavaScript payload that induces the viewer's browser to issue the malicious `GET` request. 
   Remember that this must cause a top-level navigation in order for the session cookie to be included. The following is one possible approach:
       `<script> document.location = "https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email?email=pwned@web-security-academy.net&_method=POST"; </script>`
3. Store and deliver the exploit to the victim to solve the lab

##### Bypassing SameSite restrictions using on-site gadgets
If a cookie is set with the `SameSite=Strict` attribute:
browsers won't include it in any cross-site requests. 
=>
You may be able to get around this limitation:
if you can find -->  a gadget 
                that results in a secondary request within the same site.

One possible gadget is:
a client-side redirect that -->  dynamically constructs the redirection target using attacker-
                          controllable input like URL parameters.

As far as browsers are concerned:
these client-side redirects -->  - aren't really redirects at all
						   - the resulting request is just treated as an ordinary, standalone request.
Most importantly:
this is a same-site request and, as such -->   will include all cookies related to the site, 
                                       regardless of any restrictions that are in place.
=>
If you can manipulate this gadget:
- to elicit a malicious secondary request
  =>
  this can enable you to bypass any SameSite cookie restrictions completely

###### SameSite Strict bypass via client-side redirect
<span style="background:#fff88f">Study the change email function</span>
1. In Burp's browser, log in to your own account and change your email address.
2. In Burp, go to the **Proxy > HTTP history** tab.
3. Study the `POST /my-account/change-email` request and notice that this doesn't contain any unpredictable tokens, 
   so may be vulnerable to CSRF if you can bypass any [SameSite](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions) cookie restrictions.

4. Look at the response to your `POST /login` request. 
   Notice that the website explicitly specifies `SameSite=Strict` when setting session cookies. 
   This prevents the browser from including these cookies in cross-site requests

<span style="background:#fff88f">Identify a suitable gadget</span>
1. In the browser, go to one of the blog posts and post an arbitrary comment. 
   Observe that you're initially sent to a confirmation page at `/post/comment/confirmation?postId=x` but, after a few seconds, you're taken back to the blog post.

2. In Burp, go to the proxy history and notice that this redirect is handled client-side using the imported JavaScript file `/resources/js/commentConfirmationRedirect.js`.
	![[Pasted image 20240912144821.png|400]]
1. Study the JavaScript and notice that this uses the `postId` query parameter to dynamically construct the path for the client-side redirect.
    
4. In the proxy history, right-click on the `GET /post/comment/confirmation?postId=x` request and select **Copy URL**.
    
5. In the browser, visit this URL, but change the `postId` parameter to an arbitrary string.  `/post/comment/confirmation?postId=foo`
6. Observe that you initially see the post confirmation page before the client-side JS attempts to redirect you to a path containing your injected string, for example, `/post/foo`.

7. Try injecting a [path traversal](https://portswigger.net/web-security/file-path-traversal) sequence so that the dynamically constructed redirect URL will point to your account page:
   `/post/comment/confirmation?postId=1/../../my-account`
8. Observe that the browser normalizes this URL and successfully takes you to your account page. 
   =>
   This confirms that you can use the `postId` parameter to elicit a `GET` request for an arbitrary endpoint on the target site

<span style="background:#fff88f">Bypass the SameSite restrictions</span>
1. In the browser, go to the exploit server and create a script that induces the viewer's browser to send the `GET` request you just tested. 
   The following is one possible approach:
   
```html
<script>
    document.location = "https://YOUR-LAB-ID.web-security-academy.net/post/comment/confirmation?postId=../my-account";
</script>
```
2. Store and view the exploit yourself.
3. Observe that when the client-side redirect takes place, 
   you still end up on your logged-in account page. 
   This confirms that the browser included your authenticated session cookie in the second request, even though the initial comment-submission request was initiated from an arbitrary external site

<span style="background:#fff88f">Craft an exploit</span>
1. Send the `POST /my-account/change-email` request to Burp Repeater.
2. In Burp Repeater, right-click on the request and select **Change request method**. 
   Burp automatically generates an equivalent `GET` request.

3. Send the request. 
   Observe that the endpoint allows you to change your email address using a `GET` request.

4. Go back to the exploit server and change the `postId` parameter in your exploit so that the redirect causes the browser to send the equivalent `GET` request for changing your email address:
   
```html
<script>
    document.location = "https://YOUR-LAB-ID.web-security-academy.net/post/comment/confirmation?postId=1/../../my-account/change-email?email=pwned%40web-security-academy.net%26submit=1";
</script>
```

5. Change the email `pwned%40web-security-academy.net` es -->  `b%40b.it`
7. Store and Deliver the exploit to the victim. After a few seconds, the lab is solved

##### Bypassing SameSite restrictions via vulnerable sibling domains
Whether you're testing someone else's website or trying to secure your own:
it's essential to keep in mind that -->    a request can still be same-site even if it's issued
								 cross-origin

Make sure you:
- thoroughly audit all of the available attack surface
- including any sibling domains
  In particular:
  vulnerabilities that enable you to elicit an arbitrary secondary request (es XSS)
  can:
  compromise site-based defenses completely
  =>
  exposing all of the site's domains to cross-site attacks

###### SameSite Strict bypass via sibling domain
https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-sibling-domain

### Bypassing Referer-based CSRF defenses
Aside from defenses that employ CSRF tokens, some applications make use of the HTTP `Referer` header to attempt to defend against CSRF attacks, normally by verifying that the request originated from the application's own domain. This approach is generally less effective and is often subject to bypasses.

The HTTP Referer header:
is an optional request header that contains the URL of the web page that linked to the resource that is being requested.

#### Validation of Referer can be circumvented
 Some applications validate the Referer header in a naive way that can be bypassed. For example, if the application validates that the domain in the Referer starts with the expected value, then the attacker can place this as a subdomain of their own domain:
`http://vulnerable-website.com.attacker-website.com/csrf-attack`

Likewise, if the application simply validates that the Referer contains its own domain name, then the attacker can place the required value elsewhere in the URL:
`http://attacker-website.com/csrf-attack?vulnerable-website.com`

##### CSRF with broken Referer validation
1. Open Burp's browser and log in to your account. Submit the "Update email" form, and find the resulting request in your Proxy history.
2. Send the request to Burp Repeater. Observe that if you change the domain in the Referer HTTP header, the request is rejected.
3. Copy the original domain of your lab instance and append it to the Referer header in the form of a query string. The result should look something like this:
   `Referer: https://arbitrary-incorrect-domain.net?YOUR-LAB-ID.web-security-academy.net`
4. Send the request and observe that it is now accepted. The website seems to accept any Referer header as long as it contains the expected domain somewhere in the string.
   =>
5. Create a CSRF proof of concept exploit as described in the solution to the [CSRF vulnerability with no defenses](https://portswigger.net/web-security/csrf/lab-no-defenses) lab and host it on the exploit server. Edit the JavaScript so that the third argument of the `history.pushState()` function includes a query string with your lab instance URL as follows:
   `history.pushState("", "", "/?YOUR-LAB-ID.web-security-academy.net")`
   This will cause the Referer header in the generated request to contain the URL of the target site in the query string, just like we tested earlier.

6. If you store the exploit and test it by clicking "View exploit", you may encounter the "invalid Referer header" error again. This is because many browsers now strip the query string from the Referer header by default as a security measure. To override this behavior and ensure that the full URL is included in the request, go back to the exploit server and add the following header to the "Head" section:
   `Referrer-Policy: unsafe-url`
   Note that unlike the normal Referer header, the word "referrer" must be spelled correctly in this case.

7. Change the email address in your exploit so that it doesn't match your own.
8. Store the exploit, then click "Deliver to victim" to solve the lab

## Prevent CSRF vulnerabilities
https://portswigger.net/web-security/csrf/preventing