## Definition
enable an attacker to read arbitrary files on the server that is running an application. 
This include:
- Application code and data
- Credentials for back-end systems
- Sensitive operating system files

In some cases, an attacker might be able to:
- write to arbitrary files on the server
- allowing them to modify application data or behavior
- ultimately take full control of the server

## Reading arbitrary files
Imagine a shopping application that displays images.
It uses the following HTML:
`<img src="/loadImage?filename=218.png">`
=>
- The `loadImage` URL takes a `filename` parameter 
- returns the contents of the specified file
- The image files are stored on disk in the location `/var/www/images/`
=>
- To return an image:
  the application appends the requested filename to this base directory
  =>
  `/var/www/images/218.png`

<span style="color:rgb(255, 0, 0)">This app implements no defenses against path traversal attacks.</span>
=>
you can request the following URL to retrieve the `/etc/passwd` file from the server's FS:
`https://insecure-website.com/loadImage?filename=../../../etc/passwd`
=>
- from `/var/www/images/'
- go back free directories
- and open `etc/passwd`

Example for windows:
`https://insecure-website.com/loadImage?filename=..\..\..\windows\win.ini`

## Common obstacles to exploiting path traversal
### Absolute path
Sometime you can avoid a path traversal and use an absolute path:
`filename=/etc/passwd`

### Nested traversal sequences
`....//` or `....\/`
example:
- open burp suite
- open the browser and enable foxy proxy
- in burp go to Target > Image
- Open the image in the browser with right click and -->  Open Image in a new Tab
- in Burp click on the GET request for the image
- send to Repeater
- in the browser look at the `filename` attribute and the img name
- in burp in the right section click on add Request Query Parameter
	- name -->  `filename`
	- value -->  the img name
- now click on Send to send the request
- see the render to check if the img has been showed
- now modify the img name with the path traversal:
=>
`filename=....//....//....//etc/passwd`

otherwise:
- in burp enable interception
- on the browser open the img in a new tab
- in burp send the GET request of the img to the Repeater
- modify the `filename` with the path traversal
- disable the interception

### Strip any directory
Sometimes:
- in URL path 
- or the `filename` parameter of a `multipart/form-data` request
web servers may -->  strip any directory traversal sequences before passing your input to the app
=>
you can sometimes bypass this kind of sanitization by:
<font color="#00b050">URL encoding, or even double URL encoding</font>, the `../` characters. 
=>
This results in `%2e%2e%2f` and `%252e%252e%252f` respectively. 
Various non-standard encodings, such as `..%c0%af` or `..%ef%bc%8f`, may also work.

example:
instead of -->  `../../../ect/passwd`
do -->  `..%252f..%252f..%252fetc/passwd`

### Expected base folder
Sometimes the app require the right base folder followed by the traversal path
=>
if the base folder is -->  `/var/www/images/`
it becomes -->  `filename=/var/www/images/../../../etc/passwd`

### Expected extension
In the same way sometimes the app required that image extension
=>
you can:
- insert the path traversal
- use a NULL  byte to terminate the file path `%00`
- insert the extension

example:
`filename=../../../etc/passwd%00.png`

## Prevent a path traversal attack
Best way:
- avoid passing user-supplied input to filesystem APIs altogether

If you can't avoid passing user-supplied input to filesystem APIs:
=>
- Validate the user input before processing it
- After -->   append the input to the base directory and use a platform filesystem API to canonicalize the path

Example in Java to validate the canonical path

```Java
File file = new File(BASE_DIRECTORY, userInput); 
if (file.getCanonicalPath().startsWith(BASE_DIRECTORY)) { 
	// process file 
}
```
