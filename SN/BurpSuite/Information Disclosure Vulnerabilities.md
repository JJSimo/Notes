## Definition
when a website unintentionally reveals sensitive information to its users
Some basic examples of information disclosure:
- Revealing the names of hidden directories, their structure, and their contents via a `robots.txt` file or directory listing
- Providing access to source code files via temporary backups
- Explicitly mentioning database table or column names in error messages
- Unnecessarily exposing highly sensitive information, such as credit card details
- Hard-coding API keys, IP addresses, database credentials, and so on in the source code
- Hinting at the existence or absence of resources, usernames, and so on via subtle differences in application behavior

## How do information disclosure vulnerabilities arise
- **Failure to remove internal content from public content:**
  For example, developer comments in markup are sometimes visible to users in the production environment.
- **Insecure configuration of the website and related technologies:** 
  For example, failing to disable debugging and diagnostic features can sometimes provide attackers with useful tools to help them obtain sensitive information. 
  Default configurations can also leave websites vulnerable, for example, by displaying overly verbose error messages.
- **Flawed design and behavior of the application:** 
  For example, if a website returns distinct responses when different error states occur, this can also allow attackers to enumerate sensitive data

## How to test for information disclosure vuln
- Fuzzing
- Using Burp Scanner
- Using Burp's engagement tools
- Engineering informative responses

### Fuzzing
If you identify interesting parameters:
=>
you can try submitting unexpected data types and specially crafted fuzz strings 
(to see what effect this has)

You can automate much of this process using tools such as Burp Intruder:
- Add payload positions to parameters and use pre-built wordlists of fuzz strings to test a high volume of different inputs in quick succession.
- Easily identify differences in responses by comparing HTTP status codes, response times, lengths, and so on.
- Use grep matching rules to quickly identify occurrences of keywords, such as `error`, `invalid`, `SELECT`, `SQL`, and so on.
- Apply grep extraction rules to extract and compare the content of interesting items within responses

### Using Burp Scanner
- This provides live scanning features for auditing items while you browse
- or you can schedule automated scans to crawl and audit the target site on your behalf

### Using Burp's engagement tools
Burp provides several engagement tools:
that you can use to -->  find interesting information in the target website more easily.

You can access the engagement tools:
- from the context menu > right-click on any HTTP message > Burp Proxy entry
- or item in the site map > go to "Engagement tools"

Some of the main engagement tools:

#### Search
You can use this tool to look for any expression within the selected item

#### Find comments
You can use this tool to quickly extract any developer comments found in the selected item

#### Discover content
You can use this tool to identify additional content and functionality that is not linked from the website's visible content

### Engineering informative responses
Verbose error messages:
can sometimes -->   disclose interesting info while you go about your normal testing workflow. 

In some cases:
you will be able to manipulate the website in order to extract arbitrary data via an error message

## Common sources of information disclosure
Below a list of common examples of places were you can look to see if sensitive info is exposed

### Files for web crawlers 
- Many websites provide files at `/robots.txt` and `/sitemap.xml` -->  to help crawlers navigate their site

these files:
often list specific directories that -->  the crawlers should skip, 
                                 _<span style="color:rgb(255, 0, 0)">for example, bc they may contain sensitive info</span> _
                                 
 
### Directory Listings
Web servers can be configured to -->  automatically list the contents of directories that do 
                                 not have an index page present
This can aid an attacker:
by enabling them to quickly identify the resources at a given path

### Developer comments
During development, in-line HTML comments are sometimes added to the markup.
=>
comments can sometimes be 
- forgotten, missed
- even left in deliberately bc --> someone wasn't fully aware of the security implications

### Error messages
One of the most common causes of information disclosure is verbose error messages
As a general rule:
you should pay close attention to --> <span style="color:rgb(153, 102, 255)"> all error messages</span> you encounter during auditing

The content of error messages:
can reveal info -->   about what input or data type is expected from a given parameter
This can help you to:
arrow down your attack by identifying exploitable parameters

Also they can:
- provide information about different technologies being used by the website

example:
- change the value of the `productId` parameter to a non-integer data type, such as a string
- the unexpected data type causes an exception, and a full stack trace is displayed in the response.
### Debugging data
For debugging purposes, many websites generate <span style="color:rgb(153, 102, 255)">custom error mx</span> and <span style="color:rgb(153, 102, 255)">logs</span>:
that contain large amounts of information about -->   the application's behavior

Debug messages can sometimes contain vital info for developing an attack, including:
- Values for key session variables that can be manipulated via user input
- Hostnames and credentials for back-end components
- File and directory names on the server
- Keys used to encrypt data transmitted via the client

### User account pages
this pages usually contain:
sensitive information -->   such as the user's email address, phone number, API key...

Some websites contain logic flaws -->  that potentially allow an attacker to leverage these 
	                             pages in order to view other users' data
For example:
consider a website that determines which user's account page to load based on a `user` parameter.
`GET /user/personal-info?user=carlos`

An attacker:
- may not be able to load another users' account page entirely
- but the logic for fetching and rendering the user's registered email address, for example:
	- might not check that the `user` param matches the user that is currently logged in
	- =>
	  In this case:
	  simply changing the `user` parameter:
		  - would allow an attacker to display arbitrary users' email addresses on their own account page

### Source code disclosure via backup files
Obtaining source code access:
makes it much easier for an attacker to understand the application's behavior

- Sensitive data is sometimes even hard-coded within the source code.

### Information disclosure due to insecure configuration
Websites are sometimes vulnerable as a result of -->  improper configuration
In some cases:
- developers might forget to disable various debugging options in the production env.
  For example:
  the HTTP `TRACE` method -->  is designed for diagnostic purposes. 
  =>
  If enabled:
  - the web server will respond to requests that use the `TRACE` method 
  - by echoing in the response the exact request that was received

(This behavior is often harmless, but occasionally leads to information disclosure, such as the name of internal authentication headers that may be appended to requests by reverse proxies)

#### LAB TRACE
- there is an admin panel in the website
- open it -->  you'll see that only admin account can access it
- analyze this packet in burp, send it to Repeater
- modify the HTTP method to `TRACE` and send the packet
- Look at the response:
	- There is the `X-Custom-IP-Authorization` header, containing your IP address
	- This is used to determine whether or not the request came from the `localhost` IP address
	  =>
- go to Proxy > Proxy setting > search HTTP match and replace rules
- click Add
	- leave Match field empty
	- Type -->  Request Header
	- Replace field -->  `X-Custom-IP-Authorization: 127.0.0.1`
Now:
- reload the admin page
- you're logged in as admin

### Version control history
- Virtually all websites are developed using some form of version control system, such as Git.
- By default, a Git project stores all of its version control data in a folder called `.git`
- Occasionally, websites expose this directory in the production environment. 
	- In this case, you might be able to access --> it by simply browsing to `/.git`

Often you can:
- download the entire `.git` directory

#### LAB
- the website has `/.git`
- => wget -r `http://....../.git`
- Open it using git Cola
- Notice that there is a commit with the message `"Remove admin password from config"`
- =>
  you can see the diff in the `admin.conf` file![[Pasted image 20240906105209.png]]

## Prevent information disclosure vulnerabilities
Best practices:
- Make sure that everyone involved in producing the website is fully aware of what information is considered sensitive
- Audit any code for potential information disclosure as part of your QA or build processes. 
- Use generic error messages as much as possible. Don't provide attackers with clues about application behavior unnecessarily.
- Double-check that any debugging or diagnostic features are disabled in the production environment.
- Make sure you fully understand the configuration settings, and security implications, of any third-party technology that you implement.
