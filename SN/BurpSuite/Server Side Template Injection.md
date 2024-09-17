## Definition
when an attacker is able to:
- use native template syntax
	- to inject a malicious payload into a template
		- which is then executed server-side

Template engines are designed to:
- generate web pages by combining fixed templates with volatile data. 
=>
Server-side template injection attacks can occur:
- when user input is concatenated directly into a template
- rather than passed in as data.
- This allows attackers to:
	- inject arbitrary template directives 
		- in order to manipulate the template engine,
		- often enabling them to take complete control of the server

As the name suggests, server-side template injection payloads:
are delivered and evaluated -->    server-side, 
                            potentially making them much more dangerous than a typical client-side template injection

## How arise
Server-side template injection vulnerabilities arise:
when user input:
- is concatenated into templates 
- rather than being passed in as data.

Static templates that simply provide placeholders into which dynamic content is rendered:
- are generally not vulnerable to server-side template injection

The classic example is:
an email that greets each user by their name, 
such as the following extract from a Twig template:
`$output = $twig->render("Dear {first_name},", array("first_name" => $user.first_name) );`

This is not vulnerable to server-side template injection:
because the user's first name -->   is merely passed into the template as data.

However, as templates are simply strings:
- developers sometimes directly concatenate user input into templates prior to rendering.

Let's take a similar example to the one above, but this time:
- users are able to customize parts of the email before it is sent
  
For example, they might be able to choose the name that is used:
`$output = $twig->render("Dear " . $_GET['name']);`

In this example, instead of a static value being passed into the template:
- part of the template itself is being dynamically generated using the `GET` parameter `name`
- As template syntax is evaluated server-side:
	- this potentially allows an attacker to place a server-side template injection payload inside the `name` parameter as follows:
	  `http://vulnerable-website.com/?name={{bad-stuff-here}}`

Vulnerabilities like this:
- are sometimes caused by accident 
	- due to poor template design by people unfamiliar with the security implications

However, sometimes:
- this behavior is actually implemented intentionally. 
- For example, some websites:
	- deliberately allow certain privileged users, such as content editors, 
		- to edit or submit custom templates by design. 
		- This poses a huge security risk if an attacker is able to compromise an account with such privileges

## Constructing a server-side template injection attack
Identifying server-side template injection vulnerabilities and crafting a successful attack:
- typically involves the following high-level process
  ![[Pasted image 20240917093828.png|350]]

### Detect
The simplest initial approach is to:
- try fuzzing the template by injecting a sequence of special ch commonly used in template expressions
	- such as `${{<%[%'"}}%\`

If an exception is raised,:
=>
the injected template syntax is -->  potentially being interpreted by the server in some way

This is one sign that a vulnerability to server-side template injection may exist

Server-side template injection vulnerabilities:
occur in two distinct contexts -->  each of which requires its own detection method

they are:
- Plain text context
- Code context
#### Plain text context
Most template languages allow you to:
- freely input content either by using HTML tags directly or by using the template's native syntax
	- which will be rendered to HTML on the back-end before the HTTP response is sent

For example, consider a template that contains the following vulnerable code:
`render('Hello ' + username)`

During auditing, we test for server-side template injection by requesting a URL such as:
`http://vulnerable-website.com/?username=${7*7}`
=>
If the resulting output contains `Hello 49`:
- this shows that the mathematical operation is being evaluated server-side
- This is a good proof of concept for a server-side template injection vulnerability.

Note that the specific syntax required to successfully evaluate the mathematical operation:
- will vary -->   depending on which template engine is being used

#### Code context
In other cases, the vulnerability:
- is exposed by user input -->    being placed within a template expression,
                            as we saw earlier with our email example

This may take the form of:
- a user-controllable variable name -->  being placed inside a parameter, such as:

```
greeting = getQueryParameter('greeting')
engine.render("Hello {{"+greeting+"}}", data)
```
=>
On the website, the resulting URL would be something like:
`http://vulnerable-website.com/?greeting=data.username`

This would be rendered in the output to `Hello Carlos`, for example.

This context is easily missed during assessment:
- because it doesn't result in obvious XSS 
- and is almost indistinguishable from a simple hashmap lookup.

One method of testing for server-side template injection in this context:
- is to first establish that the parameter doesn't contain a direct XSS vulnerability 
- by injecting arbitrary HTML into the value:
  `http://vulnerable-website.com/?greeting=data.username<tag>`

In the absence of XSS:
- this will usually either result in a -->    blank entry in the output (just `Hello` with no 
							     username) encoded tags, or an error message. 
The next step is to:
- try and break out of the statement using common templating syntax and attempt to inject arbitrary HTML after it:
  `http://vulnerable-website.com/?greeting=data.username}}<tag>`

If this again results in an error or blank output:
=>
- you have either used syntax from the wrong templating language 
- or, if no template-style syntax appears to be valid, server-side template injection is not possible

Alternatively, if the output is rendered correctly, along with the arbitrary HTML:
=>
this is a key indication that -->   a server-side template injection vulnerability is present:
Es:
`Hello Carlos<tag>`

### Identify
Once you have detected the template injection potential:
the next step is to -->   identify the template engine

Although there are a huge number of templating languages:
- many of them use -->    very similar syntax 
				      that is specifically chosen not to clash with HTML characters
- As a result:
	- it can be relatively simple to create probing payloads 
		- to test which template engine is being used.

Simply submitting invalid syntax:
- is often enough bc the resulting error mex will tell you exactly what the template engine is
- and sometimes even which version

For example, the invalid expression `<%=foobar%>` triggers the following response from the Ruby-based ERB engine:
```
(erb):1:in `<main>': undefined local variable or method `foobar' for main:Object (NameError)
from /usr/lib/ruby/2.5.0/erb.rb:876:in `eval'
from /usr/lib/ruby/2.5.0/erb.rb:876:in `result'
from -e:4:in `<main>'
```

Otherwise, you'll need to:
- manually test different language-specific payloads 
- study how they are interpreted by the template engine.
- Using a process of elimination based on which syntax appears to be valid or invalid:
	- you can narrow down the options quicker than you might think

A common way of doing this is to:
- inject arbitrary mathematical operations using syntax from different template engines.
=>
You can then observe whether they are successfully evaluated. 
To help with this process, you can use a decision tree similar to the following:
![[Pasted image 20240917100300.png|700]]

You should be aware that:
- the same payload can sometimes return:
	- a successful response in more than one template language

For example, the payload `{{7*'7'}}` returns:
- `49` in Twig 
- `7777777` in Jinja2
=>
it is important not to jump to conclusions based on a single successful response

### Exploit
Once you discover a server-side template injection vulnerability:
- and identify the template engine being used
	- successful exploitation typically involves the following process:
		- Read
			- Template Syntax
			- Security Documentation
			- Documented exploits
		- Explore the environment 
		- Create a custom attack

#### Read
Unless you already know the template engine inside out:
- reading its documentation -->  is usually the first place to start

##### Learn the basic template syntax
Learning the basic syntax is obviously important:
- along with key functions and handling of variables

Even something as simple as learning how to embed native code blocks in the template:
- can sometimes quickly lead to an exploit

For example, once you know that the Python-based Mako template engine is being used:
- achieving remote code execution could be as simple as:

```
<%
                import os
                x=os.popen('id').read()
                %>
                ${x}
```

###### Basic server-side template injection
- Notice that when you try to view more details about the first product, a `GET` request uses the `message` parameter to render `"Unfortunately this product is out of stock"` on the home page.
- In the ERB documentation, discover that the syntax `<%= someExpression %>` is used to evaluate an expression and render the result on the page.
- Use ERB template syntax to create a test payload containing a mathematical operation, for example:
  `<%= 7*7 %>`
- URL-encode this payload and insert it as the value of the `message` parameter in the URL
	=>
	- capture a GET request for "View Details" of one of the product
	- send it to repeater
	- change the `/?message=...` to `/?message=<%= 7*7 %>`
	- then select `<%= 7*7 %>` and press CTRL+U to URL encode
	- send the packet
- The output will be the number 49. 
	- This indicates that we may have a server-side template injection vulnerability.
- From the Ruby documentation, discover the `system()` method, which can be used to execute arbitrary operating system commands.
- Construct a payload to delete Carlos's file as follows:
  `<%= system("rm /home/carlos/morale.txt") %>`
- => 
  `/?message=<%= system("rm /home/carlos/morale.txt") %>` and URL encode again the payload

###### Basic server-side template injection (code context)
- While proxying traffic through Burp, log in and post a comment on one of the blog posts.
- Notice that on the "My account" page, you can select whether you want the site to use your full name, first name, or nickname. 
	- When you submit your choice, a `POST` request sets the value of the parameter `blog-post-author-display` to either `user.name`, `user.first_name`, or `user.nickname`. 
	- When you load the page containing your comment, the name above your comment is updated based on the current value of this parameter
	  
- In Burp, go to "Proxy" > "HTTP history" and find the request that sets this parameter, namely `POST /my-account/change-blog-post-author-display`, and send it to Burp Repeater.
- Study the Tornado documentation to discover that template expressions are surrounded with double curly braces, such as `{{someExpression}}`. 
	- In Burp Repeater, notice that you can escape out of the expression and inject arbitrary template syntax as follows:
	  `blog-post-author-display=user.name}}{{7*7}}`
	  
- Reload the page containing your test comment. 
	- Notice that the username now says `Peter Wiener49}}`, indicating that a server-side template injection vulnerability may exist in the code context.
	- 
- In the Tornado documentation, identify the syntax for executing arbitrary Python: 
  `{% somePython %}`
  
- Study the Python documentation to discover that by importing the `os` module, you can use the `system()` method to execute arbitrary system commands.
- Combine this knowledge to construct a payload that deletes Carlos's file:
  `{% import os %} {{os.system('rm /home/carlos/morale.txt')`
- In Burp Repeater, go back to `POST /my-account/change-blog-post-author-display`. 
	- Break out of the expression, and inject your payload into the parameter, remembering to URL-encode it as follows:
	  `blog-post-author-display=user.name}}{%25+import+os+%25}{{os.system('rm%20/home/carlos/morale.txt')`
- Reload the page containing your comment to execute the template and solve the lab

##### Read about the security implications
In addition to providing the fundamentals of how to create and use templates:
- the documentation may also provide some sort of -->  "Security" section

The name of this section will vary:
- but it will usually outline all the potentially -->    dangerous things that people should 
										  avoid doing with the template 
- This can be an invaluable resource:
	- even acting as a kind of cheat sheet
		- for which behaviors you should look for during auditing, 
		  as well as how to exploit them.

Even if there is no dedicated "Security" section:
- if a particular built-in object or function can pose a security ris
  =>
  there is almost always a warning of some kind in the documentation
  - The warning may not provide much detail
  - but at the very least it should flag this particular built-in as something to investigate.

For example, in ERB, the documentation reveals that you can list all directories and then read arbitrary files as follows:
```
<%= Dir.entries('/') %>
<%= File.open('/example/arbitrary-file').read %>
```

###### Server-side template injection using documentation
