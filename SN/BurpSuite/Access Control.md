## Definition
In the context of web applications, access control is dependent on authentication and session management:
- **Authentication** -->  confirms that the user is who they say they are.
- **Session management** -->  identifies which subsequent HTTP requests are being made by that same user.
- <span style="color:rgb(153, 102, 255)">Access control </span> -->  determines whether the user is allowed to carry out the action that 
		             they are attempting to perform.

### Vertical access controls
Vertical access controls are mechanisms that:
restrict access to sensitive functionality to specific types of users.
=>
Different types of users have access to different application functions.

### Horizontal access controls
restrict access to resources to specific users.
=>
different users have access to a subset of resources of the same type

### Context-dependent access controls
restrict access to functionality and resources based upon the state of the app or the user's interaction with it.
=>
Context-dependent access controls prevent a user performing actions in the wrong order.

## Examples of broken access controls
### Vertical privilege escalation
If a user can gain access to functionality that they are not permitted to access then this is vertical privilege escalation. 
For example:
- if a non-administrative user can gain access to an admin page 
- where they can delete user accounts
=>
this is vertical privilege escalation

#### Unprotected functionality
Vertical escalation happens when for example:
application does not enforce any protection for sensitive functionality

example:
- administrative functions might be linked from an administrator's welcome page but not from a user's welcome page. 
- However, a user might be able to access the administrative functions by browsing to the relevant admin URL.

##### Unprotected admin functionality
- navigate to `.../robots.txt`
   ![[Pasted image 20240906112526.png]]
- go to that link =>  you are inside the admin account

#### Unprotected admin functionality with unpredictable URL
In some cases:
sensitive functionality is concealed by giving it a less predictable URL

Imagine an application that hosts administrative functions at the following URL:
`https://insecure-website.com/administrator-panel-yb556`

This might not be directly guessable by an attacker. However, the application might still leak the URL to users. The URL might be disclosed in JavaScript that constructs the user interface based on the user's role:

```Java
`<script> 
	var isAdmin = false; 
	if (isAdmin) { 
		... 
		var adminPanelTag = document.createElement('a')
		adminPanelTag.setAttribute('https://insecure-website.com/administrator-  panel-yb556'); 
		adminPanelTag.innerText = 'Admin panel'; ... 
	} 
</script>`
```
#### Parameter-based access control methods
Some applications:
- determine the user's access rights or role at login
- and then store this information in a user-controllable location

This could be:
- A hidden field.
- A cookie.
- A preset query string parameter.

The application makes access control decisions based on the submitted value. 
For example:
`https://insecure-website.com/login/home.jsp?admin=true 
`https://insecure-website.com/login/home.jsp?role=1`

This approach is insecure:
bc a user can -->  modify the value and access functionality they're not authorized to

example with a cookie:
- login as wiener
- check cookie
- you'll find a cookie with a value admin=false
- change it to true
  ![[Pasted image 20240906114831.png]]

example with role:
- login
- change email using the form
- look at that packet
- in the response it sets that `roleid`
- =>
  - send the request to Repeater
  - add the `roleid` with `2`
  - forward the packet
  - access to `/admin`
  - you're logged in as admin
![[Pasted image 20240906115611.png]]

#### Broken access control resulting from platform misconfiguration
Some apps enforce access controls at the platform layer
=>
They do this by:
restricting access to specific URLs and HTTP methods based on the user's role. 

For example, an application might configure a rule as follows:
`DENY: POST, /admin/deleteUser, managers`

This rule denies access to the `POST` method on the URL `/admin/deleteUser`, for users in the managers group. 

Various things can go wrong in this situation, leading to access control bypasses:
Some app frameworks support various non-standard HTTP headers that can be used to override the URL in the original request, such as `X-Original-URL` and `X-Rewrite-URL`. 
=>
- If a website uses rigorous front-end controls to restrict access based on the URL,
- but the application allows the URL to be overridden via a request header
  =>
  it might be possible to bypass the access controls using a request like the following:
  `POST / HTTP/1.1 X-Original-URL: /admin/deleteUser`

##### URL-based access control can be circumvented
- load `/admin` page
- send the request to burp > Repeater
- change the URL in the request to `/`
- add in the end `X-Original-URL: /invalid`
- the app returns not found =>  the server supports `X-Original-URL`
  =>
  to delete `carlos`:
	- change the URL in the request to `/?username=carlos`
	- add in the end `X-Original-URL: /admin/delete`

##### URL-based access control can be circumvented 2
- login as admin
- change the role to carlos
- capture this packet and send it to Repeater
- now logout and login as wiener
- capture the response and copy your `sessionID`
  =>
  now:
- paste the `sessionID` in the packet that you have in the Repeater
- right click on the packet > Change request method 
- change the username to `wiener`
![[Pasted image 20240906124400.png]]


### Horizontal privilege escalation
occurs if a user is able to gain access to resources belonging to another user
example:
- an employee can access the records of other employees as well as their own

Horizontal privilege escalation attacks may use similar types of exploit methods to vertical privilege escalation. 
For example:
a user might access their own account page using the following URL:
`https://insecure-website.com/myaccount?id=123`

If an attacker:
- modifies the `id` parameter value to that of another user,
  =>
  - they might gain access to another user's account page
  - and the associated data and functions

#### User ID controlled by request parameter with unpredictable user IDs
when we login we have this id that identifies our account:![[Pasted image 20240906125954.png]]
=>
we need to find the `carlos` id
=>
- navigate to the post into the website
- find a post that was posted by `carlos`
- click on his name and in the URL you'll find his id -->  copy it
  =>
- capture the login request for `wiener` with burp and send it to Repeater
- change the id with the one copied
- in the response you'll find the `carlos` API

### Horizontal to vertical privilege escalation
Often:
a horizontal privilege escalation attack -->  can be turned into a vertical privilege escalation

For example:
- a horizontal escalation might allow an attacker to reset or capture the password belonging to another user
- If the attacker targets an administrative user 
- and compromises their account
  =>
  - they can gain administrative access
  - so perform vertical privilege escalation

An attacker might be able to gain access to another user's account page using the parameter tampering technique already described for horizontal privilege escalation:
`https://insecure-website.com/myaccount?id=456`

If the target user is an application administrator
=>
- then the attacker will gain access to an administrative account page
- This page might disclose the administrator's password 
- or provide a means of changing it
- or might provide direct access to privileged functionality

### Insecure direct object references
Insecure direct object references (IDORs):
- are a subcategory of access control vulnerabilities.
occur if:
- an application uses user-supplied input to access objects directly 
- and an attacker can modify the input to obtain unauthorized access

### Access control vulnerabilities in multi-step processes
Many websites implement important functions over a series of steps. 
This is common when:
- A variety of inputs or options need to be captured.
- The user needs to review and confirm details before the action is performed.

For example, 
the administrative function to update user details might involve the following steps:
1. Load the form that contains details for a specific user.
2. Submit the changes.
3. Review the changes and confirm

Sometimes:
a website will implement rigorous access controls over some of these steps
but -->   ignore others
=>
- Imagine a website where access controls are correctly applied to the first and second steps
- but not to the third step
=>
- The website assumes that a user will only reach step 3 if they have already completed the first steps, which are properly controlled.
=>
An attacker can gain unauthorized access to the function:
- <span style="color:rgb(0, 186, 80)">by skipping the first two steps</span> 
- directly submitting the request for the third step with the required parameters

### Referer-based access control
Some websites base access controls on the -->  `Referer` header submitted in the HTTP request. 
The `Referer` header:
- can be added to requests by browsers -->  to indicate which page initiated a request

For example:
- an application enforces access control over the main administrative page at `/admin`
- but for sub-pages such as `/admin/deleteUser` only inspects the `Referer` header. 
  =>
- If the `Referer` header contains the main `/admin` URL --> then the request is allowed

In this case, the `Referer` header:
can be fully controlled by an attacker. 
=>
This means that they can:
- forge direct requests to sensitive sub-pages by supplying the required `Referer` header
- gain unauthorized access

## How to prevent access control vulnerabilities
Access control vulnerabilities can be prevented by taking a defense-in-depth approach and applying the following principles:
- Never rely on obfuscation alone for access control.
- Unless a resource is intended to be publicly accessible, deny access by default.
- Wherever possible, use a single application-wide mechanism for enforcing access controls.
- At the code level, make it mandatory for developers to declare the access that is allowed for each resource, and deny access by default.
- Thoroughly audit and test access controls to ensure they work as designed