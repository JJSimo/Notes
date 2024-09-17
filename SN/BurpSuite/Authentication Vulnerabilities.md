## Definition
Authentication (auth) -->  process of verifying the identity of a user or client
Authorization -->  verifying whether a user is allowed to do something

<span style="background:#fff88f">3 types:</span>
- Something you <span style="color:rgb(153, 102, 255)">know</span>
- Something you <span style="color:rgb(153, 102, 255)">have</span>
- Something you <span style="color:rgb(153, 102, 255)">are</span> 

<span style="background:#fff88f">2 reasons for auth vuln:</span>
- auth mechanisms are weak -->  no protection for brute-force attacks
- broken authentication 
	- Logic flaws or 
	- poor coding in the implementation 
	  -->
	  that allow the auth mechanisms to be bypassed entirely by an attacker

<span style="background:#fff88f">Impact:</span>
you can have access to all the data and functionality that the compromised account has
=>
if it's an admin account that is compromised =>  you have access to the whole app

(even a low-lvl account can still grant an attacker access to data that they otherwise shouldn't have)

## Vulnerabilities in password-based login
In those website where the auth method is done by a login:
the security of the website is compromised if:
an attacker is able to either -->  obtain or guess the login credentials of another user

### Bruteforce
While attempting to brute-force a login page:
you should pay particular attention to any differences in:
- <span style="color:rgb(153, 102, 255)">Status codes</span>:
  if a guess returns a different status code from all the others 
  =>  this is a strong indication that the username was correct               
  
  Best practice to mitigate this -->  return always the same status code 

- <span style="color:rgb(153, 102, 255)">Error messages</span>:
  sometimes you have different err mex if the username is wrong, the pass is wrong, or both

- <span style="color:rgb(153, 102, 255)">Response times</span>:

#### How to bruteforce
- Open the login page and enable foxy proxy
- open burp, go to Proxy > turn on interception
- on the login page send random credentials 
- on burp click on the packet, right click, send to Intruder
- one parameter --> sniper
- two parameters -->  cluster bomb
- select the parameter value and click on Add (on the right)
- go to the Payloads tab
- insert the wordlist (for both in case of multiple parameters)
- click on start attack

#### Different responses
Do the process described in [[Authentication Vulnerabilities#How to bruteforce]]
- only use the username as parameter 
before starting the attack:
- go to the Settings tab
- for this lab when you enter an invalid username or password it returns the mex:
  `Invalid username or password.`
  =>
- under Grep - Extract click add and paste -->  that string (Invalid...) 
- click on Ok
- start the attack
- You will find a new column with the Grep that you've added 
  =>
  Filter for that column and look for the record that hasn't the string `Invalid username or password.`
  =>
  this is the right username

Now repeat the bruteforce using the right username and the wordlist for the password to find the correct password (no need to use the grep now)

#### Different time response
##### Bypass Limit Attempts from same IP
Since this challenge limit the n° of attempts from the same IP:
=>
to bypass it:
you can add as field of the header of the request captured -->  `X-Forwarded-For: number`

if for every request you change the n° =>  the IP will always change =>  <span style="color:rgb(0, 186, 80)">you'll bypass the limit</span>
=>
we'll add as parameter to the bruteforce this value and we'll increment it as number for every request.

Now let's focus on the time response:
- if you try to login with a valid user and password -->  the execution time is always more 
												or less the same
- if you use a right user but a wrong password:
	- more the password is long 
	- more is the execution time 

=>
- let's enumerate the username with a long long password 
- check the time response:
  the one that will have a long time response => it will be probably a real username

=>
- add the `X-Forwarded-For: number` as header and set the 2 parameters + a long password
- attack type Pitchfork --> in this way you can set 2 lists for the 2 parameters
  ![[Pasted image 20240904180347.png]]
	- for `X-Forwarded-For`:
		- payload type -->  Number
		- from 0 to 100
		- step 1 
		- fraction digit 0
	- for username -->  classic simple list with the username list

As you can see there is one record that has a huge difference in the response time:
![[Pasted image 20240905092942.png]]
=>
Now repeat the attack with the right username and set the second parameter to the password

#### Bruteforce with IP block protection 
Sometimes you'll be blocked after `x` login tries.
But in same cases -->  if you successfully login =>  <span style="color:rgb(0, 186, 80)">the counter is reset</span> 
=>
- if you have already a username and password
- and you want to find the password of a new user
=>
you can:
- add as a parameters both the `username` and `password`
- attack type pitchfork
- create a list of username where you alternate for each line:
	- the username that you know the password
	- the username that you want to find the password
	  
- create a list of password and before each of them write the password of the username that you already know

then:
- open the Resource Pool tab
- click on Create a New Resource Pool
- set as a Maximum Concurrent requests -->  1
- then select this Resource Pool as active
in this way:
- you are sending one request at a time
- =>
  you can ensure that your login attempts are sent to the server in the correct order

why:
- because before every bruteforce attempt -->  you need to do a correct login

launch the attack:
![[Pasted image 20240905101952.png]]

As you can see you alternate each time:
- a correct login with `wiener:peter`
- and a guess for the user `carlos`
=>
filter for Status Code:
- check the only one record that has `302` as status code for the `carlos` user

#### Work Around Bruteforce Lock Account Protection
In same cases the app will block your account after `x` login tries
what you can do:
1. Establish a list of candidate usernames that are likely to be valid. 
   (This could be through username enumeration or simply based on a list of common usernames)
2. Decide on a very small shortlist of pass that you think at least one user is likely to have. 
   The n° of pass you select must not exceed the n° of login attempts allowed. 
   => 
   if you have worked out that limit is 3 attempts =>  you need to pick a max of 3 pwd guesses
3. Using a tool such as Burp Intruder, try each of the selected pass with each of the candidate usernames.
   =>
   This way, you can attempt to brute-force every account without triggering the account lock. 
   You only need a single user to use one of the three passwords in order to compromise an account.
=>
- set as parameter only the username
- set as a password a wrong password
- in the username add a list of username where every username is repeated 5 times
- run the attack
- you'll find a user with a different response length
- if you open the response you can see that:
	- the different length is due to a different error mex
	- the err mex is `You have made too many incorrect attempts...`
	  =>
	  <span style="color:rgb(0, 186, 80)">we have found a username</span>
![[Pasted image 20240905105216.png]]

now:
- repeat the attack but set 
	- as parameter the password (and add the password list)
	- as username the correct one that we found
- before run the attack:
	- go to Settings tab
	- add a Grep- Extract field
	- Click on Refetch response and select the error![[Pasted image 20240905110150.png]]
- Now run the attack
- by filtering for the new column -->  you'll find a record with an empty value in the column
![[Pasted image 20240905110333.png]]

#### User rate limiting

Another way websites try to prevent brute-force attacks is through:
user rate limiting -->  making too many login requests within a short period of time causes
				   your IP address to be blocked. 
				   
Typically, the IP can only be unblocked in one of the following ways:
- Automatically after a certain period of time has elapsed
- Manually by an administrator
- Manually by the user after successfully completing a CAPTCHA

This method is not completely secure -->  since you can spoof your IP as we saw before

## Vulnerabilities in Multi-factor authentication
Sometimes flawed logic in two-factor authentication means that:
- after a user has completed the initial login step
- the website doesn't adequately verify that the same user is completing the second step.

For example, the user logs in with their normal credentials in the first step as follows:
`POST /login-steps/first HTTP/1.1 Host: vulnerable-website.com ... username=carlos&password=qwerty`

- They are then assigned a cookie that relates to their account
- before being taken to the second step of the login process:
`HTTP/1.1 200 OK Set-Cookie: account=carlos GET /login-steps/second HTTP/1.1 Cookie: account=carlos`

When submitting the verification code: 
- the request uses this cookie to determine which account the user is trying to access:
`POST /login-steps/second HTTP/1.1 Host: vulnerable-website.com Cookie: account=carlos ... verification-code=123456`

In this case, an attacker could:
- log in using their own credentials 
- but then change the value of the `account` cookie to any arbitrary username when submitting the verification code.
`POST /login-steps/second HTTP/1.1 Host: vulnerable-website.com Cookie: account=victim-user ... verification-code=123456`

This is extremely dangerous if the attacker is then able to brute-force the verification code as it would allow them to log in to arbitrary users' accounts based entirely on their username.

### 2FA broken logic
- we have access to `wiener:peter`
- we want to access into `carlos` account 
=>
- login as `wiener`
- capture the request in burp
- send it to repeater
- modify the `verify` field so that -->  it will be the `carlos` account to receive a 4 digits security code![[Pasted image 20240905120144.png]]
  =>
  modify it by writing `carlos`
- send the packet
- Now pause the interception
- in the browser insert a wrong security code and before submit re-enable the interception
- capture the packet in burp
- send it to Intruder
- Modify again the verify field and bruteforce the security code
  ![[Pasted image 20240905120418.png]]
- find in the result the only record with the status `302`
- double click on it > right click > Open it in browser > Copy the link
- turn off the interception > paste the link and append `/my-account`

## Vulnerabilities in other authentication mechanisms
You may find vuln in -->  functionality to allow users to manage their account
For example users can typically:
- change their password
- reset their password when they forget it

### Keeping users logged in
Usually you can stay logged in even if you close the browser
This means that:
- there is a persistent cookie stored

if you obtain this =>  you can bypass the entire login process
=>
it's important to build these cookies in a good way
So:
- no concatenation of static values, such as the username and a timestamp
- no use the password as part of the cookie
- no "encryption" using `Base64`
- no encryption without a salt

### Brute-forcing a stay-logged-in cookie
- run burp
- log in to your own account with the `Stay logged` in option selected
- Notice that this sets a `stay-logged-in` cookie
  ![[Pasted image 20240905143126.png]]
- this cookie is encoded in base64
  =>
  if you decode it you obtain -->  `wiener:51dc30ddc473d43a6011e9ebba6ca770`
  =>
- the last part is a MD5 value
	- since the first part is wiener:...
	- probably the MD5 is the password in MD5
=>
to test if this is the right guess:
- send the packet to Intruder
- select as parameter the `stay-logged-in` value
- add the `wiener` password as payload
- now we need to build the encoded string
  =>
	Under **Payload processing**, add the following rules in order:
	- Hash: `MD5` -->  we need to hash the password
	- Add prefix: `wiener:` -->  we need to append to the MD5 pwd the `username:`
	- Encode: `Base64-encode` -->  we need to encode the whole string in `base64`
	  
- we know that when we login -->  it displays the `Update email` button
- => we can use it as a `Grep Match` -->  to determine we've successfully brute-forced the cookie

By running the attack we'll see that the value generated it's the same as our cookie if we login

=>
to perform the attack
- capture in burp a packet with the url of the challenge + `/my-account`
- select as parameter the `stay-logged-in` value
- add the password list
- Under **Payload processing**, add the following rules in order:
	- Hash: `MD5` -->  we need to hash the password
	- Add prefix: `carlos:` -->  we need to append to the MD5 pwd the `username:`
	- Encode: `Base64-encode` -->  we need to encode the whole string in `base64`
- run it
- check the record with the different Status Code
- Open it > right click > Show response in browser > finish
- you're logged in as `carlos`


### Password reset broken logic
- open burp (don't activate interception)
- click the **Forgot your password?** link and enter `wiener`
- Click the **Email client** button to view the password reset email that was sent
- Click the link in the email
- Reset your password to whatever you want.
- open burp
- go to Proxy and HTTP history
- search the packet that sends the request to reset the password
- send it to Repeater
- observe that the password reset functionality still works even if you delete the value of the `temp-forgot-password-token` parameter in both the URL and request body. 
  =>
  _<span style="color:rgb(0, 186, 80)">This confirms that the token is not being checked when you submit the new password</span>_
=>
- delete the token in the 2 field
- change the username as `carlos`
- change the password to something you want
- send the packet
- open the browser and login with the new password
![[Pasted image 20240905152238.png]]


### Password reset poisoning via middleware
https://portswigger.net/web-security/learning-paths/authentication-vulnerabilities/vulnerabilities-in-other-authentication-mechanisms/authentication/other-mechanisms/lab-password-reset-poisoning-via-middleware#
![[Pasted image 20240905155204.png]]


![[Pasted image 20240905155809.png]]

### Password brute-force via password change
If you enter a valid current password, but 2 different new passwords:
the message says -->   `New passwords do not match`
=>
We can use this message to enumerate correct passwords
=>
- login with the `wiener` credentials
- change the password
- capture that packet on burp
- send it to Intruder
	- change the username to  `carlos`
	- make sure the 2 new passwords are different
	- add as parameter the current password
	- upload the password list
	- if you run the attack -->  one of the record will have a different length
![[Pasted image 20240905181738.png]]

## Prevent Authentication attacks
### Prevent username enumeration
 it is important to:
- use identical, generic error messages
- and make sure they really are identical

You should always 
- return the same HTTP status code with each login request
- make the response times in different scenarios as indistinguishable as possible.