## Definition
JSON web tokens (JWTs):
standardized format for sending cryptographically signed JSON data between systems. They can:
- theoretically contain any kind of data
- but are most commonly used to send information ("claims") about users as part of authentication, session handling, and access control mechanisms.

Unlike with classic session tokens:
- all of the data that a server needs is stored:
	- client-side within the JWT itself
=>
This makes JWTs:
- a popular choice for highly distributed websites 
	- where users need to interact seamlessly with multiple back-end servers.

### JWT format
A JWT consists of 3 parts:
- a header
- a payload
- a signature. 

These are each separated by a dot, as shown in the following example:![[Pasted image 20240918094242.png]]

The header and payload parts of a JWT are just -->   base64url-encoded JSON objects

The header contains -->  metadata about the token itself
the payload contains -->  the actual "claims" about the user

For example, you can decode the payload from the token above to reveal the following claims:
![[Pasted image 20240918094328.png|450]]

### JWT signature
The server that issues the token:
- typically generates the signature by hashing the header and payload.

In some cases:
- they also encrypt the resulting hash

Either way, this process involves -->  a secret signing key
=>
This mechanism:
- provides a way for servers to verify that none of the data within the token has been tampered with since it was issued:
	- As the signature is directly derived from the rest of the token:
		- changing a single byte of the header or payload results in a mismatched signature.
    
	- Without knowing the server's secret signing key:
		- it shouldn't be possible to generate the correct signature for a given header or payload

### JWT vs JWS vs JWE
The JWT specification:
- is actually very limited
- It only defines:
	- a format for representing information ("claims") as a JSON object 
		- that can be transferred between two parties

In practice, JWTs aren't really used as a standalone entity
=>
The JWT spec is extended by both the:
- JSON Web Signature (JWS) 
- JSON Web Encryption (JWE) specifications, 
- which define concrete ways of actually implementing JWTs.

In other words, a JWT is usually -->  either a JWS or JWE token.
When people use the term "JWT":
- they almost always mean a JWS token. 
- JWEs are very similar, 
  except that the actual contents of the token are encrypted rather than just encoded.

## JWT attacks
Involve a user:
- sending modified JWTs to the server 
	- in order to achieve a malicious goal. 
	- Typically, this goal is to:
		- bypass authentication 
		- access controls by 
		  impersonating another user who has already been authenticated

### How arise
 JWT vulnerabilities typically arise due to:
 - flawed JWT handling within the application itself
 
 The various specifications related to JWTs:
 - are relatively flexible by design, 
	 - allowing website developers to decide many implementation details for themselves.
	 - This can result in them:
		 - accidentally introducing vulnerabilities even when using battle-hardened libraries.

These implementation flaws usually mean that:
- the signature of the JWT is not verified properly. 
  =>
- This enables an attacker to:
	- tamper with the values passed to the app via the token's payload.
	- Even if the signature is robustly verified:
		- whether it can truly be trusted relies heavily on the server's secret key remaining a secret. 
		- If this key is leaked in some way, or can be guessed or brute-forced:
			- an attacker can generate a valid signature for any arbitrary token, compromising the entire mechanism. 

## Exploiting flawed JWT signature verification
By design, servers don't usually store any information about the JWTs that they issue. Instead:
- each token is an entirely self-contained entity.
  =>
- This has several advantages, but also introduces a fundamental problem:
	- the server doesn't actually know anything about the original contents of the token
	- or even what the original signature was.
	  =>
	- if the server doesn't verify the signature properly:
		- there's nothing to stop an attacker from making arbitrary changes to the rest of the token.

For example, consider a JWT containing the following claims:
```
{
    "username": "carlos",
    "isAdmin": false
}
```

If the server identifies the session based on this `username`:
- modifying its value might enable an attacker to:
	- impersonate other logged-in users. 

Similarly, if the `isAdmin` value is used for access control:
- this could provide a simple vector for privilege escalation.

### Accepting arbitrary signatures
JWT libraries:
typically provide -->  one method for verifying tokens and another that just decodes them. 

For example, the Node.js library `jsonwebtoken` -->   has `verify()` and `decode()`.

Occasionally:
- developers confuse these two methods 
- and only pass incoming tokens to the `decode()` method. 
  =>
- This effectively means that the application doesn't verify the signature at all.

#### JWT authentication bypass via unverified signature
1. In the lab, log in to your own account.
2. In Burp, go to the **Proxy > HTTP history** tab and look at the post-login `GET /my-account` request. 
	1. Observe that your session cookie is a JWT.
    
3. Double-click the payload part of the token to view its decoded JSON form in the Inspector panel. 
	1. Notice that the `sub` claim contains your username. Send this request to Burp Repeater.
    
4. In Burp Repeater, change the path to `/admin` and send the request. 
	1. Observe that the admin panel is only accessible when logged in as the `administrator` user.
    
5. Select the payload of the JWT again. 
6. In the Inspector panel, change the value of the `sub` claim from `wiener` to `administrator`, then click **Apply changes**. ![[Pasted image 20240918095925.png]]

6. Send the request again. 
7. Observe that you have successfully accessed the admin panel.
7. In the response, find the URL for deleting `carlos` (`/admin/delete?username=carlos`). Send the request to this endpoint to solve the lab.

### Accepting tokens with no signature
Among other things:
- the JWT header contains an -->  `alg` parameter
  =>
- This tells the server:
	- which algorithm was used to sign the token 
	- and which algorithm it needs to use when verifying the signature
```
{
    "alg": "HS256",
    "typ": "JWT"
}
```

This is inherently flawed because:
- the server has no option but to implicitly trust user-controllable input from the token
	- which, at this point, hasn't been verified at all
	  =>
	-  In other words:
		- an attacker can directly influence how the server checks whether the token is trustworthy.

JWTs can be signed using a range of different algorithms:
- but can also be left unsigned. 
- In this case, the `alg` parameter:
	- is set to `none`
	- which indicates a so-called "unsecured JWT". 
	- Due to the obvious dangers of this:
		- servers usually reject tokens with no signature. 
	- However, as this kind of filtering relies on string parsing:
		- you can sometimes bypass these filters using classic obfuscation techniques
			- such as mixed capitalization and unexpected encodings

#### JWT authentication bypass via flawed signature verification
1. In the lab, log in to your own account.
2. In Burp, go to the **Proxy > HTTP history** tab and look at the post-login `GET /my-account` request. 
	1. Observe that your session cookie is a JWT.
    
3. Double-click the payload part of the token to view its decoded JSON form in the **Inspector** panel. 
	1. Notice that the `sub` claim contains your username. Send this request to Burp Repeater.
    
4. In Burp Repeater, change the path to `/admin` and send the request. 
	1. Observe that the admin panel is only accessible when logged in as the `administrator` user.
    
5. Select the payload of the JWT again. 
	1. In the **Inspector** panel, change the value of the `sub` claim to `administrator`, then click **Apply changes**.
    
6. Select the header of the JWT, then use the Inspector to change the value of the `alg` parameter to `none`. Click **Apply changes**.
    
7. In the message editor, remove the signature from the JWT, but remember to leave the trailing dot after the payload. (so remove the last part but maintain the dot)
    
8. Send the request and observe that you have successfully accessed the admin panel.
    
9. In the response, find the URL for deleting `carlos` (`/admin/delete?username=carlos`). 
10. Send the request to this endpoint to solve the lab

## Brute-forcing secret keys
Some signing algorithms, such as HS256 (HMAC + SHA-256):
- use an arbitrary, standalone string as the secret key
- Just like a password:
	- it's crucial that this secret can't be easily guessed or brute-forced by an attacker.
	- Otherwise:
		- they may be able to create JWTs with any header and payload values they like
		- then use the key to re-sign the token with a valid signature.

When implementing JWT applications:
- developers sometimes make mistakes like:
	- forgetting to change default or placeholder secrets
	  =>
	   They may even copy and paste code snippets they find online

### Brute-forcing secret keys using hashcat
You just need:
- a valid, signed JWT from the target server 
- a [wordlist of well-known secrets](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list)

You can then run the following command, passing in the JWT and wordlist as arguments:
`hashcat -a 0 -m 16500 <jwt> <wordlist>`

Hashcat signs the header and payload from the JWT:
- using each secret in the wordlist
- then compares the resulting signature with the original one from the server.
  =>
- If any of the signatures match:
	- hashcat outputs the identified secret in the following format, along with various other details:
	  `<jwt>:<identified-secret>`

If you run the command more than once:
- you need to include the `--show` flag -->   to output the results

#### JWT authentication bypass via weak signing key
<span style="background:#fff88f">Part 1 - Brute-force the secret key</span>
- In Burp, load the JWT Editor extension from the BApp store.
- In the lab, log in to your own account and send the post-login `GET /my-account` request to Burp Repeater.
    
- In Burp Repeater, change the path to `/admin` and send the request. 
	- Observe that the admin panel is only accessible when logged in as the `administrator` user.
    
- Copy the JWT and brute-force the secret. 
  You can do this using hashcat as follows:
  `hashcat -a 0 -m 16500 <YOUR-JWT> /path/to/jwt.secrets.list`
	- If you're using hashcat, this outputs the JWT, followed by the secret. 
	- If everything worked correctly, this should reveal that the weak secret is `secret1`
	  ![[Pasted image 20240918102029.png]]

<span style="background:#fff88f">Part 2 - Generate a forged signing key</span>
1. Using Burp Decoder, Base64 encode the secret that you brute-forced in the previous section. (secret1)
2. In Burp, go to the **JWT Editor Keys** tab and click **New Symmetric Key**. 
	1. In the dialog, click **Generate** to generate a new key in JWK format. 
	2. Note that you don't need to select a key size as this will automatically be updated later.
3. Replace the generated value for the `k` property with the Base64-encoded secret.
4. Click **OK** to save the key

<span style="background:#fff88f">Part 3 - Modify and sign the JWT</span>
1. Go back to the `GET /admin` request in Burp Repeater 
2. Go to "**JSON Web Token**" tab.
    
2. In the payload, change the value of the `sub` claim to `administrator`
3. At the bottom of the tab, click `Sign`, then select the key that you generated in the previous section.
    
4. Make sure that the `Don't modify header` option is selected, then click `OK`. 
	1. The modified token is now signed with the correct signature.
    
5. Send the request and observe that you have successfully accessed the admin panel.
6. In the response, find the URL for deleting `carlos` (`/admin/delete?username=carlos`). 
7. Send the request to this endpoint to solve the lab

## JWT header parameter injections
According to the JWS specification:
- only the `alg` header parameter is mandatory

In practice, however:
- JWT headers (also known as JOSE headers) often contain:
	- several other parameters

The following ones are of particular interest to attackers.
- `jwk` (JSON Web Key) - Provides an embedded JSON object representing the key.
- `jku` (JSON Web Key Set URL) -    Provides a URL from which servers can fetch a set of 
                             keys containing the correct key.
    
- `kid` (Key ID) -  Provides an ID that servers can use to identify the correct key in cases 
			  where there are multiple keys to choose from. 
			  Depending on the format of the key:
			  this may have a matching `kid` parameter.

As you can see, these user-controllable parameters:
- each tell the recipient server --> which key to use when verifying the signature

### Injecting self-signed JWTs via the jwk parameter
The JSON Web Signature (JWS) specification describes an optional `jwk` header parameter:
- which servers can use to -->    embed their public key directly within the token itself in 
						    JWK format

You can see an example of this in the following JWT header:
```
{
    "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
    "typ": "JWT",
    "alg": "RS256",
    "jwk": {
        "kty": "RSA",
        "e": "AQAB",
        "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
        "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9m"
    }
}
```

Ideally, servers should only use a limited whitelist of public keys:
- to verify JWT signatures

However:
- misconfigured servers sometimes use any key that's embedded in the `jwk` parameter.
=>
You can exploit this behavior by:
- signing a modified JWT using your own RSA private key
- then embedding the matching public key in the `jwk` header.

Although you can manually add or modify the jwk parameter in Burp:
- the JWT Editor extension provides a useful feature to help you test for this vulnerability: 
	1. With the extension loaded, in Burp's main tab bar, go to the **JWT Editor Keys** tab.
	1. [Generate a new RSA key.](https://portswigger.net/burp/documentation/desktop/testing-workflow/session-management/jwts#adding-a-jwt-signing-key)
	1. Send a request containing a JWT to Burp Repeater.
	1. In the message editor, switch to the extension-generated **JSON Web Token** tab and [modify](https://portswigger.net/burp/documentation/desktop/testing-workflow/session-management/jwts#editing-jwts) the token's payload however you like.
    
	1. Click **Attack**, then select **Embedded JWK**. 
		1. When prompted, select your newly generated RSA key.
    
	1. Send the request to test how the server responds.
    

You can also perform this attack manually:
- by adding the `jwk` header yourself
- However, you may also need to:
	- update the JWT's `kid` header parameter to match the `kid` of the embedded key.

The extension's built-in attack takes care of this step for you.

#### JWT authentication bypass via jwk header injection
1. In Burp, load the JWT Editor extension from the BApp store.
2. In the lab, log in to your own account and send the post-login `GET /my-account` request to Burp Repeater.
    
3. In Burp Repeater, change the path to `/admin` and send the request. 
	1. Observe that the admin panel is only accessible when logged in as the `administrator` user.
    
4. Go to the **JWT Editor Keys** tab in Burp's main tab bar.
5. Click **New RSA Key**.
6. In the dialog, click **Generate** to automatically generate a new key pair, then click **OK** to save the key. 
	1. Note that you don't need to select a key size as this will automatically be updated later.
    
7. Go back to the `GET /admin` request in Burp Repeater and switch to the extension-generated `JSON Web Token` tab.
8. In the payload, change the value of the `sub` claim to `administrator`.
    
9. At the bottom of the **JSON Web Token** tab, click **Attack**, then select **Embedded JWK**. When prompted, select your newly generated RSA key and click **OK**.
    
10. In the header of the JWT, observe that a `jwk` parameter has been added containing your public key.
11. Send the request. Observe that you have successfully accessed the admin panel.
12. In the response, find the URL for deleting `carlos` (`/admin/delete?username=carlos`). 
13. Send the request to this endpoint to solve the lab

### Injecting self-signed JWTs via the jku parameter
Instead of embedding public keys directly using the `jwk` header parameter:
- some servers let you use the `jku` (JWK Set URL) header parameter:
	- to reference a JWK Set containing the key. 
	  
- When verifying the signature:
	- the server fetches the relevant key from this URL

A JWK Set is a:
- JSON object containing -->  an array of JWKs representing different keys

You can see an example of this below.
```
{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "75d0ef47-af89-47a9-9061-7c02a610d5ab",
            "n": "o-yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw-fhvsWQ"
        },
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "d8fDFo-fS9-faS14a9-ASf99sa-7c1Ad5abA",
            "n": "fc3f-yy1wpYmffgXBxhAUJzHql79gNNQ_cb33HocCuJolwDqmk6GPM4Y_qTVX67WhsN3JvaFYw-dfg6DH-asAScw"
        }
    ]
}
```

JWK Sets like this are sometimes:
- exposed publicly via a standard endpoint, such as `/.well-known/jwks.json`.

More secure websites:
- will only fetch keys from trusted domains
- but you can sometimes take advantage of URL parsing discrepancies:
	- to bypass this kind of filtering.

#### JWT authentication bypass via jku header injection
<span style="background:#fff88f">Part 1 - Upload a malicious JWK Set</span>
- In Burp, load the JWT Editor extension from the BApp store.
- In the lab, log in to your own account and send the post-login `GET /my-account` request to Burp Repeater.
- In Burp Repeater, change the path to `/admin` and send the request. 
	- Observe that the admin panel is only accessible when logged in as the `administrator` user.
    
- Go to the **JWT Editor Keys** tab in Burp's main tab bar.
- Click **New RSA Key**.
- In the dialog, click **Generate** to automatically generate a new key pair, then click **OK** to save the key. 
	- Note that you don't need to select a key size as this will automatically be updated later.
    
- In the browser, go to the exploit server.
- Replace the contents of the **Body** section with an empty JWK Set as follows:
```
{
    "keys": [

    ]
}
```
- Back on the **JWT Editor Keys** tab, right-click on the entry for the key that you just generated, then select **Copy Public Key as JWK**.
    
- Paste the JWK into the `keys` array on the exploit server, then store the exploit. 
- The result should look something like this:
```
{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "893d8f0b-061f-42c2-a4aa-5056e12b8ae7",
            "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw"
        }
    ]
}
```
<span style="background:#fff88f">Part 2 - Modify and sign the JWT</span>
1. Go back to the `GET /admin` request in Burp Repeater and switch to the extension-generated **JSON Web Token** message editor tab.
2. In the header of the JWT, replace the current value of the `kid` parameter with the `kid` of the JWK that you uploaded to the exploit server.
    
3. Add a new `jku` parameter to the header of the JWT. 
4. Set its value to the URL of your exploit server.
4. In the payload, change the value of the `sub` claim to `administrator`.
5. At the bottom of the tab, click **Sign**, then select the RSA key that you generated in the previous section.
    
6. Make sure that the **Don't modify header** option is selected, then click **OK**. 
	1. The modified token is now signed with the correct signature.
    
7. Send the request. Observe that you have successfully accessed the admin panel.
8. In the response, find the URL for deleting `carlos` (`/admin/delete?username=carlos`).
9. Send the request to this endpoint to solve the lab.

### Injecting self-signed JWTs via the kid parameter
 Servers may use:
 -  several cryptographic keys for signing different kinds of data
   =>
    not just JWTs. 
    
For this reason, the header of a JWT:
- may contain a kid (Key ID) parameter, 
	- which helps the server -->  identify which key to use when verifying the signature.

Verification keys are often stored -->  as a JWK Set
=>
In this case, the server may simply:
- look for the JWK with the same kid as the token. 
- However, the JWS specification:
	- doesn't define a concrete structure for this ID 
	- it's just an arbitrary string of the developer's choosing.
	- For example:
		- they might use the kid parameter to point to a particular entry in a database, or even the name of a file.

If this parameter is also vulnerable to directory traversal:
- an attacker could potentially force the server to:
	- use an arbitrary file from its filesystem as the verification key. 
```
{
    "kid": "../../path/to/file",
    "typ": "JWT",
    "alg": "HS256",
    "k": "asGsADas3421-dfh9DGN-AFDFDbasfd8-anfjkvc"
}
```
 This is especially dangerous if the server:
- also supports JWTs signed using a symmetric algorithm

In this case, an attacker could potentially:
- point the kid parameter to a predictable, static file
- then sign the JWT using a secret that matches the contents of this file.

You could theoretically do this with any file:
- but one of the simplest methods is to use `/dev/null`,
	- which is present on most Linux systems. 
	  
- As this is an empty file:
	- reading it returns an empty string
	  =>
	- signing the token with a empty string -->  will result in a valid signature

#### JWT authentication bypass via kid header path traversal
<span style="background:#fff88f">Generate a suitable signing key</span>
1. In Burp, load the JWT Editor extension from the BApp store.
2. In the lab, log in to your own account and send the post-login `GET /my-account` request to Burp Repeater.
3. In Burp Repeater, change the path to `/admin` and send the request. 
	1. Observe that the admin panel is only accessible when logged in as the `administrator` user.
    
4. Go to the **JWT Editor Keys** tab in Burp's main tab bar.
5. Click **New Symmetric Key**.
6. In the dialog, click **Generate** to generate a new key in JWK format. 
	1. Note that you don't need to select a key size as this will automatically be updated later.
    
7. Replace the generated value for the `k` property with a Base64-encoded null byte (`AA==`). 
	1. Note that this is just a workaround because the JWT Editor extension won't allow you to sign tokens using an empty string.
    
8. Click **OK** to save the key.

<span style="background:#fff88f">Modify and sign the JWT</span>
1. Go back to the `GET /admin` request in Burp Repeater and switch to the extension-generated **JSON Web Token** message editor tab.
    
2. In the header of the JWT, change the value of the `kid` parameter to a [path traversal](https://portswigger.net/web-security/file-path-traversal) sequence pointing to the `/dev/null` file:
   `../../../../../../../dev/null`
3. In the JWT payload, change the value of the `sub` claim to `administrator`.
4. At the bottom of the tab, click **Sign**, then select the symmetric key that you generated in the previous section.
5. Make sure that the **Don't modify header** option is selected, then click **OK**. 
	1. The modified token is now signed using a null byte as the secret key.
    
6. Send the request and observe that you have successfully accessed the admin panel.
7. In the response, find the URL for deleting `carlos` (`/admin/delete?username=carlos`). 
8. Send the request to this endpoint to solve the lab.


### Other interesting JWT header parameters
The following header parameters may also be interesting for attackers:
- `cty` (Content Type):
	- Sometimes used to declare a media type for the content in the JWT payload. 
	- This is usually omitted from the header, but the underlying parsing library may support it anyway. 
	- If you have found a way to bypass signature verification:
		- you can try injecting a `cty` header to change the content type to `text/xml` or `application/x-java-serialized-object`
		- which can potentially enable new vectors for XXE and deserialization attacks.

- `x5c` (X.509 Certificate Chain):
	- Sometimes used to pass the X.509 public key certificate or certificate chain of the key used to digitally sign the JWT. 
	- This header parameter can be used to:
		- inject self-signed certificates, similar to the `jwk` header injection attacks discussed above. 
	- Due to the complexity of the X.509 format and its extensions:
		- parsing these certificates can also introduce vulnerabilities. 
		- Details of these attacks are beyond the scope of these materials
			- but for more details, check out CVE-2017-2800 and CVE-2018-2633.

#### JWT authentication bypass via algorithm confusion
<span style="background:#fff88f">Part 1 - Obtain the server's public key</span>
1. In Burp, load the JWT Editor extension from the BApp store.
2. In the lab, log in to your own account and send the post-login `GET /my-account` request to Burp Repeater.
3. In Burp Repeater, change the path to `/admin` and send the request. 
	1. Observe that the admin panel is only accessible when logged in as the `administrator` user.
    
4. In the browser, go to the standard endpoint `/jwks.json` and observe that the server exposes a JWK Set containing a single public key.
5. Copy the JWK object from inside the `keys` array. 
	1. Make sure that you don't accidentally copy any characters from the surrounding array.

<span style="background:#fff88f">Part 2 - Generate a malicious signing key</span>
1. In Burp, go to the **JWT Editor Keys** tab in Burp's main tab bar.
2. Click **New RSA Key**.
3. In the dialog, make sure that the **JWK** option is selected, then paste the JWK that you just copied. Click **OK** to save the key.
4. Right-click on the entry for the key that you just created, then select **Copy Public Key as PEM**.
5. Use the **Decoder** tab to Base64 encode this PEM key, then copy the resulting string.
6. Go back to the **JWT Editor Keys** tab in Burp's main tab bar.
7. Click **New Symmetric Key**. In the dialog, click **Generate** to generate a new key in JWK format. 
	1. Note that you don't need to select a key size as this will automatically be updated later.
    
8. Replace the generated value for the k property with a Base64-encoded PEM that you just created.
9. Save the key.

<span style="background:#fff88f">Part 3 - Modify and sign the token</span>
1. Go back to the `GET /admin` request in Burp Repeater and switch to the extension-generated **JSON Web Token** tab.
    
2. In the header of the JWT, change the value of the `alg` parameter to `HS256`.
3. In the payload, change the value of the `sub` claim to `administrator`.
4. At the bottom of the tab, click **Sign**, then select the symmetric key that you generated in the previous section.
    
5. Make sure that the **Don't modify header** option is selected, then click **OK**. 
	1. The modified token is now signed using the server's public key as the secret key.
    
6. Send the request and observe that you have successfully accessed the admin panel.
7. In the response, find the URL for deleting `carlos` (`/admin/delete?username=carlos`). 
8. Send the request to this endpoint to solve the lab.

#### JWT authentication bypass via algorithm confusion with no exposed key
<span style="background:#fff88f">Part 1 - Obtain two JWTs generated by the server</span>
1. In Burp, load the JWT Editor extension from the BApp store.
2. In the lab, log in to your own account and send the post-login `GET /my-account` request to Burp Repeater.
    
3. In Burp Repeater, change the path to `/admin` and send the request. 
	1. Observe that the admin panel is only accessible when logged in as the `administrator` user.
    
4. Copy your JWT session cookie and save it somewhere for later.
5. Log out and log in again.
6. Copy the new JWT session cookie and save this as well. 
	1. You now have two valid JWTs generated by the server.

<span style="background:#fff88f">Part 2 - Brute-force the server's public key</span>
1. In a terminal, run the following command, passing in the two JWTs as arguments.
   `docker run --rm -it portswigger/sig2n <token1> <token2>`
	1. Note that the first time you run this, it may take several minutes while the image is pulled from Docker Hub.
    
	1. Notice that the output contains one or more calculated values of `n`. 
	2. Each of these is mathematically possible, but only one of them matches the value used by the server. 
	3. In each case, the output also provides the following:
    
    - A Base64-encoded public key in both X.509 and PKCS1 format.
    - A tampered JWT signed with each of these keys.
    
3. Copy the tampered JWT from the first X.509 entry (you may only have one).![[Pasted image 20240918113808.png]]
4. Go back to your request in Burp Repeater and change the path back to `/my-account`.
5. Replace the session cookie with this new JWT and then send the request.
    
    - If you receive a 200 response and successfully access your account page, then this is the correct X.509 key.
        
    - If you receive a 302 response that redirects you to `/login` and strips your session cookie, then this was the wrong X.509 key. In this case, repeat this step using the tampered JWT for each X.509 key that was output by the script.

<span style="background:#fff88f">Part 3 - Generate a malicious signing key</span>
1. From your terminal window, copy the Base64-encoded X.509 key that you identified as being correct in the previous section. 
	1. Note that you need to select the key, not the tampered JWT that you used in the previous section.
    
2. In Burp, go to the **JWT Editor Keys** tab and click **New Symmetric Key**.
3. In the dialog, click **Generate** to generate a new key in JWK format.
4. Replace the generated value for the `k` property with a Base64-encoded key that you just copied. 
	1. Note that this should be the actual key, not the tampered JWT that you used in the previous section.

5. Save the key.

<span style="background:#fff88f">Part 4 - Modify and sign the token</span>
1. Go back to your request in Burp Repeater and change the path to `/admin`.
2. Switch to the extension-generated **JSON Web Token** tab.
3. In the header of the JWT, make sure that the `alg` parameter is set to `HS256`.
4. In the JWT payload, change the value of the `sub` claim to `administrator`.
5. At the bottom of the tab, click **Sign**, then select the symmetric key that you generated in the previous section.
    
6. Make sure that the **Don't modify header** option is selected, then click **OK**. 
	1. The modified token is now signed using the server's public key as the secret key.
    
7. Send the request and observe that you have successfully accessed the admin panel.
8. In the response, find the URL for deleting `carlos` (`/admin/delete?username=carlos`). 
9. Send the request to this endpoint to solve the lab.

## How to prevent JWT attacks
You can protect your own websites against many of the attacks we've covered by taking the following high-level measures:
- Use an up-to-date library for handling JWTs and make sure your developers fully understand how it works along with any security implications. 
	- Modern libraries make it more difficult for you to inadvertently implement them insecurely,
	- but this isn't foolproof due to the inherent flexibility of the related specifications.
    
- Make sure that you perform robust signature verification on any JWTs that you receive,
	- and account for edge-cases such as JWTs signed using unexpected algorithms.
    
- Enforce a strict whitelist of permitted hosts for the `jku` header.
    
- Make sure that you're not vulnerable to path traversal or SQL injection via the `kid` header parameter.

### Additional best practice for JWT handling
Although not strictly necessary to avoid introducing vulnerabilities:
- we recommend adhering to the following best practice when using JWTs in your applications:
	- Always set an expiration date for any tokens that you issue.
	- Avoid sending tokens in URL parameters where possible.
	- Include the `aud` (audience) claim (or similar) to specify the intended recipient of the token. 
		- This prevents it from being used on different websites.
    
	- Enable the issuing server to revoke tokens (on logout, for example).

