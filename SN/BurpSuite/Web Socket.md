## Definition
- initiated over HTTP 
- provide long-lived connections with asynchronous communication in both directions

WebSockets are used for all kinds of purposes:
including performing -->   user actions and transmitting sensitive information

## Manipulating WebSocket traffic
Finding WebSockets security vulnerabilities generally involves:
manipulating them -->  in ways that the application doesn't expect. 

You can use Burp Suite to:
- Intercept and modify Web Socket messages
- Replay and generate new Web Socket messages
- Manipulate Web Socket connection

### Intercepting and modifying WebSocket messages
You can use Burp Proxy to intercept and modify Web Socket messages, as follows:
- Open Burp's browser.
- Browse to the app function that uses Web Sockets. 
	- You can determine that Web Sockets are being used by:
		- using the app and looking for entries appearing in the Web Sockets history tab within Burp Proxy.
- In the Intercept tab of Burp Proxy, ensure that interception is turned on.
- When a Web Socket message is sent from the browser or server, it will be displayed in the Intercept tab for you to view or modify. 
	- Press the Forward button to forward the message

### Replaying and generating new Web Socket messages
As well as intercepting and modifying Web Socket messages on the fly:
you can replay individual messages and generate new messages. 

You can do this using Burp Repeater:
- In Burp Proxy, select a message in the Web Sockets history, or in the Intercept tab, and choose "Send to Repeater" from the context menu.
- In Burp Repeater, you can now edit the message that was selected, and send it over and over.
- You can enter a new message and send it in either direction, to the client or server.
- In the "History" panel within Burp Repeater, you can view the history of messages that have been transmitted over the Web Socket connection. 
	- This includes messages that you have generated in Burp Repeater, and also any that were generated by the browser or server via the same connection.
- If you want to edit and resend any message in the history panel:
	- you can do this by selecting the message 
	- choosing "Edit and resend" from the context menu

### Manipulating Web Socket connections
As well as manipulating Web Socket messages:
it is sometimes necessary to:
manipulate the Web Socket -->  handshake that establishes the connection.

There are various situations in which manipulating the Web Socket handshake might be necessary:
- It can enable you to reach more attack surface.
- Some attacks might cause your connection to drop so you need to establish a new one.
- Tokens or other data in the original handshake request might be stale and need updating.

You can manipulate the Web Socket handshake using Burp Repeater:
- Send a Web Socket message to Burp Repeater as already described
- In Burp Repeater, click on the pencil icon next to the Web Socket URL. 
	- This opens a wizard that lets you attach to an existing connected Web Socket, clone a connected Web Socket, or reconnect to a disconnected Web Socket.
- If you choose to clone a connected Web Socket or reconnect to a disconnected Web Socket, then the wizard will show full details of the Web Socket handshake request, which you can edit as required before the handshake is performed.
- When you click "Connect", Burp will attempt to carry out the configured handshake and display the result. 
	- if a new Web Socket connection was successfully established, you can then use this to send new messages in Burp Repeater

## Web Sockets security vulnerabilities
### Manipulating Web Socket messages to exploit vulnerabilities
The majority of input-based vulnerabilities affecting WebSockets:
- can be found and exploited by tampering with the contents of WebSocket messages

For example, suppose a chat application uses WebSockets to send chat messages between the browser and the server. 
When a user types a chat message, a WebSocket message like the following is sent to the server:
`{"message":"Hello Carlos"}`

The contents of the message are transmitted (again via Web Sockets) to another chat user:
and rendered in the user's browser as follows:
`<td>Hello Carlos</td>`

In this situation, provided no other input processing or defenses are in play:
an attacker can perform a proof-of-concept XSS attack by submitting the following Web Socket message:
`{"message":"<img src=1 onerror='alert(1)'>"}`

#### Manipulating WebSocket messages to exploit vulnerabilities
1. Click "Live chat" and send a chat message.
2. In Burp Proxy, go to the WebSockets history tab, and observe that the chat message has been sent via a WebSocket message.
3. Using the browser, send a new message containing a `<` character.
4. In Burp Proxy, find the corresponding WebSocket message and observe that the `<` has been HTML-encoded by the client before sending.
5. Ensure that Burp Proxy is configured to intercept WebSocket messages, then send another chat message.
6. Edit the intercepted message to contain the following payload:
   `<img src=1 onerror='alert(1)'>`
7. Observe that an alert is triggered in the browser. This will also happen in the support agent's browser.

Otherwise:
- turn on interception 
- capture the packet that send a message in the chat
- edit by inserting `<img src=1 onerror='alert(1)'>`
- send the packet and disable the interception

