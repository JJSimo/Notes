## Definition
allow an attacker to elicit unintended behavior
This potentially enables attackers to -->  manipulate legitimate functionality 
                                    to achieve a malicious goal

Business logic vulnerabilities often arise:
bc the design and development teams:
- make flawed assumptions about how users will interact with the application
  =>
   These bad assumptions can lead to -->  inadequate validation of user input

## Excessive trust in client-side control
1. With Burp running, log in and attempt to buy the leather jacket. 
   The order is rejected because you don't have enough store credit.
2. In Burp, go to "Proxy" > "HTTP history" and study the order process. 
   Notice that when you add an item to your cart, the corresponding request contains a `price` parameter. Send the `POST /cart` request to Burp Repeater.
3. Go to your oder checkout
1. In Burp Repeater, change the price to an arbitrary integer and send the request -->  
   `100` to put 1 eur
2. Refresh the cart and confirm that the price has changed based on your input.
4. Complete the order to solve the lab

## Failing to handle unconventional input
- add a random item to your card
- Notice that the quantity is determined by a parameter in the `POST /cart` request
- Change the `quantity` parameter to an arbitrary integer
	- then forward any remaining requests
	- Observe that the quantity in the cart was successfully updated based on your input
- Repeat this process, but request a negative quantity this time
- Now add the item that you really want to buy
- go to checkout
- if you add more negative items of the other product =>  you'll see the amount of money go down
- add enough negative items so that you can afford the real one
- then purchase the item

### Low-level logic flaw
- While proxying traffic through Burp, open the lab and go to the "Target" > "Site map" tab. 
  Right-click on the lab domain and select "Engagement tools" > "Discover content" to open the content discovery tool.
- Click "Session is not running" to start the content discovery. 
  After a short while, look at the "Site map" tab in the dialog. 
  Notice that it discovered the path `/admin`.
- Try to browse to `/admin`. Although you don't have access, an error message indicates that `DontWannaCry` users do.
- Go to the account registration page. 
  Notice the message telling `DontWannaCry` employees to use their company email address.
- From the button in the lab banner, open the email client. Make a note of the unique ID in the domain name for your email server (`@YOUR-EMAIL-ID.web-security-academy.net`).
- Go back to the lab and register with an exceptionally long email address in the format:
   `very-long-string@YOUR-EMAIL-ID.web-security-academy.net`
   The `very-long-string` should be at least 200 characters long.

- Go to the email client and notice that you have received a confirmation email. 
  Click the link to complete the registration process.
- Log in and go to the "My account" page. 
  Notice that your email address has been truncated to 255 characters.
- Log out and go back to the account registration page.
- Register a new account with another long email address, but this time include `dontwannacry.com` as a subdomain in your email address as follows:
  `very-long-string@dontwannacry.com.YOUR-EMAIL-ID.web-security-academy.net`
  Make sure that the `very-long-string` is the right number of characters so that the "`m`" at the end of `@dontwannacry.com` is character 255 exactly.

- Go to the email client and click the link in the confirmation email that you have received. Log in to your new account and notice that you now have access to the admin panel. The confirmation email was successfully sent to your email client, but the application server truncated the address associated with your account to 255 characters. 
  As a result, you have been able to register with what appears to be a valid `@dontwannacry.com` address. You can confirm this from the "My account" page.
- Go to the admin panel and delete `carlos` to solve the lab

### Inconsistent security controls
1. Open the lab then go to the "Target" > "Site map" tab in Burp. 
   Right-click on the lab domain and select "Engagement tools" > "Discover content" to open the content discovery tool.
2. Click "Session is not running" to start the content discovery. 
   After a short while, look at the "Site map" tab in the dialog. 
   Notice that it discovered the path `/admin`.
3. Try and browse to `/admin`. 
   Although you don't have access, the error message indicates that `DontWannaCry` users do.
4. Go to the account registration page. 
   Notice the message telling `DontWannaCry` employees to use their company email address. 
   Register with an arbitrary email address in the format:
   `anything@your-email-id.web-security-academy.net`
   You can find your email domain name by clicking the "Email client" button.

5. Go to the email client and click the link in the confirmation email to complete the registration.
6. Log in using your new account and go to the "My account" page. 
   Notice that you have the option to change your email address. 
   Change your email address to an arbitrary `@dontwannacry.com` address.
7. Notice that you now have access to the admin panel, where you can delete `carlos` to solve the lab.

## Users won't always supply mandatory input
### Weak isolation on dual-use endpoint
- With Burp running, log in and access your account page.
- Change your password.
- Study the `POST /my-account/change-password` request in Burp Repeater.
- Notice that if you remove the `current-password` parameter entirely, 
  you are able to successfully change your password without providing your current one.
- Observe that the user whose password is changed is determined by the `username` parameter. Set `username=administrator` and send the request again.
- Log out and notice that you can now successfully log in as the `administrator` using the password you just set.
- Go to the admin panel and delete `carlos` to solve the lab

## Users won't always follow the intended sequence
## 2FA broken logic
- With Burp running, log in to your own account and investigate the 2FA verification process. 
  Notice that in the `POST /login2` request, the `verify` parameter is used to determine which user's account is being accessed.
- Log out of your account.
- Send the `GET /login2` request to Burp Repeater. 
  Change the value of the `verify` parameter to `carlos` and send the request. 
  This ensures that a temporary 2FA code is generated for Carlos.
- Go to the login page and enter your username and password. 
  Then, submit an invalid 2FA code.
- Send the `POST /login2` request to Burp Intruder.
- In Burp Intruder, set the `verify` parameter to `carlos` and add a payload position to the `mfa-code` parameter. Brute-force the verification code.
- Load the 302 response in the browser.
- Click **My account** to solve the lab
### Insufficient workflow validation
1. With Burp running, log in and buy any item that you can afford with your store credit.
2. Study the proxy history. Observe that when you place an order, the `POST /cart/checkout` request redirects you to an order confirmation page. Send `GET /cart/order-confirmation?order-confirmation=true` to Burp Repeater.
3. Add the leather jacket to your basket.
4. In Burp Repeater, resend the order confirmation request. Observe that the order is completed without the cost being deducted from your store credit and the lab is solved.

### Authentication bypass via flawed state machine
- With Burp running, complete the login process and notice that you need to select your role before you are taken to the home page.
- Use the content discovery tool to identify the `/admin` path.
- Try browsing to `/admin` directly from the role selection page and observe that this doesn't work.
- Log out and then go back to the login page. 
- In Burp, turn on proxy intercept then log in.
- Forward the `POST /login` request. 
- The next request is `GET /role-selector`. 
  Drop this request and then browse to the lab's home page. 
- Turn off interception
- Observe that your role has defaulted to the `administrator` role and you have access to the admin panel.
- Delete `carlos` to solve the lab
## Domain-specific flaws
### Flawed enforcement of business rules
1. Log in and notice that there is a coupon code, `NEWCUST5`.
2. At the bottom of the page, sign up to the newsletter. You receive another coupon code, `SIGNUP30`.
3. Add the leather jacket to your cart.
4. Go to the checkout and apply both of the coupon codes to get a discount on your order.
5. Try applying the codes more than once. Notice that if you enter the same code twice in a row, it is rejected because the coupon has already been applied. However, if you alternate between the two codes, you can bypass this control.
6. Reuse the two codes enough times to reduce your order total to less than your remaining store credit. Complete the order to solve the lab

## Providing an encryption oracle
### Authentication bypass via encryption oracle
