# Dynamic URL Macro

This Burp extension allows you use a macro when a form has a dynamic target.

To use it, first create a macro that includes both the request to fetch the form, and the POST submission. Then create a session
handling rule with an action to *Invoke a Burp extension* Select an action handler like *Dynamic URL macro: Macro 1*

The extension extracts the action from the first `<form>` tag on a page, and if the subsequent request uses the POST method,
overrides the URL in this request.

The normal macro behaviour of extracting form values and updating subsequent requests does not work. This might be possible
to implement in future by redesigning the extension to use the `IHttpListener` interface.