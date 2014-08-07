# Authorize-Google
[Authorize](http://github.com/soapbox/authorize) strategy for Google authentication.

## Getting Started
- Install [Authorize](http://github.com/soapbox/authorize) into your application
to use this Strategy.
- Visit [API Console](code.google.com/apis/console/) and configure your application
based on the scopes you would like to support.

## Installation
Add the following to your `composer.json`
```
"require": {
	...
	"soapbox/authorize-google": "dev-master",
	...
}
```

### app/config/app.php
Add the following to your `app.php`, note this will be removed in future
versions since it couples us with Laravel, and it isn't required for the library
to function
```
'providers' => array(
	...
	"SoapBox\AuthorizeGoogle\AuthorizeGoogleServiceProvider",
	...
)
```

## Usage

### Login
```php

use SoapBox\Authorize\Authenticator;
use SoapBox\Authorize\Exceptions\InvalidStrategyException;
...
$settings = [
	'application_name' => 'set_this_on_dev_console',
	'id' => 'get_this_from_google',
	'secret' => 'get_this_from_google',
	'redirect_url' => 'http://example.com/social/google/callback',
	'developer_key' => 'get_this_from_google'
];

//If you already have an accessToken from a previous authentication attempt
$parameters = ['accessToken' => 'sometoken'];

$strategy = new Authenticator('google', $settings);

$user = $strategy->authenticate($parameters);

```

### Endpoint
```php

use SoapBox\Authroize\Authenticator;
use SoapBox\Authorize\Exceptions\InvalidStrategyException;
...
$settings = [
	'code' => 'this_is_posted_by_google_to_the_specified_redirect_url'
];

$strategy = new Authenticator('google', $settings);
$user = $strategy->endpoint();

```
