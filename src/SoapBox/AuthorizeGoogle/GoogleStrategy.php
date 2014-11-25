<?php namespace SoapBox\AuthorizeGoogle;

use SoapBox\Authorize\Helpers;
use SoapBox\Authorize\User;
use SoapBox\Authorize\Contact;
use SoapBox\Authorize\Session;
use SoapBox\Authorize\Router;
use SoapBox\Authorize\Exceptions\AuthenticationException;
use SoapBox\Authorize\Strategies\SingleSignOnStrategy;

class GoogleStrategy extends SingleSignOnStrategy {

	/**
	 * An array of the permissions we require for the application.
	 */
	private $scope = array('https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.google.com/m8/feeds/');

	private $state;
	private $google;
	private $client;
	private $clientId;

	private $session;
	private $router;

	/**
	 * Initializes the Google Authentication with our id and secret
	 *
	 * @param array $settings [
	 *		'application_name' => string,
	 *		'id' => string,
	 *		'secret' => string,
	 *		'redirect_url' => string,
	 *		'developer_key' => string
	 *	]
	 * @param Session $session Provides the strategy a place to store / retrieve data
	 * @param Router $router Provides the strategy a mechanism to redirect users
	 */
	public function __construct(array $settings = [], Session $session, Router $router) {
		if( !isset($settings['application_name']) ||
			!(
				(isset($settings['id']) && isset($settings['secret'])) || isset($settings['developer_key'])
			) ||
			!isset($settings['redirect_url']) ) {
			throw new MissingArgumentsException(
				'Required parameters application_name, [id and secret] or developer_key, or redirect_url are missing'
			);
		}

		$this->session = $session;
		$this->router = $router;

		$client = new \Google_Client();
		$client->setApplicationName($settings['application_name']);
		$client->setRedirectUri($settings['redirect_url']);
		if (isset($setting['id']) && isset($setting['secret'])) {
			$client->setClientId($settings['id']);
			$client->setClientSecret($settings['secret']);
		} else {
			$client->setDeveloperKey($settings['developer_key']);
		}
		if (isset($settings['state'])) {
			$this->state = $settings['state'];
		}

		$this->client = $client;
		$this->clientId = $settings['id'];
		$this->google = new \Google_Auth_OAuth2($client);
	}

	/**
	 * Used to authenticate our user with Google OAuth. Redirects user to Google's
	 * authentication page.
	 *
	 * @param array parameters []
	 */
	public function login(array $parameters = []) {
		if (isset($this->state)) {
			$this->router->redirect($this->google->createAuthUrl(implode(' ', $this->scope)) . '&state=' . $this->state);
		} else {
			$this->router->redirect($this->google->createAuthUrl(implode(' ', $this->scope)));
		}
	}

	/**
	 * In order to pass authentication this class requires that it be passed a
	 * 'code' from the service utilizing it.
	 *
	 * @return string[] The list of parameters required to authenticate with google
	 */
	public function expects() {
		return ['code'];
	}

	/**
	 * Used to retrieve the user from the strategy.
	 *
	 * @param array parameters The parameters required to authenticate against
	 *	this strategy. (i.e. accessToken)
	 *
	 * @throws AuthenticationException If the provided parameters do not
	 *	successfully authenticate.
	 *
	 * @return User A mixed array representing the authenticated user.
	 */
	public function getUser(array $parameters = []) {
		if (isset($parameters['accessToken'])) {
			$this->client->setAccessToken($parameters['accessToken']);
		} else if (isset($parameters['code'])) {
			$this->client->authenticate($parameters['code']);
		}

		if ($this->client->getAccessToken()) {
			$plus = new \Google_Service_Plus($this->client);

			$googleUser = $plus->people->get('me');
			$key = json_decode($parameters['accessToken']);

			$attributes = $this
				->client
				->verifyIdToken($key->id_token)
				->getAttributes();

			$user = new User;
			$user->id = $attributes['payload']['sub'];
			$user->email = $attributes['payload']['email'];
			$user->accessToken = $this->client->getAccessToken();
			$user->firstname = $googleUser['name']['givenName'];
			$user->lastname = $googleUser['name']['familyName'];

			return $user;
		}
		throw new AuthenticationException();
	}

	/**
	 * Used to retrieve the friends of this user that are also using this app
	 *
	 * @param array parameters The parameters required to authenticate against
	 *	this strategy. (i.e. accessToken)
	 *
	 * @throws AuthenticationException If the provided parameters do not
	 *	successfully authenticate.
	 *
	 * @return array A list of userId's that are friends of this user.
	 */
	public function getFriends(array $parameters = []) {
		if (isset($parameters['accessToken'])) {
			$this->client->setAccessToken($parameters['accessToken']);
		} else if (isset($parameters['code'])) {
			$this->client->authenticate($parameters['code']);
		}

		if ($this->client->getAccessToken()) {
			$continue = true;
			$results = [];
			$url = "https://www.google.com/m8/feeds/contacts/default/full?alt=json&max-results=700&v=3.0";
			while ($continue) {
				$request = new \Google_Http_Request($url);
				$request = $this->client->getAuth()->sign($request);
				$result = $this->client->execute($request);
				$results = array_merge($results, $result['feed']['entry']);
				$continue = false;
				foreach ($result['feed']['link'] as $link) {
					if ($link['rel'] == 'next') {
						$url = $link['href'];
						$continue = true;
					}
				}
			}

			$friends = [];

			foreach ($results as $contact) {
				$friend = new Contact;
				$friend->email =
					isset($contact['gd$email'][0]['address']) ?
						(string) $contact['gd$email'][0]['address'] : '';
				$friend->displayName =
					isset($contact['title']['$t']) ?
						(string) $contact['title']['$t'] : '';
				$friends[] = $friend;
			}

			return $friends;
		}
		throw new AuthenticationException();
	}

}
