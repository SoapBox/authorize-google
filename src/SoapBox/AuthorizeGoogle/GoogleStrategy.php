<?php namespace SoapBox\AuthorizeGoogle;

use SoapBox\Authorize\Helpers;
use SoapBox\Authorize\User;
use SoapBox\Authorize\Contact;
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
	 * @param callable $store A callback that will store a KVP (Key Value Pair).
	 * @param callable $load A callback that will return a value stored with the
	 *	provided key.
	 */
	public function __construct($settings = []) {
		if( !isset($settings['application_name']) ||
			!(
				(isset($settings['id']) && isset($settings['secret'])) || isset($settings['developer_key'])
			) ||
			!isset($settings['redirect_url']) ) {
			throw new MissingArgumentsException(
				'Required parameters application_name, [id and secret] or developer_key, or redirect_url are missing'
			);
		}

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
	public function login($parameters = []) {
		if (isset($this->state)) {
			Helpers::redirect($this->google->createAuthUrl(implode(' ', $this->scope)) . '&state=' . $this->state);
		} else {
			Helpers::redirect($this->google->createAuthUrl(implode(' ', $this->scope)));
		}
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
	public function getUser($parameters = array()) {
		if (isset($parameters['accessToken'])) {
			$this->client->setAccessToken($parameters['accessToken']);
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
	public function getFriends($parameters = array()) {
		if (isset($parameters['accessToken'])) {
			$this->client->setAccessToken($parameters['accessToken']);
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

	/**
	 * Used to handle tasks after login. This could include retrieving our users
	 * token after a successful authentication.
	 *
	 * @return array Mixed array of the tokens and other components that
	 *	validate our user.
	 */
	public function endpoint($parameters = array()) {
		$this->client->authenticate($parameters['code']);
		return $this->getUser(['accessToken' => $this->client->getAccessToken()]);
	}

}
