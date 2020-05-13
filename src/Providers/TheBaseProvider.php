<?php

namespace Overtrue\Socialite\Providers;

use DOMElement;
use GuzzleHttp\Cookie\CookieJar;
use Symfony\Component\HttpFoundation\Request;
use Overtrue\Socialite\AccessToken;
use Overtrue\Socialite\AccessTokenInterface;
use Overtrue\Socialite\AuthorizeFailedException;
use Overtrue\Socialite\ProviderInterface;
use Overtrue\Socialite\User;
use phpQuery as pq;
use RuntimeException;

/**
 * Class DouYinProvider.
 *
 * @author haoliang@qiyuankeji.vip
 *
 * @see http://open.douyin.com/platform
 */
class TheBaseProvider extends AbstractProvider implements ProviderInterface
{
    /**
     * Thebase接口域名.
     *
     * @var string
     */
    protected $baseUrl = 'https://api.thebase.in';

    /**
     * 作用于分割符号
     *
     * @var string
     */
    protected $scopeSeparator = ' ';

    /**
     * cookies
     *
     * @var CookieJar
     */
    private $jar;

    /**
     * 应用授权作用域.
     *
     * @var array
     */
    protected $scopes = ['read_users', 'read_users_mail', 'read_items', 'read_orders', 'read_savings', 'write_items', 'write_orders'];

    /**
     * Create a new provider instance.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @param string                                    $clientId
     * @param string                                    $clientSecret
     * @param string|null                               $redirectUrl
     */
    public function __construct(Request $request, $clientId, $clientSecret, $redirectUrl = null)
    {
        parent::__construct($request, $clientId, $clientSecret, $redirectUrl);
        $this->jar = new CookieJar();
    }

    /**
     * 获取登录页面地址.
     *
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase($this->baseUrl.'/1/oauth/authorize', $state);
    }

    protected function getLoginUrl() {
        return $this->baseUrl.'/1/oauth/authorize';
    }

    /**
     * 获取access_token地址.
     *
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return $this->baseUrl.'/1/oauth/token';
    }

    protected function formatScopes(array $scopes, $scopeSeparator)
    {
        return implode($scopeSeparator, $scopes);
    }

    protected function getCodeFields($state = null)
    {
        $fields = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUrl,
            'scope' => $this->formatScopes($this->scopes, $this->scopeSeparator),
            'response_type' => 'code',
        ];

        if ($this->usesState()) {
            $fields['state'] = $state;
        }

        return $fields;
    }

    /**
     * 获取access_token接口参数.
     *
     * @param string $code
     *
     * @return array
     */
    protected function getTokenFields($code)
    {
        return [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'code' => $code,
            'redirect_uri' => $this->redirectUrl,
            'grant_type' => 'authorization_code',
        ];
    }

    /**
     * 格式化token.
     *
     * @param \Psr\Http\Message\StreamInterface|array $body
     *
     * @return \Overtrue\Socialite\AccessTokenInterface
     */
    protected function parseAccessToken($body)
    {
        if (!is_array($body)) {
            $body = json_decode($body, true);
        }

        if (empty($body['access_token'])) {
            throw new AuthorizeFailedException('Authorize Failed: '.json_encode($body, JSON_UNESCAPED_UNICODE), $body);
        }

        return new AccessToken($body);
    }

    /**
     * 通过token 获取用户信息.
     *
     * @param AccessTokenInterface $token
     *
     * @return array|mixed
     */
    protected function getUserByToken(AccessTokenInterface $token)
    {
        $response = $this->getHttpClient()->get($this->baseUrl.'/1/users/me/', [
            'headers' => [
                'Authorization' => 'Bearer '.$token->getToken(),
            ],
        ]);

        return json_decode($response->getBody()->getContents(), true);

    }

    /**
     * 格式化用户信息.
     *
     * @param array $user
     *
     * @return User
     */
    protected function mapUserToObject(array $user)
    {
        return new User([
            'id' => $this->arrayItem($user, 'open_id'),
            'username' => $this->arrayItem($user, 'nickname'),
            'nickname' => $this->arrayItem($user, 'nickname'),
            'avatar' => $this->arrayItem($user, 'avatar'),
        ]);
    }

    /**
     * 自动登录授权.
     *
     */
    public function autoAuthorize() {
        $data = $this->getAuthorizeData();
        $code = $this->loginAndGetCode($data);

        $accessToken = $this->getAccessToken($code);;
        return $accessToken;
    }

    /**
     * 获取登录所需数据.
     *
     */
    public function getAuthorizeData() {

        $state = null;

        if ($this->usesState()) {
            $state = $this->makeState();
        }

        $authUrl = $this->getAuthUrl($state);

        $response = $this->getHttpClient()->get($authUrl, ['debug' => true, 'cookies' => $this->jar]);

        $params = array();

        if($response->getStatusCode() == 200) {
            $document = pq::newDocumentHTML($response->getBody());
            $document->
            find('#UserIndexForm input[type="hidden"]')->
            each(function(DOMElement $element) use(&$params) {
                $params[$element->getAttribute("name")] = $element->getAttribute("value");
            });

            return $params;
        }

        throw new RuntimeException("Failed to get authorize form data in url");
    }

    /**
     * 模拟登录并且获取code.
     *
     */
    public function loginAndGetCode($data) {

        $response = $this->getHttpClient()->post($this->getLoginUrl(), [
            'debug' => true,
            'allow_redirects' => false,
            'cookies' => $this->jar,
            'form_params' => array_merge($data, $this->getLoginData())
        ]);

        if($response->getStatusCode() == 302) {
            $url = current($response->getHeader('Location'));
            if($this->verifyURL($url) !== false) {
                parse_str(parse_url($url, PHP_URL_QUERY),$variable);
                return $variable['code'];
            }
        }

        throw new RuntimeException("Failed to get code in url");
    }

    /**
     * 获取用户登录的信息
     * @return array
     */
    protected function getLoginData() {
        return ['data[User][mail_address]' => $this->parameters['username'],
            'data[User][password]' => $this->parameters['password'],
            'auth_yes' => '\u30A2\u30D7\u30EA\u3092\u8A8D\u8A3C\u3059\u308B',
        ];
    }

    /**
     * 验证url有没有code
     * @return mixed
     */
    public function verifyURL($url) {
        return strpos($url, 'code');
    }
}
