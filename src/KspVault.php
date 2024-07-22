<?php

namespace AndangSecure;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use AlibabaCloud\Darabonba\EncodeUtil\EncodeUtil;
use AlibabaCloud\Darabonba\SignatureUtil\SignatureUtil;

class KspVault
{
    private $domain;
    private $appid;
    private $appsecret;
    private $client;
    private $token;
    private $private;

    /**
     * 构造函数用于初始化类实例
     *
     * 该函数在类被实例化时自动调用，用于设置类的属性，包括域名、应用ID和应用密钥。
     * 这些属性对于后续的API调用或数据访问操作至关重要，它们共同识别并授权类操作特定的应用程序资源。
     *
     * @param string $domain 应用程序的域名或URL，用于API调用或数据访问的endpoint。
     * @param string $appid 应用程序的唯一标识符，用于识别调用API的应用程序。
     * @param string $appsecret 应用程序的密钥，用于验证应用程序的身份和访问权限。
     */
    public function __construct($domain, $appid, $appsecret)
    {
        $this->domain = $domain;
        $this->appid = $appid;
        $this->appsecret = $appsecret;
        $this->client = new Client([
            'base_uri' => $this->domain,
            'timeout'  => 2.0,
            'verify' => false
        ]);
    }

    /**
     * 获取访问令牌
     *
     * 本函数用于通过发送POST请求到指定的API端点，获取一个访问令牌。
     * 请求包括应用的ID和密钥，以及指定的域名信息。获取到的访问令牌
     * 将用于后续对API的授权访问。
     *
     * @return array 返回包含访问令牌的HTTP响应
     */
    private function getToken(){
        $client =  $this->client;
        try {
            $response = $client->request('POST', '/v1/ksp/open_api/login', [
                'json' =>  [
                    'appid' => $this->appid,
                    'appsecret' => $this->appsecret,
                    'domain' => 1,
                ],
            ]);

            // 获取响应内容并解析为数组// 输出响应数据
            return json_decode($response->getBody(), true);
        } catch (RequestException $e) {
            // 捕获请求异常并输出错误信息
            return array(
                'code' => 1,
                'msg' => '请求失败',
                'data' => array(
                    'error' => $e->getMessage(),
                    'error_description' => $e->getMessage(),
                    'error_code' => $e->getCode(),
                    'error_uri' => $e->getFile(),
                    'error_line' => $e->getLine(),
                )
            );
        }
    }


    public function GetKeyValueByLabel($label){
        $tokenRes = $this->getToken();
        if($tokenRes['code'] == 0){
            $this->token = $tokenRes['data']['token'];
        } else {
            return array(
                'code' => 1,
                'msg' => '请求失败111',
                'data' => "");
        }

        // 获取公私钥
        $rsaKeyArr = $this->getRsaKey();
        if($rsaKeyArr){
            $this->private = $rsaKeyArr['pri'];
        } else {
            return array(
                'code' => 1,
                'msg' => '请求失败',
                'data' => "");
        }
        // 处理公钥的开头和结尾，只保留主体部分
        $pubContent = preg_replace('/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----/', '', $rsaKeyArr['pub']);

        $sendData =  [
            'label' => $label,
            'version' => "1",
            'pub' => $pubContent,
        ];
        // 计算SHA-256哈希值
        $hash = hash('sha256', json_encode($sendData));
        // 将哈希值转换为大写的Hex编码字符串
        $hashUppercase = strtoupper($hash);
        $date = gmdate('D, d M Y H:i:s \G\M\T', time());
        $CanonicalizedKMSHeaders = "x-ksp-acccesskeyid:".$this->appid."\n"
                    ."x-ksp-apiname:credential/cipher\n"
                    ."x-ksp-version:ksp-1.8.6";
        $CanonicalizedResource = "/";

        $SignString = "post\n".$hashUppercase."\n"
            ."application/json\n"
            .$date."\n"
            .$CanonicalizedKMSHeaders."\n".$CanonicalizedResource;

        // 去除私钥的开头和结尾，只保留主体部分
        $secret = preg_replace('/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----/', '', $rsaKeyArr['pri']);
        $sig = EncodeUtil::base64EncodeToString(SignatureUtil::SHA256withRSASign($SignString, $secret));

        $client =  $this->client;
        try {
            $response = $client->request('POST', '/v1/ksp/open_api/credential/cipher', [
                'json' =>  $sendData,
                "headers" => [
                    'token' => $this->token,
                    "Content-SHA256" => $hashUppercase,
                    "x-ksp-acccesskeyid" => $this->appid,
                    "x-ksp-apiname" => 'credential/cipher',
                    "Content-Type" => 'application/json',
                    "Sign-Header" => $sig,
                    "Date" => gmdate('D, d M Y H:i:s \G\M\T', time())
                ],
            ]);

            // 获取响应内容并解析为数组
            $responseData = json_decode($response->getBody(), true);

            // 解密凭据 先私钥解密后aes解密
            openssl_private_decrypt(base64_decode($responseData['data']['cipher_key']), $decryptedData, $this->private);

            // 待解密的数据（base64编码）
            $encryptedData = $responseData['data']['ciphertext'];

            $decryptedData = $this->aesCbcDecrypt($encryptedData, $decryptedData);
            return array(
                'code' => 0,
                'msg' => '请求成功',
                'data' => $decryptedData);
            // 输出响应数据
            return $responseData;
        } catch (RequestException $e) {
            // 捕获请求异常并输出错误信息
            return array(
                'code' => 1,
                'msg' => '获取凭据失败',
                'data' => array(
                    'error' => $e->getMessage(),
                    'error_description' => $e->getMessage(),
                    'error_code' => $e->getCode(),
                    'error_uri' => $e->getFile(),
                    'error_line' => $e->getLine(),
                )
            );
        }
    }

    function aesCbcDecrypt($ciphertext, $key) {
        // 将base64编码的密文解码
        $ciphertext = base64_decode($ciphertext);

        // 检查密钥长度是否为16, 24或32字节
        $keyLength = strlen($key);
        if ($keyLength != 16 && $keyLength != 24 && $keyLength != 32) {
            throw new Exception("The key length is illegal");
        }

        // 创建一个AES解密器
        $blockSize = 16;
        $iv = substr($key, 0, $blockSize);

        // 解密
        $plaintext = openssl_decrypt($ciphertext, 'aes-128-cbc', $key, OPENSSL_RAW_DATA, $iv);

        return $plaintext;
    }

    /**
     * 生成RSA公私钥对
     *
     * 本函数用于创建一个RSA密钥对，并将私钥和公钥以文本形式打印出来。
     * RSA是一种广泛使用的公钥加密算法，可用于数据加密和数字签名。
     *
     * @return array
     */
    private function getRsaKey()
    {
        // 配置密钥生成参数，指定密钥长度为2048位，使用RSA算法
        // 配置密钥参数
        $config = array(
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        );

        // 生成新的密钥对
        // 生成公私钥对
        $res = openssl_pkey_new($config);

        // 检查密钥对生成是否失败，如果失败，则输出错误信息并终止程序
        if ($res === false) {
            die('生成密钥失败: ' . openssl_error_string());
        }

        // 导出私钥，$privateKey将存储私钥内容
        // 提取私钥
        openssl_pkey_export($res, $privateKey);

        // 获取公钥详细信息，其中包含公钥内容
        // 提取公钥
        $publicKeyDetails = openssl_pkey_get_details($res);
        // 从公钥详细信息中提取公钥
        $publicKey = $publicKeyDetails["key"];

        // 打印私钥和公钥
        // 打印公私钥
        return  [
            'pri' => $privateKey,
            'pub' => $publicKey,
        ];
    }
    public function say(){
        echo "vault";
    }
}