<?php

class RongCloudOperation {

    //appkey
    public $appkey;
    public $appSecret;
    //你的secretid
    public $secretid;
    // 私钥路径 设置方法 https://open.tuputech.com/account/cert
    public $rsa_private_key_path = './rsa_private_key.pem';
    //图谱公钥路径 下载地址 http://api.open.tuputech.com/v2/pipe/558e37eba636676972c8ab94
    public $open_tuputech_com_public_key_path = "./open_tuputech_com_public_key.pem";
    //融云删除图片的链接
    public $deleteUrl = "https://api.cn.ronghub.com/image/delete.json";

    public function __construct($secretid, $appSecret, $appkey) {
        $this->secretid = $secretid;
        $this->appSecret = $appSecret;
        $this->appkey = $appkey;
    }

    /**
     * 
     * @param string $imageUrl 图片地址
     * @param string $taskUrl 验证任务链接地址
     * @return array
     */
    public function curl($data, $url, $header = false) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        if ($header) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
            $data = http_build_query($data);
        }
        curl_setopt($ch, CURLOPT_DNS_USE_GLOBAL_CACHE, FALSE);
        curl_setopt($ch, CURLOPT_HEADER, false);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        $output = curl_exec($ch);
        curl_close($ch);
        return $output;
    }

    /**
     * 写日志，方便测试（看网站需求，也可以改成把记录存入数据库）
     * 注意：服务器需要开通fopen配置
     * @param $word 要写入日志里的文本内容 默认值：空值
     */
    public function logResult($word = '') {
        $fp = fopen("log.txt", "a");
        flock($fp, LOCK_EX);
        fwrite($fp, "执行日期：" . strftime("%Y%m%d%H%M%S", time()) . "\n" . $word . "\n");
        flock($fp, LOCK_UN);
        fclose($fp);
    }

    /**
     * 验证
     * @param string $imageUrl 图片链接
     * @param string $taskUrl  任务链接
     * @param float  $rate     机器最小肯定率
     */
    public function verify($imageUrl, $taskUrl, $rate) {
        $timestamp = time(); //当前时间
        $nonce = rand(100, 999999); //随机数
        $sign_string = $this->secretid . "," . $timestamp . "," . $nonce;

        //计算签名
        $private_key_pem = file_get_contents($this->rsa_private_key_path);
        $pkeyid = openssl_get_privatekey($private_key_pem);
        openssl_sign($sign_string, $signature, $pkeyid, OPENSSL_ALGO_SHA256);
        $signature = base64_encode($signature);

        $data = 'secretId=' . $this->secretid . '&timestamp=' . $timestamp . '&nonce=' . $nonce . '&signature=' . urlencode($signature) . '&image=' . urlencode($imageUrl);
        //图片验证
        $output = $this->curl($data, $taskUrl);
        if ($output !== false) {
            $data = json_decode($output, true);

            $signature = $data['signature'];
            $json = $data['json'];
            $public_key_pem = file_get_contents($this->open_tuputech_com_public_key_path);
            $pkeyid2 = openssl_get_publickey($public_key_pem);
            //利用openssl_verify进行验证，结果1表示验证成功，0表示验证失败
            $result = openssl_verify($json, base64_decode($signature), $pkeyid2, "sha256WithRSAEncryption");
            if ($result == 1) {
                $json = json_decode($data['json'], 1);
                if ($json['code'] == 0) {

                    foreach ($json['fileList'] as $value) {
                        //如果是黄图切不需要人工审核则执行删除操作
                        if ($value['review'] && $value['rate'] > $rate && $value['label'] == 0) {
                            $header = $this->createHeader();
                            $deleteData = array('url' =>$value['name']);
                            $request = $this->curl($deleteData, $this->deleteUrl, $header);
                            $request = json_decode($request,1);
                            if (isset($request['code']) && $request['code'] == 200) {
                                $this->logResult(var_export($value, 1) . "\n" . "删除成功");
                            } else {
                                $this->logResult(var_export($value, 1) . "\n" . var_export($request, 1));
                            }
                        }
                    }
                }
                $this->logResult("验证完毕");
                return true;
            } else {
                return false;
                $this->logResult("验证错误失败");
            }
        }
    }

    /**
     * 复审删除
     * @param string $data
     * @param string $signatrue
     */
    public function review($data, $signature, $label) {
        $public_key_pem = file_get_contents($this->open_tuputech_com_public_key_path);
        $pkeyid2 = openssl_get_publickey($public_key_pem);
        $result = openssl_verify($data, base64_decode($signature), $pkeyid2, "sha256WithRSAEncryption");

        if ($result) {
            $data = json_decode($data, 1);
            foreach ($data['reviews'] as $value) {
                //判断是否是换图
                if ($value['label'] == 0) {
                    $header = $this->createHeader();
                    $deleteData = array('url' =>$value['filename']);
                    $request = $this->curl($deleteData, $this->deleteUrl, $header);
                    $request = json_decode($request,1);
                    if (isset($request['code']) && $request['code'] == 200) {
                        $this->logResult(var_export($value, 1) . "\n" . "删除成功");
                    } else {
                        $this->logResult(var_export($value, 1) . "\n" . var_export($request, 1));
                    }
                }
            }
            $this->logResult("验证完毕");
        }
    }

    /**
     * 创建头信息
     */
    public function createHeader() {
        srand((double) microtime() * 1000000);
        $time = explode(" ", microtime());
        $time = $time [1] . ($time [0] * 1000);
        $time2 = explode(".", $time);
        $timestamp = $time2 [0]; // 毫秒级时间戳

        $nonce = rand(); // 获取随机数。
        $arr = array($this->appSecret, $nonce, $timestamp);
        sort($arr);
        $str = implode("", $arr);
        $signature = sha1($str);

        $header = array(
            'Content-Type: application/x-www-form-urlencoded',
            'App-Key:' . $this->appkey,
            'RC-Nonce:' . $nonce,
            'RC-Timestamp: ' . $timestamp,
            'RC-Signature: ' . $signature,
        );
        return $header;
    }

}
$secretid = '**********************'; //你的 图谱 secretid
$appSecret = '*************'; //融云App Secret
$appkey = '************'; //融云 App Key
$taskUrl = 'http://api.open.tuputech.com/v2/classification/54bcfc31329af61034f7c2f8/54bcfc6c329af61034f7c2fc';

$re = new RongCloudOperation($secretid, $appSecret, $appkey);
//$re->logResult(var_export($_REQUEST,1));
//路由过来的图片消息
if ($_REQUEST['objectName'] == 'RC:ImgMsg') {
    $content = json_decode($_REQUEST['content'], 1);

   $re->logResult(var_export($content, 1));
    $re->verify($content['imageUri'], $taskUrl, 0.8);
}


//图片复审回调
if ($_REQUEST['signature'] && $_REQUEST['json']) {
   $re->logResult(var_export($_REQUEST['json'], 1));
    $re->review($_REQUEST['json'], $_REQUEST['signature']);
}


