<?php
/**
 * @return bool 微信平台验证成为开发者
 */
function checkSignature()
{
    $signature = $_GET["signature"];
    $timestamp = $_GET["timestamp"];
    $nonce = $_GET["nonce"];

    $token = 'wxtoken'; //微信 token
    $tmpArr = array($token, $timestamp, $nonce);
    sort($tmpArr, SORT_STRING);
    $tmpStr = implode( $tmpArr );
    $tmpStr = sha1( $tmpStr );

    if( $tmpStr == $signature ){
        return true;
    }else{
        return false;
    }
}


/**
 * @param $password
 * @param $secretAccessKey
 * @return string AES加密的密码
 */
function aesEncrypt($password, $secretAccessKey){
    $password = pkcs5Pad($password);
    $secretAccessKey = substr($secretAccessKey, 0, 16);
    $encrypted = openssl_encrypt($password, 'AES-128-ECB', $secretAccessKey, OPENSSL_RAW_DATA);
    return base64_encode(substr($encrypted, 0, 16));
}

function pkcs5Pad($password){
    $pad = 16 - (strlen($password) % 16);
    return $password.str_repeat(chr($pad), $pad);
}


/**
 * @param $username
 * @param $password
 * @return string
 * 发送登录请求，返回 accessToken
 */
function login($username, $password){
    $aesPassword = aesEncrypt($password, 'sfVmIeixogKJIZgE');
    //发送登录请求
    $curl = curl_init();
    curl_setopt_array($curl, array(
        CURLOPT_PORT => "8102",
        CURLOPT_URL => "http://jxgcgl.zjou.edu.cn:8102/webroot/decision/login",
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_ENCODING => "",
        CURLOPT_MAXREDIRS => 10,
        CURLOPT_NOSIGNAL => 1,
        CURLOPT_TIMEOUT_MS => 4500,
        CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
        CURLOPT_CUSTOMREQUEST => "POST",
        CURLOPT_POSTFIELDS => "{\"username\":\"$username\",\"password\":\"$aesPassword\",\"validity\":-1,\"encrypted\":true}",
        CURLOPT_HTTPHEADER => array(
            "Cache-Control: no-cache",
            "Content-Type: application/json;charset=UTF-8",
        ),
    ));
    $response = curl_exec($curl);
    $err = curl_error($curl);
    curl_close($curl);
    if ($err) {
        over("cURL Error #:$err");
    }
    $accessToken = json_decode($response) -> data -> accessToken;
    if (empty($accessToken)){
        over('登录失败，用户名或密码错误');
    }
    return $accessToken;
}


/**
 * @param $accessToken
 * @return string 返回获取到的id
 */
function getId($accessToken){
    $curl = curl_init();
    curl_setopt_array($curl, array(
        CURLOPT_PORT => "8102",
        CURLOPT_URL => "http://jxgcgl.zjou.edu.cn:8102/webroot/decision/v10/mobile/entries",
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_ENCODING => "",
        CURLOPT_MAXREDIRS => 10,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
        CURLOPT_CUSTOMREQUEST => "GET",
        CURLOPT_HTTPHEADER => array(
            "Authorization: Bearer $accessToken",
            "Cache-Control: no-cache",
            "__device__: android"
        ),
    ));
    $response = curl_exec($curl);
    $err = curl_error($curl);
    curl_close($curl);
    if ($err)
        over("cURL Error #:$err");
    $id = json_decode($response) -> data[1] -> id;
    if (empty($id))
        over('id获取失败');
    return $id;
}


/**
 * @param $accessToken
 * @param $id
 * @return string
 * 获取sessionid
 */
function getSessionid($accessToken, $id){
    $curl = curl_init();
    curl_setopt_array($curl, array(
        CURLOPT_PORT => "8102",
        CURLOPT_URL => "http://jxgcgl.zjou.edu.cn:8102/webroot/decision/v10/entry/access/{$id}?op=fs_main&cmd=entry_report&__parameters__=%257B%257D",
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_ENCODING => "",
        CURLOPT_MAXREDIRS => 10,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
        CURLOPT_CUSTOMREQUEST => "GET",
        CURLOPT_HTTPHEADER => array(
            "Authorization: Bearer $accessToken",
            "Cache-Control: no-cache",
            "Content-Type: application/json;charset=UTF-8",
            "__device__: android"
        ),
    ));
    $response = curl_exec($curl);
    $err = curl_error($curl);
    curl_close($curl);
    if ($err)
        over("cURL Error #:$err");
    $sessionid = json_decode($response) -> sessionid;
    if (empty($sessionid))
        over('id获取失败');
    return $sessionid;
}


/**
 * @param $accessToken
 * @param $sessionid
 * 打卡，无返回值
 */
function clockin($accessToken, $sessionid){
    $curl = curl_init();
    curl_setopt_array($curl, array(
        CURLOPT_PORT => "8102",
        CURLOPT_URL => "http://jxgcgl.zjou.edu.cn:8102/webroot/decision/view/report",
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_ENCODING => "",
        CURLOPT_MAXREDIRS => 10,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
        CURLOPT_CUSTOMREQUEST => "POST",
        CURLOPT_POSTFIELDS => "op=fr_write&cmd=submit_w_report&reportXML=%253C%253Fxml%2520version%253D%25221.0%2522%2520encoding%253D%2522UTF-8%2522%2520%253F%253E%253CWorkBook%253E%253CVersion%253E6.5%253C%252FVersion%253E%253CReport%2520class%253D%2522com.fr.report.WorkSheet%2522%2520name%253D%25220%2522%253E%253CCellElementList%253E%253CC%2520c%253D%25222%2522%2520r%253D%252269%2522%253E%253CO%2520t%253D%2522S%2522%253E%253C!%255BCDATA%255B2%255D%255D%253E%253C%252FO%253E%253C%252FC%253E%253C%252FCellElementList%253E%253C%252FReport%253E%253C%252FWorkBook%253E",
        CURLOPT_HTTPHEADER => array(
            "Authorization: Bearer $accessToken",
            "Cache-Control: no-cache",
            "Content-Type: application/x-www-form-urlencoded",
            "__device__: android",
            "sessionID: $sessionid"
        ),
    ));
    $response = curl_exec($curl);
    $err = curl_error($curl);
    curl_close($curl);
    if ($err)
        over("cURL Error #:$err");
    $clockinResult = json_decode($response)[0]->fr_submitinfo->success;
    if ($clockinResult)
        return true;
    else
        return false;
}


/**
 * @param $accessToken
 * @param $sessionid
 * 关闭会话，无返回值
 * @param $curl
 */
function closeSession($accessToken, $sessionid){
    $curl = curl_init();
    curl_setopt_array($curl, array(
        CURLOPT_PORT => "8102",
        CURLOPT_URL => "http://jxgcgl.zjou.edu.cn:8102/webroot/decision/view/report?sessionID={$sessionid}&op=closesessionid",
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_ENCODING => "",
        CURLOPT_MAXREDIRS => 10,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
        CURLOPT_CUSTOMREQUEST => "GET",
        CURLOPT_HTTPHEADER => array(
            "Authorization: Bearer $accessToken",
            "Cache-Control: no-cache",
        ),
    ));
//    $response = curl_exec($curl);
//    $err = curl_error($curl);
    curl_close($curl);
}


/**
 * @param $accessToken
 * @param $sessionid
 * @param $curl
 * @return string
 * 获取打卡状态
 */
function getStatus($accessToken, $sessionid){
    $curl = curl_init();
    curl_setopt_array($curl, array(
        CURLOPT_PORT => "8102",
        CURLOPT_URL => "http://jxgcgl.zjou.edu.cn:8102/webroot/decision/view/report?op=fr_write&cmd=read_by_json&toVanCharts=true&dynamicHyperlink=true&sessionID=$sessionid&reportIndex=%200&pn=1&__cutpage__=%20&fine_api_v_json=3",
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_ENCODING => "",
        CURLOPT_MAXREDIRS => 10,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
        CURLOPT_CUSTOMREQUEST => "GET",
        CURLOPT_HTTPHEADER => array(
            "Authorization: Bearer $accessToken",
            "Cache-Control: no-cache",
            "__device__: android"
        ),
    ));

    $response = curl_exec($curl);
    $err = curl_error($curl);
    curl_close($curl);
    if ($err) {
        over("cURL Error #:" . $err);
    } else {
        preg_match('/\{"row":0,"col":2,.*"contentCss":"fh tac vab bw fwb pl2"\}\}/', $response, $matches);
        return json_decode($matches[0]) -> text;
    }
}


function autotalk($msg){
    $curl = curl_init();
    curl_setopt_array($curl, array(
        CURLOPT_URL => "http://api.qingyunke.com/api.php?key=free&appid=0&msg=$msg",
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_ENCODING => "",
        CURLOPT_MAXREDIRS => 10,
        CURLOPT_NOSIGNAL => 1,
        CURLOPT_TIMEOUT_MS => 4500,
        CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
        CURLOPT_CUSTOMREQUEST => "GET",
        CURLOPT_HTTPHEADER => array(
            "Cache-Control: no-cache",
        ),
    ));

    $response = curl_exec($curl);
    $err = curl_error($curl);

    curl_close($curl);

    if ($err) {
        over("cURL Error #:" . $err);
    } else {
        over('JARVIS: '.str_replace('{br}', "\n", json_decode($response) -> content));
    }

}


///**
// * @param $returnMsg
// * 回复消息并结束脚本
// */
//function over($returnMsg){
//    exit("<xml><ToUserName>{$GLOBALS['fromUserName']}</ToUserName><FromUserName>{$GLOBALS['toUserName']}</FromUserName><CreateTime>{$GLOBALS['createTime']}</CreateTime><MsgType>{$GLOBALS['msgType']}</MsgType><Content>$returnMsg</Content></xml>");
//}