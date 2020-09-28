<?php
require 'funcDef.php';

/**
 * @param $returnMsg
 *
 */
function over($returnMsg){
    throw new Exception($returnMsg);
}

if (php_sapi_name() == 'apache2handler')
    exit('此脚本禁止外部访问');
if (php_sapi_name() == 'cli'){
    $connection = mysqli_connect('127.0.0.1', 'root', '123456', 'autoclockin');
    $sql = "select username, password from user where valid = 1 and autoclockin = 1;";
    $result = mysqli_query($connection, $sql);
    while($user = mysqli_fetch_assoc($result)){
        try{
            $accessToken = login($user['username'], $user['password']);
            $id = getId($accessToken);
            $sessionid = getSessionid($accessToken, $id);
            if (clockin($accessToken, $sessionid)) {
                closeSession($accessToken, $sessionid);
                echo $user['username'],'  打卡成功';
            }else{
                closeSession($accessToken, $sessionid);
                echo $user['username'],'  打卡失败';
            }
            sleep(60);
        } catch (Exception $e){
            echo 'Caught exception: ',$e->getMessage(),"\n";
            sleep(60);
            continue;
        }

    }

}