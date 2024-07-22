<?php
// 引入composer 包
require __DIR__.'/vendor/autoload.php';
// 引入 test sdk
use AndangSecure\KspVault;

$vault_sdk = new KspVault("https://192.168.0.194:8190", "zl", "123456");

$val = $vault_sdk->GetKeyValueByLabel("wd_crzt");

print_r($val);