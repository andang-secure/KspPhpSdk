# php-sdk
 
安当数据加密组件（key application data protectio）是一种用于开发和集成加密功能的SDK ，提供了丰富的加密算法和接口，实现了数据安全加密与解密、认证、签名、验签等功能，提供了简单且高效化的加解密接口，能够快速的实现加密技术的集成与应用

## 提交反馈
 更多信息请查看官网 如需购买商业版源码请联系我们
 ### 官网地址
 上海安当技术有限公司：https://andang.cn/

### 安当加密公众号
![577d1664239ea7962bb5e1b9cdcc4d69](https://github.com/andang-secure/kadp-go/assets/150333529/f525a574-aaa8-4d94-a0fd-f4a328bab4dc)


## 项目链接
  KADP-GO ： https://github.com/andang-secure/kadp-go
  
## 项目演示
  项目演示DEMO地址：https://kadp.andang.cn/

## 接口文档
  地址：http://doc.andang.cn/web/#/6/106
  
## 使用示例
更多请查看test/KadpClient_test.go文件
  ```
//url:安当KSP地址，
//token：安当KSP令牌
//keystore地址：keystore.jks
//keystore密码："123456"
myClient, err := kadp.NewKADPClient(url, token, "keystore.jks", "123456")


//密文:encrypt，
//算法：kadp.FF1，
//tweak:"1324567",
//字母表："0123456789",
//秘钥长度："16"，
//秘钥标签":kadp112,
//开始位：2，
//结束位7

 encrypt, err := myClient.FpeEncipher(str, kadp.FF1, "1234567", "0123456789", 16, "kadp112", 2, 7)

 decipher, err := myClient.FpeDecipher(encrypt, kadp.FF1, "1234567", "0123456789", 16, "kadp112", 2, 7)

  ```
