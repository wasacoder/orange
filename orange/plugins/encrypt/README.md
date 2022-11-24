# HTTP GET params and POST body decrypt and response encrypt Plugin
USE aes-everywhere <https://github.com/mervick/aes-everywhere/tree/master/lua> to decrypt parameter pairs in URL. 

## Merge luarocks into openresty
To install openssl using luarocks
[整合luarocks](https://blog.csdn.net/hp_cpp/article/details/106985342)

## 前端应使用aes-everywhere中的js版本进行encrypt

## Confinguration
add 'encrypt' in orange.conf.plugins
add 'encryptpwd' in orange.conf. the passwd should be equal with passwd used in axios.

see axios interceptor example in /orange/plugins/encrypt/aes
execute install/encrypt.sql to add encrypt plugin configs in mysql.