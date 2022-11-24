// const JSSM4 = require("jssm4");
const http = require("axios");

 
// var sKey = "qawsedrftgyhujik";
// var sm4 = new JSSM4(sKey);
 
// ["ABC", "abc", "ABCabc", "ABC123", "abc123", "123", "你好吗"].map(
//   (text) => {
//     console.log("原文：", text);
//     console.time("加密耗时");
//     var endata = sm4.encryptData_ECB(text);
//     console.timeEnd("加密耗时");
//     console.log("密文：", endata);
//     console.time("解密耗时");
//     var dedata = sm4.decryptData_ECB(endata);
//     console.timeEnd("解密耗时");
//     console.log("解密：", dedata);
//     console.log("-----------");
//   }
// );


var AES256  = require('aes-everywhere');
var pwd = 'WfSVH9sfkdDS.'

function getParamObj(wholeUrl) {
    let params = null;
    let url = wholeUrl;
    let queryParams = url.split("?");
    queryParams = Array.isArray(queryParams) && queryParams[1] ? queryParams[1] : "";
 
    params = {};
    let vars = queryParams.split("&");
    for (let i = 0; i < vars.length; i++) {
        let pair = vars[i].split("=");
        params[pair[0]] = pair[1];
    }
 
    return params;
}

function getUrlWithoutParams(wholeUrl) {
    let url = wholeUrl ? wholeUrl : window.location.href
    if (url.indexOf('?') > 0) {
        let baseUrl = url.substring(0, url.indexOf('?'))
        return baseUrl
    }
    return url
}


//const http = axios;
http.defaults.baseURL = '/'
http.defaults.headers = {
  "content-Type": "application/json"
};
// 请求拦截器
http.interceptors.request.use(
  config => {
    let urlParams = getParamObj(config.url)
    console.log(JSON.stringify(urlParams));
    console.log(JSON.stringify(config.params));
    let params = Object.assign(urlParams, config.params)
    console.log(JSON.stringify(params))

      // 发送之前操作config
      // 对传递的 data 进行加密
    if(null != config.params){
      config.params = {
        e:AES256.encrypt(JSON.stringify(params), pwd)
        //e:sm4.encryptData_ECB(JSON.stringify({a: 1}))
      }
      config.url = getUrlWithoutParams(config.url)
    }

    // let url = config.url
    // // get参数编码
    // if (config.method === 'get') {
    //   url += '?e=' + encodeURIComponent(AES256.encrypt(JSON.stringify(config.params),pwd))
      
    //   url = url.substring(0, url.length - 1)
    //   config.params = {}
    // }

    config.data = {
      //e:sm4.encryptData_ECB(JSON.stringify(config.data))
    }
    console.log(JSON.stringify(config.url))
    console.log(JSON.stringify(config.params))
    return config;
  },
  err => {
    // 处理错误
    return Promise.reject(err);
  }
);
http.interceptors.response.use(
  response => {
    // 返回前操作
    return response.data;
  },
  err => {
    return Promise.reject(err);
  }
);


http({
     method: 'GET',
     url:'http://127.0.0.1:8080/about?f=2'
     ,
     params:{text: '你好', tt: 'dfdf', g: '3'}
 }).then((res)=>{
    //成功的回调
    // console.log(res);
},function(error){
    //失败的回调
    console.log(error);
})