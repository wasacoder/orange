local ipairs = ipairs
local type = type

local utils = require("orange.utils.utils")
local stringy = require("orange.utils.stringy")
local orange_db = require("orange.store.orange_db")
local judge_util = require("orange.utils.judge")
local extractor_util = require("orange.utils.extractor")
local handle_util = require("orange.utils.handle")
local BasePlugin = require("orange.plugins.base_handler")
local cjson = require "cjson"
local encode_base64 = ngx.encode_base64
local decode_base64 = ngx.decode_base64
local resty_sm4 = require "resty.sm4"
local key = "qawsedrftgyhujik"
local sm4 = resty_sm4:new(key)


local function ensure_end(uri)
    if not stringy.endswith(uri, "/") then
        uri = uri.."/"
    end
    return uri
end

local function filter_rules(sid, plugin, ngx_var, ngx_var_uri, ngx_var_host)
    local rules = orange_db.get_json(plugin .. ".selector." .. sid .. ".rules")
    if not rules or type(rules) ~= "table" or #rules <= 0 then
        return false
    end

    for i, rule in ipairs(rules) do
        if rule.enable == true then
            -- judge阶段
            local pass = judge_util.judge_rule(rule, plugin)

            -- extract阶段
            local variables = extractor_util.extract_variables(rule.extractor)

            -- handle阶段
            if pass then
                if rule.log == true then
                    ngx.log(ngx.INFO, "[Encrypt-Match-Rule] ", rule.name, " host:", ngx_var_host, " uri:", ngx_var_uri)
                end

                local extractor_type = rule.extractor.type


                ngx.log(ngx.WARN, "------------->>>>>>>>>>>>>>> request follow aes logic ")
                -- 强制定义为identity， 不做任何压缩
                ngx.req.set_header("Accept-Encoding", "identity")
                local method = ngx.var.request_method

                local encrypt
                if "GET" == method then
                    local args = ngx.req.get_uri_args()
                    encrypt = args['e']
                elseif "POST" == method then
                    ngx.req.read_body()
                    local datas = cjson.decode(ngx.req.get_body_data())
                    encrypt = datas['e']
                end
                -- 获取加密后字符串
                if encrypt ~= nil then
                    --local decrypt = sm4:decrypt("TsVDX/XWiZYLOjtAQFvEKpWx3yIDxam93NnHaUzV2ww=");

                    local text = 'test'
                    local sm4 = resty_sm4:new(key)
                    --# 加密
                    local en_text = sm4:encrypt(text)
                    print(en_text)
                    --#解密
                    local de_text = sm4:decrypt(text)
                    print(en_text)
                    --local decrypt = encrypt;

                    ngx.log(ngx.INFO, "[Encrypt-Match-Rule:URL] ", rule.name, " extractor_type: ", extractor_type, " uri_args: ", encrypt);
                    ngx.log(ngx.INFO, "[Encrypt-Match-Rule:URL] ", rule.name, " extractor_type: ", extractor_type, " decrypt: ", decrypt);

                    local decode_decrypt = cjson.decode(decrypt)
                    ngx.log(ngx.INFO, "[Encrypt-Match-Rule:URL] ", rule.name, " extractor_type: ", extractor_type, " decode_decrypt: ", decode_decrypt);

                    if type(decode_decrypt) == "table" then
                        if "GET" == method then
                            ngx.req.set_uri_args("eee=123")
                        elseif "POST" == method then
                            ngx.req.set_body_data(decrypt)
                        end
                    end
                    ngx.log(ngx.INFO, "[Encrypt-Match-Rule:URL] ", rule.name, " extractor_type: ", extractor_type, " uri: ", decrypt);

                end
                return true
            else
                if rule.log == true then
                    ngx.log(ngx.INFO, "[Encrypt-NotMatch-Rule] ", rule.name, " host:", ngx_var_host, " uri:", ngx_var_uri)
                end
            end
        end
    end

    return false
end


local EncryptHandler = BasePlugin:extend()
EncryptHandler.PRIORITY = 2000

function EncryptHandler:new(store)
    EncryptHandler.super.new(self, "Encrypt-plugin")
    self.store = store
end

function EncryptHandler:access(conf)
    EncryptHandler.super.access(self)
    
    local enable = orange_db.get("encrypt.enable")
    local meta = orange_db.get_json("encrypt.meta")
    local selectors = orange_db.get_json("encrypt.selectors")
    local ordered_selectors = meta and meta.selectors
    
    if not enable or enable ~= true or not meta or not ordered_selectors or not selectors then
        return
    end

    local ngx_var = ngx.var
    local ngx_var_uri = ngx_var.uri
    local ngx_var_host = ngx_var.host

    for i, sid in ipairs(ordered_selectors) do
        ngx.log(ngx.INFO, "==[Encrypt][PASS THROUGH SELECTOR:", sid, "]")
        local selector = selectors[sid]
        if selector and selector.enable == true then
            local selector_pass 
            if selector.type == 0 then -- 全流量选择器
                selector_pass = true
            else
                selector_pass = judge_util.judge_selector(selector, "encrypt")-- selector judge
            end

            if selector_pass then
                if selector.handle and selector.handle.log == true then
                    ngx.log(ngx.INFO, "[Encrypt][PASS-SELECTOR:", sid, "] ", ngx_var_uri)
                end

                local stop = filter_rules(sid, "encrypt", ngx_var, ngx_var_uri, ngx_var_host)
                if stop then -- 不再执行此插件其他逻辑
                    return
                end
            else
                if selector.handle and selector.handle.log == true then
                    ngx.log(ngx.INFO, "[Encrypt][NOT-PASS-SELECTOR:", sid, "] ", ngx_var_uri)
                end
            end

            -- if continue or break the loop
            if selector.handle and selector.handle.continue == true then
                -- continue next selector
            else
                break
            end
        end
    end
    
end

return EncryptHandler
