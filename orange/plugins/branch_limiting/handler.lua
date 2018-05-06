local pairs = pairs
local ipairs = ipairs
local ngx_re_sub = ngx.re.sub
local ngx_re_find = ngx.re.find
local string_sub = string.sub
local orange_db = require("orange.store.orange_db")
local judge_util = require("orange.utils.judge")
local extractor_util = require("orange.utils.extractor")
local handle_util = require("orange.utils.handle")
local BasePlugin = require("orange.plugins.base_handler")
local ngx_set_uri = ngx.req.set_uri
local ngx_set_uri_args = ngx.req.set_uri_args
local ngx_decode_args = ngx.decode_args

local function set_request_uri()
    if ngx.var.request_method == "GET" then
        local request_uri = ngx.var.request_uri;
        local question_pos, _ = string.find(request_uri, '?')
        if question_pos>0 then
            local uri = string.sub(request_uri, 1, question_pos-1)
            local args = ngx.decode_args(string.sub(request_uri, question_pos+1))
            if args and args.userId then
                args.userId = args.userId + 10000
                return uri .. '?' .. ngx.encode_args(args)
            else
                return request_uri
            end
        else
            return request_uri
        end
    else
        return ngx.var.request_uri
    end
end

local function filter_rules(sid, plugin, ngx_var_uri)
    local rules = orange_db.get_json(plugin .. ".selector." .. sid .. ".rules")
    if not rules or type(rules) ~= "table" or #rules <= 0 then
        return false
    end

    for i, rule in ipairs(rules) do
        if rule.enable == true then
            -- judge阶段
            local pass = judge_util.judge_rule(rule, "rewrite")
            -- extract阶段
            local variables = extractor_util.extract_variables(rule.extractor)

            -- handle阶段
            if pass then
                local handle = rule.handle
                if handle and handle.uri_tmpl then
                    local to_rewrite = handle_util.build_uri(rule.extractor.type, handle.uri_tmpl, variables)
                    if to_rewrite and to_rewrite ~= ngx_var_uri then
                        if handle.log == true then
                            ngx.log(ngx.INFO, "[Rewrite] ", ngx_var_uri, " to:", to_rewrite)
                        end

                        local from, to, err = ngx_re_find(to_rewrite, "[%?]{1}", "jo")
                        if not err and from and from >= 1 then
                            --local qs = ngx_re_sub(to_rewrite, "[A-Z0-9a-z-_/]*[%?]{1}", "", "jo")
                            local qs = string_sub(to_rewrite, from+1)
                            if qs then
                                local args = ngx_decode_args(qs, 0)
                                if args then 
                                    ngx_set_uri_args(args) 
                                end
                            end
                        end
                        ngx_set_uri(to_rewrite, true)
                    end
                end

                return true
            end
        end
    end

    return false
end

local BranchLimitingHandler = BasePlugin:extend()
BranchLimitingHandler.PRIORITY = 2000

function BranchLimitingHandler:new(store)
    BranchLimitingHandler.super.new(self, "branch-limiting-plugin")
    self.store = store
end

function BranchLimitingHandler:rewrite(conf)
    BranchLimitingHandler.super.rewrite(self)

    local ngx_var_uri = ngx.var.uri
    local stop = filter_rules(sid, "branch_limiting", ngx_var_uri)
end

return BranchLimitingHandler
