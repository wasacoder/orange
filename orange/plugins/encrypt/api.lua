local BaseAPI = require("orange.plugins.base_api")
local common_api = require("orange.plugins.common_api")

local api = BaseAPI:new("encrypt-api", 2)
api:merge_apis(common_api("encrypt"))
return api
