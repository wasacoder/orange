local AES256 = require("aes_everywhere")

-- encryption
local enc = AES256.encrypt('你好', 'WfSVH9sfkdDS.')
print(enc)
--local enc = 'U2FsdGVkX19QImxRmrUcQKE/L0lZYHmqGOE3U/HeK58='
print(enc)
--
-- -- decryption
local dec = AES256.decrypt(enc, 'WfSVH9sfkdDS.')
print(dec)