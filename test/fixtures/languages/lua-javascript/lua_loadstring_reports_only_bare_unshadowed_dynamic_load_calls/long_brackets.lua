local diff = [[
load(source)
loadstring(source)
]]
local leveled = [==[
load(source)
]==]
--[=[
loadstring(source)
]=]
load(source)
loadstring
  (source)
local fixture = [=[load(source)]=]; loadstring(source)
--[==[ loadstring(source) ]==] load(source)
