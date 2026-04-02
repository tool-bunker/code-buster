local values = {}
local alias = values
local other = {}
local M = { lock = {} }
for key in pairs(values) do
  if values[key] == nil then return nil end
  other[key] = nil
end
for name in pairs(M.lock) do
  M.lock[name] = nil
end
for key in pairs(values) do
  alias[key] = nil
end
for index in ipairs(values) do
  table.remove(values, index)
end
for key in pairs(values) do
  if other[key] == nil then
    other[key] = values[key]
  end
end
