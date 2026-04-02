configure {
  enabled = true, -- autocommand-style option
  nested = {
    label = "kickstart",
    callback = function(value)
      value = value .. "!"
    end,
  },
}
local function update()
  local first, second = values[1], values[2]
  if first and
    second then
    first = second
  end
  for key, value in pairs(values) do
    key = tostring(key)
    value = tostring(value)
  end
  --[[
  commented_global = true
  ]]
end
undeclared = 1
