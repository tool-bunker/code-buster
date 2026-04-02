-- load(source)
--[=[
@param callback (CommandContext) -> string? -- returns string (errorText)
]=]
local value = "loadstring(source)"
require("luasnip.loaders.from_lua").load()
Loader.load(source)
Loader:load(source)
package.loadlib(path, symbol)
function Loader.load(source) return source end
function Loader:load(source) return source end
local function load(source)
  return source
end
load(source)
