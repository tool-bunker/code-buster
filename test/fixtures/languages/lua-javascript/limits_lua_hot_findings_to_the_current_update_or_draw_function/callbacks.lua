function helper(should_update)
  print("not hot")
  local helper_state = {}
end
run(function()
  print("not hot")
  local callback_state = {}
end)
function update()
  for _ = 1, 2 do
    print("frame")
    local state = {}
  end
end
function after_update()
  print("not hot")
  local after_state = {}
end
draw = function()
  while ready do
    warn("frame")
    local frame = {}
  end
end
function after_draw()
  print("not hot")
  local after_draw_state = {}
end
