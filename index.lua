
local response = [[
<!doctype html>
<html>
<head>
<meta charset=utf-8>
<title>index</title>
</head>
<body>
]]


for key,value in pairs(request) do
  response = response .. key .. ": " .. value .. "<br>"
end


response = response .. [[
</body>
</html>
]]

return response

