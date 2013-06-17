
local response = [[
<!doctype html>
<html>
<head>
<meta charset=utf-8>
<title>index</title>
</head>
<body>
]]


if counter == nil then
  counter = 1
else
  counter = counter + 1
end

response = response .. counter


response = response .. [[
</body>
</html>
]]

return response

