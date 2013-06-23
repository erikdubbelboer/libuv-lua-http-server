
response.headers["Content-Type"] = "text/html"

response.body = [[
<!doctype html>
<html>
<head>
<meta charset=utf-8>
<title>index</title>
</head>
<body>
]]


for key,value in pairs(request) do
  response.body = response.body .. key .. ": " .. value .. "<br>"
end


response.body = response.body .. [[
</body>
</html>
]]

