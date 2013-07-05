
for key,value in pairs(request) do
  response.body = response.body .. key .. ": " .. value .. "\n"
end

