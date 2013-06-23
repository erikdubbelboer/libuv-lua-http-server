
if counter == nil then
  counter = 1
else
  counter = counter + 1
end

response.body = "" .. counter

response.headers["Content-Type"] = "text/plain"

