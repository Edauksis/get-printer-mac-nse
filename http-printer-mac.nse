local shortport = require "shortport"
local http = require "http"

description = [[
Get MAC address from printers
]]

---
-- @usage
-- nmap -sS -p 9100 --script http-printer-mac <target>
--
-- @output
-- |_http-printer-mac: 00:01:02:03:04:AB
-- <snip>
--

author = "Esteban Dauksis"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.portnumber(9100, "tcp", "open")

action = function(host,port)

	local socket = nmap.new_socket()

	socket:set_timeout(5000)

	local catch = function()
		socket:close()
	end

	local try = nmap.new_try(catch)	

	-- I have identified some useful config urls
	local answer1 = http.get(host, 80, "/en/mnt/sysinfo.htm" )
	local answer2 = http.get(host, 80, "/hp/jetdirect/configpage.htm" )
	local answer3 = http.get(host, 443, "/configpage.htm" )
	local answer4 = http.get(host, 80, "/card.asp?Lang=en" )
	
	
	if answer1.status ~= 200 
		and answer2.status ~= 200 
		and answer3.status ~= 200
		and answer4.status ~= 200
					then
		return nil
	end

	-- Regex for each url
	if answer1.status == 200 then
		return answer1.body:match("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x")
	end

	if answer2.status == 200 then
		mac = answer2.body:match("%x%x%x%x%x%x%x%x%x%x%x%x")
		return string.format("%s:%s:%s:%s:%s:%s",mac:sub(1,2),mac:sub(3,4),mac:sub(5,6),mac:sub(7,8),mac:sub(9,10),mac:sub(11,12))
		-- return answer2.body:match("%x%x%x%x%x%x%x%x%x%x%x%x")
	end

	if answer3.status == 200 then
		mac = answer3.body:match("%x%x%x%x%x%x%x%x%x%x%x%x")
		return string.format("%s:%s:%s:%s:%s:%s",mac:sub(1,2),mac:sub(3,4),mac:sub(5,6),mac:sub(7,8),mac:sub(9,10),mac:sub(11,12))
	end

	if answer4.status == 200 then
		return answer4.body:match("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x")
	end

end
