--[[
	Credit to einsteinK.
	Credit to Stravant for LBI.

	Credit to the creators of all the other modules used in this.

	Sceleratis was here and decided modify some things.

	einsteinK was here again to fix a bug in LBI for if-statements
--]]

local waitDeps = {
	'FiOne';
	'LuaK';
	'LuaP';
	'LuaU';
	'LuaX';
	'LuaY';
	'LuaZ';
}
script = script.Parent.vLua
script.Name = "vLua"
for i,v in pairs(waitDeps) do script:WaitForChild(v) end

local luaX = require(script.LuaX)
local luaY = require(script.LuaY)
local luaZ = require(script.LuaZ)
local luaU = require(script.LuaU)
local fiOne = require(script.FiOne)
local vEnv
do
	local vEnvModule = script.VirtualEnv
	vEnv = vEnvModule and require(vEnvModule)()
end

luaX:init()
local LuaState = {}
local LuaMain = {}

function LuaMain.loadstring(str, env)
	local f,writer,buff,name
	local env = env ~= nil and env or vEnv ~= nil and vEnv or {}
	local name = (env and env.script and env.script:GetFullName())
	local ran,error = pcall(function()
		local zio = luaZ:init(luaZ:make_getS(str), nil)
		if not zio then return error() end
		local func = luaY:parser(LuaState, zio, nil, name or "@input")
		writer, buff = luaU:make_setS()
		luaU:dump(LuaState, func, writer, buff)
		f = fiOne(buff.data, env)
	end)

	if ran then
		return f,buff.data
	else
		return nil,error
	end
end

return LuaMain