local loadAPIOriginal = os.loadAPI;
local unloadAPIOriginal = os.unloadAPI;
local shutdownOriginal = os.shutdown;

local modlist = {};

function os.loadAPI(name)
  local mname = shell.resolve(name);
  if modlist[mname] then
    return modlist[mname];
  end
  local gapiName = name:sub(name:find("/[%a_$]+$"))..""
  gapiName = name:sub(2);
  loadAPIOriginal(mname);
  modlist[mname] = _G[gapiName];
  local gapi = _G[gapiName];
  return gapi;
end

function os.unloadAPI(name)
  local mname = shell.resolve(name);
  unloadAPIOriginal(mname);
  local gapi = modlist[mname];
  modlist[mname] = nil;
  if gapi.__mod_info then
    if gapi.__mod_info.onUnload then
      gapi.__mod_info.onUnload();
    end
  end
end

function os.shutdown()
  for _,v in pairs(modlist) do
    if v.__mod_info then
      if v.__mod_info.onUnload then
        v.__mod_info.onUnload();
      end
    end
  end
end


