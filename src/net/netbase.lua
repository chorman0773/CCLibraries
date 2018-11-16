---
--Implements Vconn, the basic intercomputer communication protocol
--Vconn is transmitted over rednet, with computers uniquely identified by a SHA-1 Hash
--of there label and id.
--Each Vconn packet takes the following format
--<command>"VCONN"<netId><message>
if not StrUtils then
  os.loadAPI("/usr/bin/misc/StrUtils");
end
if not aes then
  os.loadAPI("/usr/bin/crypt/aes");
end
if not shalua then
  os.loadAPI("/usr/bin/crypt/sha");
end
if not rsa then
  os.loadAPI("/usr/bin/crypt/rsa");
end
if not diffh then
  os.loadAPI("/usr/bin/crypt/key/diffh");
end
__mod_info = {onunload=function()
  netKeys:destroy();
  netA:destroy();
end};
local netId = os.computerId();
local netName = os.computerLabel();
local netCode = StrUtils.SHA1(netName..netId);

local netKeys =  rsa.makeRSA1024KeyPair();
local netA = diffh.makeExponent();
local N = diffh.big("35,880,571,854,643");
local k = diffh.big("17");
local fnResults = {};


local vconnCoroutine = coroutine.create(vconnLoop);

local callbackFns = {};

functionResultListEnd = {};

local commands = {string.char(0x7f,0,0,0x3C),string.char(0x7f,0,0,0)}

local function vconnOpen(mtarget)
  rednet.open(mtarget);
  rednet.send(string.char(0x7F,0,0,0x3C).."VCONN"..netCode);
  rednet.host("vconn",netCode);
end

local function vconnEstablish(rcode, vconnId)
  local vconn = {__vconnId=vconnId}
end

local function vconnLoop()
  while true do
    local id,message,_ = rednet.recieve(1);
    if not id then
      coroutine.yield(true,table.unpack(fnResults));
    end
    local cmd = message:sub(1,4);
    local vconn = message:sub(5,10);
    local code = message:sub(11,51);
    local data = message:sub(52);
    if vconn ~= "VCONN" then
      break; --TODO may implement other base protocols other then VCONN, but for now its just VCONN
    end
    if callbackFns[cmd] then
      fnResults = {table.unpack(fnResults),callbackFns[cmd](id,code,data)};
    end
  end
end

function vconnRegisterCallback(cmdId,callback,...)
  local callbackArgs = {...};
  callbackFns[commands[cmdId]] = function(id,code,data)
    return callback(id,code,data,table.unpack(callbackArgs));
  end
end


function vconnRecieveClosed(id,code,data,qkey,qiv,kpub)
  local kkrcode = data:sub(1,41);
  if kkrcode~=netCode then
    return
  end
  local kkdataUcrypt;
  local kkdataSig = data:sub(-rsa.signLen(kpub,sha.SHA512_256));
  data = data:sub(42,-rsa.signLen(kpub)-1);
  kkdataUcrypt,qiv = aes.decrypt256_cbc(data,qkey,qiv);
  if not rsa.verify(code..kkdataUcrypt,kpub,sha.SHA512_256) then
    return false,"Signature Does not match, either data got corrupted or someone is tapping the communication",functionResultListEnd;
  end
  return kkdataUcrypt,qiv,functionResultListEnd;
end

function vconnSendClosed(data,tocode,qkey,qiv,spriv,spub)
  local kkdataSig = rsa.sign(netCode..data,spriv,sha.SHA512_256); 
  local kkdata;
  kkdata,qiv = aes.encrypt256_cbc(data,qkey,qiv);
  rednet.broadcast(string.char(0x7f,0,0,0x11)..netCode.."VCONN"..tocode..kkdata);
  return qiv;
end

local function vconnKeyExchange()

end