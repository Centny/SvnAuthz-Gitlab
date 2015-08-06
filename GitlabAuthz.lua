---------------------------------------
--------------configure----------------
---------------------------------------

--the gitlab server address.
local glab="https://192.168.1.8"
--the namespace which mapping to svn.
local ns="namespace"
--show debug log.
local debug="false"
local cache_time=30
local cache_path="/tmp"
local svn_base="/var/www/svn/repos"
local svn_admin="/usr/bin/svnadmin"
local svn_token="fff<sha1>"
---------------------------------------
--
--
require "apache2"
require "luahc"
require "string"
require "json"
require "os"
require "io"

--read josn
function read_j(f)
  local lf=io.open(f,"r")
  if lf==nil then
    return nil
  end
  local tdata=lf:read("*all")
  lf:close()
  return json.decode(tdata)
end

--write json
function write_j(f,o)
  local lf=assert(io.open(f,"w"))
  lf:write(json.encode(o))
  lf:close()
end

--http get
function h_get(r,url,args,debug)
  local noerr, res = pcall(
    function ()
      local gres=luahc.get(url,args)
      if gres.lcode~=0 or gres.ccode~=0 or gres.rcode>=300 or gres.rcode<200 or gres.data==nil then
        if debug=="true" then
          r:warn("GitlabAuthz->http get "..url.." error("..json.encode(gres)..")")
        end
        return nil
      else
        return json.decode(gres.data)
      end
    end)
  if noerr then
    return res
  else
    r:err("GitlabAuthz->http get "..url..", reponse json error("..json.encode(res)..")")
    return nil
  end
end

--http post
function h_post(r,url,args,header,debug)
  local noerr, res = pcall(
    function ()
      local gres=luahc.post(url,args,header)
      if gres.lcode~=0 or gres.ccode~=0 or gres.rcode>=300 or gres.rcode<200 or gres.data==nil then
        if debug=="true" then
          r:warn("GitlabAuthz->http post "..url.." error("..json.encode(gres)..")")
        end
        return nil
      else
        return json.decode(gres.data)
      end
    end)
  if noerr then
    return res
  else
    r:err("GitlabAuthz->http post "..url..", reponse json error("..json.encode(res)..")")
    return nil
  end
end

--common WWW-Authenticate response
function unauth(r)
  r.err_headers_out['WWW-Authenticate'] = 'Basic realm="'..r.auth_name..'"'
  return 401
end

function _Authz_(r,level)
  local need=1000
  if r.method=="GET" or r.method=="OPTIONS" or r.method=="REPORT" or r.method=="PROPFIND" then
    need=20
  else
    need=30
  end
  if level<need then
    if debug=="true" then
      r:warn('GitlabAuthz->user '..r.user..' access level('..level..') is denied to '..r.method.." "..r.uri..", >="..need.." need")
    end
    return unauth(r)
  else
    if debug=="true" then
      r:warn('GitlabAuthz->user '..r.user..' access level('..level..') is access to '..r.method.." "..r.uri)
    end
    return apache2.OK
  end
end

--Authz hook for checking access level from gitlab by user/password.
function Hook(r)
  if r==nil then
    return unauth(r)
  end
  r.user=''
  local noerr,res=pcall(
    function()
      return _Hook_(r)
    end)
  if noerr then
    return res
  else
    r:err("GitlabAuthz->error("..res..") for "..r.uri)
    return unauth(r)
  end
end

---
function _Hook_(r)
  --clear timeout cache.
  local now=os.time()
  --
  if glab==nil or string.len(glab)<1 then
    r:err("GitlabAuthz->the authz url is not set")
    return unauth(r)
  end
  if debug=="true" then
    r:warn("GitlabAuthz->running authz by ns("..ns.."),Gtilab("..glab..") to "..r.uri)
  end
  local auth = r.headers_in['Authorization']
  if auth==nil or string.len(auth)<1 then
    return unauth(r)
  end
  local bauth=string.gsub(auth,"^Basic%s*","")
  auth=r:base64_decode(bauth)
  local _,eidx=string.find(auth,":")
  if eidx==nil or eidx<1 then
    r:warn("GitlabAuthz->Invalid Basic Authorization("..auth..")")
    return unauth(r)
  end
  r.user=string.sub(auth,0,eidx-1)
  local pwd_=string.sub(auth,eidx+1)
  --check user/password whether is setting.
  if r.user==nil or string.len(r.user)<1 or pwd_==nil or string.len(pwd_)<1 then
    r:warn("GitlabAuthz->user or password is not setting")
    return unauth(r)
  end
  local path=string.match(string.match(r.uri,"^/?[^/]*/[^/]*"),"[^/]*$")
  local cache_f=cache_path.."/"..r.user.."_"..ns.."_"..path
  local cache=read_j(cache_f)
  if cache~=nil and now-cache.t<cache_time then
    --cache found
    cache.t=now
    write_j(cache_f,cache)
    if debug=="true" then
      r:warn('GitlabAuthz->user '..r.user..' access level('..cache.access_level..') to '..r.uri.."(cache)")
    end
    return _Authz_(r,cache.access_level)
  end
  --request gitlab server for checking auth.
  local usr=h_post(r,glab.."/api/v3/session",{login=r.user,password=pwd_},{path=r.uri},debug)
  if usr==nil then
    r.user=''
    return unauth(r)
  end
  local tp=ns.."%2F"..path
  --check if user auth faild
  if usr.username==nil or string.len(usr.username)<1 or usr.state==nil or usr.state~="active" or usr.private_token==nil or string.len(usr.private_token)<1 then
    r.user=''
    r:err('GitlabAuthz->login error->'..json.encode(usr))
    return unauth(r)
  end
  r.user=usr.username
  if debug=="true" then
    r:warn('GitlabAuthz->check auth to '..r.uri.." by "..tp.." with user->"..json.encode(usr))
  end
  local mbs=h_get(r,string.format(glab.."/api/v3/projects/%s/members?private_token=%s",tp,usr.private_token),{},debug)
  if mbs==nil then
    r.user=''
    return unauth(r)
  end
  local access_level=1000
  for _, mb in pairs(mbs) do
    --found user and access level greater special level.
    if mb.username==r.user then
      access_level=mb.access_level
      break
    end
  end
  --writing cache
  write_j(cache_f,{t=now,access_level=access_level})
  if debug=="true" then
    r:warn('GitlabAuthz->user '..r.user..' access level('..access_level..') to '..r.uri.." by "..tp)
  end
  return _Authz_(r,access_level)
end

--handler for adding resp
function Addp(r)
  if r==nil then
    return 500
  end
  local noerr,res=pcall(
    function()
      return _Addp_(r)
    end)
  if noerr then
    return res
  else
    r:err("GitlabAuthz->error("..res..") for "..r.uri)
    return 500
  end
end

--inner
function _Addp_(r)
  local token=string.gsub(r.uri,"/[^/]*/[^/]*/","")
  if token==nil then
    r:err("recieve invalid require(token is not found)")
    return 400
  end
  if r:sha1(token)~=svn_token then
    r:err("recieve unauthorized require")
    return 401
  end
  local body_=r:requestbody()
  if body_==nil then
    r:err("recieve invalid body(nil)")
    return 400
  end
  local body=json.decode(body_)
  if body==nil then
    r:err("recieve invalid body->"..body_)
    return 400
  end
  --ignore other event.
  if body.event_name~="project_create" then
    if debug=="true" then
      r:warn("receive event->"..body_.."(skipped)")
    end
    return apache2.OK
  end
  --ignore other namespace
  if (ns.."/"..body.path)~=body.path_with_namespace then
    if debug=="true" then
      r:warn("receive other namespace create project->"..body_.."(skipped)")
    end
    return apache2.OK
  end
  local resp=svn_base.."/"..body.path
  local exist_f=io.open(resp,"r")
  if exist_f~=nil then
    r:warn("responsitory "..resp.." exsits(skip create)")
    return apache2.OK
  end
  local res=os.execute(svn_admin.." create "..resp)
  if res==nil then
    r:err("create responsitory on "..resp.." error")
    return 500
  else
    r:warn("create responsitory on "..resp.." success")
    return apache2.OK
  end
end


