require "apache2"
require "luahc"
require "string"
require "json"
require "mime"
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

function Hook(r,ss)
  local auth = r.headers_in['Authorization']
  if auth == nil or string.len(auth)<1 then
    r.err_headers_out['WWW-Authenticate'] = 'Basic realm="'..r.auth_name..'"'
    return 401
  end
  r.user=''
  return apache2.OK
end

--AuhtzProvider by gitlab
--glab:the gitlab api base url,eg:https://www.gitlab.com/
--ns:the gitlabe respo namesapce.
--debug:true/false to open debug log.
function Authz(r,glab,ns,level,debug)
  local noerr,res=pcall(
    function()
      return _Authz_(r,glab,ns,level,debug)
    end)
  if noerr then
    return res
  else
    r:err("GitlabAuthz->error("..res..") for "..r.uri)
    return apache2.AUTHZ_DENIED
  end
end

--inner implemented to AuhtzProvider
function _Authz_(r,glab,ns,level,debug)
  if r==nil then
    error("error calling")
    return apache2.AUTHZ_DENIED
  end
  if glab==nil or string.len(glab)<1 then
    r:err("GitlabAuthz->the authz url is not set")
    return apache2.AUTHZ_DENIED
  end
  if debug=="true" then
    r:warn("GitlabAuthz->running authz by ns("..ns.."),".."level("..level.."),Gtilab("..glab..") to "..r.uri)
  end
  local auth = r.headers_in['Authorization']
  if auth==nil or string.len(auth)<1 then
    r:warn("GitlabAuthz->Authorization head not found(miss LuaHookAccessChecker?)")
    return apache2.AUTHZ_DENIED
  end
  auth=string.gsub(auth,"^Basic%s*","")
  auth=r:base64_decode(auth)
  local _,eidx=string.find(auth,":")
  if eidx==nil or eidx<1 then
    r:warn("GitlabAuthz->Invalid Basic Authorization("..auth..")")
    return apache2.AUTHZ_DENIED
  end
  r.user=string.sub(auth,0,eidx-1)
  local pwd_=string.sub(auth,eidx+1)
  --check user/password whether is setting.
  if r.user==nil or string.len(r.user)<1 or pwd_==nil or string.len(pwd_)<1 then
    r:warn("GitlabAuthz->user or password is not setting")
    return apache2.AUTHZ_DENIED
  end
  --request SSO server for checking auth.
  local usr=h_post(r,glab.."/api/v3/session",{login=r.user,password=pwd_},{path=r.uri},debug)
  if usr==nil then
    r.user=''
    return apache2.AUTHZ_DENIED
  end
  --check if user auth faild
  if usr.username==nil or string.len(usr.username)<1 or usr.state==nil or usr.state~="active" or usr.private_token==nil or string.len(usr.private_token)<1 then
    r.user=''
    r:err('GitlabAuthz->login error->'..json.encode(usr))
    return apache2.AUTHZ_DENIED
  end
  local tp=ns.."%2F"..string.match(string.match(r.uri,"^/?[^/]*/[^/]*"),"[^/]*$")
  if debug=="true" then
    r:info('GitlabAuthz->check auth to '..r.uri.." by "..tp.." with user->"..json.encode(usr))
  end
  local mbs=h_get(r,string.format(glab.."/api/v3/projects/%s/members?private_token=%s",tp,usr.private_token),{},debug)
  if mbs==nil then
    r.user=''
    return apache2.AUTHZ_DENIED
  end
  for _, mb in pairs(mbs) do
    --found user and access level greater special level.
    if mb.username==r.user and mb.access_level>=tonumber(level) then
      return apache2.AUTHZ_GRANTED
    end
  end
  r:warn("GitlabAuthz->user("..r.user..") not access by "..tp.." to "..r.uri)
  -- access configure not found,
  r.err_headers_out['WWW-Authenticate'] = 'Basic realm="'..r.auth_name..'"'
  return apache2.AUTHZ_DENIED
end
