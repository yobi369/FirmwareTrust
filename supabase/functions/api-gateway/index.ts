import { apiTokenAllows, type ApiTokenRecord } from "./api_tokens.ts";
import { verifyEd25519Manifest } from "./verification.ts";

const corsHeaders={
  "Access-Control-Allow-Origin":"*",
  "Access-Control-Allow-Headers":"authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods":"GET, POST, OPTIONS",
  "Content-Type":"application/json",
};
function respond(body:unknown,status=200){return new Response(JSON.stringify(body),{status,headers:corsHeaders});}
function defaultKey(raw:string|undefined):string|null{
  if(!raw)return null;
  try{const value=JSON.parse(raw).default;return typeof value==="string"&&value?value:null;}catch{return null;}
}
async function jsonResponse(response:Response){
  const value=await response.json().catch(()=>null);
  return {ok:response.ok,status:response.status,value};
}

Deno.serve(async(req)=>{
  if(req.method==="OPTIONS")return new Response("ok",{headers:corsHeaders});
  if(req.method!=="GET"&&req.method!=="POST")return respond({error:"Method not allowed"},405);
  const url=new URL(req.url);
  if(!url.pathname.endsWith("/releases"))return respond({error:"Supported route: /releases"},404);

  const authorization=req.headers.get("authorization")||"";
  const tokenMatch=authorization.match(/^Bearer (ft_live_[A-Za-z0-9_-]{43})$/);
  if(!tokenMatch)return respond({error:"A valid FirmwareTrust API bearer token is required"},401);

  const supabaseUrl=Deno.env.get("SUPABASE_URL");
  const publishableKey=defaultKey(Deno.env.get("SUPABASE_PUBLISHABLE_KEYS"));
  const secretKey=defaultKey(Deno.env.get("SUPABASE_SECRET_KEYS"));
  if(!supabaseUrl||!publishableKey||!secretKey)return respond({error:"API gateway is not configured"},503);
  const publicHeaders={apikey:publishableKey,Authorization:"Bearer "+publishableKey,"Content-Type":"application/json"};
  const serviceHeaders={apikey:secretKey,Authorization:"Bearer "+secretKey,"Content-Type":"application/json"};

  try{
    let body:Record<string,unknown>={};
    if(req.method==="POST"){
      const rawBody=await req.text();
      if(new TextEncoder().encode(rawBody).length>1_000_000)return respond({error:"Request body exceeds the 1 MB limit"},413);
      try{body=JSON.parse(rawBody);}catch{return respond({error:"Request body must be valid JSON"},400);}
      if(!body||typeof body!=="object"||Array.isArray(body))return respond({error:"JSON object body required"},400);
    }
    const projectId=String(req.method==="POST"?(body.project_id||""):(url.searchParams.get("project_id")||""));
    if(req.method==="POST"&&!projectId)return respond({error:"project_id is required"},400);
    const requiredScope=req.method==="GET"?"releases:read":"releases:write";
    const authResponse=await fetch(supabaseUrl+"/rest/v1/rpc/verify_api_token",{
      method:"POST",headers:publicHeaders,
      body:JSON.stringify({raw_token:tokenMatch[1],required_scope:requiredScope,target_project:projectId||null})
    });
    const authResult=await jsonResponse(authResponse);
    if(!authResult.ok){
      const status=authResult.status===403?403:401;
      return respond({error:status===403?"API token scope or project access denied":"API token is invalid, expired or revoked"},status);
    }
    const verified=authResult.value as {token_id:string;organization_id:string;created_by:string;scopes:string[];project_ids:string[];expires_at:string};
    const claims:ApiTokenRecord={id:verified.token_id,organization_id:verified.organization_id,created_by:verified.created_by,
      scopes:verified.scopes,project_ids:verified.project_ids,expires_at:verified.expires_at,revoked_at:null};
    if(!apiTokenAllows(claims,tokenMatch[1],claims.organization_id,projectId||"",requiredScope)){
      return respond({error:"API token scope or project access denied"},403);
    }
    if(req.method==="GET"){
      const query=new URLSearchParams({
        select:"id,project_id,version,artifact_name,artifact_sha256,status,created_at,published_at",
        organization_id:"eq."+claims.organization_id,
        order:"created_at.desc",
        limit:"100"
      });
      if(projectId)query.set("project_id","eq."+projectId);
      const result=await fetch(supabaseUrl+"/rest/v1/releases?"+query.toString(),{headers:serviceHeaders});
      const data=await jsonResponse(result);
      if(!data.ok)return respond({error:"Release registry query failed"},502);
      return respond({releases:data.value||[],count:Array.isArray(data.value)?data.value.length:0},200);
    }

    const version=String(body.version||"").trim();
    const artifactName=String(body.artifact_name||"").trim();
    const artifactSha=String(body.artifact_sha256||"").toLowerCase();
    const manifest=body.manifest as Record<string,unknown>;
    if(version.length<1||version.length>100||artifactName.length<1||artifactName.length>255||!/^[a-f0-9]{64}$/.test(artifactSha)||!manifest||typeof manifest!=="object"){
      return respond({error:"version, artifact_name, SHA-256 digest and signed manifest are required"},400);
    }

    const memberQuery=new URLSearchParams({select:"role",organization_id:"eq."+claims.organization_id,user_id:"eq."+claims.created_by,limit:"1"});
    const memberResponse=await fetch(supabaseUrl+"/rest/v1/organization_memberships?"+memberQuery.toString(),{headers:serviceHeaders});
    const member=await jsonResponse(memberResponse);
    if(!member.ok||!Array.isArray(member.value)||member.value.length!==1||!["owner","admin","release_manager","developer"].includes(member.value[0].role)){
      return respond({error:"API token creator is no longer authorized to register releases"},403);
    }

    const projectQuery=new URLSearchParams({select:"id",id:"eq."+projectId,organization_id:"eq."+claims.organization_id,limit:"1"});
    const projectResponse=await fetch(supabaseUrl+"/rest/v1/projects?"+projectQuery.toString(),{headers:serviceHeaders});
    const project=await jsonResponse(projectResponse);
    if(!project.ok||!Array.isArray(project.value)||project.value.length!==1)return respond({error:"Project does not belong to the API token organization"},404);

    const signature=manifest.signature as Record<string,unknown>|undefined;
    const registry=manifest.trust_registry as Record<string,unknown>|undefined;
    const artifact=manifest.artifact as Record<string,unknown>|undefined;
    if(!signature||!registry||!artifact||registry.provider!=="firmwaretrust"||
      registry.organization_id!==claims.organization_id||registry.project_id!==projectId||
      artifact.filename!==artifactName||artifact.digest_algorithm!=="sha256"||String(artifact.digest).toLowerCase()!==artifactSha||
      signature.algorithm!=="Ed25519"||typeof signature.key_id!=="string"){
      return respond({error:"Manifest registry scope or artifact metadata does not match the request"},422);
    }

    const keyQuery=new URLSearchParams({
      select:"public_key_pem,key_fingerprint,status,valid_from,valid_until",
      organization_id:"eq."+claims.organization_id,
      project_id:"eq."+projectId,
      key_fingerprint:"eq."+signature.key_id.toLowerCase(),
      algorithm:"eq.Ed25519",
      status:"eq.active",
      limit:"1"
    });
    const keyResponse=await fetch(supabaseUrl+"/rest/v1/signing_keys?"+keyQuery.toString(),{headers:serviceHeaders});
    const keyResult=await jsonResponse(keyResponse);
    const key=Array.isArray(keyResult.value)?keyResult.value[0]:null;
    if(!keyResult.ok||!key||Date.parse(key.valid_from)>Date.now()||(key.valid_until&&Date.parse(key.valid_until)<=Date.now())){
      return respond({error:"Manifest signing key is not active in the registry"},422);
    }
    let verification:{valid:boolean;manifestSha256:string;signatureSha256:string};
    try{verification=await verifyEd25519Manifest(manifest,String(key.public_key_pem));}
    catch{return respond({error:"Manifest Ed25519 signature material is malformed"},422);}
    if(!verification.valid)return respond({error:"Manifest Ed25519 signature verification failed"},422);

    const registration=await fetch(supabaseUrl+"/rest/v1/rpc/register_verified_release",{
      method:"POST",headers:serviceHeaders,
      body:JSON.stringify({
        target_org:claims.organization_id,target_project:projectId,target_version:version,
        target_artifact_name:artifactName,target_artifact_sha256:artifactSha,target_manifest:manifest,
        target_actor:claims.created_by,target_key_fingerprint:String(signature.key_id).toLowerCase(),
        target_manifest_sha256:verification.manifestSha256,target_signature_sha256:verification.signatureSha256
      })
    });
    const registered=await jsonResponse(registration);
    if(!registered.ok)return respond({error:registered.value?.message||"Trusted release registration failed"},registered.status>=400&&registered.status<500?registered.status:502);
    return respond({release_id:registered.value?.release_id,signature_verified:true,attestation_created:true,token_id:verified.token_id},201);
  }catch{return respond({error:"API gateway request could not be completed"},400);}
});
