"use strict";
(() => {
  const $ = id => document.getElementById(id);
  const state = { config:null, session:null, organizations:[], organization:null, projects:[], project:null, releases:[], policies:[] };
  const esc = value => String(value ?? "").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const slugify = value => value.toLowerCase().trim().replace(/[^a-z0-9]+/g,"-").replace(/^-|-$/g,"").slice(0,63);
  const message = (id,text,error=false) => { const el=$(id);el.textContent=text;el.classList.toggle("error",error); };
  const token = () => state.session?.access_token || "";
  const headers = extra => ({apikey:state.config.publishableKey,Authorization:"Bearer "+token(),...(extra||{})});
  async function request(path,options={}) {
    const response=await fetch(state.config.url+path,{...options,headers:headers(options.headers||{})});
    const raw=await response.text();let data=null;try{data=raw?JSON.parse(raw):null}catch{data=raw}
    if(!response.ok)throw new Error(data?.msg||data?.message||data?.error_description||data?.error||("Request failed ("+response.status+")"));
    return data;
  }
  async function authRequest(path,body) {
    const response=await fetch(state.config.url+"/auth/v1/"+path,{method:"POST",headers:{apikey:state.config.publishableKey,"Content-Type":"application/json"},body:JSON.stringify(body)});
    const data=await response.json().catch(()=>({}));if(!response.ok)throw new Error(data.msg||data.message||data.error_description||"Authentication failed");return data;
  }
  function saveSession(session){state.session=session;if(session)sessionStorage.setItem("ft_session",JSON.stringify(session));else sessionStorage.removeItem("ft_session");}
  async function signIn(){try{const email=$("auth-email").value.trim(),password=$("auth-password").value;if(!email||!password)throw new Error("Enter your email and password.");const data=await authRequest("token?grant_type=password",{email,password});if(!data.access_token)throw new Error("No active session returned. Check email confirmation settings.");saveSession(data);await showWorkspace();}catch(e){message("auth-message",e.message,true)}}
  async function signUp(){try{const email=$("auth-email").value.trim(),password=$("auth-password").value;if(!email||password.length<8)throw new Error("Enter a valid email and a password of at least 8 characters.");const data=await authRequest("signup",{email,password});if(data.access_token){saveSession(data);await showWorkspace();}else message("auth-message","Account created. Check your email to confirm the address, then sign in.");}catch(e){message("auth-message",e.message,true)}}
  async function showWorkspace(){$("auth-card").classList.add("hidden");$("workspace").classList.remove("hidden");$("signed-in-as").textContent=state.session.user?.email||"Signed in";await loadOrganizations();}
  async function loadOrganizations(){
    const list=$("org-list");list.innerHTML="<p class='muted'>Loading organizations…</p>";
    try{state.organizations=await request("/rest/v1/organizations?select=id,name,slug,created_at&order=created_at.desc")||[];
      if(!state.organizations.length){list.innerHTML="<p class='muted'>No organizations yet. Create your first organization.</p>";return;}
      list.innerHTML=state.organizations.map(org=>"<div class='record-item "+(state.organization?.id===org.id?"selected":"")+"'><div><strong>"+esc(org.name)+"</strong><small>"+esc(org.slug)+"</small><small>Organization ID: <code>"+esc(org.id)+"</code></small></div><button class='btn ghost' data-org='"+esc(org.id)+"'>Open</button></div>").join("");
      list.querySelectorAll("[data-org]").forEach(button=>button.addEventListener("click",()=>selectOrganization(button.dataset.org)));
      if(state.organization)await selectOrganization(state.organization.id,false);
    }catch(e){list.innerHTML="<p class='muted'>"+esc(e.message)+"</p>"}
  }
  async function createOrganization(){try{const name=$("org-name").value.trim(),slug=slugify($("org-slug").value||name);if(name.length<2||slug.length<2)throw new Error("Enter an organization name and valid slug.");await request("/rest/v1/rpc/create_organization",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({org_name:name,org_slug:slug})});$("org-name").value="";$("org-slug").value="";message("auth-message","Organization created. You are its owner.");await loadOrganizations();}catch(e){message("auth-message",e.message,true)}}
  async function selectOrganization(id){state.organization=state.organizations.find(org=>org.id===id)||null;if(!state.organization)return;$("project-tools").classList.remove("hidden");$("project-heading").textContent=state.organization.name+" · Projects";$("project-subtitle").textContent="Create and manage projects inside this organization.";$("release-tools").classList.add("hidden");await loadProjects();}
  async function loadProjects(){const list=$("project-list");list.innerHTML="<p class='muted'>Loading projects…</p>";try{state.projects=await request("/rest/v1/projects?select=id,name,slug,created_at&organization_id=eq."+encodeURIComponent(state.organization.id)+"&order=created_at.desc")||[];if(!state.projects.length){list.innerHTML="<p class='muted'>No projects yet. Create the first project.</p>";return;}list.innerHTML=state.projects.map(project=>"<div class='record-item "+(state.project?.id===project.id?"selected":"")+"'><div><strong>"+esc(project.name)+"</strong><small>"+esc(project.slug)+"</small><small>Project ID: <code>"+esc(project.id)+"</code></small></div><button class='btn ghost' data-project='"+esc(project.id)+"'>Releases</button></div>").join("");list.querySelectorAll("[data-project]").forEach(button=>button.addEventListener("click",()=>selectProject(button.dataset.project)));}catch(e){list.innerHTML="<p class='muted'>"+esc(e.message)+"</p>"}}
  async function createProject(){try{const name=$("project-name").value.trim(),slug=slugify($("project-slug").value||name);if(!state.organization||name.length<2||slug.length<2)throw new Error("Choose an organization and enter a valid project name.");await request("/rest/v1/projects",{method:"POST",headers:{"Content-Type":"application/json","Prefer":"return=minimal"},body:JSON.stringify({organization_id:state.organization.id,name,slug,created_by:state.session.user.id})});$("project-name").value="";$("project-slug").value="";await loadProjects();}catch(e){message("auth-message",e.message,true)}}
  async function selectProject(id){state.project=state.projects.find(project=>project.id===id)||null;if(!state.project)return;$("release-tools").classList.remove("hidden");$("key-tools").classList.remove("hidden");$("sbom-tools").classList.remove("hidden");$("release-subtitle").textContent="Draft releases for "+state.project.name+". Registry stores metadata and digests, not firmware binaries.";await Promise.all([loadReleases(),loadKeys(),loadSboms(),loadPolicies()]);await loadProjects();}
  async function loadReleases(){const list=$("release-list");list.innerHTML="<p class='muted'>Loading release history…</p>";try{const rows=await request("/rest/v1/releases?select=id,version,artifact_name,artifact_sha256,status,created_at&organization_id=eq."+encodeURIComponent(state.organization.id)+"&project_id=eq."+encodeURIComponent(state.project.id)+"&order=created_at.desc")||[];state.releases=rows;const releaseSelect=$("policy-release");if(releaseSelect)releaseSelect.innerHTML=rows.map(row=>"<option value=\""+esc(row.id)+"\">"+esc(row.version+" · "+row.artifact_name)+"</option>").join("");if(!rows.length){list.innerHTML="<p class='muted'>No releases registered for this project.</p>";return;}list.innerHTML=rows.map(release=>"<div class='record-item'><div><strong>"+esc(release.version)+" · "+esc(release.artifact_name)+"</strong><small>"+esc(release.status)+" · SHA-256 "+esc(release.artifact_sha256)+"</small></div><span class='status-text'>"+new Date(release.created_at).toLocaleDateString()+"</span></div>").join("");}catch(e){list.innerHTML="<p class='muted'>"+esc(e.message)+"</p>"}}
  async function loadSboms(){
    const list=$("sbom-list"),findings=$("sbom-findings");
    list.innerHTML="<p class=muted>Loading SBOM inventory…</p>";findings.innerHTML="<p class=muted>Loading vulnerability findings…</p>";
    try{
      const org=encodeURIComponent(state.organization.id),project=encodeURIComponent(state.project.id);
      const documents=await request("/rest/v1/sbom_documents?select=id,format,spec_version,document_sha256,ingested_at,scan_status,scan_source,scanned_at,scanned_component_count,finding_count,scan_warning&organization_id=eq."+org+"&project_id=eq."+project+"&order=ingested_at.desc&limit=20");
      const sbomIds=(documents||[]).map(item=>item.id);
      const rows=sbomIds.length?await request("/rest/v1/vulnerability_findings?select=advisory_id,severity,summary,fixed_version,observed_at&sbom_id=in.("+sbomIds.join(",")+")&order=observed_at.desc&limit=50"):[];
      list.innerHTML=documents?.length?documents.map(item=>"<div class=record-item><div><strong>"+esc(String(item.format).toUpperCase())+" · "+esc(item.spec_version||"version unspecified")+"</strong><small>SHA-256 "+esc(item.document_sha256)+"</small><small>Scan: "+esc(item.scan_status||"pending")+" · "+esc(item.finding_count||0)+" findings · "+esc(item.scanned_component_count||0)+" components checked</small>"+(item.scan_warning?"<small>"+esc(item.scan_warning)+"</small>":"")+"</div><span class=status-text>"+new Date(item.ingested_at).toLocaleDateString()+"</span></div>").join(""):"<p class=muted>No SBOM documents ingested for this project.</p>";
      findings.innerHTML=rows?.length?rows.map(item=>"<div class=record-item><div><strong>"+esc(item.advisory_id)+" · "+esc(item.severity||"unrated")+"</strong><small>"+esc(item.summary||"No advisory summary supplied")+"</small><small><a href=https://osv.dev/vulnerability/"+encodeURIComponent(item.advisory_id)+" target=_blank rel=noopener>View OSV advisory</a></small>"+(item.fixed_version?"<small>Fixed version: "+esc(item.fixed_version)+"</small>":"")+"</div><span class=status-text>"+new Date(item.observed_at).toLocaleDateString()+"</span></div>").join(""):"<p class=muted>No vulnerability findings recorded for this organization yet.</p>";
    }catch(e){list.innerHTML="<p class=muted>"+esc(e.message)+"</p>";findings.innerHTML="";}
  }
  async function ingestSbom(){
    try{
      const file=$("sbom-file").files?.[0];
      if(!state.project||!file)throw new Error("Choose a CycloneDX JSON or SPDX JSON SBOM first.");
      if(file.size>5*1024*1024)throw new Error("SBOM files must be 5 MB or smaller.");
      const documentText=await file.text();
      const result=await request("/functions/v1/ingest-sbom",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({organization_id:state.organization.id,project_id:state.project.id,document_text:documentText})});
      $("sbom-file").value="";
      const scan=result.scan_status==="complete"?"OSV scan completed":result.scan_status==="partial"?"OSV scan partially completed":result.scan_status==="unavailable"?"SBOM saved; OSV service was unavailable":"SBOM saved; no versioned package URLs were available for OSV scanning";
      message("auth-message",scan+". Components: "+result.component_count+". Findings: "+(result.finding_count||0)+".");
      await loadSboms();
    }catch(e){message("auth-message",e.message,true)}
  }
  async function createRelease(){
    try{
      const version=$("release-version").value.trim(),artifact=$("release-artifact").value.trim(),sha=$("release-sha").value.trim().toLowerCase();
      const manifestFile=$("release-manifest").files?.[0];
      if(!state.project||!version||!artifact||!/^[a-f0-9]{64}$/.test(sha))throw new Error("Enter a version, artifact filename and 64-character SHA-256 digest.");
      if(manifestFile){
        let manifest;try{manifest=JSON.parse(await manifestFile.text())}catch{throw new Error("The selected signed manifest is not valid JSON.");}
        await request("/functions/v1/register-release",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({organization_id:state.organization.id,project_id:state.project.id,version,artifact_name:artifact,artifact_sha256:sha,manifest})});
        message("auth-message","Signed manifest verified against an active registered key. Draft release saved and audit event appended.");
      }else{
        await request("/rest/v1/releases",{method:"POST",headers:{"Content-Type":"application/json","Prefer":"return=minimal"},body:JSON.stringify({organization_id:state.organization.id,project_id:state.project.id,version,artifact_name:artifact,artifact_sha256:sha,created_by:state.session.user.id,manifest:{source:"enterprise-console",evidence_state:"unsigned_metadata"}})});
        message("auth-message","Unsigned draft metadata saved. Attach a signed manifest to validate the signer and key status.");
      }
      $("release-version").value="";$("release-artifact").value="";$("release-sha").value="";$("release-manifest").value="";
      await loadReleases();
    }catch(e){message("auth-message",e.message,true)}
  }
  function publicKeyDer(pem){
    const match=pem.match(/-----BEGIN PUBLIC KEY-----([\s\S]+?)-----END PUBLIC KEY-----/);
    if(!match)throw new Error("Paste a PEM-encoded PUBLIC KEY, not a private key.");
    const raw=atob(match[1].replace(/\s/g,""));
    if(raw.length<32||raw.length>12000)throw new Error("Public key PEM is malformed or too large.");
    return Uint8Array.from(raw,c=>c.charCodeAt(0));
  }
  async function fingerprintForPem(pem){
    const der=publicKeyDer(pem);
    const publicKey=await crypto.subtle.importKey("spki",der,{name:"Ed25519"},true,["verify"]);
    const raw=new Uint8Array(await crypto.subtle.exportKey("raw",publicKey));
    const digest=await crypto.subtle.digest("SHA-256",raw);
    return Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,"0")).join("").slice(0,16);
  }
  async function updateKeyFingerprint(){
    try{$("key-fingerprint").value=await fingerprintForPem($("key-pem").value.trim());}
    catch{$("key-fingerprint").value="";}
  }
  async function loadKeys(){
    const list=$("key-list");list.innerHTML="<p class='muted'>Loading signing keys…</p>";
    try{
      const keys=await request("/rest/v1/signing_keys?select=id,key_fingerprint,algorithm,status,valid_from,valid_until,revoked_reason,project_id&organization_id=eq."+encodeURIComponent(state.organization.id)+"&project_id=eq."+encodeURIComponent(state.project.id)+"&order=created_at.desc")||[];
      if(!keys.length){list.innerHTML="<p class='muted'>No registered signing keys for this project.</p>";return;}
      list.innerHTML=keys.map(key=>"<div class='record-item'><div><strong>"+esc(key.algorithm)+" · "+esc(key.status)+"</strong><small>"+esc(key.key_fingerprint)+"</small><small>Valid from "+new Date(key.valid_from).toLocaleString()+(key.valid_until?" · until "+new Date(key.valid_until).toLocaleString():"")+(key.revoked_reason?" · "+esc(key.revoked_reason):"")+"</small></div>"+(key.status==="active"?"<div class='key-row-actions'><button class='btn ghost' data-rotate-key='"+esc(key.id)+"'>Rotate</button><button class='btn danger' data-revoke-key='"+esc(key.id)+"'>Revoke</button></div>":"")+"</div>").join("");
      list.querySelectorAll("[data-rotate-key]").forEach(button=>button.addEventListener("click",()=>rotateKey(button.dataset.rotateKey)));
      list.querySelectorAll("[data-revoke-key]").forEach(button=>button.addEventListener("click",()=>revokeKey(button.dataset.revokeKey)));
    }catch(e){list.innerHTML="<p class='muted'>"+esc(e.message)+"</p>"}
  }
  async function registerKey(){
    try{
      const pem=$("key-pem").value.trim(),algorithm=$("key-algorithm").value;
      if(!state.project)throw new Error("Select a project first.");
      const fingerprint=await fingerprintForPem(pem);$("key-fingerprint").value=fingerprint;
      await request("/rest/v1/signing_keys",{method:"POST",headers:{"Content-Type":"application/json","Prefer":"return=minimal"},body:JSON.stringify({organization_id:state.organization.id,project_id:state.project.id,key_fingerprint:fingerprint,algorithm,public_key_pem:pem,status:"active",created_by:state.session.user.id})});
      $("key-pem").value="";$("key-fingerprint").value="";message("auth-message","Public signing key registered. Its private key was not uploaded.");await loadKeys();
    }catch(e){message("auth-message",e.message,true)}
  }
  async function rotateKey(oldKeyId){
    try{
      const pem=$("key-pem").value.trim(),algorithm=$("key-algorithm").value;
      if(!pem)throw new Error("Paste the successor public key PEM before selecting Rotate.");
      const fingerprint=await fingerprintForPem(pem);$("key-fingerprint").value=fingerprint;
      await request("/rest/v1/rpc/rotate_signing_key",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target_org:state.organization.id,old_key_id:oldKeyId,new_fingerprint:fingerprint,new_public_key_pem:pem,new_algorithm:algorithm})});
      $("key-pem").value="";$("key-fingerprint").value="";message("auth-message","Key rotation completed. The predecessor is marked rotated and the successor is active.");await loadKeys();
    }catch(e){message("auth-message",e.message,true)}
  }
  async function revokeKey(keyId){
    try{
      const reason=$("key-revoke-reason").value.trim();
      if(reason.length<3)throw new Error("Enter a meaningful revocation reason first.");
      if(!window.confirm("Revoke this signing key? This action is irreversible."))return;
      await request("/rest/v1/rpc/revoke_signing_key",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target_org:state.organization.id,target_key_id:keyId,reason})});
      $("key-revoke-reason").value="";message("auth-message","Signing key revoked. The revocation was recorded in the audit history.");await loadKeys();
    }catch(e){message("auth-message",e.message,true)}
  }

  async function loadPolicies(){
    const list=$("policy-list");if(!list)return;
    list.innerHTML="<p class='muted'>Loading release policies…</p>";
    try{
      state.policies=await request("/rest/v1/release_policies?select=id,name,version,project_id,enabled,rules,created_at&organization_id=eq."+encodeURIComponent(state.organization.id)+"&or=(project_id.is.null,project_id.eq."+encodeURIComponent(state.project.id)+")&order=version.desc")||[];
      list.innerHTML=state.policies.length?state.policies.map(policy=>"<div class='record-item'><div><strong>"+esc(policy.name)+" · v"+esc(policy.version)+"</strong><small>"+(policy.project_id?"Project policy":"Organization policy")+" · "+(policy.enabled?"Enabled":"Disabled")+"</small><small><code>"+esc(JSON.stringify(policy.rules))+"</code></small></div></div>").join(""):"<p class='muted'>No release policies defined for this project.</p>";
    }catch(e){list.innerHTML="<p class='muted'>"+esc(e.message)+"</p>"}
  }
  async function createPolicy(){
    try{
      const name=$("policy-name").value.trim(),scope=$("policy-scope").value;
      let rules;try{rules=JSON.parse($("policy-rules").value)}catch{throw new Error("Policy rules must be valid JSON.");}
      if(name.length<3||!rules||Array.isArray(rules)||typeof rules!=="object")throw new Error("Enter a policy name and a JSON object of rules.");
      const existing=state.policies.filter(p=>p.name===name&&p.project_id===(scope==="project"?state.project.id:null));
      const version=existing.reduce((max,p)=>Math.max(max,Number(p.version)||0),0)+1;
      await request("/rest/v1/release_policies",{method:"POST",headers:{"Content-Type":"application/json","Prefer":"return=minimal"},body:JSON.stringify({organization_id:state.organization.id,project_id:scope==="project"?state.project.id:null,name,version,rules,enabled:true,created_by:state.session.user.id})});
      $("policy-name").value="";message("policy-result","Policy version "+version+" saved. Only organization owners/admins can create policies.");await loadPolicies();
    }catch(e){message("policy-result",e.message,true)}
  }
  async function evaluatePolicy(){
    try{
      const releaseId=$("policy-release").value;if(!releaseId)throw new Error("Select a release to evaluate.");
      const result=await request("/rest/v1/rpc/evaluate_release_policy",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target_release:releaseId})});
      $("policy-result").textContent=JSON.stringify(result,null,2);
    }catch(e){message("policy-result",e.message,true)}
  }
  function clearKeyForm(){$("key-pem").value="";$("key-fingerprint").value="";}
  async function signOut(){try{if(token())await fetch(state.config.url+"/auth/v1/logout",{method:"POST",headers:headers()})}catch{}saveSession(null);state.organization=null;state.project=null;$("workspace").classList.add("hidden");$("auth-card").classList.remove("hidden");message("auth-message","Signed out.");}
  async function init(){try{const response=await fetch("/api/config",{cache:"no-store"});if(!response.ok)throw new Error("Enterprise backend configuration is unavailable.");state.config=await response.json();const saved=sessionStorage.getItem("ft_session");if(saved){try{state.session=JSON.parse(saved);await showWorkspace()}catch{saveSession(null)}}}catch(e){message("auth-message",e.message,true)}}
  $("register-key").addEventListener("click",registerKey);$("clear-key-form").addEventListener("click",clearKeyForm);$("key-pem").addEventListener("change",updateKeyFingerprint);
  $("sign-in").addEventListener("click",signIn);$("sign-up").addEventListener("click",signUp);$("sign-out").addEventListener("click",signOut);$("create-org").addEventListener("click",createOrganization);$("create-project").addEventListener("click",createProject);$("create-release").addEventListener("click",createRelease);$("create-policy").addEventListener("click",createPolicy);$("evaluate-policy").addEventListener("click",evaluatePolicy);$("ingest-sbom").addEventListener("click",ingestSbom);$("refresh-workspace").addEventListener("click",loadOrganizations);
  $("org-name").addEventListener("input",()=>{if(!$("org-slug").dataset.edited)$("org-slug").value=slugify($("org-name").value)});$("org-slug").addEventListener("input",()=>{$("org-slug").dataset.edited="true"});
  $("project-name").addEventListener("input",()=>{if(!$("project-slug").dataset.edited)$("project-slug").value=slugify($("project-name").value)});$("project-slug").addEventListener("input",()=>{$("project-slug").dataset.edited="true"});
  init();
})();