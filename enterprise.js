"use strict";
(() => {
  const $ = id => document.getElementById(id);
  const state = { config:null, session:null, organizations:[], organization:null, organizationRole:null, projects:[], project:null, releases:[], policies:[], apiTokens:[], invitationToken:null };
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
  async function showWorkspace(){$("auth-card").classList.add("hidden");$("workspace").classList.remove("hidden");$("signed-in-as").textContent=state.session.user?.email||"Signed in";await loadOrganizations();renderInviteCard();}
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
  async function selectOrganization(id){$("invite-link").value="";$("api-token-secret").value="";$("copy-invite-link").disabled=true;$("copy-api-token").disabled=true;state.organization=state.organizations.find(org=>org.id===id)||null;if(!state.organization)return;state.project=null;$('api-token-org-wide').checked=false;$('api-token-secret').value='';$('copy-api-token').disabled=true;$("project-tools").classList.remove("hidden");$("project-heading").textContent=state.organization.name+" · Projects";$("project-subtitle").textContent="Create and manage projects inside this organization.";["release-tools","key-tools","sbom-tools","policy-tools","team-tools","api-token-tools"].forEach(id=>$(id).classList.add("hidden"));const membership=await request("/rest/v1/organization_memberships?select=role&organization_id=eq."+encodeURIComponent(state.organization.id)+"&user_id=eq."+encodeURIComponent(state.session.user.id)+"&limit=1");state.organizationRole=membership?.[0]?.role||null;if(["owner","admin"].includes(state.organizationRole)){$("team-tools").classList.remove("hidden");$("api-token-tools").classList.remove("hidden");await loadInvitations();}await loadProjects();if(["owner","admin"].includes(state.organizationRole))await loadApiTokens();}
  function renderInviteCard(){
    const card=$("invite-card");if(!card)return;
    if(state.invitationToken){card.classList.remove("hidden");$("accept-invitation").disabled=!state.session;$("invite-message").textContent=state.session?"Signed in as "+(state.session.user?.email||"your account")+". Accept to join the organization.":"Sign in or create an account with the invited email address to continue.";}
    else card.classList.add("hidden");
  }
  async function loadInvitations(){
    if(!state.organization||!["owner","admin"].includes(state.organizationRole))return;
    const list=$("invite-list");list.innerHTML="<p class='muted'>Loading invitations…</p>";
    try{
      const rows=await request("/rest/v1/organization_invitations?select=id,email,role,expires_at,accepted_at,revoked_at,created_at&organization_id=eq."+encodeURIComponent(state.organization.id)+"&order=created_at.desc&limit=50")||[];
      list.innerHTML=rows.length?rows.map(invite=>{
        const expired=Date.parse(invite.expires_at)<=Date.now();
        const status=invite.accepted_at?"Accepted":invite.revoked_at?"Revoked":expired?"Expired":"Pending";
        return "<div class='record-item'><div><strong>"+esc(invite.email)+" · "+esc(invite.role)+"</strong><small>"+status+" · expires "+new Date(invite.expires_at).toLocaleString()+"</small></div>"+(!invite.accepted_at&&!invite.revoked_at&&!expired?"<button class='btn danger' data-revoke-invite='"+esc(invite.id)+"'>Revoke</button>":"")+"</div>";
      }).join(""):"<p class='muted'>No team invitations have been created.</p>";
      list.querySelectorAll("[data-revoke-invite]").forEach(button=>button.addEventListener("click",()=>revokeInvitation(button.dataset.revokeInvite)));
    }catch(e){list.innerHTML="<p class='muted'>"+esc(e.message)+"</p>"}
  }
  async function createInvitation(){
    try{
      if(!state.organization||!["owner","admin"].includes(state.organizationRole))throw new Error("Only organization owners and admins can invite members.");
      const email=$("invite-email").value.trim(),role=$("invite-role").value,days=Number($("invite-expiry").value);
      if(!email)throw new Error("Enter the invitee email address.");
      const result=await request("/rest/v1/rpc/create_organization_invitation",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target_org:state.organization.id,target_email:email,target_role:role,expires_in_days:days})});
      const link=window.location.origin+"/enterprise.html?invite="+encodeURIComponent(result.token);
      $("invite-link").value=link;$("copy-invite-link").disabled=false;$("invite-email").value="";
      message("invite-result","Invitation created for "+result.email+". Share this link with the invitee; the token is shown only once and expires "+new Date(result.expires_at).toLocaleString()+".");
      await loadInvitations();
    }catch(e){message("invite-result",e.message,true)}
  }
  async function copyInvitationLink(){
    const link=$("invite-link").value;if(!link)return;
    try{await navigator.clipboard.writeText(link);message("invite-result","Invitation link copied. Share it only with the intended invitee.");}
    catch{ $("invite-link").focus();$("invite-link").select();message("invite-result","Select and copy the invitation link manually.");}
  }
  async function revokeInvitation(invitationId){
    if(!window.confirm("Revoke this organization invitation? The invite link will stop working."))return;
    try{await request("/rest/v1/rpc/revoke_organization_invitation",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target_invitation:invitationId})});message("invite-result","Invitation revoked.");await loadInvitations();}
    catch(e){message("invite-result",e.message,true)}
  }
  async function acceptInvitation(){
    try{
      if(!state.session)throw new Error("Sign in or create an account using the invited email address first.");
      if(!state.invitationToken)throw new Error("No invitation token was found in this link.");
      const result=await request("/rest/v1/rpc/accept_organization_invitation",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({invitation_token:state.invitationToken})});
      state.invitationToken=null;const url=new URL(window.location.href);url.searchParams.delete("invite");window.history.replaceState({}, "", url.toString());
      $("invite-card").classList.add("hidden");message("auth-message","Invitation accepted. You joined the organization as "+result.role+".");
      state.organization=null;await loadOrganizations();const org=state.organizations.find(item=>item.id===result.organization_id);if(org)await selectOrganization(org.id);
    }catch(e){message("invite-message",e.message,true)}
  }
  function renderTokenProjectOptions(){
    const list=$("api-token-projects");if(!list)return;
    list.innerHTML=state.projects.length?state.projects.map(project=>"<label><input type='checkbox' name='api-token-project' value='"+esc(project.id)+"' "+(state.project?.id===project.id?"checked":"")+( $("api-token-org-wide")?.checked?" disabled":"")+"> "+esc(project.name)+"</label>").join(""):"<p class='muted'>No projects yet; create a project or explicitly enable organization-wide access.</p>";
  }
  async function loadApiTokens(){
    if(!state.organization||!["owner","admin"].includes(state.organizationRole))return;
    const list=$("api-token-list");list.innerHTML="<p class='muted'>Loading API tokens…</p>";
    try{
      const rows=await request("/rest/v1/api_token_registry?select=id,name,token_prefix,scopes,project_ids,expires_at,revoked_at,last_used_at,created_at&organization_id=eq."+encodeURIComponent(state.organization.id)+"&order=created_at.desc&limit=50")||[];
      state.apiTokens=rows;
      list.innerHTML=rows.length?rows.map(item=>{
        const expired=item.expires_at&&Date.parse(item.expires_at)<=Date.now();
        const status=item.revoked_at?"Revoked":expired?"Expired":"Active";
        const scopeLabel=(item.scopes||[]).join(", ");
        const projectLabel=(item.project_ids||[]).length?item.project_ids.length+" project(s)":"Organization-wide";
        return "<div class='record-item'><div><strong>"+esc(item.name)+" · "+esc(item.token_prefix)+"</strong><small>"+status+" · "+esc(scopeLabel)+" · "+esc(projectLabel)+"</small><small>Expires "+(item.expires_at?new Date(item.expires_at).toLocaleString():"unknown")+" · Last used "+(item.last_used_at?new Date(item.last_used_at).toLocaleString():"Never")+"</small></div>"+(!item.revoked_at&&!expired?"<button class='btn danger' data-revoke-api-token='"+esc(item.id)+"'>Revoke</button>":"")+"</div>";
      }).join(""):"<p class='muted'>No API tokens have been created.</p>";
      list.querySelectorAll("[data-revoke-api-token]").forEach(button=>button.addEventListener("click",()=>revokeApiToken(button.dataset.revokeApiToken)));
    }catch(e){list.innerHTML="<p class='muted'>"+esc(e.message)+"</p>"}
  }
  async function createApiToken(){
    try{
      if(!state.organization||!["owner","admin"].includes(state.organizationRole))throw new Error("Only organization owners and admins can create API tokens.");
      const name=$("api-token-name").value.trim();
      const scopes=Array.from(document.querySelectorAll("input[name='api-token-scope']:checked")).map(input=>input.value);
      const organizationWide=$("api-token-org-wide").checked;
      const projectIds=organizationWide?[]:Array.from(document.querySelectorAll("input[name='api-token-project']:checked")).map(input=>input.value);
      const expiry=$("api-token-expiry").value;
      if(name.length<3)throw new Error("Token name must contain at least three characters.");
      if(!scopes.length)throw new Error("Select at least one API scope.");
      if(!organizationWide&&!projectIds.length)throw new Error("Select at least one project, or explicitly enable organization-wide access.");
      if(!expiry)throw new Error("Choose an expiry date.");
      const expiresAt=new Date(expiry+"T23:59:59Z");
      if(Number.isNaN(expiresAt.getTime())||expiresAt<=new Date())throw new Error("Choose a future expiry date.");
      const result=await request("/rest/v1/rpc/create_api_token",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target_org:state.organization.id,target_name:name,target_scopes:scopes,target_project_ids:projectIds,target_expires_at:expiresAt.toISOString()})});
      $("api-token-secret").value=result.token;$("copy-api-token").disabled=false;$("api-token-name").value="";
      message("api-token-result","Token created. Copy the secret now; it cannot be retrieved again. The stored database value is only a SHA-256 hash.");
      await loadApiTokens();
    }catch(e){message("api-token-result",e.message,true)}
  }
  async function copyApiToken(){
    const secret=$("api-token-secret").value;if(!secret)return;
    try{await navigator.clipboard.writeText(secret);message("api-token-result","API token copied. Store it in your CI/CD secret manager; never commit it.");}
    catch{$("api-token-secret").focus();$("api-token-secret").select();message("api-token-result","Select and copy the token manually, then store it securely.");}
  }
  async function revokeApiToken(tokenId){
    if(!window.confirm("Revoke this API token? Existing integrations using it will immediately lose access. This cannot be undone."))return;
    try{await request("/rest/v1/rpc/revoke_api_token",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target_org:state.organization.id,target_token_id:tokenId})});message("api-token-result","API token revoked. Revocation is irreversible.");await loadApiTokens();}
    catch(e){message("api-token-result",e.message,true)}
  }
  async function loadProjects(){const list=$("project-list");list.innerHTML="<p class='muted'>Loading projects…</p>";try{state.projects=await request("/rest/v1/projects?select=id,name,slug,created_at&organization_id=eq."+encodeURIComponent(state.organization.id)+"&order=created_at.desc")||[];renderTokenProjectOptions();if(!state.projects.length){list.innerHTML="<p class='muted'>No projects yet. Create the first project.</p>";return;}list.innerHTML=state.projects.map(project=>"<div class='record-item "+(state.project?.id===project.id?"selected":"")+"'><div><strong>"+esc(project.name)+"</strong><small>"+esc(project.slug)+"</small><small>Project ID: <code>"+esc(project.id)+"</code></small></div><button class='btn ghost' data-project='"+esc(project.id)+"'>Releases</button></div>").join("");list.querySelectorAll("[data-project]").forEach(button=>button.addEventListener("click",()=>selectProject(button.dataset.project)));}catch(e){list.innerHTML="<p class='muted'>"+esc(e.message)+"</p>"}}
  async function createProject(){try{const name=$("project-name").value.trim(),slug=slugify($("project-slug").value||name);if(!state.organization||name.length<2||slug.length<2)throw new Error("Choose an organization and enter a valid project name.");await request("/rest/v1/projects",{method:"POST",headers:{"Content-Type":"application/json","Prefer":"return=minimal"},body:JSON.stringify({organization_id:state.organization.id,name,slug,created_by:state.session.user.id})});$("project-name").value="";$("project-slug").value="";await loadProjects();}catch(e){message("auth-message",e.message,true)}}
  async function selectProject(id){state.project=state.projects.find(project=>project.id===id)||null;if(!state.project)return;$("release-tools").classList.remove("hidden");$("key-tools").classList.remove("hidden");$("sbom-tools").classList.remove("hidden");$("policy-tools").classList.remove("hidden");$("release-subtitle").textContent="Draft releases for "+state.project.name+". Registry stores metadata and digests, not firmware binaries.";await Promise.all([loadReleases(),loadKeys(),loadSboms(),loadPolicies()]);await loadProjects();}
  async function loadReleases(){const list=$("release-list");list.innerHTML="<p class='muted'>Loading release history…</p>";try{const rows=await request("/rest/v1/releases?select=id,version,artifact_name,artifact_sha256,status,created_at&organization_id=eq."+encodeURIComponent(state.organization.id)+"&project_id=eq."+encodeURIComponent(state.project.id)+"&order=created_at.desc")||[];state.releases=rows;const releaseSelect=$("policy-release");if(releaseSelect)releaseSelect.innerHTML=rows.map(row=>"<option value=\""+esc(row.id)+"\">"+esc(row.version+" · "+row.artifact_name)+"</option>").join("");if(!rows.length){list.innerHTML="<p class='muted'>No releases registered for this project.</p>";return;}list.innerHTML=rows.map(release=>"<div class='record-item'><div><strong>"+esc(release.version)+" · "+esc(release.artifact_name)+"</strong><small>"+esc(release.status)+" · SHA-256 "+esc(release.artifact_sha256)+"</small><small>"+(release.status==="approved"?"Approved; publish only after server-side verification and policy checks pass.":release.status==="pending_approval"?"Awaiting independent review against pinned policy.":release.status==="rejected"?"Review rejected. Create a new release revision to resubmit.":release.status==="published"?"Published; immutable release evidence is retained.":"Draft release; submit it for policy review when evidence is ready.")+"</small></div><div class='release-row-actions'>"+(release.status==="draft"?"<button class='btn ghost' data-request-review='"+esc(release.id)+"'>Request review</button>":release.status==="pending_approval"?"<button class='btn primary' data-approve-release='"+esc(release.id)+"'>Approve</button><button class='btn danger' data-reject-release='"+esc(release.id)+"'>Reject</button>":release.status==="approved"?"<button class='btn primary' data-publish-release='"+esc(release.id)+"'>Publish release</button>":"")+"<span class='status-text'>"+new Date(release.created_at).toLocaleDateString()+"</span></div></div>").join("");list.querySelectorAll("[data-request-review]").forEach(button=>button.addEventListener("click",()=>requestReview(button.dataset.requestReview)));list.querySelectorAll("[data-approve-release]").forEach(button=>button.addEventListener("click",()=>submitReview(button.dataset.approveRelease,"approved")));list.querySelectorAll("[data-reject-release]").forEach(button=>button.addEventListener("click",()=>submitReview(button.dataset.rejectRelease,"rejected")));list.querySelectorAll("[data-publish-release]").forEach(button=>button.addEventListener("click",()=>publishRelease(button.dataset.publishRelease)));}catch(e){list.innerHTML="<p class='muted'>"+esc(e.message)+"</p>"}}
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

  async function publishRelease(releaseId){
    try{
      if(!window.confirm("Publish this approved firmware release? The database will re-check policy evidence and the server-side signature attestation."))return;
      const result=await request("/rest/v1/rpc/publish_release",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target_release:releaseId})});
      message("auth-message","Release published at "+new Date(result.published_at).toLocaleString()+".");
      await loadReleases();
    }catch(e){message("auth-message",e.message,true)}
  }
  async function requestReview(releaseId){
    try{
      const result=await request("/rest/v1/rpc/request_release_approval",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target_release:releaseId})});
      message("auth-message","Release submitted for review. Policy version pinned: "+result.policy_id);
      await loadReleases();await loadPolicies();
    }catch(e){message("auth-message",e.message,true)}
  }
  async function submitReview(releaseId,decision){
    try{
      const comment=window.prompt(decision==="approved"?"Optional approval comment:":"Reason for rejecting this release:");
      if(comment===null)return;
      if(decision==="rejected"&&!comment.trim())throw new Error("A rejection reason is required.");
      const result=await request("/rest/v1/rpc/submit_release_approval",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target_release:releaseId,approval_decision:decision,approval_comment:comment.trim()||null})});
      const evaluation=result.policy_evaluation;
      if(decision==="approved"&&result.status==="pending_approval"){
        message("auth-message","Approval recorded, but the release remains pending because policy evidence is incomplete: "+(evaluation?.reasons||[]).join("; "),true);
      }else{
        message("auth-message","Review decision recorded. Release status: "+result.status+".");
      }
      await loadReleases();
      if(evaluation)$("policy-result").textContent=JSON.stringify(evaluation,null,2);
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
      if(!state.organization||!state.project)throw new Error("Select a project before creating a release policy.");
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
  async function signOut(){try{if(token())await fetch(state.config.url+"/auth/v1/logout",{method:"POST",headers:headers()})}catch{}saveSession(null);$("invite-link").value="";$("api-token-secret").value="";$("copy-invite-link").disabled=true;$("copy-api-token").disabled=true;state.organization=null;state.organizationRole=null;state.project=null;$("team-tools").classList.add("hidden");$("api-token-tools").classList.add("hidden");$("workspace").classList.add("hidden");$("auth-card").classList.remove("hidden");renderInviteCard();message("auth-message","Signed out.");}
  async function init(){try{state.invitationToken=new URLSearchParams(window.location.search).get("invite");const tokenExpiry=new Date(Date.now()+90*86400000);$("api-token-expiry").value=tokenExpiry.toISOString().slice(0,10);renderInviteCard();const response=await fetch("/api/config",{cache:"no-store"});if(!response.ok)throw new Error("Enterprise backend configuration is unavailable.");state.config=await response.json();const saved=sessionStorage.getItem("ft_session");if(saved){try{state.session=JSON.parse(saved);await showWorkspace()}catch{saveSession(null)}}}catch(e){message("auth-message",e.message,true)}}
  $("api-token-org-wide").addEventListener("change",()=>document.querySelectorAll("input[name=api-token-project]").forEach(input=>input.disabled=$("api-token-org-wide").checked));
  $("create-api-token").addEventListener("click",createApiToken);$("copy-api-token").addEventListener("click",copyApiToken);$("create-invitation").addEventListener("click",createInvitation);$("copy-invite-link").addEventListener("click",copyInvitationLink);$("accept-invitation").addEventListener("click",acceptInvitation);$("register-key").addEventListener("click",registerKey);$("clear-key-form").addEventListener("click",clearKeyForm);$("key-pem").addEventListener("change",updateKeyFingerprint);
  $("sign-in").addEventListener("click",signIn);$("sign-up").addEventListener("click",signUp);$("sign-out").addEventListener("click",signOut);$("create-org").addEventListener("click",createOrganization);$("create-project").addEventListener("click",createProject);$("create-release").addEventListener("click",createRelease);$("create-policy").addEventListener("click",createPolicy);$("evaluate-policy").addEventListener("click",evaluatePolicy);$("ingest-sbom").addEventListener("click",ingestSbom);$("refresh-workspace").addEventListener("click",loadOrganizations);
  $("org-name").addEventListener("input",()=>{if(!$("org-slug").dataset.edited)$("org-slug").value=slugify($("org-name").value)});$("org-slug").addEventListener("input",()=>{$("org-slug").dataset.edited="true"});
  $("project-name").addEventListener("input",()=>{if(!$("project-slug").dataset.edited)$("project-slug").value=slugify($("project-name").value)});$("project-slug").addEventListener("input",()=>{$("project-slug").dataset.edited="true"});
  init();
})();