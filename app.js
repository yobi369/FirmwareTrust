"use strict";
const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const dec = new TextDecoder();
const bytesToB64 = (bytes) => { let s=""; for (const b of bytes) s+=String.fromCharCode(b); return btoa(s); };
const b64ToBytes = (s) => Uint8Array.from(atob(s), c=>c.charCodeAt(0));
const pem = (label, bytes) => `-----BEGIN ${label}-----\n${bytesToB64(bytes).match(/.{1,64}/g).join("\n")}\n-----END ${label}-----\n`;
const readFile = (input) => { const f=input.files?.[0]; if(!f) throw new Error("Select the required file first."); return f; };
const canonical = (value) => {
  if (Array.isArray(value)) return "["+value.map(canonical).join(",")+"]";
  if (value && typeof value==="object") return "{"+Object.keys(value).sort().map(k=>JSON.stringify(k)+":"+canonical(value[k])).join(",")+"}";
  return JSON.stringify(value);
};
const digest = async (data) => new Uint8Array(await crypto.subtle.digest("SHA-256",data));
const hex = (b) => Array.from(b,x=>x.toString(16).padStart(2,"0")).join("");
const keyId = async (rawPublic) => hex(await digest(rawPublic)).slice(0,16);
const show = (id, html, kind="success") => { const el=$(id); el.className="result "+kind; el.innerHTML=html; el.classList.remove("hidden"); };
const fail = (id, err) => show(id,"<h4>Unable to complete</h4><p>"+escapeHtml(err.message||String(err))+"</p>","failure");
const escapeHtml = (s) => String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const download = (name, data, type="application/octet-stream") => { const blob=new Blob([data],{type}); const url=URL.createObjectURL(blob); const a=document.createElement("a"); a.href=url; a.download=name; a.click(); setTimeout(()=>URL.revokeObjectURL(url),1500); };
const setBusy = (button,busy,label) => { button.disabled=busy; if(busy){button.dataset.label=button.textContent;button.textContent=label;}else{button.textContent=button.dataset.label||label;} };
async function deriveVaultKey(pass,salt,iterations){
  const material=await crypto.subtle.importKey("raw",enc.encode(pass),"PBKDF2",false,["deriveKey"]);
  return crypto.subtle.deriveKey({name:"PBKDF2",hash:"SHA-256",salt,iterations},material,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
}
async function createIdentity(){
  const btn=$("generate-key"); setBusy(btn,true,"Generating keys…");
  try{
    if(!crypto?.subtle) throw new Error("Web Crypto is unavailable. Open this site in a modern browser over HTTPS.");
    const pass=$("key-pass").value, confirm=$("key-pass-confirm").value;
    if(pass.length<12) throw new Error("Use a passphrase of at least 12 characters.");
    if(pass!==confirm) throw new Error("The passphrases do not match.");
    const pair=await crypto.subtle.generateKey({name:"Ed25519"},true,["sign","verify"]);
    const pkcs8=new Uint8Array(await crypto.subtle.exportKey("pkcs8",pair.privateKey));
    const spki=new Uint8Array(await crypto.subtle.exportKey("spki",pair.publicKey));
    const raw=new Uint8Array(await crypto.subtle.exportKey("raw",pair.publicKey));
    const salt=crypto.getRandomValues(new Uint8Array(16)), iv=crypto.getRandomValues(new Uint8Array(12)), iterations=310000;
    const aes=await deriveVaultKey(pass,salt,iterations);
    const ciphertext=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv},aes,pkcs8));
    const vault={format:"FirmwareTrust encrypted private-key vault",version:1,algorithm:"Ed25519",kdf:"PBKDF2-SHA-256",iterations,cipher:"AES-256-GCM",salt:bytesToB64(salt),iv:bytesToB64(iv),ciphertext:bytesToB64(ciphertext),public_key_spki:bytesToB64(spki),key_id:await keyId(raw),created_at:new Date().toISOString()};
    const label=$("key-label").value.trim()||"FirmwareTrust key";
    download("firmwaretrust-"+label.toLowerCase().replace(/[^a-z0-9]+/g,"-").replace(/^-|-$/g,"")+".ftkey",JSON.stringify(vault,null,2),"application/json");
    download("firmwaretrust-public-key.pem",pem("PUBLIC KEY",spki),"application/x-pem-file");
    $("key-pass").value=""; $("key-pass-confirm").value="";
    show("identity-result",`<h4>Signing identity created</h4><p>Key ID: <code>${vault.key_id}</code></p><p>Algorithm: Ed25519 · Vault encryption: AES-256-GCM · PBKDF2 iterations: ${iterations.toLocaleString()}</p><p>Two files downloaded: encrypted private-key vault (.ftkey) and public key (.pem). Store the vault safely and keep the public key separate for verification.</p>`);
  }catch(e){fail("identity-result",e)}finally{setBusy(btn,false,"Generate encrypted key vault")}
}
async function unlockVault(file,pass){
  let vault; try{vault=JSON.parse(await file.text())}catch{throw new Error("The key vault is not valid JSON.");}
  if(vault.format!=="FirmwareTrust encrypted private-key vault"||vault.version!==1||vault.algorithm!=="Ed25519"||vault.cipher!=="AES-256-GCM"||vault.kdf!=="PBKDF2-SHA-256") throw new Error("Unsupported or invalid FirmwareTrust key vault.");
  if(!Number.isInteger(vault.iterations)||vault.iterations<100000||vault.iterations>2000000) throw new Error("Unsafe or unsupported KDF iteration count.");
  try{
    const aes=await deriveVaultKey(pass,b64ToBytes(vault.salt),vault.iterations);
    const pkcs8=await crypto.subtle.decrypt({name:"AES-GCM",iv:b64ToBytes(vault.iv)},aes,b64ToBytes(vault.ciphertext));
    const privateKey=await crypto.subtle.importKey("pkcs8",pkcs8,{name:"Ed25519"},false,["sign"]);
    return {privateKey,vault};
  }catch{throw new Error("Could not unlock the vault. Check the passphrase and file integrity.");}
}
async function signRelease(){
 const btn=$("sign-release");setBusy(btn,true,"Signing artifact…");
 try{
  const firmware=readFile($("sign-firmware")),vaultFile=readFile($("sign-vault")),pass=$("sign-pass").value;
  if(!pass)throw new Error("Enter the key-vault passphrase.");
  const unlocked=await unlockVault(vaultFile,pass);
  const privateKey=unlocked.privateKey;
  const publicPemFileName="firmwaretrust-public-key.pem";
  // Recover the public key from the PKCS#8 private key through a temporary extractable import.
  const vaultJson=JSON.parse(await vaultFile.text());
  if(!vaultJson.public_key_spki) throw new Error("This vault does not contain its public verification key. Generate a new key vault using the current workbench.");
  const spki=b64ToBytes(vaultJson.public_key_spki);
  const publicKey=await crypto.subtle.importKey("spki",spki,{name:"Ed25519"},true,["verify"]);
  const raw=new Uint8Array(await crypto.subtle.exportKey("raw",publicKey));
  const id=await keyId(raw);
  if(id!==vaultJson.key_id)throw new Error("Vault public key fingerprint does not match its key ID.");
  const challenge=crypto.getRandomValues(new Uint8Array(32));
  const proof=new Uint8Array(await crypto.subtle.sign({name:"Ed25519"},privateKey,challenge));
  if(!await crypto.subtle.verify({name:"Ed25519"},publicKey,proof,challenge))throw new Error("The private key does not match the public key stored in this vault.");
  const fileBytes=new Uint8Array(await firmware.arrayBuffer()), hash=hex(await digest(fileBytes));
  const payload={schema_version:"1.0",artifact:{filename:firmware.name,size_bytes:fileBytes.length,digest_algorithm:"sha256",digest:hash},signature:{algorithm:"Ed25519",key_id:id},created_at:new Date().toISOString().replace(/\.\d{3}Z$/,"Z")};
  const signature=new Uint8Array(await crypto.subtle.sign({name:"Ed25519"},privateKey,enc.encode(canonical(payload))));
  const manifest={...payload,signature:{...payload.signature,value:bytesToB64(signature)}};
  const name=firmware.name+".manifest.json";
  download(name,JSON.stringify(manifest,null,2)+"\n","application/json");
  show("sign-result",`<h4>Release manifest signed</h4><p>Artifact: <b>${escapeHtml(firmware.name)}</b> · ${fileBytes.length.toLocaleString()} bytes</p><p>SHA-256: <code>${hash}</code></p><p>Signer key ID: <code>${id}</code></p><p>Manifest downloaded: <b>${escapeHtml(name)}</b>. Keep it with the exact firmware artifact and distribute the public key through a separate trusted channel.</p>`);
 }catch(e){fail("sign-result",e)}finally{$("sign-pass").value="";setBusy(btn,false,"Create signed release manifest")}
}
async function verifyRelease(){
 const btn=$("verify-release");setBusy(btn,true,"Verifying…");$("tamper-test").disabled=true;
 try{
  const firmware=readFile($("verify-firmware")),manifestFile=readFile($("verify-manifest")),pubFile=readFile($("verify-public"));
  const manifest=JSON.parse(await manifestFile.text()),pubText=await pubFile.text();
  const match=pubText.match(/-----BEGIN PUBLIC KEY-----([\s\S]+?)-----END PUBLIC KEY-----/);
  if(!match)throw new Error("Public key must be a PEM-encoded SubjectPublicKeyInfo file.");
  const spki=b64ToBytes(match[1].replace(/\s/g,""));
  const publicKey=await crypto.subtle.importKey("spki",spki,{name:"Ed25519"},false,["verify"]);
  const raw=new Uint8Array(await crypto.subtle.exportKey("raw",publicKey));
  const id=await keyId(raw);
  if(!manifest||manifest.schema_version!=="1.0"||!manifest.artifact||!manifest.signature||manifest.signature.algorithm!=="Ed25519"||typeof manifest.signature.value!=="string")throw new Error("Manifest schema or signature fields are invalid.");
  if(manifest.signature.key_id!==id)throw new Error("Trust anchor mismatch: the supplied public key does not match the manifest key ID.");
  const fileBytes=new Uint8Array(await firmware.arrayBuffer()), actualHash=hex(await digest(fileBytes));
  if(manifest.artifact.digest_algorithm!=="sha256"||manifest.artifact.digest!==actualHash||manifest.artifact.size_bytes!==fileBytes.length)throw new Error("Artifact integrity FAILED: digest or byte-size mismatch. The selected file is not the signed artifact.");
  const payload=JSON.parse(JSON.stringify(manifest));delete payload.signature.value;
  const signature=b64ToBytes(manifest.signature.value);
  const valid=await crypto.subtle.verify({name:"Ed25519"},publicKey,signature,enc.encode(canonical(payload)));
  if(!valid)throw new Error("Signature verification FAILED: signed manifest data is invalid or has been altered.");
  window.lastVerified={fileBytes,manifest,publicKey};
  $("tamper-test").disabled=false;
  show("verify-result",`<h4>✓ Release verified successfully</h4><p>Signature: <b>VALID</b> · Artifact integrity: <b>MATCH</b> · Trust anchor: <b>MATCH</b></p><p>Artifact: ${escapeHtml(firmware.name)} · ${fileBytes.length.toLocaleString()} bytes</p><p>SHA-256: <code>${actualHash}</code></p><p>Signer key ID: <code>${id}</code></p><p>This verifies the cryptographic relationship between this artifact, manifest and supplied key. It does not certify the firmware as safe or authorize the signer.</p>`);
  $("tamper-result").classList.add("hidden");
 }catch(e){fail("verify-result",e)}finally{setBusy(btn,false,"Verify release")}
}
async function loadDemoRelease(){
 const btn=$("load-demo");setBusy(btn,true,"Preparing sample…");
 try{
  if(!crypto?.subtle)throw new Error("Web Crypto is unavailable in this browser.");
  const pair=await crypto.subtle.generateKey({name:"Ed25519"},true,["sign","verify"]);
  const publicSpki=new Uint8Array(await crypto.subtle.exportKey("spki",pair.publicKey));
  const raw=new Uint8Array(await crypto.subtle.exportKey("raw",pair.publicKey));
  const artifactBytes=enc.encode(`FIRMWARETRUST SAMPLE ARTIFACT
product=demo-controller
version=0.1.0
build=investor-preview
This is synthetic demonstration data, not deployable device firmware.
`);
  const hash=hex(await digest(artifactBytes)), id=await keyId(raw);
  const payload={schema_version:"1.0",artifact:{filename:"firmwaretrust-demo-v0.1.0.bin",size_bytes:artifactBytes.length,digest_algorithm:"sha256",digest:hash},signature:{algorithm:"Ed25519",key_id:id},created_at:new Date().toISOString().replace(/\.\d{3}Z$/,"Z")};
  const signature=new Uint8Array(await crypto.subtle.sign({name:"Ed25519"},pair.privateKey,enc.encode(canonical(payload))));
  const manifest={...payload,signature:{...payload.signature,value:bytesToB64(signature)}};
  const assign=(input,file)=>{const dt=new DataTransfer();dt.items.add(file);input.files=dt.files;};
  assign($("verify-firmware"),new File([artifactBytes],payload.artifact.filename,{type:"application/octet-stream"}));
  assign($("verify-manifest"),new File([JSON.stringify(manifest,null,2)],"firmwaretrust-demo.manifest.json",{type:"application/json"}));
  assign($("verify-public"),new File([pem("PUBLIC KEY",publicSpki)],"firmwaretrust-demo-public.pem",{type:"application/x-pem-file"}));
  $("verify-result").classList.add("hidden");$("tamper-result").classList.add("hidden");$("tamper-test").disabled=true;
  show("verify-result","<h4>Sample release loaded</h4><p>A temporary Ed25519 identity signed a synthetic firmware artifact in memory. No private key was exported or retained. Select <b>Verify release</b> to validate the sample, then run the tamper test.</p>");
 }catch(e){fail("verify-result",e)}finally{setBusy(btn,false,"Load sample release")}
}
async function tamperTest(){
 try{
  if(!window.lastVerified)throw new Error("Verify a release first.");
  const original=window.lastVerified.fileBytes.slice();
  if(!original.length)throw new Error("An empty file cannot be modified for this demonstration.");
  original[0]^=1;
  const changed=hex(await digest(original));
  const expected=window.lastVerified.manifest.artifact.digest;
  const detected=changed!==expected;
  if(!detected)throw new Error("Unexpected result: changed bytes produced the same digest.");
  show("tamper-result",`<h4>✓ Tampering detected</h4><p>A copy of the selected firmware was changed in memory. No file on your device was modified.</p><p>Expected SHA-256: <code>${expected}</code></p><p>Modified SHA-256: <code>${changed}</code></p><p>The digest mismatch means this modified artifact would be rejected before signature acceptance.</p>`);
 }catch(e){fail("tamper-result",e)}
}
document.querySelectorAll(".step-tab").forEach(btn=>btn.addEventListener("click",()=>{
 document.querySelectorAll(".step-tab").forEach(b=>{b.classList.toggle("active",b===btn);b.setAttribute("aria-selected",b===btn?"true":"false")});
 document.querySelectorAll(".panel").forEach(p=>{const active=p.id==="panel-"+btn.dataset.tab;p.hidden=!active;p.classList.toggle("active",active)});
}));
$("generate-key").addEventListener("click",createIdentity);
$("sign-release").addEventListener("click",signRelease);
$("verify-release").addEventListener("click",verifyRelease);
$("tamper-test").addEventListener("click",tamperTest);\n$("load-demo").addEventListener("click",loadDemoRelease);
if(!window.isSecureContext||!crypto?.subtle){$("crypto-support").textContent="Secure Web Crypto is unavailable in this browser/context.";}else{$("crypto-support").textContent="Web Crypto available · Ed25519 support will be checked when you generate a key.";}
