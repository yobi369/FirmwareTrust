function canonical(value: unknown): string {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value && typeof value === "object") {
    const record=value as Record<string,unknown>;
    return "{"+Object.keys(record).sort().map(key=>JSON.stringify(key)+":"+canonical(record[key])).join(",")+"}";
  }
  return JSON.stringify(value)??"null";
}
function toHex(bytes:Uint8Array):string{return Array.from(bytes,b=>b.toString(16).padStart(2,"0")).join("");}
function pemDer(pem:string):ArrayBuffer{
  const match=pem.match(/-----BEGIN PUBLIC KEY-----([\s\S]+?)-----END PUBLIC KEY-----/);
  if(!match)throw new Error("Registered public key PEM is invalid");
  const binary=atob(match[1].replace(/\s/g,""));
  if(binary.length<32||binary.length>512)throw new Error("Registered public key PEM has an invalid size");
  const der=new Uint8Array(binary.length);for(let i=0;i<binary.length;i++)der[i]=binary.charCodeAt(i);
  return der.buffer;
}
export async function verifyEd25519Manifest(manifest:Record<string,unknown>,publicKeyPem:string){
  const signature=manifest.signature as Record<string,unknown>|undefined;
  if(!signature||signature.algorithm!=="Ed25519"||typeof signature.value!=="string")throw new Error("Manifest signature metadata is invalid");
  const payload=JSON.parse(JSON.stringify(manifest)) as Record<string,unknown>;
  delete (payload.signature as Record<string,unknown>).value;
  const signatureBinary=atob(signature.value);
  const signatureBytes=Uint8Array.from(signatureBinary,c=>c.charCodeAt(0));
  if(signatureBytes.length!==64)throw new Error("Ed25519 signatures must be exactly 64 bytes");
  const payloadBytes=new TextEncoder().encode(canonical(payload));
  const publicKey=await crypto.subtle.importKey("spki",pemDer(publicKeyPem),{name:"Ed25519"},false,["verify"]);
  const valid=await crypto.subtle.verify({name:"Ed25519"},publicKey,signatureBytes,payloadBytes);
  const manifestDigest=await crypto.subtle.digest("SHA-256",payloadBytes);
  const signatureDigest=await crypto.subtle.digest("SHA-256",signatureBytes);
  return {valid,manifestSha256:toHex(new Uint8Array(manifestDigest)),signatureSha256:toHex(new Uint8Array(signatureDigest))};
}
