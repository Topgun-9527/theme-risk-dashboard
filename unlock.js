'use strict';
let unlockedAssets=null;
const bytes=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const message=document.querySelector('#message');
function openView(view){
  if(!unlockedAssets||!['theme','risk'].includes(view))return;
  const html=new TextDecoder().decode(bytes(unlockedAssets[view+'/index.html']));
  const files=Object.fromEntries(Object.entries(unlockedAssets).filter(([name])=>name.startsWith(view+'/')&&!name.endsWith('.html')));
  const encoded=JSON.stringify(files).replaceAll('<','\\u003c');
  const shim=`<script>const sealedFiles=${encoded};window.fetch=async function(input){const raw=typeof input==='string'?input:input.url;const path=new URL(raw,'https://sealed.invalid/${view}/').pathname.slice(1);if(!Object.hasOwn(sealedFiles,path))throw new Error('Unbundled data request');const data=Uint8Array.from(atob(sealedFiles[path]),c=>c.charCodeAt(0));return new Response(data,{status:200,headers:{'content-type':path.endsWith('.json')?'application/json':'text/csv','cache-control':'no-store'}})};<\/script>`;
  const frame=document.querySelector('#dashboard');frame.srcdoc=html.replace(/<head\b[^>]*>/i,m=>m+shim);frame.style.display='block';
}
document.querySelector('#unlock').addEventListener('submit',async event=>{
  event.preventDefault();message.textContent='正在解密…';
  try{
    const response=await fetch('.sealed/bundle.json',{cache:'no-store'});
    if(!response.ok)throw new Error('bundle_missing');
    const bundle=await response.json();
    if(bundle.schema_version!==1||bundle.kdf.iterations<600000||bundle.cipher.name!=='AES-GCM')throw new Error('format');
    const field=document.querySelector('#password');const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(field.value),'PBKDF2',false,['deriveKey']);field.value='';
    const key=await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:bytes(bundle.kdf.salt),iterations:bundle.kdf.iterations},material,{name:'AES-GCM',length:256},false,['decrypt']);
    const compressed=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(bundle.cipher.iv),tagLength:128,additionalData:new TextEncoder().encode(bundle.cipher.additional_data)},key,bytes(bundle.ciphertext));
    const stream=new Blob([compressed]).stream().pipeThrough(new DecompressionStream('gzip'));unlockedAssets=(await new Response(stream).json()).assets;
    document.querySelector('#unlock').style.display='none';document.querySelector('#views').style.display='flex';message.textContent='已解锁 · '+bundle.public_metadata.run_date;
    openView(new URLSearchParams(location.search).get('view')||'theme');
  }catch(error){message.textContent=error.message==='bundle_missing'?'等待发布首份加密数据。':'无法解锁，请检查口令或稍后重试。';}
});
document.querySelectorAll('[data-view]').forEach(button=>button.addEventListener('click',()=>openView(button.dataset.view)));
document.querySelector('#lock').addEventListener('click',()=>{unlockedAssets=null;location.reload();});
