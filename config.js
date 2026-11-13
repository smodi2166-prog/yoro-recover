window.RC = {
  url: "https://pglxotjvbcklzswziggs.supabase.co",
  key: "sb_publishable_rN-7pM93dxKoAn5RCFgbiQ_gnUJlL0j", // publishable key: safe to be public; data is protected by database rules
  contact: "care@yorohealth.com"
};
window.rcClient = function(){ return window.supabase.createClient(RC.url, RC.key); };
window.esc = function(s){ return String(s==null?"":s).replace(/[&<>"']/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];}); };
