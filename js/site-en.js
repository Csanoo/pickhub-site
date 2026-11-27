(function(){
  document.documentElement.classList.add('js');
  var views=['home','about','services','process','contact'];
  function show(){
    var h=(location.hash||'').replace('#','');
    if(views.indexOf(h)<0) h='home';
    document.querySelectorAll('[data-view]').forEach(function(v){v.classList.toggle('on',v.getAttribute('data-view')===h)});
    document.querySelectorAll('[data-nav]').forEach(function(a){
      if(a.getAttribute('data-nav')===h) a.setAttribute('aria-current','page'); else a.removeAttribute('aria-current');
    });
    window.scrollTo(0,0);
  }
  window.addEventListener('hashchange',show);
  show();

  var units=document.querySelectorAll('.unit'),t=document.getElementById('rackT'),d=document.getElementById('rackD');
  units.forEach(function(u){u.addEventListener('click',function(){
    units.forEach(function(x){x.setAttribute('aria-pressed','false')});
    u.setAttribute('aria-pressed','true');
    t.textContent=u.getAttribute('data-t'); d.textContent=u.getAttribute('data-d');
  })});

  var form=document.getElementById('inq'),err=document.getElementById('f-err'),res=document.getElementById('result'),out=document.getElementById('resultText'),copy=document.getElementById('copyBtn');
  form.addEventListener('submit',function(e){
    e.preventDefault();
    var f=form.elements;
    if(!f.company.value.trim()||!f.name.value.trim()||!f.email.value.trim()||!f.msg.value.trim()){
      err.textContent='Please fill in company, name, email, and message.'; res.classList.remove('on'); return;
    }
    if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(f.email.value.trim())){
      err.textContent='Please check the email address.'; res.classList.remove('on'); return;
    }
    err.textContent='';
    out.textContent='[PICKHUB inquiry]\nCompany: '+f.company.value.trim()+'\nName: '+f.name.value.trim()+'\nEmail: '+f.email.value.trim()+'\nPhone: '+(f.tel.value.trim()||'-')+'\nService: '+f.type.value+'\n\n'+f.msg.value.trim();
    res.classList.add('on');
    copy.textContent='Copy text';
  });
  copy.addEventListener('click',function(){
    try{
      navigator.clipboard.writeText(out.textContent).then(function(){copy.textContent='Copied'},function(){copy.textContent='Could not copy. Please select the text and copy it manually.'});
    }catch(e){copy.textContent='Could not copy. Please select the text and copy it manually.'}
  });
})();
