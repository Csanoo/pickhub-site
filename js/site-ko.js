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
      err.textContent='회사명, 담당자, 이메일, 문의 내용을 입력해 주세요.'; res.classList.remove('on'); return;
    }
    if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(f.email.value.trim())){
      err.textContent='이메일 주소 형식을 확인해 주세요.'; res.classList.remove('on'); return;
    }
    err.textContent='';
    out.textContent='[PICKHUB 문의]\n회사명: '+f.company.value.trim()+'\n담당자: '+f.name.value.trim()+'\n이메일: '+f.email.value.trim()+'\n연락처: '+(f.tel.value.trim()||'-')+'\n문의 분야: '+f.type.value+'\n\n'+f.msg.value.trim();
    res.classList.add('on');
    copy.textContent='내용 복사';
  });
  copy.addEventListener('click',function(){
    try{
      navigator.clipboard.writeText(out.textContent).then(function(){copy.textContent='복사했습니다'},function(){copy.textContent='복사하지 못했습니다. 직접 선택해 복사해 주세요'});
    }catch(e){copy.textContent='복사하지 못했습니다. 직접 선택해 복사해 주세요'}
  });
})();
