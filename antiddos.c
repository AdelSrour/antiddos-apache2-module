#include "httpd.h"
#include "http_core.h"
#include <netdb.h>
#include <arpa/inet.h>

const char *antiddos_client_data[80];
const char *antiddos_client_token[80];
const char *antiddos_client_token_en[200];
const char *antiddos_remotehost = NULL;
const char *antiddos_remotehost_ip = NULL;
const char *antiddos_challange_cookie = NULL;
const char *antiddos_challange_cookie_screen = NULL;
	  
module AP_MODULE_DECLARE_DATA antiddos_module;

static int ddos_checker(request_rec *r) 
{	   
    if (r->prev == NULL && r->main == NULL) {
		
	  //Allow custom sections
	  if ((apr_table_get(r->headers_in, "User-Agent")) && (strcmp(apr_table_get(r->headers_in, "User-Agent"), "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:53.0) Gecko/20100101 intcheats.com")  == 0)){
		return (DECLINED);
	  }
	  if ((r->useragent_ip) && (strcmp(r->useragent_ip, "173.0.81.1") == 0)){
		return (DECLINED);
	  }
	  if (strcmp(r->uri, "/favicon.ico") == 0){
		return (DECLINED); 
	  }
		
      //Allow search engines
	  antiddos_remotehost = ap_get_remote_host(r->connection, r->per_dir_config, REMOTE_DOUBLE_REV, NULL);
	  if (antiddos_remotehost){
		struct hostent *bothostver;
	    struct in_addr **botaddr_list;
	    bothostver = gethostbyname(antiddos_remotehost);
	    if (bothostver){
		    botaddr_list = (struct in_addr **) bothostver->h_addr_list;
		    antiddos_remotehost_ip = inet_ntoa(*botaddr_list[0]);
	    }	
	  }  
	  if ((antiddos_remotehost) && (antiddos_remotehost_ip) && (strcmp(r->useragent_ip, antiddos_remotehost_ip) == 0)
		  && ((ap_strcasestr(antiddos_remotehost, ".googlebot.com")) 
	      || (ap_strcasestr(antiddos_remotehost, ".google.com"))
		  || (ap_strcasestr(antiddos_remotehost, ".search.msn.com"))
		  || (ap_strcasestr(antiddos_remotehost, ".yandex.net"))
		  || (ap_strcasestr(antiddos_remotehost, ".yandex.com"))
		  || (ap_strcasestr(antiddos_remotehost, ".crawl.baidu.com"))
		  || (ap_strcasestr(antiddos_remotehost, ".crawl"))
		  || (ap_strcasestr(antiddos_remotehost, "bot."))
		  )){
		  return (DECLINED);
	  }	  
	  
	  //Client token
	  snprintf(antiddos_client_data, sizeof antiddos_client_data, "%s%s%s", r->useragent_ip, r->hostname, apr_table_get(r->headers_in, "User-Agent"));
	  apr_md5_encode(antiddos_client_data, "0", &antiddos_client_data, sizeof antiddos_client_data);	
	
      size_t len = strlen(antiddos_client_data);
      if (len > 1){ memmove(antiddos_client_token, antiddos_client_data+1, len-1); }
	  
	  //Read cookie from client
	  ap_cookie_read(r, "_brc", &antiddos_challange_cookie);	
	  ap_cookie_read(r, "_brcx", &antiddos_challange_cookie_screen);
	
	  //Private node
	  if ((antiddos_challange_cookie_screen) && (atoi(antiddos_challange_cookie_screen) > 50) && (strcmp(r->uri, "/cdn-firewall") == 0) && (apr_table_get(r->headers_in, "Content-type"))){
	   if (!antiddos_challange_cookie || strcmp(antiddos_challange_cookie, antiddos_client_token)){
		  ap_set_content_type(r, "text/html");  
		  apr_base64_encode(antiddos_client_token_en, antiddos_client_token, sizeof antiddos_client_token);
		  ap_rprintf(r, "if ((window.innerHeight > 50) && (screen.width > 50)){ var token = \"[ُُِ]ًًِ]%sّّّّّّّّ@!!ٍَََََّّّّّّّّّّّّّّّّّّّّّّّّّّّّّّّّّّّّّّي#ً]ظٍِ]\"; document.cookie = \"_brc=\" + window.atob(token.replace(/[^A-Za-z0-9._+/=]/g, '')).split('\\0')[0] + \"; expires=Thu, 20 Dec 2030 12:00:00 UTC; path=/;\"; location.reload(true); }", antiddos_client_token_en); 
          r->status = 200;
          return DONE;
	   } else {
		  ap_set_content_type(r, "text/html");  
		  apr_base64_encode(antiddos_client_token_en, antiddos_client_token, sizeof antiddos_client_token);
		  ap_rprintf(r, "if ((window.innerHeight > 50) && (screen.width > 50)){ location.reload(true); }"); 
          r->status = 200;
          return DONE;
	   }
	  }
	  
	  //compare the cookie value
	  if ((!antiddos_challange_cookie) || (!antiddos_challange_cookie_screen) || (atoi(antiddos_challange_cookie_screen) < 50) || (strcmp(antiddos_challange_cookie, antiddos_client_token))){
		  ap_set_content_type(r, "text/html");  
		  ap_rprintf(r, "<!DOCTYPE HTML><HTML><HEAD><title>Please wait a moment</title><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,user-scalable=no\"><script>document.cookie = \"_brcx=\" + window.innerHeight + \"; expires=Thu, 20 Dec 2030 12:00:00 UTC; path=/;\";</script><script>function human_check(){var xhttp = new XMLHttpRequest();xhttp.onreadystatechange = function() {if (this.readyState == 4) { eval(this.responseText); }};xhttp.open(\"GET\", \"//%s/cdn-firewall?t=\"+ new Date().getTime(), true);xhttp.setRequestHeader(\"Content-type\", \"application/x-www-form-urlencoded\");xhttp.send();}</script><style>.load-anim-grid {width: 50px;height: 50px;}.load-anim-grid .load-anim {width: 33%;height: 33%;background-color: #333;float: left;-webkit-animation: load-animGridScaleDelay 1.3s infinite ease-in-out;animation: load-animGridScaleDelay 1.3s infinite ease-in-out; }.load-anim-grid .load-anim1 {-webkit-animation-delay: 0.2s;animation-delay: 0.2s; }.load-anim-grid .load-anim2 {-webkit-animation-delay: 0.3s;animation-delay: 0.3s; }.load-anim-grid .load-anim3 {-webkit-animation-delay: 0.4s;animation-delay: 0.4s; }.load-anim-grid .load-anim4 {-webkit-animation-delay: 0.1s;animation-delay: 0.1s; }.load-anim-grid .load-anim5 {-webkit-animation-delay: 0.2s;animation-delay: 0.2s; }.load-anim-grid .load-anim6 {-webkit-animation-delay: 0.3s;animation-delay: 0.3s; }.load-anim-grid .load-anim7 {-webkit-animation-delay: 0s;animation-delay: 0s; }.load-anim-grid .load-anim8 {-webkit-animation-delay: 0.1s;animation-delay: 0.1s; }.load-anim-grid .load-anim9 {-webkit-animation-delay: 0.2s;animation-delay: 0.2s; }@-webkit-keyframes load-animGridScaleDelay {0%, 70%, 100% {-webkit-transform: scale3D(1, 1, 1);transform: scale3D(1, 1, 1);} 35% {-webkit-transform: scale3D(0, 0, 1);transform: scale3D(0, 0, 1); }}@keyframes load-animGridScaleDelay {0%, 70%, 100% {-webkit-transform: scale3D(1, 1, 1);transform: scale3D(1, 1, 1);} 35% {-webkit-transform: scale3D(0, 0, 1);transform: scale3D(0, 0, 1);} }</style></HEAD><BODY style=\"background-color: #F3F3F3;font-family: 'Open Sans', sans-serif;\"><script>setTimeout(function(){ human_check(); }, 5000);</script><div style=\"position: fixed;top: 50%;left: 50%;transform: translate(-50%, -50%);\"><center><div class=\"load-anim-grid\"><div class=\"load-anim load-anim1\"></div><div class=\"load-anim load-anim2\"></div><div class=\"load-anim load-anim3\"></div><div class=\"load-anim load-anim4\"></div><div class=\"load-anim load-anim5\"></div><div class=\"load-anim load-anim6\"></div><div class=\"load-anim load-anim7\"></div><div class=\"load-anim load-anim8\"></div><div class=\"load-anim load-anim9\"></div></div></center></div></BODY></HTML>", r->hostname); 
          r->status = 403;
          return DONE;
	  }
	}
	
	//the client passed the check	
    return OK;
}

static apr_status_t destroy_token_list(void *not_used) {
  free(antiddos_client_data);
  free(antiddos_client_token);
  free(antiddos_client_token_en);
  free(antiddos_remotehost);
  free(antiddos_remotehost_ip);
  free(antiddos_challange_cookie);
  free(antiddos_challange_cookie_screen);
}

static void register_hooks(apr_pool_t *p) {
	ap_hook_access_checker(ddos_checker, NULL, NULL, APR_HOOK_MIDDLE);
	apr_pool_cleanup_register(p, NULL, apr_pool_cleanup_null, destroy_token_list);
}

module AP_MODULE_DECLARE_DATA antiddos_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,            // Per-directory configuration handler
    NULL,            // Merge handler for per-directory configurations
    NULL,            // Per-server configuration handler
    NULL,            // Merge handler for per-server configurations
    NULL,            // Any directives we may have for httpd
    register_hooks   // Our hook registering function
};