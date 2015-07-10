#include "exp1.h"
#include <openssl/ssl.h>/*for HTTPS*/

typedef struct
{
  char cmd[64];
  char path[256];
  char real_path[256];
  char type[64];
  /****basic&Digest*****/
  char date[64];
  char location[256]; /*301での移動先*/
  char WWW_Authenticate[256]; /*認証が必要なことを示す*/
  char req_Authorization[256];
  int auth_code;
  /***********/
  int code;
  int size;
  char param_data[2048];/*FOR POST CGI*/
  int param_len;/*FOR POST CGI*/
} exp1_info_type;

typedef struct 
{
  char A1[256];
  char realm[64];
  char nonce[256];
  char qop[64];
  char nc[64];
  char cnonce[128];
  
  char uri[128];  /*cmd:uriでA2作成*/
  char A2[128];

  char actors[512];
  char response[64];
  
} info_digest;

int exp1_http_session(int sock);
int exp1_parse_header(char* buf, int size, exp1_info_type* info, info_digest* digest);
void exp1_parse_status(char* status, exp1_info_type *pinfo);
void exp1_check_file(exp1_info_type *info);
void exp1_http_reply(int sock, exp1_info_type *info, info_digest *digest);
void exp1_send_404(int sock);
void exp1_send_file(int sock, char* filename ,exp1_info_type *info);
int exp1_tcp_listen(int port);
double gettimeofday_sec();

/************for 3XX,4XX********************/
char* gerRespMsg(int code);
/*************************************/

/************for HTTPS********************/
int exp1_https_session(int sock, SSL *ssl);
void exp1_https_reply(int sock, SSL *ssl, exp1_info_type *info, info_digest *digest);
void exp1_send_file_https(int sock, SSL *ssl, char* filename, exp1_info_type *info);
void exp1_send_404_https(int sock, SSL *ssl);

#define PUBLICKEYFILE "public.key"
#define PRIVATEKEYFILE "private.key"
/*************************************/

/***********FOR POST*****************/
int exp1_parse_post_data(char *buf, exp1_info_type *pinfo);
/***********************************/

/************basic********************/
void basic64(exp1_info_type *info);
void authorization_status_basic(char* status_auth, exp1_info_type *pinfo);
/**************************************/

/************Basic&Digest********************/
void parse_header_authorization2(char* status_auth, char* buf, char* sp);
/*******************************************/

/************Digest********************/
void digest_auth(info_digest *digest,exp1_info_type *info);
void make_md5(info_digest *digest, char* digest_char);
void parse_header_authorization(char* buf, int size, exp1_info_type* info, info_digest *digest);
void authorization_status_digest(char* status_auth, exp1_info_type *info, info_digest *digest);
void make_info_digest(char* status_auth, char* digest_char, const char* key, int n);
/**************************************/

int main(int argc, char **argv) {
  int sock_listen;

  /************for HTTPS********************/
  SSL_CTX* ctx;
  SSL_library_init();
  ctx = SSL_CTX_new( TLSv1_method() );
  /**************************************/

  sock_listen = exp1_tcp_listen(13091);

  while(1){
    struct sockaddr addr;
    int sock_client;
    int len;
    SSL *ssl;/*for HTTPS*/

    sock_client = accept(sock_listen, &addr, (socklen_t*) &len);

    if(argc >=2 && strcmp(argv[1],"https")==0){
      /************for HTTPS********************/
      ssl = SSL_new(ctx);
      SSL_set_fd(ssl,sock_client);
      SSL_use_certificate_file(ssl, PUBLICKEYFILE, SSL_FILETYPE_PEM );
      SSL_use_PrivateKey_file(ssl, PRIVATEKEYFILE, SSL_FILETYPE_PEM );
      SSL_accept(ssl);
      exp1_https_session(sock_client, ssl);/*httpsで通信*/ 
      if(ssl != NULL){
	SSL_shutdown(ssl);
	SSL_free(ssl);  
	ssl = NULL;
      } 
      shutdown(sock_client, SHUT_RDWR);
      close(sock_client);
      /************************************/
    }else{
      exp1_http_session(sock_client);/*httpで通信*/
      shutdown(sock_client, SHUT_RDWR);
      close(sock_client);
    }
  }
}

int exp1_http_session(int sock)
{
  char buf[2048];
  int recv_size = 0;
  exp1_info_type info;
  info_digest digest;
  int ret = 0;

  while(ret == 0){
    int size = recv(sock, buf + recv_size, 2048, 0);
   
    /*write(2,buf + recv_size,size);*//*for debugging*/

    if(size == -1){
      return -1;
    }

    recv_size += size;
    ret = exp1_parse_header(buf, recv_size, &info, &digest);
  
    /*****************************PSOT**********************/
    info.param_len = 0;
    if(strcmp(info.cmd,"POST")==0 || strcmp(info.cmd,"post")==0 ){
      /*リクエストがPOSTである */ 
      if(recv_size < sizeof(buf)){
	buf[recv_size]='\0';
      }else{
	buf[sizeof(buf)-1]='\0';
      }
      info.param_data[0] = '\0';/*初期化*/
      exp1_parse_post_data(buf, &info);
    } 
    /*******************************************************/  
  }
  
  exp1_http_reply(sock, &info, &digest);

  return 0;
}

int exp1_https_session(int sock, SSL* ssl){/*for HTTPS*/

  char buf[2048];
  int recv_size = 0;
  exp1_info_type info;
  info_digest digest;
  int ret = 0;
  double start,now;
  start = gettimeofday_sec();

  while(ret == 0){
    int size = SSL_read(ssl, buf + recv_size, 2048 );

    now = gettimeofday_sec();
    if(size == -1 || now - start > 5.0){/*5秒以上たったら強制終了*/
      return -1;
    }

    /*write(2,buf,size);*/ /*for debugging*/

    recv_size += size;
    ret = exp1_parse_header(buf, recv_size, &info, &digest);
  
    /*****************************PSOT**********************/
    info.param_len = 0;
    if(strcmp(info.cmd,"POST")==0 || strcmp(info.cmd,"post")==0 ){
      /*リクエストがPOSTである */ 
      if(recv_size < sizeof(buf)){
	buf[recv_size]='\0';
      }else{
	buf[sizeof(buf)-1]='\0';
      }
      info.param_data[0] = '\0';/*初期化*/
      exp1_parse_post_data(buf, &info);
    } 
    /*******************************************************/  
  }
  exp1_https_reply(sock, ssl, &info, &digest);

  return 0;
}

int exp1_parse_header(char* buf, int size, exp1_info_type* info, info_digest* digest)
{
  char status[1024];
  int i, j;

  enum state_type
  {
    PARSE_STATUS,
    PARSE_END
  }state;

  state = PARSE_STATUS;
  j = 0;
  for(i = 0; i < size; i++){
    switch(state){
    case PARSE_STATUS:
      if(buf[i] == '\r'){
	status[j] = '\0';
	j = 0;
	state = PARSE_END;
	exp1_parse_status(status, info);
	exp1_check_file(info);
      }else{
	status[j] = buf[i];
	j++;
      }
      break;
    }

    if(state == PARSE_END){
      if(info->code == 401){
        parse_header_authorization(buf,size,info,digest);
      }
      return 1;
    }
  }

  return 0;
}

/*****************************Digest**********************/
void parse_header_authorization(char* buf, int size, exp1_info_type* info, info_digest *digest) 
{ /*リクエストヘッダにあるAuthorizationをstatus_authに格納していく*/

  int i, j;
  char status_auth[512];
  char *sp;

  sp = strstr(buf, "Authorization");/*AuthorizationのAの部分のポインタを返す*/
  if(sp != NULL){
    j = 0; 
    for(i = sp - buf; i < strlen(buf); i++){
      if(buf[i] == '\r'){
        break;
      }
      status_auth[j] = buf[i];
      j++;
    }
  }

  if(info->auth_code == 0) {
    authorization_status_basic(status_auth, info);
  } else if(info->auth_code == 1) {
    authorization_status_digest(status_auth, info, digest);
  }
}

void authorization_status_basic(char* status_auth, exp1_info_type *pinfo)
{ /*Authorizationのidとpathの部分をid_passに格納していく*/
  char id_pass[1024];
  char* pext;
  int i, j, spacecount;
  j = 0;
  spacecount = 0;

  for(i = 0; i < strlen(status_auth); i++){
    if(status_auth[i] == '\n'){
      break;
    }
    if(spacecount == 2) { /*2回目のスペースの後に目的のデータが存在*/
      id_pass[j] = status_auth[i];
      j++;
    }
    if(status_auth[i] == ' '){
      spacecount++;
    }
  }
  strcpy(pinfo->req_Authorization, id_pass);
  basic64(pinfo);
}

void make_info_digest(char* status_auth, char* digest_char, const char* key, int n){
  int i, j;
  char *sp;
  char *status;
  char endkey = '\"';
  if(strcmp(key, "qop=") == 0 || strcmp(key, "nc=") == 0){
    endkey = ',';
  }

  sp = strstr(status_auth, key);
  if(sp != NULL){
    j = 0;
    status = (char *)calloc(1024, sizeof(char));
    if (status_auth == NULL) {
      exit(0);
    } 
    for(i = (sp - status_auth) + n; i < strlen(status_auth); i++){
      if(status_auth[i] == endkey){
        break;
      }
      status[j] = status_auth[i];
      j++;
    }
    strcpy(digest_char, status);
    free(status);
  }
}

void authorization_status_digest(char* status_auth, exp1_info_type *info, info_digest *digest)
{ /*Authorizationのidとpathの部分をid_passに格納していく*/
  char* pext;
  int i, j;
  char *sp;

  make_info_digest(status_auth, digest->realm, "realm=\"", 7);
  make_info_digest(status_auth, digest->nonce, "nonce=\"", 7);
  make_info_digest(status_auth, digest->uri, "uri=\"", 5);
  make_info_digest(status_auth, digest->response, "response=\"", 10);
  make_info_digest(status_auth, digest->qop, "qop=", 4);
  make_info_digest(status_auth, digest->nc, "nc=", 3);
  make_info_digest(status_auth, digest->cnonce, "cnonce=\"", 8);

  digest_auth(digest, info);

}
/*******************************************************/


int exp1_parse_post_data(char *buf, exp1_info_type *pinfo){/*FOR POST*/
  int i;
  
  char content_type_urlenc[] = "Content-Type: application/x-www-form-urlencoded";/*URLエンコードでのアップロード*/
  char content_type_multi[] = "Content-Type: multipart/form-data; boundary=";    /*マルチパートでのエンコード*/
  char content_len_text[] = "Content-Length: ";
  char content_data_before_text[] = "\r\n\r\n";
  char file_name_before_text[] ="filename=\"";  /*ファイル名の直前にある文字列*/
  char data_name_before_text[] = "name=\"";     /*データのnameの直前にある文字列*/

  FILE *upload_fp;
  char boundary[1024];/*マルチパートでのPOSTデータの境界文字列*/
  char filename[1024];/*アップロードされたファイル名*/
  char dataname[1024];/*アップロードされたデータのname*/

  enum state_type
  {
    PARSE_TYPE,            /*URLエンコードかマルチパートかを判断*/
    PARSE_LEN,             /*URLエンコードならば文字列の長さを取り出す*/
    PARSE_STRING_DATA,     /*URLエンコードならばデータを取り出す*/
    PARSE_DATA_NAME,       /*マルチパートならばデータのデータのnameを取り出す*/
    PARSE_FILE_NAME,       /*マルチパートならばファイル名を探す(文字列アップロードならばない)*/
    PARSE_FILE_DATA,       /*マルチパートならファイルのデータを取り出す*/
    PARSE_DATA,            /*マルチパートで文字列のアップロードなら文字列を取り出す*/
    PARSE_END
  }state;

  state = PARSE_TYPE;

  for(i = 0; i < strlen(buf); i++){
    switch(state){
    case PARSE_TYPE:
      if(strncmp(buf+i, content_type_urlenc, strlen(content_type_urlenc))==0){
	i += strlen(content_type_urlenc);
	state = PARSE_LEN;
      }else if(strncmp(buf+i,  content_type_multi, strlen(content_type_multi)) ==0){
	int j=0;
	i += strlen(content_type_multi);

	boundary[0] = '-';/*最初に--を追加しておく*/
	boundary[1] = '-';
	for(j=2; buf[i]!='\r';j++,i++){
	  boundary[j] = buf[i];
	}
	boundary[j] = '\0';

	i--;
	state = PARSE_DATA_NAME;
      }
      break;
    case PARSE_LEN:
      if(strncmp(buf+i, content_len_text, strlen(content_len_text))==0){
	int j;
	char len_str[10];
	i += strlen(content_len_text);
	for(j=0; buf[i]!='\r';j++,i++){
	  len_str[j] = buf[i];
	}
	len_str[j] = '\0';
	pinfo->param_len = atoi(len_str);
	i--;
	state = PARSE_STRING_DATA;
      }
      break;
    case PARSE_STRING_DATA:
      if(strncmp(buf+i, content_data_before_text, strlen(content_data_before_text))==0){
	int j;

	i += strlen(content_data_before_text);

	for(j=0; j<pinfo->param_len; j++){
	  pinfo->param_data[j] = buf[i+j];
	}
	pinfo->param_data[j] = '\0';
	i--;
	state = PARSE_END;
      }
      break;
    case PARSE_DATA_NAME:
      if(strncmp(buf+i, data_name_before_text, strlen(data_name_before_text))==0){
	int j;

	i += strlen(data_name_before_text);
	for(j=0;buf[i]!='"';i++,j++){
	  dataname[j] = buf[i];
	}
	dataname[j] = '\0';

	if(buf[i+1] ==';'){
	  /*filenameが存在するのでファイルアップロードである*/
	  state = PARSE_FILE_NAME;
	}else{
	  /*filenameが存在しないので文字列のアップロードである*/
	  state = PARSE_DATA;
	}
      }
      break;
    case PARSE_FILE_NAME:
      if(strncmp(buf+i, file_name_before_text, strlen(file_name_before_text))==0){
	int j;

	usleep(10);  /*一定時間待って同じファイル名が生成されるのを防止*/
	sprintf(filename,"./upload/%lf_", gettimeofday_sec());/*ファイル名に時刻を付加して、重複を防止*/

	j=strlen(filename);
	i += strlen(file_name_before_text);
	for(;buf[i]!='"';j++,i++){
	  filename[j] = buf[i];
	}
	filename[j] = '\0';
	i--;
	state = PARSE_FILE_DATA;
      }
      break;
    case PARSE_FILE_DATA:
      if(strncmp(buf+i, content_data_before_text, strlen(content_data_before_text))==0){
	int j;
	char filename_tmp[1024];
	char *real_filename;
	char data[2048];
	strcpy(filename_tmp,filename);
	real_filename = strstr(filename_tmp,"_");/*時間を付加していない実際のファイル名部分のポインタ取得*/

	i += strlen(content_data_before_text);
	for(j=0; j<sizeof(data)-1 && strncmp(buf+i,boundary,strlen(boundary))!=0; j++,i++){/*ファイル内容取り出し*/
	  data[j] = buf[i];
	}
	data[j] = '\0';
	i+=strlen(boundary);

	if(strlen(real_filename) > 1){/*実際のファイル名がない場合アップロードさせない*/
	  /*ファイル書き込み*/
	  upload_fp = fopen(filename,"w");
	  if(upload_fp==NULL){
	    printf("file open error\n");
	    exit(1);
	  }
	  for(j=0;data[j] != '\0';j++){
	    fputc(data[j],upload_fp);
	  }
	  fclose(upload_fp);
	}
	
	if(strncmp(buf+i,"--",2)==0){/*終了*/
	  state = PARSE_END;
	}else{/*次のファイルへ*/
	  state = PARSE_DATA_NAME;
	}
      }
      break;
    case PARSE_DATA:
      if(strncmp(buf+i, content_data_before_text, strlen(content_data_before_text))==0){
	int j;
	char data[2048];
	
	i+=strlen(content_data_before_text);
	for(j=0; j<sizeof(data)-1 && strncmp(buf+i,boundary,strlen(boundary))!=0 && buf[i]!='\r'; j++,i++){/*ファイル内容取り出し*/
	  data[j] = buf[i];
	}
	data[j] = '\0';
	i+=strlen(boundary);
	
	if(strlen(pinfo->param_data)<=0){/*これまでにデータが格納されていない*/
	  sprintf(pinfo->param_data,"%s=%s",dataname,data);
	}else{/*すでにデータが一部格納されている*/
	  sprintf(pinfo->param_data,"%s&%s=%s",pinfo->param_data,dataname,data);
	}
	pinfo->param_len = strlen(pinfo->param_data);

	if(strncmp(buf+i,"--",2)==0){/*終了*/
	  state = PARSE_END;
	}else{/*次のファイルへ*/
	  state = PARSE_DATA_NAME;
	}
      }
      break;
    }
    if(state == PARSE_END){
      return 1;
    }
  }
  return 0;
}

void exp1_parse_status(char* status, exp1_info_type *pinfo)
{
  char cmd[1024];
  char path[1024];
  char* pext;
  int i, j;

  enum state_type
  {
    SEARCH_CMD,
    SEARCH_PATH,
    SEARCH_END
  }state;

  state = SEARCH_CMD;
  j = 0;
  for(i = 0; i < strlen(status); i++){
    switch(state){
    case SEARCH_CMD:
      if(status[i] == ' '){
	cmd[j] = '\0';
	j = 0;
	state = SEARCH_PATH;
      }else{
	cmd[j] = status[i];
	j++;
      }
      break;
    case SEARCH_PATH:
      if(status[i] == ' '){
	path[j] = '\0';
	j = 0;
	state = SEARCH_END;
      }else{
	path[j] = status[i];
	j++;
      }
      break;
    }
  }
  strcpy(pinfo->cmd, cmd);
  strcpy(pinfo->path, path);
}

void exp1_check_file(exp1_info_type *info)
{
  struct stat s;
  int ret,ret2;
  char* pext;

  sprintf(info->real_path, "html%s", info->path);
  ret = stat(info->real_path, &s);

  if((s.st_mode & S_IFMT) == S_IFDIR){
    sprintf(info->real_path, "%s/index.html", info->real_path);
  }

  ret = stat(info->real_path, &s);
  ret2 = access(info->real_path, R_OK);

  if(ret == -1){
    info->code = 404;
  }else if (strcmp(info->real_path, "html/301a.html") == 0){
    strcpy(info->location, "/301b.html"); /*遷移先URL設定*/
    info->code = 301; 
  }else if (strcmp(info->real_path, "html/302a.html") == 0){
    strcpy(info->location, "/302b.html"); /*遷移先URL設定*/
    info->code = 302; 
  }else if (strcmp(info->real_path, "html/showname303.php") == 0){
    strcpy(info->location, "/303b.html"); /*遷移先URL設定*/
    info->code = 303;
  }else if (strcmp(info->real_path, "html/307a.html") == 0){
    strcpy(info->location, "/307b.html"); /*遷移先URL設定*/
    info->code = 307;
  }else if(strcmp(info->real_path, "html/secretb.html") == 0){
    strcpy(info->WWW_Authenticate, "Basic realm =\"secret file\"");
    info->auth_code = 0;
    info->code = 401;
  }else if(strcmp(info->real_path, "html/secretd.html") == 0){
    strcpy(info->WWW_Authenticate, "Digest realm =\"secret file\", nonce=\"RMH1usDrAwA=6dc290ea3304de42a7347e0a94089ff5912ce0de\", algorithm=MD5, qop=\"auth\"");
    info->auth_code = 1;
    info->code = 401;
  }else if(ret2 == -1){
    /*ファイルの読み取り権限が無い場合403にする。*/
    info->code = 403;
  }else if (strcmp(info->real_path, "html/teapot.html") == 0){
    info->code = 418;
  }else{
    info->code = 200;
    info->size = (int) s.st_size;
  }

  pext = strstr(info->path, ".");
  if(pext != NULL && strcmp(pext, ".html") == 0){
    strcpy(info->type, "text/html");
  }else if(pext != NULL && strcmp(pext, ".jpg") == 0){
    strcpy(info->type, "image/jpeg");
  }else if(pext != NULL && strcmp(pext, ".avi") == 0){
    strcpy(info->type, "video/avi");
  }else if(pext != NULL && strcmp(pext, ".mp4") == 0){
    strcpy(info->type, "video/mp4");
  } else if(pext != NULL && strcmp(pext,".php") == 0) {
    strcpy(info->type,"text/html");
  }else if(pext == NULL ){/*CGI*/
    strcpy(info->type, "text/html");
  }
}

/** ステータスコードからメッセージを取得 */
char* getRespMsg (int code) {
  switch (code) {
    /*1XX: Informational (情報)*/

    /*3XX: Redirection (転送)*/
  case 200: return "OK";    break;
  case 300: return "Multiple Choices";    break;  
  case 301: return "Moved Permanently";   break;  
  case 302: return "Found";   break;  
  case 303: return "See Other";   break; 
  case 307: return "Temporary Redirect";    break;

    /*4XX: Client Error (クライアントエラー)*/
  case 401: return "Authorization Required";    break;
  case 403: return "Forbidden";   break;
  case 404: return "Not Found";   break; /*要求したリソースが見つからなかった*/
  case 418: return "I'm a teapot"; break; /*よくわからん*/
  }
}

void exp1_http_reply(int sock, exp1_info_type *info, info_digest *digest)
{
  char buf[16384];
  int len;
  int ret;
  time_t timer;
  struct tm *date;

  if(info->code == 401){
    if(info->auth_code == 0){
      if(strcmp(info->req_Authorization, "secret:pass") == 0){
        info->code = 200;
      }else{
      	strcpy(info->path, "/401.html");
        sprintf(info->real_path, "html%s", info->path);
      }
    }else if (info->auth_code == 1 && digest->actors != NULL){
      if(strcmp(digest->response, digest->actors) == 0){
        info->code = 200;
      }else{
      	strcpy(info->path, "/401.html");
        sprintf(info->real_path, "html%s", info->path);
      }
    }
  }else if(info->code == 403){
    strcpy(info->path, "/403.html");
    sprintf(info->real_path, "html%s", info->path);
  }else if(info->code == 404){
    exp1_send_404(sock);
    printf("404 not found %s\n", info->path);
    return;
  }

  timer = time(NULL);
  date = localtime(&timer);
  strcpy(info->date, asctime(date));
 
  len = sprintf(buf, "HTTP/1.0 %d %s\r\n",info->code,getRespMsg(info->code));
  len += sprintf(buf + len, "Content-Length: %d\r\n", info->size);
  len += sprintf(buf + len, "Content-Type: %s\r\n", info->type);
  len += sprintf(buf + len, "Date: %s\r\r\n", info->date);
  if(info->code == 301 || info->code == 302 || info->code == 303 || info->code == 307) {
    len += sprintf(buf + len, "Location: %s\r\n", info->location);
  }
  if(info->code == 401) {
    len += sprintf(buf + len, "WWW-Authenticate: %s\r\n", info->WWW_Authenticate);
  }
  len += sprintf(buf + len, "\r\n");
 
  ret = send(sock, buf, len, 0); /*レスポンスコード送信*/

  if(ret < 0){
    shutdown(sock, SHUT_RDWR);
    close(sock);
    return;
  }

  exp1_send_file(sock, info->real_path,info);
}

void  exp1_https_reply(int sock, SSL *ssl, exp1_info_type *info, info_digest *digest)/*for HTTPS*/
{
  char buf[16384];
  int len;
  int ret;
  time_t timer;
  struct tm *date;

  if(info->code == 401){
    if(info->auth_code == 0){
      if(strcmp(info->req_Authorization, "secret:pass") == 0){
        info->code = 200;
      }
    }else if (info->auth_code == 1 && digest->actors != NULL){
      if(strcmp(digest->response, digest->actors) == 0){
        info->code = 200;
      }
    }else{
      strcpy(info->path, "/401.html");
      sprintf(info->real_path, "html%s", info->path);
    }
  }else if(info->code == 403){
    strcpy(info->path, "/403.html");
    sprintf(info->real_path, "html%s", info->path);
  }else if(info->code == 404){
    exp1_send_404(sock);
    printf("404 not found %s\n", info->path);
    return;
  }

  timer = time(NULL);
  date = localtime(&timer);
  strcpy(info->date, asctime(date));
 
  len = sprintf(buf, "HTTP/1.0 %d %s\r\n",info->code,getRespMsg(info->code));
  len += sprintf(buf + len, "Content-Length: %d\r\n", info->size);
  len += sprintf(buf + len, "Content-Type: %s\r\n", info->type);
  len += sprintf(buf + len, "Date: %s\r\r\n", info->date);
  if(info->code == 301 || info->code == 302 || info->code == 303 || info->code == 307) {
    len += sprintf(buf + len, "Location: %s\r\n", info->location);
  }
  if(info->code == 401) {
    len += sprintf(buf + len, "WWW-Authenticate: %s\r\n", info->WWW_Authenticate);
  }
  len += sprintf(buf + len, "\r\n");
 
  ret = SSL_write(ssl, buf, len); /*レスポンスコード送信*/

  if(ret < 0){
    if(ssl != NULL){
      SSL_shutdown(ssl);
      SSL_free(ssl);
      ssl = NULL;
    }
    shutdown(sock, SHUT_RDWR);
    close(sock);
    return;
  }

  exp1_send_file_https(sock,ssl,info->real_path,info);
}

/************Basic********************/
void basic64(exp1_info_type *info)
{
  char template[] = "/tmp/fileXXXXXX";
  int fd;
  FILE *fp;
  char cmd[1024];
  char id_pass[256];
 
  fd = mkstemp(template);

  if ((fp = fdopen(fd, "r")) == NULL){
    exit(1);
  }

  sprintf(cmd, "echo %s | base64 -d > %s", info->req_Authorization, template);
  system(cmd); 
  fgets(id_pass, 256, fp);  /*id_passにid:passの形でデータが入る*/

  strcpy(info->req_Authorization, id_pass); /*デコードされたidとpassが入る*/

  fclose(fp);
  remove(template);
}
/**************************************/

/************Digest********************/
void digest_auth(info_digest *digest, exp1_info_type *info)
{
  int fd;
  FILE *fp;

  if ((fp = fopen("digestpass.txt", "r")) == NULL){
    exit(1);
  } 
  
  fgets(digest->A1, 256, fp);
  fclose(fp);

  sprintf(digest->A2, "%s:%s", info->cmd, digest->uri);
  make_md5(digest, digest->A2);

  sprintf(digest->actors, "%s:%s:%s:%s:%s:%s", digest->A1, digest->nonce, digest->nc, digest->cnonce, digest->qop, digest->A2);
  make_md5(digest, digest->actors);
  /*digest->actorの値とdigest->responseの値が同じなら認証成功*/
}

void make_md5(info_digest *digest, char* digest_char)
{
  char template[] = "/tmp/fileXXXXXX";
  int fd;
  FILE *fp;
  char cmd[1024];

  fd = mkstemp(template);
  if ((fp = fdopen(fd, "r")) == NULL){
    exit(1);
  }
  sprintf(cmd, "printf '%s' | md5sum > %s", digest_char, template);
  system(cmd);
  fscanf(fp, "%s", digest_char);
  fclose(fp);
  remove(template); 

}
/***********************************/

void exp1_send_404(int sock)
{
  char buf[16384];
  int ret;

  sprintf(buf, "HTTP/1.0 404 Not Found\r\n\r\n");
 
  ret = send(sock, buf, strlen(buf), 0);

  if(ret < 0){
    shutdown(sock, SHUT_RDWR);
    close(sock);
  }
}

void exp1_send_404_https(int sock,SSL *ssl)
{
  char buf[16384];
  int ret;

  sprintf(buf, "HTTP/1.0 404 Not Found\r\n\r\n");

  /*ret = send(sock, buf, strlen(buf), 0);*/
  ret = SSL_write(ssl,buf,strlen(buf));

  if(ret < 0){
    if(ssl != NULL){
      SSL_shutdown(ssl);
      SSL_free(ssl);
      ssl = NULL;
    }
    shutdown(sock, SHUT_RDWR);
    close(sock);
  }
}

void exp1_send_file(int sock, char* filename,exp1_info_type *info)
{
  FILE *fp;
  int len;
  char buf[16384];
  char command[128];/*for CGI 実行するコマンド*/
  /* char env_variable[128];/\*for CGI 環境変数設定用文字列*\/ */
  char *pext;/*for CGI*/

  pext = strstr(filename, ".");
  /************for CGI**************************/
  if(pext == NULL){/*要求がCGI(C)*/
    if(info->param_len > 0){/*POSTパラメータあり*/
      sprintf(command,"echo \"%s\" | ./%s", info->param_data, filename);
    }else{
      sprintf(command,"./%s", filename);
    }
    fp = popen(command,"r");
  } else if(pext != NULL && strcmp(pext,".php") == 0){/*要求がCGI(PHP)*/
    if(info->param_len > 0){/*POSTパラメータあり*/
      sprintf(command,"echo \"%s\" | php %s", info->param_data, filename);
    }else{
      sprintf(command,"php %s",filename);
    }
    fp = popen(command,"r");
  }else{
    fp = fopen(filename, "r");/*CGI以外のファイルだったら普通に開く*/ 
  }
  /**********************************************/

  if(fp == NULL){
    shutdown(sock, SHUT_RDWR);
    close(sock);
    return;
  }

  len = fread(buf, sizeof(char), 16384, fp);
  while(len > 0){
    int ret = send(sock, buf, len, 0);
    if(ret < 0){
      shutdown(sock, SHUT_RDWR);
      close(sock);
      break;
    }
    len = fread(buf, sizeof(char), 1460, fp);
  
  }

  fclose(fp);
}

void exp1_send_file_https(int sock, SSL *ssl, char* filename,exp1_info_type *info)/*for HTTPS*/
{
  FILE *fp;
  int len;
  char buf[16384];
  char *pext;/*CGI*/
  char command[128];
  /* char env_variable[128];/\*環境変数設定用文字列*\/ */

  pext = strstr(filename, ".");
  if(pext == NULL){/*要求がCGI(C)*/
    if(info->param_len > 0){
      sprintf(command,"echo \"%s\" | ./%s", info->param_data, filename);
    }else{
      sprintf(command,"./%s", filename);
    }
    fp = popen(command,"r");
  } else if(pext != NULL && strcmp(pext,".php") == 0){/*要求がCGI(PHP)*/
    if(info->param_len > 0){/*POSTパラメータあり*/
      sprintf(command,"echo \"%s\" | php %s", info->param_data, filename);
    }else{
      sprintf(command,"php %s",filename);
    }
    fp = popen(command,"r");
  }else{
    fp = fopen(filename, "r");    
  }
  
  if(fp == NULL){
    if(ssl != NULL){
      SSL_shutdown(ssl);
      SSL_free(ssl);
      ssl = NULL;
    }
    shutdown(sock, SHUT_RDWR);
    close(sock);
    return;
  }

  len = fread(buf, sizeof(char), 16384, fp);
  while(len > 0){
    int ret = SSL_write(ssl, buf, len);
    if(ret < 0){
      if(ssl != NULL){
	SSL_shutdown(ssl);
	SSL_free(ssl);
	ssl = NULL;
      }
      shutdown(sock, SHUT_RDWR);
      close(sock);
      break;
    }
    len = fread(buf, sizeof(char), 1460, fp);
  }
 
  fclose(fp);
}

int exp1_tcp_listen(int port)
{
  int sock;
  struct sockaddr_in addr;
  const int yes = 1;
  int ret;

  sock = socket(PF_INET, SOCK_STREAM, 0);
  if(sock < 0) {
    perror("socket");
    exit(1);
  }

  bzero((char *) &addr, sizeof(addr));
  addr.sin_family = PF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(port);
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

  ret =  bind(sock, (struct sockaddr *)&addr, sizeof(addr));
  if(ret < 0) {
    perror("bind");
    exit(1);
  }

  ret = listen(sock, 5);
  if(ret < 0) {
    perror("reader: listen");
    close(sock);
    exit(-1);
  }

  return sock;
}

double gettimeofday_sec(){
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec + tv.tv_usec * 1e-6;
}
