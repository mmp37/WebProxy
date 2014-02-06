/* this is not a working program yet, but should help you get started */
//@Author: Matthew Parides

#include <stdio.h>
#include "csapp.h"
#include "proxy.h"
#include <pthread.h>

#define   LOG_FILE      "proxy.log"
#define   DEBUG_FILE	"proxy.debug"

/*============================================================
 * function declarations
 *============================================================*/

int  find_target_address(char * uri,
			 char * target_address,
			 char * path,
			 int  * port);


void  format_log_entry(char * logstring,
		       int sock,
		       char * uri,
		       int size);
		       
void *webTalk(void* args);
void *secureTalk(int clientfd, rio_t client, char* host, char* version, int serverPort);
void ignore();

int debug;
int proxyPort;
int debugfd;
int logfd;
pthread_mutex_t mutex;

/* main function for the proxy program */

int main(int argc, char *argv[])
{
  int count = 0;
  int listenfd, connfd, clientlen, optval, serverPort, i;
  struct sockaddr_in clientaddr;
  struct hostent *hp;
  char *haddrp;
  sigset_t sig_pipe; 
  pthread_t tid;
  int *args;
  
  if (argc < 2) {
    printf("Usage: ./%s port [debug] [serverport]\n", argv[0]);
    exit(1);
  }

  proxyPort = atoi(argv[1]);

  /* turn on debugging if user enters a 1 for the debug argument */

  if(argc > 2)
    debug = atoi(argv[2]);
  else
    debug = 0;

  if(argc == 4)
    serverPort = atoi(argv[3]);
  else
    serverPort = 80;

  /* deal with SIGPIPE */

  Signal(SIGPIPE, ignore);
  
  if(sigemptyset(&sig_pipe) || sigaddset(&sig_pipe, SIGPIPE))
    unix_error("creating sig_pipe set failed");

  if(sigprocmask(SIG_BLOCK, &sig_pipe, NULL) == -1)
    unix_error("sigprocmask failed");

  /* important to use SO_REUSEADDR or can't restart proxy quickly */

  listenfd = Open_listenfd(proxyPort);
  optval = 1;
  setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void*)&optval, sizeof(int)); 
  
  if(debug) debugfd = Open(DEBUG_FILE, O_CREAT | O_TRUNC | O_WRONLY, 0666);

  logfd = Open(LOG_FILE, O_CREAT | O_TRUNC | O_WRONLY, 0666);    
  
  /* protect log file with a mutex */

  Pthread_mutex_init(&mutex, NULL);
  

  /* not wait for new requests from browsers */

  while(1) {
    clientlen = sizeof(clientaddr);

    connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen);
    printf("connfd: %d listenfd: %d\n", connfd, listenfd);
    
    hp = Gethostbyaddr((const char *)&clientaddr.sin_addr.s_addr,
		       sizeof(clientaddr.sin_addr.s_addr), AF_INET);

    haddrp = inet_ntoa(clientaddr.sin_addr);
    args = malloc(2*sizeof(int));
    args[0] = connfd; args[1] = serverPort;

    /* spawn a thread to process the new connection */
    Pthread_create(&tid, NULL, webTalk, (void*) args);
    Pthread_detach(tid);
  }


  /* should never get here, but if we do, clean up */

  Close(logfd);  
  if(debug) Close(debugfd);

  pthread_mutex_destroy(&mutex);
  
}

void parseAddress(char* url, char* host, char** file, int* serverPort)
{
	char buf[MAXLINE];
	char* point1, *point2;
	char *saveptr;

	if(strstr(url, "http://"))
		url = &(url[7]);
	*file = strchr(url, '/');
	
	strcpy(buf, url);
	point1 = strchr(url, ':');
	strcpy(host, url);
	strtok_r(host, ":/", &saveptr);

	if(!point1) {
		*serverPort = 80;
		return;
	}
	*serverPort = atoi(strtok_r(NULL, ":/", &saveptr));
}


/* WebTalk()
 *
 * Once a connection has been established, webTalk handles
 * the communication.
 */


/* this function is not complete */
/* you'll do the bulk of your work here */

void *webTalk(void* args)
{
	//pthread_mutex_lock(&mutex);
	int numBytes, lineNum, serverfd, clientfd, serverPort;
	int tries = 0;
	int byteCount = 0;
	char buf1[MAXLINE], buf2[MAXLINE], buf3[MAXLINE], buf4[MAXLINE];
	char url[MAXLINE], logString[MAXLINE], host[MAXLINE];
	char *token, *cmd, *version, *file;
	rio_t server, client;
	char slash[10];
	strcpy(slash, "/");
	char *saveptr;
	char ip[100];
	char* buf5[MAXLINE];
	char* line[10000];
	void* ret = (void*)malloc (16);


	clientfd = ((int*)args)[0];
	serverPort = ((int*)args)[1];
	free(args);

	Rio_readinitb(&client, clientfd);
	
	/* Determine whether request is GET or CONNECT */


	numBytes = Rio_readlineb(&client, buf1, MAXLINE);
	char request[sizeof(buf1)];
	strcpy(request, buf1);
	if(strlen(buf1)>0 && !strstr(buf1, "127.0.0.1")) { //was getting some odd requests to localhost that were breaking the proxy
		//printf("request1: %s\n", request);
		cmd = strtok_r(buf1, " \r\n", &saveptr);
		strcpy(url, strtok_r(NULL, " \r\n", &saveptr));


		parseAddress(url, host, &file, &serverPort); // ) {
		if(!file) file = slash;
			if(debug) 
			{	sprintf(buf3, "%s %s %i\n", host, file, serverPort); 
				Write(debugfd, buf3, strlen(buf3));}

		if(!strcmp(cmd, "CONNECT")) {
			secureTalk(clientfd, client, host, version, serverPort);
			return ret; 
		}
		else if(strcmp(cmd, "GET")) {
			if (debug) printf("%s",cmd);
			return ret;
			//app_error("Not GET or CONNECT");
		}


		if(serverPort == 0)
			serverPort = 80;
		while(tries < 3) {
			serverfd = open_clientfd(host, serverPort);
			if(serverfd >= 0) {
				//pthread_mutex_unlock(&mutex);
				//printf("TRY:%d\n", tries);
				FILE* sockwfp = Fdopen(serverfd, "w");
				Fputs(request, sockwfp);
				char* conClose = "Connection: close\r\n";
				while(numBytes = Rio_readlineb(&client, buf1, MAXLINE)) {
					//printf("numbytes: %d\n", numBytes);
					//printf("buf1: %s\n", buf1);
					if(numBytes == 2) {
						Fputs(buf1, sockwfp);
						fflush(sockwfp);
						
						break;
					}
					else if(strstr(buf1, "Connection:"))
					{
						Fputs(conClose, sockwfp);
						continue;
					}
					else {
						Fputs(buf1, sockwfp);
					}
				}

				int numServBytes;
				while (1) {
					//if(errno == EINTR)
					//	continue;

					numServBytes = rio_readp(serverfd, buf4, MAXLINE);
					if(numServBytes<= 0 || errno == 54)
						break;
					rio_writen(clientfd, buf4, numServBytes);
					printf("buffer: %s\n", buf4);
					//printf("numservbytes: %d\n", numServBytes);
				}
				shutdown(clientfd, 1);
				//shutdown(serverfd, 1);

				/* you should insert your code for processing connections here */

			        /* code below writes a log entry at the end of processing the connection */

				pthread_mutex_lock(&mutex);
				
				format_log_entry(logString, serverfd, url, byteCount);
				Write(logfd, logString, strlen(logString));
				
				pthread_mutex_unlock(&mutex);
				
				/* 
				When EOF is detected while reading from the server socket,
				send EOF to the client socket by calling shutdown(clientfd,1);
				(and vice versa) 
				*/
				fclose(sockwfp);	
				Close(clientfd);
				close(serverfd);
				return ret;
			}
			else if(errno == ETIMEDOUT || errno == ECONNREFUSED) {
				tries++;
				//printf("TRY:%d\n", tries);
				continue;
			}
			else {
				return ret;
			}
		}
	}
	return ret;
}

void serverRead(void* args) {
	int numServBytes, clientfd, serverfd;
	char buf4[MAXLINE];
	clientfd = ((int*)args)[0];
	serverfd = ((int*)args)[1];
	free(args);
	numServBytes=1;
	
	while(1) {
		//if(errno == EINTR) {
		//	continue;
		//}
		if(fcntl(serverfd,F_GETFD)!=-1 && errno == 0) {
			if((numServBytes = rio_readp(serverfd, buf4, MAXLINE)) < 0)
				if(errno != EPIPE && errno != 0)
					break;
		}
		else
			break;
		if(fcntl(clientfd,F_GETFD)!=-1 && errno == 0) {
			//printf("numbytesserv:%d//sfd:%d//cfd:%d\n ", numServBytes, serverfd, clientfd);
			if(numServBytes <= 0) {
				rio_writen(clientfd, "\r\n\r\n", strlen("\r\n\r\n"));
				break;
			}
			rio_writen(clientfd, buf4, numServBytes);
		}
		else
			break;
	}
	Close(serverfd);
	//shutdown(clientfd, 1);
	//shutdown(serverfd, 0);
}

void *secureTalk(int clientfd, rio_t client, char* host, char* version, int serverPort) {
	void* ret = (void*) malloc(16);
	pthread_t tid;
	int* args;
	args = malloc(2*sizeof(int));
	int	serverfd = Open_clientfd(host, serverPort);
	if(serverfd >= 0) {
	    args[0] = clientfd; args[1] = serverfd;
	    rio_writep(clientfd, "HTTP/1.1 200 OK\r\n\r\n", strlen("HTTP/1.1 200 OK\r\n\r\n"));
		Pthread_create(&tid, NULL, serverRead, (void*) args);
		Pthread_detach(tid);
		char* buf1[MAXLINE], buf4[MAXLINE];
		int numBytes, numCliBytes;
		char* request[MAXLINE];
		numCliBytes = 1;
		
		while(1) {
			//if(errno == EINTR)
			//	continue;
			if(fcntl(clientfd,F_GETFD) != -1){
				if((numCliBytes = rio_readp(clientfd, buf4, MAXLINE)) < 0)
					if(errno != EPIPE && errno != 0)
						break;
			}
			else
				break;
			if(fcntl(serverfd,F_GETFD)!=-1 && errno == 0) {
				//printf("numbytescli:%d//sfd:%d//cfd:%d\n ", numCliBytes, serverfd, clientfd);
				if(numCliBytes <= 0) {
					rio_writep(serverfd, "\r\n\r\n", strlen("\r\n\r\n"));
					break;
				}
				rio_writep(serverfd, buf4, numCliBytes);
			}
			else
				break;
		}
		//shutdown(serverfd,1);
		//shutdown(clientfd,0);
		Close(clientfd);
		//Close(serverfd);
	}
	return ret;
}


void ignore()
{
	;
}


/*============================================================
 * url parser:
 *    find_target_address()
 *        Given a url, copy the target web server address to
 *        target_address and the following path to path.
 *        target_address and path have to be allocated before they 
 *        are passed in and should be long enough (use MAXLINE to be 
 *        safe)
 *
 *        Return the port number. 0 is returned if there is
 *        any error in parsing the url.
 *
 *============================================================*/

/*find_target_address - find the host name from the uri */
int  find_target_address(char * uri, char * target_address, char * path,
                         int  * port)

{
 

    if (strncasecmp(uri, "http://", 7) == 0) {
	char * hostbegin, * hostend, *pathbegin;
	int    len;
       
	/* find the target address */
	hostbegin = uri+7;
	hostend = strpbrk(hostbegin, " :/\r\n");
	if (hostend == NULL){
	  hostend = hostbegin + strlen(hostbegin);
	}
	
	len = hostend - hostbegin;

	strncpy(target_address, hostbegin, len);
	target_address[len] = '\0';

	/* find the port number */
	if (*hostend == ':')   *port = atoi(hostend+1);

	/* find the path */

	pathbegin = strchr(hostbegin, '/');

	if (pathbegin == NULL) {
	  path[0] = '\0';
	  
	}
	else {
	  pathbegin++;	
	  strcpy(path, pathbegin);
	}
	return 0;
    }
    target_address[0] = '\0';
    return -1;
}



/*============================================================
 * log utility
 *    format_log_entry
 *       Copy the formatted log entry to logstring
 *============================================================*/

void format_log_entry(char * logstring, int sock, char * uri, int size)
{
    time_t  now;
    char    buffer[MAXLINE];
    struct  sockaddr_in addr;
    unsigned  long  host;
    unsigned  char a, b, c, d;
    int    len = sizeof(addr);

    now = time(NULL);
    strftime(buffer, MAXLINE, "%a %d %b %Y %H:%M:%S %Z", localtime(&now));

    if (getpeername(sock, (struct sockaddr *) & addr, &len)) {
	unix_error("Can't get peer name");
    }

    host = ntohl(addr.sin_addr.s_addr);
    a = host >> 24;
    b = (host >> 16) & 0xff;
    c = (host >> 8) & 0xff;
    d = host & 0xff;

    sprintf(logstring, "%s: %d.%d.%d.%d %s %d\n", buffer, a,b,c,d, uri, size);
}
