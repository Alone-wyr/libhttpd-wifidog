/* vim: tabstop=4 softtabstop=4 shiftwidth=4 expandtab
** Copyright (c) 2002  Hughes Technologies Pty Ltd.  All rights
** reserved.
**
** Terms under which this software may be used or copied are
** provided in the  specific license associated with this product.
**
** Hughes Technologies disclaims all warranties with regard to this
** software, including all implied warranties of merchantability and
** fitness, in no event shall Hughes Technologies be liable for any
** special, indirect or consequential damages or any damages whatsoever
** resulting from loss of use, data or profits, whether in an action of
** contract, negligence or other tortious action, arising out of or in
** connection with the use or performance of this software.
**
**
** $Id$
**
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <unistd.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netdb.h>
#endif

#include "config.h"
#include "httpd.h"
#include "httpd_priv.h"

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>
#endif

char *
httpdUrlEncode(str)
const char *str;
{
    char *new, *cp;

    new = (char *)_httpd_escape(str);
    if (new == NULL) {
        return (NULL);
    }
    cp = new;
    while (*cp) {
        if (*cp == ' ')
            *cp = '+';
        cp++;
    }
    return (new);
}

char *
httpdRequestMethodName(request * r)
{
    switch (r->request.method) {
    case HTTP_GET:
        return ("GET");
    case HTTP_POST:
        return ("POST");
    default:
        return ("INVALID");
    }
}

httpVar *
httpdGetVariableByName(request * r, const char *name)
{
    httpVar *curVar;

    curVar = r->variables;
    while (curVar) {
        if (strcmp(curVar->name, name) == 0)
            return (curVar);
        curVar = curVar->nextVariable;
    }
    return (NULL);
}

httpVar *
httpdGetVariableByPrefix(request * r, const char *prefix)
{
    httpVar *curVar;

    if (prefix == NULL)
        return (r->variables);
    curVar = r->variables;
    while (curVar) {
        if (strncmp(curVar->name, prefix, strlen(prefix)) == 0)
            return (curVar);
        curVar = curVar->nextVariable;
    }
    return (NULL);
}

int
httpdSetVariableValue(request * r, const char *name, const char *value)
{
    httpVar *var;

    var = httpdGetVariableByName(r, name);
    if (var) {
        if (var->value)
            free(var->value);
        var->value = strdup(value);
        return (0);
    } else {
        return (httpdAddVariable(r, name, value));
    }
}

httpVar *
httpdGetVariableByPrefixedName(request * r, const char *prefix, const char *name)
{
    httpVar *curVar;
    int prefixLen;

    if (prefix == NULL)
        return (r->variables);
    curVar = r->variables;
    prefixLen = strlen(prefix);
    while (curVar) {
        if (strncmp(curVar->name, prefix, prefixLen) == 0 && strcmp(curVar->name + prefixLen, name) == 0) {
            return (curVar);
        }
        curVar = curVar->nextVariable;
    }
    return (NULL);
}

httpVar *
httpdGetNextVariableByPrefix(curVar, prefix)
httpVar *curVar;
const char *prefix;
{
    if (curVar)
        curVar = curVar->nextVariable;
    while (curVar) {
        if (strncmp(curVar->name, prefix, strlen(prefix)) == 0)
            return (curVar);
        curVar = curVar->nextVariable;
    }
    return (NULL);
}

int
httpdAddVariable(request * r, const char *name, const char *value)
{
    httpVar *curVar, *lastVar, *newVar;

    while (*name == ' ' || *name == '\t')
        name++;
    newVar = malloc(sizeof(httpVar));
    bzero(newVar, sizeof(httpVar));
    newVar->name = strdup(name);
    newVar->value = strdup(value);
    lastVar = NULL;
    curVar = r->variables;
    while (curVar) {
		//遍历request上的所有变量...查看是否有相同name的变量.
        if (strcmp(curVar->name, name) != 0) {
            lastVar = curVar;
            curVar = curVar->nextVariable;
            continue;
        }
		//到这里代表有相同name的.
        while (curVar) {
            lastVar = curVar;
			//相同name有不同的value..遍历到最后一个value.
            curVar = curVar->nextValue;
        }
		//添加到链表末尾.
        lastVar->nextValue = newVar;
		//因此...从这里返回的原因是当前variable列表中有了相同的name存在..
        return (0);
    }
	//这里是没有相同name的存在..
	//但是要判断是不是存放第一个variable..如果不是则直接添加到链表的最后一个中.
    if (lastVar)
        lastVar->nextVariable = newVar;
    else
		//这个分支是当前变量为第一个变量....
        r->variables = newVar;
    return (0);
}

httpd *
httpdCreate(host, port)
char *host;
int port;
{
    httpd *new;
    int sock, opt;
    struct sockaddr_in addr;

    /*
     ** Create the handle and setup it's basic config
     */
    new = malloc(sizeof(httpd));
    if (new == NULL)
        return (NULL);
    bzero(new, sizeof(httpd));
    new->port = port;
    if (host == HTTP_ANY_ADDR)
        new->host = HTTP_ANY_ADDR;
    else
        new->host = strdup(host);
    new->content = (httpDir *) malloc(sizeof(httpDir));
    bzero(new->content, sizeof(httpDir));
    new->content->name = strdup("");

    /*
     ** Setup the socket
     */
#ifdef _WIN32
    {
        WORD wVersionRequested;
        WSADATA wsaData;
        int err;

        wVersionRequested = MAKEWORD(2, 2);

        err = WSAStartup(wVersionRequested, &wsaData);

        /* Found a usable winsock dll? */
        if (err != 0)
            return NULL;

        /* 
         ** Confirm that the WinSock DLL supports 2.2.
         ** Note that if the DLL supports versions greater 
         ** than 2.2 in addition to 2.2, it will still return
         ** 2.2 in wVersion since that is the version we
         ** requested.
         */

        if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {

            /* 
             ** Tell the user that we could not find a usable
             ** WinSock DLL.
             */
            WSACleanup();
            return NULL;
        }

        /* The WinSock DLL is acceptable. Proceed. */
    }
#endif

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        free(new);
        return (NULL);
    }
#	ifdef SO_REUSEADDR
    opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(int)) < 0) {
        close(sock);
        free(new);
        return NULL;
    }
#	endif
    new->serverSock = sock;
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    if (new->host == HTTP_ANY_ADDR) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        addr.sin_addr.s_addr = inet_addr(new->host);
    }
    addr.sin_port = htons((u_short) new->port);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        free(new);
        return (NULL);
    }
    listen(sock, 128);
    new->startTime = time(NULL);
    return (new);
}

void
httpdDestroy(server)
httpd *server;
{
    if (server == NULL)
        return;
    if (server->host)
        free(server->host);
    free(server);
}

request *
httpdGetConnection(server, timeout)
httpd *server;
struct timeval *timeout;
{
    int result;
    fd_set fds;
    struct sockaddr_in addr;
    socklen_t addrLen;
    char *ipaddr;
    request *r;
    /* Reset error */
    server->lastError = 0;
    FD_ZERO(&fds);
    FD_SET(server->serverSock, &fds);
    result = 0;
    while (result == 0) {
        result = select(server->serverSock + 1, &fds, 0, 0, timeout);
        if (result < 0) {
            server->lastError = -1;
            return (NULL);
        }
        if (timeout != 0 && result == 0) {
            server->lastError = 0;
            return (NULL);
        }
        if (result > 0) {
            break;
        }
    }
    /* Allocate request struct */
    r = (request *) malloc(sizeof(request));
    if (r == NULL) {
        server->lastError = -3;
        return (NULL);
    }
    memset((void *)r, 0, sizeof(request));
    /* Get on with it */
    bzero(&addr, sizeof(addr));
    addrLen = sizeof(addr);
    r->clientSock = accept(server->serverSock, (struct sockaddr *)&addr, &addrLen);
    ipaddr = inet_ntoa(addr.sin_addr);
    if (ipaddr) {
        strncpy(r->clientAddr, ipaddr, HTTP_IP_ADDR_LEN);
        r->clientAddr[HTTP_IP_ADDR_LEN - 1] = 0;
    } else
        *r->clientAddr = 0;
    r->readBufRemain = 0;
    r->readBufPtr = NULL;

    /*
     ** Check the default ACL
     */
    if (server->defaultAcl) {
        if (httpdCheckAcl(server, r, server->defaultAcl)
            == HTTP_ACL_DENY) {
            httpdEndRequest(r);
            server->lastError = 2;
            return (NULL);
        }
    }
    return (r);
}

int
httpdReadRequest(httpd * server, request * r)
{
    char buf[HTTP_MAX_LEN];
    int count, inHeaders;
    char *cp, *cp2;
    int _httpd_decode();

    /*
     ** Setup for a standard response
     */
    strcpy(r->response.headers, "Server: Hughes Technologies Embedded Server\n");
    strcpy(r->response.contentType, "text/html");
    strcpy(r->response.response, "200 Output Follows\n");
    r->response.headersSent = 0;

    /*
     ** Read the request
     */
    count = 0;
    inHeaders = 1;
    while (_httpd_readLine(r, buf, HTTP_MAX_LEN) > 0) {
        count++;

        /*
         ** Special case for the first line.  Scan the request
         ** method and path etc
         */
        if (count == 1) {
            /*
             ** First line.  Scan the request info
             */
             /*
第一行的内容一般如下:
	GET / HTTP/1.1   包含3个部分, method = GET path = / verion = HTTP/1.1
*/
	//1. 获取方法get 或者是post
            cp = cp2 = buf;
	//判断是否为英文字母..如果是则返回1..
            while (isalpha((unsigned char)*cp2))
                cp2++;
            *cp2 = 0;
            if (strcasecmp(cp, "GET") == 0)
                r->request.method = HTTP_GET;
            if (strcasecmp(cp, "POST") == 0)
                r->request.method = HTTP_POST;
            if (r->request.method == 0) {
                _httpd_net_write(r->clientSock, HTTP_METHOD_ERROR, strlen(HTTP_METHOD_ERROR));
                _httpd_net_write(r->clientSock, cp, strlen(cp));
                _httpd_writeErrorLog(server, r, LEVEL_ERROR, "Invalid method received");
                return (-1);
            }
	//2.获取path.
            cp = cp2 + 1;
            while (*cp == ' ')
                cp++;
            cp2 = cp;
            while (*cp2 != ' ' && *cp2 != 0)
                cp2++;
            *cp2 = 0;	
            strncpy(r->request.path, cp, HTTP_MAX_URL);
            r->request.path[HTTP_MAX_URL - 1] = 0;
	//处理path.
            _httpd_sanitiseUrl(r->request.path);
            continue;
        }

        /*
         ** Process the headers
         */
        if (inHeaders) {
            if (*buf == 0) {
                /*
                 ** End of headers.  Continue if there's
                 ** data to read
                 */
                break;
            }

            if (strncasecmp(buf, "Authorization: ", 15) == 0) {
                cp = strchr(buf, ':');
                if (cp) {
                    cp += 2;

                    if (strncmp(cp, "Basic ", 6) != 0) {
                        /* Unknown auth method */
                    } else {
                        char authBuf[100];

                        cp = strchr(cp, ' ') + 1;
                        _httpd_decode(cp, authBuf, 100);
                        r->request.authLength = strlen(authBuf);
                        cp = strchr(authBuf, ':');
                        if (cp) {
                            *cp = 0;
                            strncpy(r->request.authPassword, cp + 1, HTTP_MAX_AUTH);
                            r->request.authPassword[HTTP_MAX_AUTH - 1] = 0;
                        }
                        strncpy(r->request.authUser, authBuf, HTTP_MAX_AUTH);
                        r->request.authUser[HTTP_MAX_AUTH - 1] = 0;
                    }
                }
            }
            /* acv@acv.ca/wifidog: Added decoding of host: if
             * present. */
            if (strncasecmp(buf, "Host: ", 6) == 0) {
                cp = strchr(buf, ':');
                if (cp) {
                    cp += 2;
                    strncpy(r->request.host, cp, HTTP_MAX_URL);
                    r->request.host[HTTP_MAX_URL - 1] = 0;
                }
            }
            /* End modification */
            continue;
        }
    }

    /*
     ** Process any URL data
     */
    cp = strchr(r->request.path, '?');
	//如果path中包含了'?'，则需要处理一下这个path.因为有?的path代表是有传递参数的...
	//cp确定到'?'位置...
	//把query拷贝到request.query上.
    if (cp != NULL) {
		//相当于把path的'?'给替换成了'\0'..那相当于把path给截断成2个字符串啦.
		//一个就是真正的path..后面字符串接着参数.cp指向第一个参数..(不再是那个'?'字符了)
        *cp++ = 0;
		//把参数拷贝到requery字符串中.
        strncpy(r->request.query, cp, sizeof(r->request.query));
        r->request.query[sizeof(r->request.query) - 1] = 0;
		//把path带的参数存放到request结构体中.
        _httpd_storeData(r, cp);
    }

    return (0);
}

void
httpdEndRequest(request * r)
{
    _httpd_freeVariables(r->variables);
    shutdown(r->clientSock, 2);
    close(r->clientSock);
    free(r);
}

void
httpdFreeVariables(request * r)
{
    _httpd_freeVariables(r->variables);
}

void
httpdDumpVariables(request * r)
{
    httpVar *curVar, *curVal;

    curVar = r->variables;
    while (curVar) {
        printf("Variable '%s'\n", curVar->name);
        curVal = curVar;
        while (curVal) {
            printf("\t= '%s'\n", curVal->value);
            curVal = curVal->nextValue;
        }
        curVar = curVar->nextVariable;
    }
}

void
httpdSetFileBase(server, path)
httpd *server;
const char *path;
{
    strncpy(server->fileBasePath, path, HTTP_MAX_URL);
    server->fileBasePath[HTTP_MAX_URL - 1] = 0;
}

int
httpdAddFileContent(server, dir, name, indexFlag, preload, path)
httpd *server;
char *dir, *name;
int (*preload) ();
int indexFlag;
char *path;
{
    httpDir *dirPtr;
    httpContent *newEntry;

    dirPtr = _httpd_findContentDir(server, dir, HTTP_TRUE);
    newEntry = malloc(sizeof(httpContent));
    if (newEntry == NULL)
        return (-1);
    bzero(newEntry, sizeof(httpContent));
    newEntry->name = strdup(name);
    newEntry->type = HTTP_FILE;
    newEntry->indexFlag = indexFlag;
    newEntry->preload = preload;
    newEntry->next = dirPtr->entries;
    dirPtr->entries = newEntry;
    if (*path == '/') {
        /* Absolute path */
        newEntry->path = strdup(path);
    } else {
        /* Path relative to base path */
        newEntry->path = malloc(strlen(server->fileBasePath) + strlen(path) + 2);
        snprintf(newEntry->path, HTTP_MAX_URL, "%s/%s", server->fileBasePath, path);
    }
    return (0);
}

int
httpdAddWildcardContent(server, dir, preload, path)
httpd *server;
char *dir;
int (*preload) ();
char *path;
{
    httpDir *dirPtr;
    httpContent *newEntry;

    dirPtr = _httpd_findContentDir(server, dir, HTTP_TRUE);
    newEntry = malloc(sizeof(httpContent));
    if (newEntry == NULL)
        return (-1);
    bzero(newEntry, sizeof(httpContent));
    newEntry->name = NULL;
    newEntry->type = HTTP_WILDCARD;
    newEntry->indexFlag = HTTP_FALSE;
    newEntry->preload = preload;
    newEntry->next = dirPtr->entries;
    dirPtr->entries = newEntry;
    if (*path == '/') {
        /* Absolute path */
        newEntry->path = strdup(path);
    } else {
        /* Path relative to base path */
        newEntry->path = malloc(strlen(server->fileBasePath) + strlen(path) + 2);
        snprintf(newEntry->path, HTTP_MAX_URL, "%s/%s", server->fileBasePath, path);
    }
    return (0);
}

/*

比如:
httpdAddCContent(webserver, "/", "wifidog", 0, NULL, http_callback_wifidog);
httpdAddCContent(webserver, "/wifidog", "", 0, NULL, http_callback_wifidog);
httpdAddCContent(webserver, "/wifidog", "about", 0, NULL, http_callback_about);
httpdAddCContent(webserver, "/wifidog", "status", 0, NULL, http_callback_status);
httpdAddCContent(webserver, "/wifidog", "auth", 0, NULL, http_callback_auth);
httpdAddCContent(webserver, "/wifidog", "disconnect", 0, NULL, http_callback_disconnect);

1. 创建"/"目录，该目录下有内容"wifidig"
2. 在"目录下"创建"wifidog"目录，该目录下有内容""
3. 在"/wifidog"目录下创建内容"about"
4. 在"/wifidog"目录下创建内容"status"
5. 在"/wifidog"目录下创建内容"auth"
6. 在"/wifidog"目录下创建内容"disconnect"

*/
int
httpdAddCContent(server, dir, name, indexFlag, preload, function)
httpd *server;
char *dir;
char *name;
int indexFlag;
int (*preload) ();
void (*function) ();
{
    httpDir *dirPtr;
    httpContent *newEntry;

    dirPtr = _httpd_findContentDir(server, dir, HTTP_TRUE);
    newEntry = malloc(sizeof(httpContent));
    if (newEntry == NULL)
        return (-1);
    bzero(newEntry, sizeof(httpContent));
    newEntry->name = strdup(name);
    newEntry->type = HTTP_C_FUNCT;
    newEntry->indexFlag = indexFlag;
    newEntry->function = function;
    newEntry->preload = preload;
	//httpDir代表着一个目录..这里就是添加内容到这个目录下吧...添加到dir->entries指向的链表....
    newEntry->next = dirPtr->entries;
    dirPtr->entries = newEntry;
    return (0);
}

int
httpdAddCWildcardContent(server, dir, preload, function)
httpd *server;
char *dir;
int (*preload) ();
void (*function) ();
{
    httpDir *dirPtr;
    httpContent *newEntry;

    dirPtr = _httpd_findContentDir(server, dir, HTTP_TRUE);
    newEntry = malloc(sizeof(httpContent));
    if (newEntry == NULL)
        return (-1);
    bzero(newEntry, sizeof(httpContent));
    newEntry->name = NULL;
    newEntry->type = HTTP_C_WILDCARD;
    newEntry->indexFlag = HTTP_FALSE;
    newEntry->function = function;
    newEntry->preload = preload;
    newEntry->next = dirPtr->entries;
    dirPtr->entries = newEntry;
    return (0);
}

int
httpdAddStaticContent(server, dir, name, indexFlag, preload, data)
httpd *server;
char *dir;
char *name;
int indexFlag;
int (*preload) ();
char *data;
{
    httpDir *dirPtr;
    httpContent *newEntry;

    dirPtr = _httpd_findContentDir(server, dir, HTTP_TRUE);
    newEntry = malloc(sizeof(httpContent));
    if (newEntry == NULL)
        return (-1);
    bzero(newEntry, sizeof(httpContent));
    newEntry->name = strdup(name);
    newEntry->type = HTTP_STATIC;
    newEntry->indexFlag = indexFlag;
    newEntry->data = data;
    newEntry->preload = preload;
    newEntry->next = dirPtr->entries;
    dirPtr->entries = newEntry;
    return (0);
}

void
httpdSendHeaders(request * r)
{
    _httpd_sendHeaders(r, 0, 0);
}

void
httpdSetResponse(request * r, const char *msg)
{
    strncpy(r->response.response, msg, HTTP_MAX_URL - 1);
    r->response.response[HTTP_MAX_URL - 1] = 0;
}

void
httpdSetContentType(request * r, const char *type)
{
    strncpy(r->response.contentType, type, HTTP_MAX_URL - 1);
    r->response.contentType[HTTP_MAX_URL - 1] = 0;
}

void
httpdAddHeader(request * r, const char *msg)
{
    int size;
    size = HTTP_MAX_HEADERS - 2 - strlen(r->response.headers);
    if (size > 0) {
        strncat(r->response.headers, msg, size);
        if (r->response.headers[strlen(r->response.headers) - 1] != '\n')
            strcat(r->response.headers, "\n");
    }
}

void
httpdSetCookie(request * r, const char *name, const char *value)
{
    char buf[HTTP_MAX_URL];

    snprintf(buf, HTTP_MAX_URL, "Set-Cookie: %s=%s; path=/;", name, value);
    httpdAddHeader(r, buf);
}

void
httpdOutput(request * r, const char *msg)
{
    const char *src;
    char buf[HTTP_MAX_LEN], varName[80], *dest;
    int count;

    src = msg;
	//buf存放替换掉了变量后的msg.
    dest = buf;
	//count记录当前msg的长度..因为要替换变量的值..替换后的msg长度是有限制的...
    count = 0;
    memset(buf, 0, HTTP_MAX_LEN);
    while (*src && count < HTTP_MAX_LEN) {
		//一直查找...直到找到$为止....因为在这个msg中...可以替换变量...
		//
        if (*src == '$') {
            const char *tmp;
            char *cp;
            int count2;
            httpVar *curVar;

            tmp = src + 1;
            cp = varName;
            count2 = 0;
			//isalnum判断是不是字母或数字..或者是'_'的字符..都是满足条件的..
            while (*tmp && (isalnum((unsigned char)*tmp) || *tmp == '_') && count2 < 80) {
				//保存变量名到varName数组...
                *cp++ = *tmp++;
                count2++;
            }
            *cp = 0;
			//通过变varName保存的变量名来获取value.
            curVar = httpdGetVariableByName(r, varName);
			//确保替换变量后的msg长度还是合法的.
            if (curVar && ((count + strlen(curVar->value)) < HTTP_MAX_LEN)) {
				//把变量的value保存到目的.
                strcpy(dest, curVar->value);
				//目的数组的指针向前...
                dest = dest + strlen(dest);
				//这里很奇怪....照理说count应该是记录整个msg的长度的.包括替换掉变量后..
				//而这里strlen(dest)其实，返回的是0的..相当于替换掉变量后..没有记录替换的数据的长度..
				//同时也没有记录变量名的长度..比如说: msg: <!>$hello<!>  而且$hello=wyr_alone.
				//替换掉后的msg为<!>wyr_alone<!>  而最终计算的count=6... 不记录wyr_alone的长度.
                count += strlen(dest);
				//src指向源..前进一个'$'字符和变量名的长度..
                src = src + strlen(varName) + 1;
                continue;
            } else {
            	//没有找到变量...
                *dest++ = *src++;
                count++;
                continue;
            }
        }
        *dest++ = *src++;
        count++;
    }
    *dest = 0;
    r->response.responseLength += strlen(buf);
    if (r->response.headersSent == 0)
        httpdSendHeaders(r);
    _httpd_net_write(r->clientSock, buf, strlen(buf));
}

#ifdef HAVE_STDARG_H
void
httpdPrintf(request * r, const char *fmt, ...)
{
#else
void
httpdPrintf(va_alist)
va_dcl
{
    request *r;;
    const char *fmt;
#endif
    va_list args;
    char buf[HTTP_MAX_LEN];

#ifdef HAVE_STDARG_H
    va_start(args, fmt);
#else
    va_start(args);
    r = (request *) va_arg(args, request *);
    fmt = (char *)va_arg(args, char *);
#endif
    if (r->response.headersSent == 0)
        httpdSendHeaders(r);
    vsnprintf(buf, HTTP_MAX_LEN, fmt, args);
    va_end(args); /* Works with both stdargs.h and varargs.h */
    r->response.responseLength += strlen(buf);
    _httpd_net_write(r->clientSock, buf, strlen(buf));
}

//调用这个函数的前面都会调用httpdReadRequest函数，它会读取来自服务器的返回.
//然后根据需求填充request结构体..
//而这个函数，根据填充好了的request结构体来执行不同的处理。
void
httpdProcessRequest(httpd * server, request * r)
{
    char dirName[HTTP_MAX_URL], entryName[HTTP_MAX_URL], *cp;
    httpDir *dir;
    httpContent *entry;

    r->response.responseLength = 0;
	//拷贝请求的path.
    strncpy(dirName, httpdRequestPath(r), HTTP_MAX_URL);
    dirName[HTTP_MAX_URL - 1] = 0;
	//reverse chr 反向查找第一次出现字符的位置.
    cp = strrchr(dirName, '/');
    if (cp == NULL) {
        /* printf("Invalid request path '%s'\n", dirName); */
        return;
    }
	//保存起来entry name.
    strncpy(entryName, cp + 1, HTTP_MAX_URL);
    entryName[HTTP_MAX_URL - 1] = 0;
	//这里会判断多重目录??
	//比如dirName = /wifidog/auth
	//在处理dirName之后, entryName = "auth", cp指向'a'的位置.
	//判断 cp != dirName是成立的, dirName指向第一个'/', cp指向第二个'/'
	//设置*cp = 0..相当于让dirName从"/wifidog/auth"变成了"/wifidog了.. 而auth=已经保存到了entryName.

	//那如果dirName = "/wifidog" 那么会判断cp != dirName是不成立的 *(cp + 1) = 0.
	//会让dirName从"/wifidog"变成 "/"

	//最终的结果就是把dir和entry给分开来....
    if (cp != dirName)
        *cp = 0;
    else
        *(cp + 1) = 0;

	//1.查找是否有该dir
    dir = _httpd_findContentDir(server, dirName, HTTP_FALSE);
    if (dir == NULL) {
        _httpd_send404(server, r);
        _httpd_writeAccessLog(server, r);
        return;
    }
	//2.查找是否有entry.
    entry = _httpd_findContentEntry(r, dir, entryName);
    if (entry == NULL) {
        _httpd_send404(server, r);
        _httpd_writeAccessLog(server, r);
        return;
    }
	
    if (entry->preload) {
		//是否需要预加载..
        if ((entry->preload) (server) < 0) {
            _httpd_writeAccessLog(server, r);
            return;
        }
    }
    switch (entry->type) {
    case HTTP_C_FUNCT:
    case HTTP_C_WILDCARD:
        (entry->function) (server, r);
        break;

    case HTTP_STATIC:
        _httpd_sendStatic(server, r, entry->data);
        break;

    case HTTP_FILE:
        httpdSendFile(server, r, entry->path);
        break;

    case HTTP_WILDCARD:
        if (_httpd_sendDirectoryEntry(server, r, entry, entryName) < 0) {
            _httpd_send404(server, r);
        }
        break;
    }
    _httpd_writeAccessLog(server, r);
}

void
httpdSetAccessLog(server, fp)
httpd *server;
FILE *fp;
{
    server->accessLog = fp;
}

void
httpdSetErrorLog(server, fp)
httpd *server;
FILE *fp;
{
    server->errorLog = fp;
}

int
httpdAuthenticate(request * r, const char *realm)
{
    char buffer[255];

    if (r->request.authLength == 0) {
        httpdSetResponse(r, "401 Please Authenticate");
        snprintf(buffer, sizeof(buffer), "WWW-Authenticate: Basic realm=\"%s\"\n", realm);
        httpdAddHeader(r, buffer);
        httpdOutput(r, "\n");
        return (0);
    }
    return (1);
}

int
httpdSetErrorFunction(httpd * server, int error, void (*function) ())
{
    char errBuf[80];

    switch (error) {
    case 304:
        server->errorFunction304 = function;
        break;
    case 403:
        server->errorFunction403 = function;
        break;
    case 404:
        server->errorFunction404 = function;
        break;
    default:
        snprintf(errBuf, 80, "Invalid error code (%d) for custom callback", error);
        _httpd_writeErrorLog(server, NULL, LEVEL_ERROR, errBuf);
        return (-1);
        break;
    }
    return (0);
}

void
httpdSendFile(httpd * server, request * r, const char *path)
{
    char *suffix;
    struct stat sbuf;

    suffix = strrchr(path, '.');
    if (suffix != NULL) {
        if (strcasecmp(suffix, ".gif") == 0)
            strcpy(r->response.contentType, "image/gif");
        if (strcasecmp(suffix, ".jpg") == 0)
            strcpy(r->response.contentType, "image/jpeg");
        if (strcasecmp(suffix, ".xbm") == 0)
            strcpy(r->response.contentType, "image/xbm");
        if (strcasecmp(suffix, ".png") == 0)
            strcpy(r->response.contentType, "image/png");
        if (strcasecmp(suffix, ".css") == 0)
            strcpy(r->response.contentType, "text/css");
    }
    if (stat(path, &sbuf) < 0) {
        _httpd_send404(server, r);
        return;
    }
    if (_httpd_checkLastModified(r, sbuf.st_mtime) == 0) {
        _httpd_send304(server, r);
    } else {
        _httpd_sendHeaders(r, sbuf.st_size, sbuf.st_mtime);

        _httpd_catFile(r, path);
    }
}

void
httpdForceAuthenticate(request * r, const char *realm)
{
    char buffer[255];

    httpdSetResponse(r, "401 Please Authenticate");
    snprintf(buffer, sizeof(buffer), "WWW-Authenticate: Basic realm=\"%s\"\n", realm);
    httpdAddHeader(r, buffer);
    httpdOutput(r, "\n");
}
