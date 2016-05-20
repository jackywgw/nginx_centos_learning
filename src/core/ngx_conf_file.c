
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

#define NGX_CONF_BUFFER  4096

static ngx_int_t ngx_conf_handler(ngx_conf_t *cf, ngx_int_t last);
static ngx_int_t ngx_conf_read_token(ngx_conf_t *cf);
static void ngx_conf_flush_files(ngx_cycle_t *cycle);


static ngx_command_t  ngx_conf_commands[] = {

    { ngx_string("include"),
      NGX_ANY_CONF|NGX_CONF_TAKE1,
      ngx_conf_include,
      0,
      0,
      NULL },

      ngx_null_command
};


ngx_module_t  ngx_conf_module = {
    NGX_MODULE_V1,
    NULL,                                  /* module context */
    ngx_conf_commands,                     /* module directives */
    NGX_CONF_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_conf_flush_files,                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


/* The eight fixed arguments */

static ngx_uint_t argument_number[] = {
    NGX_CONF_NOARGS,
    NGX_CONF_TAKE1,
    NGX_CONF_TAKE2,
    NGX_CONF_TAKE3,
    NGX_CONF_TAKE4,
    NGX_CONF_TAKE5,
    NGX_CONF_TAKE6,
    NGX_CONF_TAKE7
};


char *
ngx_conf_param(ngx_conf_t *cf)
{
    char             *rv;
    ngx_str_t        *param;
    ngx_buf_t         b;
    ngx_conf_file_t   conf_file;

    param = &cf->cycle->conf_param;

    if (param->len == 0) {
        return NGX_CONF_OK;
    }

    ngx_memzero(&conf_file, sizeof(ngx_conf_file_t));

    ngx_memzero(&b, sizeof(ngx_buf_t));

    b.start = param->data;
    b.pos = param->data;
    b.last = param->data + param->len;
    b.end = b.last;
    b.temporary = 1;

    conf_file.file.fd = NGX_INVALID_FILE;
    conf_file.file.name.data = NULL;
    conf_file.line = 0;

    cf->conf_file = &conf_file;
    cf->conf_file->buffer = &b;

    rv = ngx_conf_parse(cf, NULL);

    cf->conf_file = NULL;

    return rv;
}


char *
ngx_conf_parse(ngx_conf_t *cf, ngx_str_t *filename)
{
    char             *rv;
    ngx_fd_t          fd;
    ngx_int_t         rc;
    ngx_buf_t         buf;
    ngx_conf_file_t  *prev, conf_file;
    enum {
        parse_file = 0,
        parse_block,
        parse_param
    } type;

#if (NGX_SUPPRESS_WARN)
    fd = NGX_INVALID_FILE;
    prev = NULL;
#endif

    if (filename) {

        /* open configuration file */
        /*以只读的方式打开配置文件*/
        fd = ngx_open_file(filename->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
        if (fd == NGX_INVALID_FILE) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                               ngx_open_file_n " \"%s\" failed",
                               filename->data);
            return NGX_CONF_ERROR;
        }
        /*暂时记录conf_file*/
        prev = cf->conf_file;

        cf->conf_file = &conf_file;/*将conf_file指向函数内部变量conf_file的地址*/
        /*将配置文件的文件信息stat数据存入conf_file->file.info中*/
        if (ngx_fd_info(fd, &cf->conf_file->file.info) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
                          ngx_fd_info_n " \"%s\" failed", filename->data);
        }

        cf->conf_file->buffer = &buf;

        buf.start = ngx_alloc(NGX_CONF_BUFFER, cf->log);
        if (buf.start == NULL) {
            goto failed;
        }

        buf.pos = buf.start;
        buf.last = buf.start;
        buf.end = buf.last + NGX_CONF_BUFFER;
        buf.temporary = 1;

        cf->conf_file->file.fd = fd;
        cf->conf_file->file.name.len = filename->len;
        cf->conf_file->file.name.data = filename->data;
        cf->conf_file->file.offset = 0;
        cf->conf_file->file.log = cf->log;
        cf->conf_file->line = 1;//起始行数为1
        /*如果入参filename存在，则type类型为parse_file*/
        type = parse_file;

    } else if (cf->conf_file->file.fd != NGX_INVALID_FILE) {/*如果filename不存在，并且配置文件句柄不为-1,则type类型为parse_block*/

        type = parse_block;

    } else {/*其它情况下type为parse_param*/
        type = parse_param;
    }


    for ( ;; ) {
        rc = ngx_conf_read_token(cf);

        /*
         * ngx_conf_read_token() may return
         *
         *    NGX_ERROR             there is error
         *    NGX_OK                the token terminated by ";" was found
         *    NGX_CONF_BLOCK_START  the token terminated by "{" was found
         *    NGX_CONF_BLOCK_DONE   the "}" was found
         *    NGX_CONF_FILE_DONE    the configuration file is done
         */
        /*error*/
        if (rc == NGX_ERROR) {
            goto done;
        }
        /*the "}" was found*/
        if (rc == NGX_CONF_BLOCK_DONE) {

            if (type != parse_block) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "unexpected \"}\"");
                goto failed;
            }

            goto done;
        }
        /*the configure file is done*/
        if (rc == NGX_CONF_FILE_DONE) {

            if (type == parse_block) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "unexpected end of file, expecting \"}\"");
                goto failed;
            }

            goto done;
        }
        /*the token terminated by "{" was found*/
        if (rc == NGX_CONF_BLOCK_START) {

            if (type == parse_param) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "block directives are not supported "
                                   "in -g option");
                goto failed;
            }
        }
        
        /*只有这两种情况会走到此处 rc == NGX_OK || rc == NGX_CONF_BLOCK_START */
        /*指令解析有两种方式，其一是使用nginx内建的指令解析机制，其二是使用第三方自定义指令解析机制。*/
        /*1. 使用第三方自定义指令解析机制,如http模块，在初始化cf结构的时候会指定，如果没有指定则执行内建的指令解析机制*/
        if (cf->handler) {
            ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,"cf->handler is not null");
            /*
             * the custom handler, i.e., that is used in the http's
             * "types { ... }" directive
             */

            if (rc == NGX_CONF_BLOCK_START) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "unexpected \"{\"");
                goto failed;
            }

            rv = (*cf->handler)(cf, NULL, cf->handler_conf);
            if (rv == NGX_CONF_OK) {
                continue;
            }

            if (rv == NGX_CONF_ERROR) {
                goto failed;
            }

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, rv);

            goto failed;
        }

        /*2. 使用nginx内建的指令解析机制*/
        rc = ngx_conf_handler(cf, rc);

        if (rc == NGX_ERROR) {
            goto failed;
        }
    }

failed:

    rc = NGX_ERROR;

done:
    /*关闭文件句柄，还原conf_file值*/
    if (filename) {
        if (cf->conf_file->buffer->start) {
            ngx_free(cf->conf_file->buffer->start);
        }

        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
                          ngx_close_file_n " %s failed",
                          filename->data);
            rc = NGX_ERROR;
        }

        cf->conf_file = prev;
    }

    if (rc == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_conf_handler(ngx_conf_t *cf, ngx_int_t last)
{
    char           *rv;
    void           *conf, **confp;
    ngx_uint_t      i, found;
    ngx_str_t      *name;
    ngx_command_t  *cmd;

    name = cf->args->elts;//配置数据数组首个元素为关键字名称
    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,"name=%s",name->data);
    found = 0;
    /*循环所有模块的所有命令，去寻找命令关键字*/
    for (i = 0; ngx_modules[i]; i++) {

        cmd = ngx_modules[i]->commands;
        if (cmd == NULL) {
            continue;
        }
        /*循环command数组，查找匹配命令关键字*/
        for ( /* void */ ; cmd->name.len; cmd++) {
            /*名字长度不一样，直接跳过*/
            if (name->len != cmd->name.len) {
                continue;
            }
            /*名字长度一样，但是命令不匹配，跳过该命令*/
            if (ngx_strcmp(name->data, cmd->name.data) != 0) {
                continue;
            }
            /*找到了匹配的关键字，设置found为1*/
            found = 1;
            /*只有处理的模块的类型是NGX_CONF_MODULE或者是当前正在处理的模块类型，才可能被执行。
             * nginx中有一种模块类型是NGX_CONF_MODULE，当前只有ngx_conf_module一种，只支持一条指令“include”。
             * “include”指令的实现我们后面再进行介绍。*/
            /*确保不同模块的相同名字的命令不会被解析*/
            if (ngx_modules[i]->type != NGX_CONF_MODULE
                && ngx_modules[i]->type != cf->module_type)
            {
                continue;
            }

            /* is the directive's location right ? */
            /*default type is zeros now*/
            ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,"cmd->type=0x%xi,cf->cmd_type=0x%xi",cmd->type,cf->cmd_type);
            //ngx_log_stderr(0,"cmd->type=0x%xi,cf->cmd_type=0x%xi",(unsigned int)cmd->type,(unsigned int)cf->cmd_type);
            /*指令的Context类型必须有当前解析的Context类型，设置对应的标记位
             * 这里的cf->cmd_type一开始在ngx_init_cycle中设置为conf.cmd_type = NGX_MAIN_CONF;
             * 在遇到其它类型的时候会在某个command处理函数中重新设置cmd_type*/
            if (!(cmd->type & cf->cmd_type)) {
                continue;
            }
            /*非块指令必须以";"结尾*/
            if (!(cmd->type & NGX_CONF_BLOCK) && last != NGX_OK) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                  "directive \"%s\" is not terminated by \";\"",
                                  name->data);
                return NGX_ERROR;
            }
            /*块指令必须后接"{"*/
            if ((cmd->type & NGX_CONF_BLOCK) && last != NGX_CONF_BLOCK_START) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "directive \"%s\" has no opening \"{\"",
                                   name->data);
                return NGX_ERROR;
            }

            /* is the directive's argument count right ? */
            
            /*指令参数个数必须正确。注意指令参数有最大值NGX_CONF_MAX_ARGS，目前值为8
             * 在cmd_type中会指定指令参数的个数，NGX_CONF_FLAG关键字后面刚好跟1个参数，NGX_CONF_1MORE 表示至少2个，NGX_CONF_2MORE：至少3个*/
            if (!(cmd->type & NGX_CONF_ANY)) {

                if (cmd->type & NGX_CONF_FLAG) {

                    if (cf->args->nelts != 2) {
                        goto invalid;
                    }

                } else if (cmd->type & NGX_CONF_1MORE) {

                    if (cf->args->nelts < 2) {
                        goto invalid;
                    }

                } else if (cmd->type & NGX_CONF_2MORE) {

                    if (cf->args->nelts < 3) {
                        goto invalid;
                    }

                } else if (cf->args->nelts > NGX_CONF_MAX_ARGS) {

                    goto invalid;

                } else if (!(cmd->type & argument_number[cf->args->nelts - 1]))
                {
                    goto invalid;
                }
            }
/*这里举一个例子用于下面的解析NGX_DIRECT_CONF 和 NGX_MAIN_CONF
 * 假设分配2个void*大小的数组指针，void ****ctx = malloc(sizeof(void*)*2);
 *1. 假设a=1，并且ctx[0] = &a;这就类似于NGX_DIRECT_CONF的情况：
 *   即通过conf=ctx[0]就可以取到a的地址，(void**)仅仅是为了强制转换，也可以不用
 *2. NGX_MAIN_CONF的情况，ctx[1]目前没有被赋予地址，而是在后续的set函数里面设置，
 *   那么先设置conf=&ctx[1],并且将conf传入后续的set函数，然后在set函数里面设置，同样达到
 *   给ctx赋值的目的。同样(void**)仅仅是为了强制转换
 * */
            /* set up the directive's configuration context */
            /*获取指令工作的conf指针*/
            conf = NULL;
            ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "ngx_modules[%d]->index=%d,NGX_DIRECT_CONF=0x%xi,NGX_MAIN_CONF=0x%xi",i,ngx_modules[i]->index,NGX_DIRECT_CONF,NGX_MAIN_CONF);
            /*NGX_DIRECT_CONF常量单纯用来指定配置存储区的寻址方法，只用于core模块*/
            if (cmd->type & NGX_DIRECT_CONF) {
                ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,"NGX_DIRECT_CONF");
                /*这里可以直接取数组元素，是因为前面已经调用过了conf_create函数,这里的内存已经分配好了*/
                conf = ((void **) cf->ctx)[ngx_modules[i]->index]; /*这里的(void **)只是做一个强制类型转换，实际上只要cf->ctx[ngx_modules[i]->index];就可以了*/

            } else if (cmd->type & NGX_MAIN_CONF) {
                /*NGX_MAIN_CONF常量有两重含义，
                 * 其一是指定指令的使用上下文是main（其实还是指core模块），
                 * 所以，在代码中常常可以见到使用上下文是main的指令的cmd->type属性定义如下：
                 * NGX_MAIN_CONF|NGX_DIRECT_CONF|...
                 * 表示指令使用上下文是main，conf寻址方式是直接寻址。
                 * 其二是指定配置存储区的寻址方法。
                 * 使用NGX_MAIN_CONF还表示指定配置存储区的寻址方法的指令有4个：“events”、“http”、“mail”、“imap”。
                 * 这四个指令也有共同之处——都是使用上下文是main的块指令，
                 * 并且块中的指令都使用其他类型的模块（分别是event模块、http模块、mail模块和mail模块）来处理。
                 *
                 * NGX_MAIN_CONF|NGX_CONF_BLOCK|...
                 * 后面分析ngx_http_block()函数时，再具体分析为什么需要NGX_MAIN_CONF这种配置寻址方式。*/
                ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,"NGX_MAIN_CONF");
                conf = &(((void **) cf->ctx)[ngx_modules[i]->index]);/*在这里取地址，是因为要在set函数里面在对ctx进行内存的分配和设置*/

            } else if (cf->ctx) {
                ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,"cf->ctx is not null");
                /*除开core模块，其他类型的模块都会使用第三种配置寻址方式，也就是根据cmd->conf的值从cf->ctx中取出对应的配置。
                 * 举http模块为例，cf->conf的可选值是
                 * NGX_HTTP_MAIN_CONF_OFFSET、NGX_HTTP_SRV_CONF_OFFSET、NGX_HTTP_LOC_CONF_OFFSET，
                 * 分别对应“http{}”、“server{}”、“location{}”这三个http配置级别。*/
                /*conf is the offset of the cmd, values are:
                 * NGX_HTTP_MAIN_CONF_OFFSET
                 * NGX_HTTP_SRV_CONF_OFFSET
                 * NGX_HTTP_LOC_CONF_OFFSET
                *cf->ctx = conf->ctx = cycle->conf_ctx, ****conf_ctx*
                *confp is where stores specific configure pointer array*
                *use epoll 和worker_connectinos 都是使用的这种方式*/
                /*此处的cf->ctx一般来说会被第二种配置解析是重新分配，如在函数ngx_events_block中就会把这个ctx值重新赋值*/
                confp = *(void **) ((char *) cf->ctx + cmd->conf);

                if (confp) {
                    /**/
                    conf = confp[ngx_modules[i]->ctx_index];/*这里的这个值是在event，http，mail，imap中重新分配的*/
                }
            }
            /*调用command set回调函数执行配置赋值*/
            rv = cmd->set(cf, cmd, conf);

            if (rv == NGX_CONF_OK) {
                return NGX_OK;
            }

            if (rv == NGX_CONF_ERROR) {
                return NGX_ERROR;
            }

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%s\" directive %s", name->data, rv);

            return NGX_ERROR;
        }
    }

    if (found) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%s\" directive is not allowed here", name->data);

        return NGX_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unknown directive \"%s\"", name->data);

    return NGX_ERROR;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid number of arguments in \"%s\" directive",
                       name->data);

    return NGX_ERROR;
}


static ngx_int_t
ngx_conf_read_token(ngx_conf_t *cf)
{
    u_char      *start, ch, *src, *dst;
    off_t        file_size;
    size_t       len;
    ssize_t      n, size;
    ngx_uint_t   found, need_space, last_space, sharp_comment, variable;
    ngx_uint_t   quoted, s_quoted, d_quoted, start_line;
    ngx_str_t   *word;
    ngx_buf_t   *b;

    found = 0;
    need_space = 0;
    last_space = 1;
    sharp_comment = 0;
    variable = 0;
    quoted = 0;
    s_quoted = 0;
    d_quoted = 0;

    cf->args->nelts = 0;/*设置保存参数的数组个数为0，即清空保存配置的数组*/
    /*获取配置文件的buffer*/
    b = cf->conf_file->buffer;
    /*上一次读取结束的文件buf位置,第一次读取时为文件的起始位置*/ 
    start = b->pos;
    /*上一次读取的结束行数*/
    start_line = cf->conf_file->line;
    /*配置文件大小(字节)*/
    file_size = ngx_file_size(&cf->conf_file->file.info);
    ngx_conf_log_error(NGX_LOG_DEBUG,cf,0,"file_size=%lu,start_line=%uz",file_size,start_line);
    for ( ;; ) {
        /*第一次，b->pos = b->last,后续b->last指向读取buffer的结尾，
         * 从第2次循环开始，如果为真，表示前一次读取的buffer已经全部解析完毕，需要进入判断一下是否文件已经读完，或者没有读完的话，继续读取
         * 第2次以后if为真的情况是，文件的大小大于buffer的长度(4096)，此时需要多次读取*/
        if (b->pos >= b->last) {
            /*如果偏移量大于文件大小,说明文件已读取完毕，返回NGX_CONF_FILE_DONE*/
            if (cf->conf_file->file.offset >= file_size) {

                if (cf->args->nelts > 0 || !last_space) {

                    if (cf->conf_file->file.fd == NGX_INVALID_FILE) {
                        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                           "unexpected end of parameter, "
                                           "expecting \";\"");
                        return NGX_ERROR;
                    }

                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                  "unexpected end of file, "
                                  "expecting \";\" or \"}\"");
                    return NGX_ERROR;
                }
                ngx_conf_log_error(NGX_LOG_DEBUG,cf,0,"start =%d,pos=%d",start,b->pos);
                return NGX_CONF_FILE_DONE;
            }
            /*这个两个值在重新执行for循环的情况下应该相等，因为前面刚刚把b->pos赋值给了start*/
            len = b->pos - start; /*len表示还有多少已扫描但是没有被解析*/
            /*如果这个长度超过了最大文件buffer,NGX_CONF_BUFFER(4096)，出错返回*/
            if (len == NGX_CONF_BUFFER) {
                cf->conf_file->line = start_line;

                if (d_quoted) {
                    ch = '"';

                } else if (s_quoted) {
                    ch = '\'';

                } else {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "too long parameter \"%*s...\" started",
                                       10, start);
                    return NGX_ERROR;
                }

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "too long parameter, probably "
                                   "missing terminating \"%c\" character", ch);
                return NGX_ERROR;
            }
            /**/
            if (len) {
                ngx_memmove(b->start, start, len);
            }

            size = (ssize_t) (file_size - cf->conf_file->file.offset);
            /*即文件大小大于分配的buffer长度，size取为buffer长度*/
            if (size > b->end - (b->start + len)) {
                size = b->end - (b->start + len);
            }
            /*读取size大小的文件数据到buf中，起始地址为b->start + len,修改文件偏移量*/
            n = ngx_read_file(&cf->conf_file->file, b->start + len, size,
                              cf->conf_file->file.offset);

            if (n == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (n != size) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   ngx_read_file_n " returned "
                                   "only %z bytes instead of %z",
                                   n, size);
                return NGX_ERROR;
            }
            /*修改当前buf的位置b->pos*/
            b->pos = b->start + len;
            /*指向数据的结尾*/
            b->last = b->pos + n;
            start = b->start;
        }
        /*一个字节一个字节地循环处理文件buff内容*/
        ch = *b->pos++;
        /*如果是换行符*/
        if (ch == LF) {
            cf->conf_file->line++;//处理的行数+1

            if (sharp_comment) {//修改注释行标记位
                sharp_comment = 0;
            }
        }
        /*如果前面是#开头的注释，直接跳过#后面的所有字符，直到上面的遇到换行符后，
         * 将该注释标记去除，表示注释结束，新的行开始0*/
        if (sharp_comment) {
            continue;
        }
        /*前面有反斜杠转义字符\,说明这个字符是一个转义字符，忽略\后面的字符*/
        if (quoted) {
            quoted = 0;
            continue;
        }
        /*need_space默认为0，单引号或者双引号结束后，需要有以下分隔符：
         * 空格，制表符，回车，换行，分号，左大括号，右小括号
         * 遇到其它都是错误的，返回error*/
        if (need_space) {
            /*如果遇到空格，制表符，回车，换行，则将need_space清空，last_space置1*/
            if (ch == ' ' || ch == '\t' || ch == CR || ch == LF) {
                last_space = 1;
                need_space = 0;
                continue;
            }
            /*如果遇到分号；则该行读取结束*/
            if (ch == ';') {
                return NGX_OK;
            }
            /*遇到'{'表示新的block的开始*/
            if (ch == '{') {
                return NGX_CONF_BLOCK_START;
            }
            
            if (ch == ')') {
                last_space = 1;
                need_space = 0;

            } else {
                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                    "unexpected \"%c\"", ch);
                 return NGX_ERROR;
            }
        }
        /*last_space初始化为1，last_space表示上一个字符为字符串分隔符,需要重新计算start,以表示新的token的起始地址*/
        if (last_space) {
            /*遇到空格，制表符，回车，换行等字符，则无需处理*/
            if (ch == ' ' || ch == '\t' || ch == CR || ch == LF) {
                continue;
            }

            start = b->pos - 1;/*更新start值，作为新的token(关键字)的起始地址*/
            start_line = cf->conf_file->line;

            switch (ch) {
            /*遇到；或者{，直接返回*/
            case ';':
            case '{':
                if (cf->args->nelts == 0) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "unexpected \"%c\"", ch);
                    return NGX_ERROR;
                }

                if (ch == '{') {
                    return NGX_CONF_BLOCK_START;
                }

                return NGX_OK;
             
            case '}': //遇到}也返回
                if (cf->args->nelts != 0) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "unexpected \"}\"");
                    return NGX_ERROR;
                }

                return NGX_CONF_BLOCK_DONE;

            case '#':/*遇到#，设置sharp_comment标记*/
                sharp_comment = 1;
                continue;

            case '\\':/*遇到\，设置quoted=1，last_space=0*/
                quoted = 1;
                last_space = 0;
                continue;

            case '"'://遇到第一个“，设置d_quoted为1
                start++;
                d_quoted = 1;
                last_space = 0;
                continue;

            case '\''://遇到第一个单引号',设置s_quoted为1
                start++;
                s_quoted = 1;
                last_space = 0;
                continue;

            default:
                last_space = 0;
            }

        } else {
            if (ch == '{' && variable) {
                continue;
            }

            variable = 0;

            if (ch == '\\') {
                quoted = 1;
                continue;
            }
            /*遇到$符，设置variable为1*/
            if (ch == '$') {
                variable = 1;
                continue;
            }

            if (d_quoted) {
                if (ch == '"') {//遇到第二个双引号”，设置d_quoted=0,need_space=1,found=1
                    d_quoted = 0;
                    need_space = 1;
                    found = 1;
                }

            } else if (s_quoted) {//遇到第二个单引号’，设置s_quoted=0,need_space=1,found=1
                if (ch == '\'') {
                    s_quoted = 0;
                    need_space = 1;
                    found = 1;
                }

            } else if (ch == ' ' || ch == '\t' || ch == CR || ch == LF
                       || ch == ';' || ch == '{')//遇到空格，制表符，回车，换行符，分号，{，设置last_space=1,found=1
            {
                last_space = 1;
                found = 1;
            }
            //正常情况下，遇到空格或分号结束时，设置了last_space=1,found=1
            if (found) {
                /*args是初始化为10个ngx_str_t大小的动态数组，在ngx_init_cycle中初始化
                 * 存放配置文件中的一行中的关键字，如：
                 * worker_processes  1;
                 * args的第一个数组元素就是 worker_process
                 * 第二个数组元素就是1*/
                word = ngx_array_push(cf->args);//找到数组可用的位置
                if (word == NULL) {
                    return NGX_ERROR;
                }
                /*文件数据的起始位置为start，当前的位置为b->pos*/
                word->data = ngx_pnalloc(cf->pool, b->pos - start + 1);
                if (word->data == NULL) {
                    return NGX_ERROR;
                }
                /*将start开始的数据拷贝到word->data中，并记录拷贝的大小len*/
                for (dst = word->data, src = start, len = 0;
                     src < b->pos - 1;
                     len++)
                {
                    if (*src == '\\') {
                        switch (src[1]) {
                        case '"':
                        case '\'':
                        case '\\':
                            src++;
                            break;

                        case 't':
                            *dst++ = '\t';
                            src += 2;
                            continue;

                        case 'r':
                            *dst++ = '\r';
                            src += 2;
                            continue;

                        case 'n':
                            *dst++ = '\n';
                            src += 2;
                            continue;
                        }

                    }
                    *dst++ = *src++;
                }
                *dst = '\0';
                word->len = len;
                /*正常情况下，遇到分号，返回一行*/
                if (ch == ';') {
                    return NGX_OK;
                }
                /*如果是一个block，如event，则返回NGX_CONF_BLOCK_START*/
                if (ch == '{') {
                    return NGX_CONF_BLOCK_START;
                }
                /*等于其它的符号，如空格，则继续循环*/
                found = 0;
            }
        }
    }
}


char *
ngx_conf_include(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char        *rv;
    ngx_int_t    n;
    ngx_str_t   *value, file, name;
    ngx_glob_t   gl;

    value = cf->args->elts;
    file = value[1];

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);

    if (ngx_conf_full_name(cf->cycle, &file, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (strpbrk((char *) file.data, "*?[") == NULL) {

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);

        return ngx_conf_parse(cf, &file);
    }

    ngx_memzero(&gl, sizeof(ngx_glob_t));

    gl.pattern = file.data;
    gl.log = cf->log;
    gl.test = 1;

    if (ngx_open_glob(&gl) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_open_glob_n " \"%s\" failed", file.data);
        return NGX_CONF_ERROR;
    }

    rv = NGX_CONF_OK;

    for ( ;; ) {
        n = ngx_read_glob(&gl, &name);

        if (n != NGX_OK) {
            break;
        }

        file.len = name.len++;
        file.data = ngx_pstrdup(cf->pool, &name);
        if (file.data == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);

        rv = ngx_conf_parse(cf, &file);

        if (rv != NGX_CONF_OK) {
            break;
        }
    }

    ngx_close_glob(&gl);

    return rv;
}


ngx_int_t
ngx_conf_full_name(ngx_cycle_t *cycle, ngx_str_t *name, ngx_uint_t conf_prefix)
{
    ngx_str_t  *prefix;

    prefix = conf_prefix ? &cycle->conf_prefix : &cycle->prefix;

    return ngx_get_full_name(cycle->pool, prefix, name);
}


ngx_open_file_t *
ngx_conf_open_file(ngx_cycle_t *cycle, ngx_str_t *name)
{
    ngx_str_t         full;
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_open_file_t  *file;

#if (NGX_SUPPRESS_WARN)
    ngx_str_null(&full);
#endif

    if (name->len) {
        full = *name;

        if (ngx_conf_full_name(cycle, &full, 0) != NGX_OK) {
            return NULL;
        }

        part = &cycle->open_files.part;
        file = part->elts;

        for (i = 0; /* void */ ; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }
                part = part->next;
                file = part->elts;
                i = 0;
            }

            if (full.len != file[i].name.len) {
                continue;
            }

            if (ngx_strcmp(full.data, file[i].name.data) == 0) {
                return &file[i];
            }
        }
    }

    file = ngx_list_push(&cycle->open_files);
    if (file == NULL) {
        return NULL;
    }

    if (name->len) {
        file->fd = NGX_INVALID_FILE;
        file->name = full;

    } else {
        file->fd = ngx_stderr;
        file->name = *name;
    }

    file->flush = NULL;
    file->data = NULL;

    return file;
}


static void
ngx_conf_flush_files(ngx_cycle_t *cycle)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_open_file_t  *file;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "flush files");

    part = &cycle->open_files.part;
    file = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            file = part->elts;
            i = 0;
        }

        if (file[i].flush) {
            file[i].flush(&file[i], cycle->log);
        }
    }
}


void ngx_cdecl
ngx_conf_log_error(ngx_uint_t level, ngx_conf_t *cf, ngx_err_t err,
    const char *fmt, ...)
{
    u_char   errstr[NGX_MAX_CONF_ERRSTR], *p, *last;
    va_list  args;

    last = errstr + NGX_MAX_CONF_ERRSTR;

    va_start(args, fmt);
    p = ngx_vslprintf(errstr, last, fmt, args);
    va_end(args);

    if (err) {
        p = ngx_log_errno(p, last, err);
    }

    if (cf->conf_file == NULL) {
        ngx_log_error(level, cf->log, 0, "%*s", p - errstr, errstr);
        return;
    }

    if (cf->conf_file->file.fd == NGX_INVALID_FILE) {
        ngx_log_error(level, cf->log, 0, "%*s in command line",
                      p - errstr, errstr);
        return;
    }

    ngx_log_error(level, cf->log, 0, "%*s in %s:%ui",
                  p - errstr, errstr,
                  cf->conf_file->file.name.data, cf->conf_file->line);
}


char *
ngx_conf_set_flag_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_str_t        *value;
    ngx_flag_t       *fp;
    ngx_conf_post_t  *post;

    fp = (ngx_flag_t *) (p + cmd->offset);

    if (*fp != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcasecmp(value[1].data, (u_char *) "on") == 0) {
        *fp = 1;

    } else if (ngx_strcasecmp(value[1].data, (u_char *) "off") == 0) {
        *fp = 0;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                     "invalid value \"%s\" in \"%s\" directive, "
                     "it must be \"on\" or \"off\"",
                     value[1].data, cmd->name.data);
        return NGX_CONF_ERROR;
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, fp);
    }

    return NGX_CONF_OK;
}


char *
ngx_conf_set_str_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_str_t        *field, *value;
    ngx_conf_post_t  *post;

    field = (ngx_str_t *) (p + cmd->offset);

    if (field->data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *field = value[1];

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, field);
    }

    return NGX_CONF_OK;
}


char *
ngx_conf_set_str_array_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_str_t         *value, *s;
    ngx_array_t      **a;
    ngx_conf_post_t   *post;

    a = (ngx_array_t **) (p + cmd->offset);

    if (*a == NGX_CONF_UNSET_PTR) {
        *a = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (*a == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    s = ngx_array_push(*a);
    if (s == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    *s = value[1];

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, s);
    }

    return NGX_CONF_OK;
}


char *
ngx_conf_set_keyval_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_str_t         *value;
    ngx_array_t      **a;
    ngx_keyval_t      *kv;
    ngx_conf_post_t   *post;

    a = (ngx_array_t **) (p + cmd->offset);

    if (*a == NULL) {
        *a = ngx_array_create(cf->pool, 4, sizeof(ngx_keyval_t));
        if (*a == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    kv = ngx_array_push(*a);
    if (kv == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    kv->key = value[1];
    kv->value = value[2];

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, kv);
    }

    return NGX_CONF_OK;
}


char *
ngx_conf_set_num_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_int_t        *np;
    ngx_str_t        *value;
    ngx_conf_post_t  *post;


    np = (ngx_int_t *) (p + cmd->offset);

    if (*np != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;
    *np = ngx_atoi(value[1].data, value[1].len);
    if (*np == NGX_ERROR) {
        return "invalid number";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, np);
    }

    return NGX_CONF_OK;
}


char *
ngx_conf_set_size_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    size_t           *sp;
    ngx_str_t        *value;
    ngx_conf_post_t  *post;


    sp = (size_t *) (p + cmd->offset);
    if (*sp != NGX_CONF_UNSET_SIZE) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *sp = ngx_parse_size(&value[1]);
    if (*sp == (size_t) NGX_ERROR) {
        return "invalid value";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, sp);
    }

    return NGX_CONF_OK;
}


char *
ngx_conf_set_off_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    off_t            *op;
    ngx_str_t        *value;
    ngx_conf_post_t  *post;


    op = (off_t *) (p + cmd->offset);
    if (*op != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *op = ngx_parse_offset(&value[1]);
    if (*op == (off_t) NGX_ERROR) {
        return "invalid value";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, op);
    }

    return NGX_CONF_OK;
}


char *
ngx_conf_set_msec_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_msec_t       *msp;
    ngx_str_t        *value;
    ngx_conf_post_t  *post;


    msp = (ngx_msec_t *) (p + cmd->offset);
    if (*msp != NGX_CONF_UNSET_MSEC) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *msp = ngx_parse_time(&value[1], 0);
    if (*msp == (ngx_msec_t) NGX_ERROR) {
        return "invalid value";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, msp);
    }

    return NGX_CONF_OK;
}


char *
ngx_conf_set_sec_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    time_t           *sp;
    ngx_str_t        *value;
    ngx_conf_post_t  *post;


    sp = (time_t *) (p + cmd->offset);
    if (*sp != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *sp = ngx_parse_time(&value[1], 1);
    if (*sp == (time_t) NGX_ERROR) {
        return "invalid value";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, sp);
    }

    return NGX_CONF_OK;
}


char *
ngx_conf_set_bufs_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char *p = conf;

    ngx_str_t   *value;
    ngx_bufs_t  *bufs;


    bufs = (ngx_bufs_t *) (p + cmd->offset);
    if (bufs->num) {
        return "is duplicate";
    }

    value = cf->args->elts;

    bufs->num = ngx_atoi(value[1].data, value[1].len);
    if (bufs->num == NGX_ERROR || bufs->num == 0) {
        return "invalid value";
    }

    bufs->size = ngx_parse_size(&value[2]);
    if (bufs->size == (size_t) NGX_ERROR || bufs->size == 0) {
        return "invalid value";
    }

    return NGX_CONF_OK;
}


char *
ngx_conf_set_enum_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_uint_t       *np, i;
    ngx_str_t        *value;
    ngx_conf_enum_t  *e;

    np = (ngx_uint_t *) (p + cmd->offset);

    if (*np != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;
    e = cmd->post;

    for (i = 0; e[i].name.len != 0; i++) {
        if (e[i].name.len != value[1].len
            || ngx_strcasecmp(e[i].name.data, value[1].data) != 0)
        {
            continue;
        }

        *np = e[i].value;

        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "invalid value \"%s\"", value[1].data);

    return NGX_CONF_ERROR;
}


char *
ngx_conf_set_bitmask_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_uint_t          *np, i, m;
    ngx_str_t           *value;
    ngx_conf_bitmask_t  *mask;


    np = (ngx_uint_t *) (p + cmd->offset);
    value = cf->args->elts;
    mask = cmd->post;

    for (i = 1; i < cf->args->nelts; i++) {
        for (m = 0; mask[m].name.len != 0; m++) {

            if (mask[m].name.len != value[i].len
                || ngx_strcasecmp(mask[m].name.data, value[i].data) != 0)
            {
                continue;
            }

            if (*np & mask[m].mask) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "duplicate value \"%s\"", value[i].data);

            } else {
                *np |= mask[m].mask;
            }

            break;
        }

        if (mask[m].name.len == 0) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "invalid value \"%s\"", value[i].data);

            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


#if 0

char *
ngx_conf_unsupported(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    return "unsupported on this platform";
}

#endif


char *
ngx_conf_deprecated(ngx_conf_t *cf, void *post, void *data)
{
    ngx_conf_deprecated_t  *d = post;

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "the \"%s\" directive is deprecated, "
                       "use the \"%s\" directive instead",
                       d->old_name, d->new_name);

    return NGX_CONF_OK;
}


char *
ngx_conf_check_num_bounds(ngx_conf_t *cf, void *post, void *data)
{
    ngx_conf_num_bounds_t  *bounds = post;
    ngx_int_t  *np = data;

    if (bounds->high == -1) {
        if (*np >= bounds->low) {
            return NGX_CONF_OK;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "value must be equal to or greater than %i",
                           bounds->low);

        return NGX_CONF_ERROR;
    }

    if (*np >= bounds->low && *np <= bounds->high) {
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "value must be between %i and %i",
                       bounds->low, bounds->high);

    return NGX_CONF_ERROR;
}
