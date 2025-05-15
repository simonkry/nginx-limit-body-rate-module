
/**
 * @file   ngx_http_limit_body_rate_filter_module.c
 * @author Kryštof Šimon <simonkry@fit.cvut.cz>
 * @date   2025-05-13 20:10:59
 *
 * @brief  nginx module for rate limiting HTTP request body data,
 *         ensuring controlled data flow per single connection.
 *
 * @credits
 * ngx_http_delay_body_filter_module exemplary module by nginx
 * @see https://nginx.org/en/docs/dev/development_guide.html#http_request_body_filters
 *
 * ngx_http_write_filter_module by nginx
 * @see  https://github.com/nginx/nginx/blob/release-1.26.3/src/http/ngx_http_write_filter_module.c
 *
 * ngx_http_limit_req_module by nginx
 * @see  https://github.com/nginx/nginx/blob/release-1.26.3/src/http/modules/ngx_http_limit_req_module.c
 *
 * ngx_limit_upload_module by cfsego
 * @see  https://github.com/cfsego/limit_upload_rate
 */


/*
 * Copyright (C) 2002-2021 Igor Sysoev
 * Copyright (C) 2011-2024 Nginx, Inc.
 * Copyright (C) 2025 Kryštof Šimon
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_chain_t                     *out;
    ngx_http_event_handler_pt        read_event_handler;
    size_t                           limit_upload_rate;
    size_t                           limit_upload_rate_after;
    ngx_event_t                      event;
} ngx_http_limit_body_rate_ctx_t;


typedef struct {
    ngx_http_complex_value_t        *limit_upload_rate;
    ngx_http_complex_value_t        *limit_upload_rate_after;
    ngx_http_complex_value_t        *limit_download_rate;
    ngx_http_complex_value_t        *limit_download_rate_after;
} ngx_http_limit_body_rate_conf_t;


static ngx_int_t ngx_http_limit_upload_body_rate_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static void ngx_http_limit_upload_body_rate_event_handler(ngx_event_t *ev);
static void ngx_http_limit_body_rate_free_chain(ngx_http_request_t *r,
    ngx_chain_t **chain);

static void *ngx_http_limit_body_rate_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_limit_body_rate_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_limit_body_rate_init(ngx_conf_t *cf);

static ngx_int_t ngx_http_limit_body_rate_handler(ngx_http_request_t *r);
static void ngx_http_limit_body_rate_timer_cleanup(void *data);


static ngx_command_t  ngx_http_limit_body_rate_commands[] = {

    { ngx_string("limit_upload_rate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
        |NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_body_rate_conf_t, limit_upload_rate),
      NULL },

    { ngx_string("limit_upload_rate_after"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
        |NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_body_rate_conf_t, limit_upload_rate_after),
      NULL },

    { ngx_string("limit_download_rate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
        |NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_body_rate_conf_t, limit_download_rate),
      NULL },

    { ngx_string("limit_download_rate_after"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
        |NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_body_rate_conf_t, limit_download_rate_after),
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_limit_body_rate_module_ctx = {
    NULL,  /* preconfiguration */
    ngx_http_limit_body_rate_init,  /* postconfiguration */

    NULL,  /* create main configuration */
    NULL,  /* init main configuration */

    NULL,  /* create server configuration */
    NULL,  /* merge server configuration */

    ngx_http_limit_body_rate_create_loc_conf,  /* create location configuration */
    ngx_http_limit_body_rate_merge_loc_conf  /* merge location configuration */
};


ngx_module_t  ngx_http_limit_body_rate_module = {
    NGX_MODULE_V1,
    &ngx_http_limit_body_rate_module_ctx,  /* module context */
    ngx_http_limit_body_rate_commands,  /* module directives */
    NGX_HTTP_MODULE,  /* module type */
    NULL,  /* init master */
    NULL,  /* init module */
    NULL,  /* init process */
    NULL,  /* init thread */
    NULL,  /* exit thread */
    NULL,  /* exit process */
    NULL,  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_request_body_filter_pt  ngx_http_next_request_body_filter;


static ngx_int_t
ngx_http_limit_upload_body_rate_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    off_t                               size_in, limit;
    ngx_int_t                           rc;
    ngx_msec_t                          current_time, start_time, delay;
    ngx_chain_t                        *ln;
    ngx_connection_t                   *c;
    ngx_http_request_body_t            *rb;
    ngx_http_limit_body_rate_ctx_t     *ctx;

    c = r->connection;

    if (c->error) {
        return NGX_ERROR;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_limit_body_rate_module);

    if (!ctx) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "limit upload body filter: no upload rate limit set");
        return ngx_http_next_request_body_filter(r, in);
    }

    if (!in && !ctx->out) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "limit upload body filter: "
                       "no input chain and buffering chain");
        return ngx_http_next_request_body_filter(r, NULL);
    }

    size_in = 0;

    for (ln = in; ln; ln = ln->next) {
        size_in += ngx_buf_size(ln->buf);
    }

    current_time = ngx_cached_time->sec * 1000 + ngx_cached_time->msec;
    start_time = r->start_sec * 1000 + r->start_msec;
    rb = r->request_body;
    rb->received += size_in;

    limit = (off_t) (ctx->limit_upload_rate * (current_time - start_time)
                     - 1000 * (rb->received - ctx->limit_upload_rate_after))
                     / 1000;

    if (ngx_chain_add_copy(r->pool, &ctx->out, in) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

#if 0
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "limit upload body filter: time_ms_diff=%ui",
                   current_time - start_time);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "limit upload body filter: timer_set=%ui",
                   ctx->event.timer_set);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "limit upload body filter: time=%T.%03M",
                   ngx_timeofday()->sec, ngx_timeofday()->msec);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "limit upload body filter: size_in=%O, received=%O, limit=%O",
                   size_in, rb->received, limit);
#endif

    if (limit < 0) {

        /* set up a timer if it hasn't already been initialized */

        if (!ctx->event.timer_set) {
            delay = (ngx_msec_t)
                    (-limit * 1000 / ctx->limit_upload_rate + 1);  /* ms */

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "limit upload body filter: delay=%ui, "
                           "setting up timer", delay);

            ngx_add_timer(&ctx->event, delay);

            rb->filter_need_buffering = 1;
        }

        rc = ngx_http_next_request_body_filter(r, NULL);

        /* set read_event_handler to handle premature client connection closure */

        if (r->read_event_handler != ngx_http_test_reading) {
            ctx->read_event_handler = r->read_event_handler;
            r->read_event_handler = ngx_http_test_reading;
        }

    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "limit upload body filter: "
                       "passing the buffer chain to the next body filter");

        /* pass the buffer chain to the next body filter */

        rc = ngx_http_next_request_body_filter(r, ctx->out);

        ngx_http_limit_body_rate_free_chain(r, &ctx->out);
    }

    return rc;
}


static void
ngx_http_limit_upload_body_rate_event_handler(ngx_event_t *ev)
{
    ngx_connection_t                *c;
    ngx_http_request_t              *r;
    ngx_http_limit_body_rate_ctx_t  *ctx;

    r = ev->data;
    c = r->connection;

    if (c->error) {
        return;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_limit_body_rate_module);

    r->read_event_handler = ctx->read_event_handler;
    r->request_body->filter_need_buffering = 0;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "limit upload body rate event handler: "
                   "post event: c->read");

    ngx_post_event(c->read, &ngx_posted_events);
}


static void
ngx_http_limit_body_rate_free_chain(ngx_http_request_t *r, ngx_chain_t **chain) {
    ngx_chain_t *cl, *ln;

    for (cl = *chain; cl; /* void */) {
        ln = cl;
        cl = cl->next;
        ngx_free_chain(r->pool, ln);
    }

    *chain = NULL;
}


static void *
ngx_http_limit_body_rate_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_limit_body_rate_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_limit_body_rate_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->limit_upload_rate = NGX_CONF_UNSET_PTR;
    conf->limit_upload_rate_after = NGX_CONF_UNSET_PTR;
    conf->limit_download_rate = NGX_CONF_UNSET_PTR;
    conf->limit_download_rate_after = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_http_limit_body_rate_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_limit_body_rate_conf_t  *conf = child;
    ngx_http_limit_body_rate_conf_t  *prev = parent;

    ngx_conf_merge_ptr_value(conf->limit_upload_rate,
        prev->limit_upload_rate, NULL);
    ngx_conf_merge_ptr_value(conf->limit_upload_rate_after,
        prev->limit_upload_rate_after, NULL);
    ngx_conf_merge_ptr_value(conf->limit_download_rate,
        prev->limit_download_rate, NULL);
    ngx_conf_merge_ptr_value(conf->limit_download_rate_after,
        prev->limit_download_rate_after, NULL);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_limit_body_rate_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt              *h;
    ngx_http_core_main_conf_t        *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_limit_body_rate_handler;

    ngx_http_next_request_body_filter = ngx_http_top_request_body_filter;
    ngx_http_top_request_body_filter = ngx_http_limit_upload_body_rate_filter;

    return NGX_OK;
}


static ngx_int_t
ngx_http_limit_body_rate_handler(ngx_http_request_t *r)
{
    size_t                            limit_upload_rate;
    ngx_http_cleanup_t               *cln;
    ngx_http_limit_body_rate_ctx_t   *ctx;
    ngx_http_limit_body_rate_conf_t  *lbcf;

    lbcf = ngx_http_get_module_loc_conf(r, ngx_http_limit_body_rate_module);
    limit_upload_rate =
            ngx_http_complex_value_size(r,lbcf->limit_upload_rate, 0);

    if (limit_upload_rate) {

        /* allocate module context (and set zeros) */

        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_limit_body_rate_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "limit body rate handler: ctx=%p", ctx);

        ngx_http_set_ctx(r, ctx, ngx_http_limit_body_rate_module);

        ctx->limit_upload_rate = limit_upload_rate;
        ctx->limit_upload_rate_after =
              ngx_http_complex_value_size(r, lbcf->limit_upload_rate_after, 0);

        ctx->event.handler = ngx_http_limit_upload_body_rate_event_handler;
        ctx->event.data = r;
        ctx->event.log = r->connection->log;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "limit body rate handler: limit_upload_rate=%uz",
                       limit_upload_rate);

        /* cleanup to remove timer in case of abnormal termination */

        cln = ngx_http_cleanup_add(r, 0);
        if (cln == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        cln->handler = ngx_http_limit_body_rate_timer_cleanup;
        cln->data = ctx;
    }

    r->limit_rate =
            ngx_http_complex_value_size(r, lbcf->limit_download_rate, 0);
    r->limit_rate_after =
            ngx_http_complex_value_size(r, lbcf->limit_download_rate_after, 0);
    r->limit_rate_set = 1;
    r->limit_rate_after_set = 1;

    return NGX_OK;
}


static void
ngx_http_limit_body_rate_timer_cleanup(void *data)
{
    ngx_http_limit_body_rate_ctx_t *ctx = data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->event.log, 0,
                   "limit body rate, timer cleanup");

    if (ctx->event.timer_set) {
        ngx_del_timer(&ctx->event);
    }
}
