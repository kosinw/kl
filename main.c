#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "mpc.h"

char buffer[256];

char *readline(char *prompt)
{
    fputs(prompt, stdout);
    fgets(buffer, 2048, stdin);
    char *cpy = malloc(strlen(buffer) + 1);
    strcpy(cpy, buffer);
    cpy[strlen(cpy) - 1] = '\0';
    return cpy;
}

#define KLASSERT(args, cond, fmt, ...)              \
    if (!(cond))                                    \
    {                                               \
        lval_t *err = lval_err(fmt, ##__VA_ARGS__); \
        lval_del(args);                             \
        return err;                                 \
    }

#define KLASSERT_NUM(func, args, num)                               \
    KLASSERT(args, args->count == num,                              \
             "Function '%s' has an incorrect number of arguments. " \
             "Got %i. Expected %i.",                                \
             func, args->count, num)

#define KLASSERT_TYPE(func, args, index, expect)            \
    KLASSERT(args, args->cell[index]->type == expect,       \
             "Function '%s' has an incorrect argument %i. " \
             "Got %s. Expected %s.",                        \
             func, index + 1, ltype_name(args->cell[index]->type), ltype_name(expect))

#define KLARGS(args, num_args, err, ...) KLASSERT(args, args->count == num_args, err, ##__VA_ARGS__)
#define KLEMPTY(args, err, ...) KLASSERT(args, args->count != 0, err, ##__VA_ARGS__)

mpc_parser_t *number;
mpc_parser_t *symbol;
mpc_parser_t *comment;
mpc_parser_t *string;
mpc_parser_t *expr;
mpc_parser_t *sexpr;
mpc_parser_t *qexpr;
mpc_parser_t *program;

struct lval;
struct lenv;

typedef struct lval lval_t;
typedef struct lenv lenv_t;

typedef lval_t *(*lbuiltin_t)(lenv_t *, lval_t *);

void lenv_put(lenv_t *e, lval_t *k, lval_t *v);
void lenv_del(lenv_t *e);
void lenv_def(lenv_t *e, lval_t *k, lval_t *v);
void lenv_add_builtin(lenv_t *e, char *name, lbuiltin_t func);
void lenv_add_builtins(lenv_t *e);

lenv_t *lenv_copy(lenv_t *e);
lenv_t *lenv_new(void);
lval_t *lenv_get(lenv_t *e, lval_t *k);

void lval_print(lval_t *v);
void lval_println(lval_t *v);
lval_t *lval_read(mpc_ast_t *t);
void lval_print_str(lval_t *v);
void lval_del(lval_t *v);

lval_t *lval_eval_sexpr(lenv_t *e, lval_t *v);
lval_t *lval_eval(lenv_t *e, lval_t *v);
lval_t *lval_pop(lval_t *v, int i);
lval_t *lval_sexpr(void);
lval_t *lval_qexpr(void);
lval_t *lval_add(lval_t *v, lval_t *x);
lval_t *lval_take(lval_t *v, int i);
lval_t *lval_join(lval_t *x, lval_t *y);
lval_t *lval_fun(lbuiltin_t func);
lval_t *lval_sym(char *name);
lval_t *lval_str(char *s);
lval_t *lval_copy(lval_t *v);
lval_t *lval_err(char *fmt, ...);
lval_t *lval_call(lenv_t *e, lval_t *f, lval_t *a);
lval_t *lval_lambda(lval_t *formals, lval_t *body);
lval_t *lval_read_str(mpc_ast_t *t);
int lval_eq(lval_t *a, lval_t *b);

lval_t *builtin_head(lenv_t *e, lval_t *a);
lval_t *builtin_tail(lenv_t *e, lval_t *a);
lval_t *builtin_list(lenv_t *e, lval_t *a);
lval_t *builtin_eval(lenv_t *e, lval_t *a);
lval_t *builtin_join(lenv_t *e, lval_t *a);
lval_t *builtin_cons(lenv_t *e, lval_t *a);
lval_t *builtin_len(lenv_t *e, lval_t *a);
lval_t *builtin_init(lenv_t *e, lval_t *a);
lval_t *builtin_def(lenv_t *e, lval_t *a);
lval_t *builtin_put(lenv_t *e, lval_t *a);
lval_t *builtin_var(lenv_t *e, lval_t *a, char *func);
lval_t *builtin_env(lenv_t *e, lval_t *a);
lval_t *builtin_exit(lenv_t *e, lval_t *a);
lval_t *builtin_fun(lenv_t *e, lval_t *a);
lval_t *builtin_lambda(lenv_t *e, lval_t *a);
lval_t *builtin_add(lenv_t *e, lval_t *a);
lval_t *builtin_sub(lenv_t *e, lval_t *a);
lval_t *builtin_mul(lenv_t *e, lval_t *a);
lval_t *builtin_div(lenv_t *e, lval_t *a);
lval_t *builtin_eq(lenv_t *e, lval_t *a);
lval_t *builtin_ne(lenv_t *e, lval_t *a);
lval_t *builtin_if(lenv_t *e, lval_t *a);
lval_t *builtin_op(lenv_t *e, lval_t *a, char *op);

lval_t *builtin_ord(lenv_t *e, lval_t *a, char *op);
lval_t *builtin_lt(lenv_t *e, lval_t *a);
lval_t *builtin_gt(lenv_t *e, lval_t *a);
lval_t *builtin_le(lenv_t *e, lval_t *a);
lval_t *builtin_ge(lenv_t *e, lval_t *a);

lval_t *builtin_load(lenv_t *e, lval_t *a);
lval_t *builtin_print(lenv_t *e, lval_t *a);
lval_t *builtin_error(lenv_t *e, lval_t *a);
lval_t *builtin_joins(lenv_t *e, lval_t *a);
lval_t *builtin_heads(lenv_t *e, lval_t *a);
lval_t *builtin_tails(lenv_t *e, lval_t *a);
lval_t *builtin_read(lenv_t *e, lval_t *a);
lval_t *builtin_show(lenv_t *e, lval_t *a);

lval_t *builtin_readfile(lenv_t *e, lval_t *a);

lval_t *builtin_or(lenv_t *e, lval_t *a);
lval_t *builtin_and(lenv_t *e, lval_t *a);
lval_t *builtin_not(lenv_t *e, lval_t *a);

typedef enum lval_type
{
    LVAL_NUM,
    LVAL_ERR,
    LVAL_SYM,
    LVAL_SEXPR,
    LVAL_QEXPR,
    LVAL_FUN,
    LVAL_STR
} lval_type_t;

char *ltype_name(lval_type_t);

struct lval
{
    // Type info.
    lval_type_t type;

    // Symbols + Numbers
    long num;

    union {
        char *err;
        char *sym;
        char *str;
    };

    // Functions
    lbuiltin_t builtin;
    lenv_t *env;
    lval_t *formals;
    lval_t *body;

    // Expressions.
    int count;
    lval_t **cell;
};

struct lenv
{
    lenv_t *par;
    int count;
    char **syms;
    lval_t **vals;
};

void lenv_add_builtin(lenv_t *e, char *name, lbuiltin_t func)
{
    lval_t *k = lval_sym(name);
    lval_t *v = lval_fun(func);
    lenv_put(e, k, v);
    lval_del(k);
    lval_del(v);
}

void lenv_add_builtins(lenv_t *e)
{
    /* List Functions */
    lenv_add_builtin(e, "list", builtin_list);
    lenv_add_builtin(e, "head", builtin_head);
    lenv_add_builtin(e, "tail", builtin_tail);
    lenv_add_builtin(e, "eval", builtin_eval);
    lenv_add_builtin(e, "join", builtin_join);
    lenv_add_builtin(e, "init", builtin_init);
    lenv_add_builtin(e, "cons", builtin_cons);
    lenv_add_builtin(e, "len", builtin_len);

    /* Variable Functions */
    lenv_add_builtin(e, "def", builtin_def);
    lenv_add_builtin(e, "fun", builtin_fun);
    lenv_add_builtin(e, "=", builtin_put);
    lenv_add_builtin(e, "\\", builtin_lambda);
    lenv_add_builtin(e, "env", builtin_env);
    lenv_add_builtin(e, "exit", builtin_exit);

    /* Mathematical Functions */
    lenv_add_builtin(e, "+", builtin_add);
    lenv_add_builtin(e, "-", builtin_sub);
    lenv_add_builtin(e, "*", builtin_mul);
    lenv_add_builtin(e, "/", builtin_div);

    /* Conditional Operator */
    lenv_add_builtin(e, "if", builtin_if);

    /* Equality & Ordering Operators */
    lenv_add_builtin(e, "==", builtin_eq);
    lenv_add_builtin(e, "!=", builtin_ne);
    lenv_add_builtin(e, "<", builtin_lt);
    lenv_add_builtin(e, "<=", builtin_le);
    lenv_add_builtin(e, ">", builtin_gt);
    lenv_add_builtin(e, ">=", builtin_ge);

    /* Boolean Logic Operators */
    lenv_add_builtin(e, "||", builtin_or);
    lenv_add_builtin(e, "&&", builtin_and);
    lenv_add_builtin(e, "!", builtin_not);

    /* String Functions */
    lenv_add_builtin(e, "load", builtin_load);
    lenv_add_builtin(e, "print", builtin_print);
    lenv_add_builtin(e, "error", builtin_error);
    lenv_add_builtin(e, "join.s", builtin_joins);
    lenv_add_builtin(e, "head.s", builtin_heads);
    lenv_add_builtin(e, "tail.s", builtin_tails);
    lenv_add_builtin(e, "read", builtin_read);
    lenv_add_builtin(e, "show", builtin_show);

    /* Platform Functions */
    lenv_add_builtin(e, "readfile", builtin_readfile);
}

lval_t *lval_num(long x)
{
    lval_t *v = malloc(sizeof(lval_t));
    v->type = LVAL_NUM;
    v->num = x;
    return v;
}

lval_t *lval_err(char *fmt, ...)
{
    lval_t *v = malloc(sizeof(lval_t));
    v->type = LVAL_ERR;

    // varargs list
    va_list va;
    va_start(va, fmt);

    // Allocated 1024 bytes of space
    v->err = malloc(1024);

    // printf into the fomat string with a maximum of 1023 characters
    vsnprintf(v->err, 1023, fmt, va);

    // Retrieve all unused memory (+ persists bugs if buffer is overan)
    v->err = realloc(v->err, strlen(v->err) + 1);

    va_end(va);
    return v;
}

lval_t *lval_call(lenv_t *e, lval_t *f, lval_t *a)
{
    if (f->builtin)
    {
        return f->builtin(e, a);
    }

    int given = a->count;
    int total = f->formals->count;

    while (a->count)
    {
        if (f->formals->count == 0)
        {
            lval_del(a);
            return lval_err(
                "Function passed too many arguments. "
                "Got %i. Expected %i.",
                given, total);
        }

        // Pop symbol from formal arguments
        lval_t *sym = lval_pop(f->formals, 0);

        // Hack in variadic arguments
        if (strcmp(sym->sym, "&") == 0)
        {
            if (f->formals->count != 1)
            {
                lval_del(a);
                return lval_err("Function format invalid. "
                                "Symbol '&' not followed by a single symbol.");
            }

            // Next formal should be bound to the rest of the arguments
            lval_t *nsym = lval_pop(f->formals, 0);
            lenv_put(f->env, nsym, builtin_list(e, a));
            lval_del(sym);
            lval_del(nsym);
            break;
        }

        // Pop argument from the list
        lval_t *val = lval_pop(a, 0);

        // Bind argument to formal
        lenv_put(f->env, sym, val);

        lval_del(sym);
        lval_del(val);
    }

    lval_del(a);

    // If there are no more arguments but there is a variadic list...
    if (f->formals->count > 0 && strcmp(f->formals->cell[0]->sym, "&") == 0)
    {
        if (f->formals->count != 2)
        {
            return lval_err(
                "Function format invalid. "
                "Symbol '&' not followed by a single symbol.");
        }

        // Yeet the & symbol.
        lval_del(lval_pop(f->formals, 0));

        /* Pop next symbol and create empty list */
        lval_t *sym = lval_pop(f->formals, 0);
        lval_t *val = lval_qexpr();

        // /* Bind to environment and delete */
        lenv_put(f->env, sym, val);
        lval_del(sym);
        lval_del(val);

        // Just return partial function if there is not at least one argument for the variadic list
        // return lval_copy(f);
    }

    // Non-partial function
    if (f->formals->count == 0)
    {
        f->env->par = e;

        return builtin_eval(
            f->env, lval_add(lval_sexpr(), lval_copy(f->body)));
    }
    else
    {
        // Partial function
        return lval_copy(f);
    }
}

lval_t *lval_sym(char *s)
{
    lval_t *v = malloc(sizeof(lval_t));
    v->type = LVAL_SYM;
    v->sym = malloc(strlen(s) + 1);
    strcpy(v->sym, s);
    return v;
}

lval_t *lval_str(char *s)
{
    lval_t *v = malloc(sizeof(lval_t));
    v->type = LVAL_STR;
    v->str = malloc(strlen(s) + 1);
    strcpy(v->sym, s);
    return v;
}

lval_t *lval_qexpr(void)
{
    lval_t *v = malloc(sizeof(lval_t));
    v->type = LVAL_QEXPR;
    v->count = 0;
    v->cell = NULL;
    return v;
}

lval_t *lval_sexpr(void)
{
    lval_t *v = malloc(sizeof(lval_t));
    v->type = LVAL_SEXPR;
    v->count = 0;
    v->cell = NULL;
    return v;
}

lenv_t *lenv_copy(lenv_t *e)
{
    lenv_t *n = malloc(sizeof(lenv_t));
    n->par = e->par;
    n->count = e->count;
    n->syms = malloc(sizeof(char *) * n->count);
    n->vals = malloc(sizeof(lval_t *) * n->count);

    for (int i = 0; i < e->count; ++i)
    {
        n->syms[i] = malloc(strlen(e->syms[i] + 1));
        strcpy(n->syms[i], e->syms[i]);
        n->vals[i] = lval_copy(e->vals[i]);
    }

    return n;
}

lenv_t *lenv_new(void)
{
    lenv_t *e = malloc(sizeof(lenv_t));
    e->count = 0;
    e->par = NULL;
    e->syms = NULL;
    e->vals = NULL;
    return e;
}

lval_t *lenv_get(lenv_t *e, lval_t *k)
{
    for (int i = 0; i < e->count; ++i)
    {
        if (strcmp(e->syms[i], k->sym) == 0)
        {
            return lval_copy(e->vals[i]);
        }
    }

    if (e->par)
    {
        return lenv_get(e->par, k);
    }

    return lval_err("Unbound Symbol '%s'", k->sym);
}

void lenv_put(lenv_t *e, lval_t *k, lval_t *v)
{
    for (int i = 0; i < e->count; ++i)
    {
        if (strcmp(e->syms[i], k->sym) == 0)
        {
            lval_del(e->vals[i]);
            e->vals[i] = lval_copy(v);
            return;
        }
    }

    e->count++;
    e->vals = realloc(e->vals, sizeof(lval_t *) * e->count);
    e->syms = realloc(e->syms, sizeof(char *) * e->count);

    e->vals[e->count - 1] = lval_copy(v);
    e->syms[e->count - 1] = malloc(strlen(k->sym) + 1);
    strcpy(e->syms[e->count - 1], k->sym);
}

void lenv_del(lenv_t *e)
{
    for (int i = 0; i < e->count; ++i)
    {
        free(e->syms[i]);
        lval_del(e->vals[i]);
    }
    free(e->syms);
    free(e->vals);
    free(e);
}

void lenv_def(lenv_t *e, lval_t *k, lval_t *v)
{
    while (e->par)
    {
        e = e->par;
    }

    lenv_put(e, k, v);
}

void lval_del(lval_t *v)
{
    switch (v->type)
    {
    case LVAL_NUM:
        break;
    case LVAL_FUN:
        if (!v->builtin)
        {
            lenv_del(v->env);
            lval_del(v->formals);
            lval_del(v->body);
        }
        break;

    case LVAL_ERR:
        free(v->err);
        break;
    case LVAL_SYM:
        free(v->sym);
        break;

    case LVAL_QEXPR:
    case LVAL_SEXPR:
        for (int i = 0; i < v->count; ++i)
        {
            lval_del(v->cell[i]);
        }

        free(v->cell);
        break;
    case LVAL_STR:
        free(v->str);
        break;
    }

    free(v);
}

lval_t *lval_read_num(mpc_ast_t *t)
{
    errno = 0;
    long x = strtol(t->contents, NULL, 10);
    return errno != ERANGE ? lval_num(x) : lval_err("**Invalid Number**");
}

lval_t *lval_read_str(mpc_ast_t *t)
{
    /* Cut off the final quote character */
    t->contents[strlen(t->contents) - 1] = '\0';
    /* Copy the string missing out the first quote character */
    char *unescaped = malloc(strlen(t->contents + 1) + 1);
    strcpy(unescaped, t->contents + 1);
    /* Pass through the unescape function */
    unescaped = mpcf_unescape(unescaped);
    /* Construct a new lval using the string */
    lval_t *str = lval_str(unescaped);
    /* Free the string and return */
    free(unescaped);
    return str;
}

lval_t *lval_add(lval_t *v, lval_t *x)
{
    v->count++;
    v->cell = realloc(v->cell, sizeof(lval_t *) * v->count);
    v->cell[v->count - 1] = x;
    return v;
}

void lval_expr_print(lval_t *v, char open, char close)
{
    putchar(open);

    for (int i = 0; i < v->count; ++i)
    {
        lval_print(v->cell[i]);

        if (i != (v->count - 1))
        {
            putchar(' '); // Put a trailing character if this is not the last expression.
        }
    }

    putchar(close);
}

// TODO(kosi): Enable todo highlighting.
lval_t *lval_eval(lenv_t *e, lval_t *v)
{
    if (v->type == LVAL_SYM)
    {
        lval_t *x = lenv_get(e, v);
        lval_del(v);
        return x;
    }

    if (v->type == LVAL_SEXPR)
    {
        return lval_eval_sexpr(e, v);
    }

    return v; // Return self
}

lval_t *lval_copy(lval_t *v)
{
    lval_t *x = malloc(sizeof(lval_t));
    x->type = v->type;

    switch (v->type)
    {
    case LVAL_FUN:
        if (v->builtin)
        {
            x->builtin = v->builtin;
        }
        else
        {
            x->builtin = NULL;
            x->env = lenv_copy(v->env);
            x->formals = lval_copy(v->formals);
            x->body = lval_copy(v->body);
        }
        break;
    case LVAL_NUM:
        x->num = v->num;
        break;

    case LVAL_ERR:
        x->err = malloc(strlen(v->err) + 1);
        strcpy(x->err, v->err);
        break;
    case LVAL_STR:
        x->err = malloc(strlen(v->err) + 1);
        strcpy(x->err, v->err);
        break;

    case LVAL_SYM:
        x->sym = malloc(strlen(v->sym) + 1);
        strcpy(x->sym, v->sym);
        break;

    case LVAL_SEXPR:
    case LVAL_QEXPR:
        x->count = v->count;
        x->cell = malloc(sizeof(lval_t *) * x->count);
        for (int i = 0; i < x->count; ++i)
        {
            x->cell[i] = lval_copy(v->cell[i]);
        }
        break;
    }

    return x;
}

lval_t *lval_pop(lval_t *v, int i)
{
    lval_t *x = v->cell[i];

    memmove(&v->cell[i], &v->cell[i + 1], sizeof(lval_t *) * (v->count - i - 1));

    v->count--;

    v->cell = realloc(v->cell, sizeof(lval_t *) * v->count);

    return x;
}

lval_t *lval_take(lval_t *v, int i)
{
    lval_t *x = lval_pop(v, i);
    lval_del(v);
    return x;
}

lval_t *builtin_def(lenv_t *e, lval_t *a)
{
    return builtin_var(e, a, "def");
}

lval_t *builtin_put(lenv_t *e, lval_t *a)
{
    return builtin_var(e, a, "=");
}

lval_t *builtin_var(lenv_t *e, lval_t *a, char *func)
{
    KLASSERT_TYPE(func, a, 0, LVAL_QEXPR);

    lval_t *syms = a->cell[0];
    for (int i = 0; i < syms->count; ++i)
    {
        KLASSERT(a, syms->cell[i]->type == LVAL_SYM,
                 "Function '%s' cannot define non-symbol. "
                 "Got %s, Expected %s.",
                 func,
                 ltype_name(syms->cell[i]->type),
                 ltype_name(LVAL_SYM));
    }

    KLASSERT(a, syms->count == a->count - 1,
             "Function '%s' passed too many arguments for symbols. "
             "Got %i, Expected %i.",
             func, syms->count, a->count - 1);

    for (int i = 0; i < syms->count; ++i)
    {
        if (strcmp(func, "def") == 0)
        {
            lenv_def(e, syms->cell[i], a->cell[i + 1]);
        }

        if (strcmp(func, "=") == 0)
        {
            lenv_put(e, syms->cell[i], a->cell[i + 1]);
        }
    }

    lval_del(a);
    return lval_sexpr();
}

lval_t *builtin_env(lenv_t *e, lval_t *a)
{
    lval_del(a);

    lval_t *l = lval_qexpr();

    for (int i = 0; i < e->count; ++i)
    {
        lval_add(l, lval_sym(e->syms[i]));
    }

    return l;
}

lval_t *builtin_exit(lenv_t *e, lval_t *a)
{
    lval_del(a);
    exit(0);
}

lval_t *builtin_fun(lenv_t *e, lval_t *a)
{
    KLASSERT_NUM("fun", a, 2);
    KLASSERT_TYPE("fun", a, 0, LVAL_QEXPR);
    KLASSERT_TYPE("fun", a, 1, LVAL_QEXPR);

    lval_t *args = lval_pop(a, 0);

    KLASSERT(a, args->count > 0, "Function 'fun' was passed empty Q-Expression for argument 1.");

    lval_t *fun_name = lval_pop(args, 0);
    lval_t *body = lval_pop(a, 0);

    KLASSERT(a, fun_name->type == LVAL_SYM, "Function name must be a symbol.");

    lval_t *lambda = lval_lambda(args, body);
    lenv_put(e, fun_name, lambda);

    lval_del(lambda);
    lval_del(body);
    lval_del(fun_name);
    lval_del(args);
    lval_del(a);

    return lval_sexpr();
}

lval_t *builtin_lambda(lenv_t *e, lval_t *a)
{
    KLASSERT_NUM("\\", a, 2);
    KLASSERT_TYPE("\\", a, 0, LVAL_QEXPR);
    KLASSERT_TYPE("\\", a, 1, LVAL_QEXPR);

    for (int i = 0; i < a->cell[0]->count; ++i)
    {
        KLASSERT(a, a->cell[0]->cell[i]->type == LVAL_SYM,
                 "Cannot define non-symbol. Got %s, Expected %s.",
                 ltype_name(a->cell[0]->cell[i]->type), ltype_name(LVAL_SYM));
    }

    lval_t *formals = lval_pop(a, 0);
    lval_t *body = lval_pop(a, 0);
    lval_del(a);

    return lval_lambda(formals, body);
}

lval_t *builtin_add(lenv_t *e, lval_t *a)
{
    KLASSERT(a, a->cell[0]->type == LVAL_NUM,
             "Function '+' passed incorrect type for argument 0. "
             "Got %s, Expected %s.",
             ltype_name(a->cell[0]->type), ltype_name(LVAL_NUM));

    KLASSERT(a, a->cell[1]->type == LVAL_NUM,
             "Function '+' passed incorrect type for argument 1. "
             "Got %s, Expected %s.",
             ltype_name(a->cell[1]->type), ltype_name(LVAL_NUM));

    return builtin_op(e, a, "+");
}

lval_t *builtin_sub(lenv_t *e, lval_t *a)
{
    return builtin_op(e, a, "-");
}

lval_t *builtin_mul(lenv_t *e, lval_t *a)
{
    return builtin_op(e, a, "*");
}

lval_t *builtin_div(lenv_t *e, lval_t *a)
{
    return builtin_op(e, a, "/");
}

lval_t *builtin_head(lenv_t *e, lval_t *a)
{
    KLASSERT_NUM("head", a, 1);

    KLASSERT(a, a->cell[0]->type == LVAL_QEXPR,
             "Function 'head' passed incorrect type for argument 0. ",
             "Got %s, Expected %s.",
             ltype_name(a->cell[0]->type), ltype_name(LVAL_QEXPR));

    KLEMPTY(a->cell[0], "Empty Q-expression passed to function 'head'.");

    lval_t *v = lval_take(a, 0);

    while (v->count > 1)
    {
        lval_del(lval_pop(v, 1));
    }
    return v;
}

lval_t *builtin_tail(lenv_t *e, lval_t *a)
{
    KLARGS(a, 1, "Too many arugments passed to function 'tail'.");
    KLASSERT(a, a->cell[0]->type == LVAL_QEXPR, "Incorrect type passed to function 'tail'.");
    KLEMPTY(a->cell[0], "Empty Q-expression passed to function 'tail'.");

    lval_t *v = lval_take(a, 0);

    lval_del(lval_pop(v, 0));
    return v;
}

lval_t *builtin_list(lenv_t *e, lval_t *a)
{
    a->type = LVAL_QEXPR;
    return a;
}

lval_t *lval_join(lval_t *x, lval_t *y)
{
    while (y->count)
    {
        x = lval_add(x, lval_pop(y, 0));
    }

    lval_del(y);
    return x;
}

lval_t *lval_fun(lbuiltin_t fun)
{
    lval_t *v = malloc(sizeof(lval_t));
    v->type = LVAL_FUN;
    v->builtin = fun;
    return v;
}

lval_t *builtin_join(lenv_t *e, lval_t *a)
{
    for (int i = 0; i < a->count; ++i)
    {
        KLASSERT(a, a->cell[i]->type == LVAL_QEXPR, "Incorrect type passed to function 'join'.");
    }

    lval_t *x = lval_pop(a, 0);

    while (a->count)
    {
        x = lval_join(x, lval_pop(a, 0));
    }

    lval_del(a);
    return x;
}

lval_t *builtin_eval(lenv_t *e, lval_t *a)
{
    KLARGS(a, 1, "Too many arguments passed to function 'eval'.");
    KLASSERT(a, a->cell[0]->type == LVAL_QEXPR, "Incorrect type passed to function 'eval'.");

    lval_t *x = lval_take(a, 0);
    x->type = LVAL_SEXPR;
    return lval_eval(e, x);
}

lval_t *builtin_load(lenv_t *e, lval_t *a)
{
    KLASSERT_NUM("load", a, 1);
    KLASSERT_TYPE("load", a, 0, LVAL_STR);

    mpc_result_t r;
    if (mpc_parse_contents(a->cell[0]->str, program, &r))
    {
        lval_t *exprs = lval_read(r.output);
        mpc_ast_delete(r.output);

        while (exprs->count)
        {
            lval_t *x = lval_eval(e, lval_pop(exprs, 0));

            if (x->type == LVAL_ERR)
            {
                lval_println(x);
            }
            lval_del(x);
        }

        lval_del(exprs);
        lval_del(a);

        return lval_sexpr();
    }
    else
    {
        char *err_msg = mpc_err_string(r.error);
        mpc_err_delete(r.error);

        /* Create new error message using it */
        lval_t *err = lval_err("Could not load file %s.", err_msg);
        free(err_msg);
        lval_del(a);

        /* Cleanup and return error */
        return err;
    }
}

lval_t *builtin_print(lenv_t *e, lval_t *a)
{
    for (int i = 0; i < a->count; ++i)
    {
        lval_print(a->cell[i]);
        putchar(' ');
    }

    putchar('\n');
    lval_del(a);

    return lval_sexpr();
}

lval_t *builtin_error(lenv_t *e, lval_t *a)
{
    KLASSERT_NUM("error", a, 1);
    KLASSERT_TYPE("error", a, 0, LVAL_STR);

    lval_t *err = lval_err(a->cell[0]->str);

    lval_del(a);
    return err;
}

lval_t *builtin_joins(lenv_t *e, lval_t *a)
{
    int total_len = 0;

    for (int i = 0; i < a->count; ++i)
    {
        KLASSERT_TYPE("join.s", a, i, LVAL_STR);
        total_len += strlen(a->cell[i]->str);
    }

    lval_t *v = lval_pop(a, 0);
    v->str = realloc(v->str, total_len + 1);

    for (int i = 0; i < a->count; ++i)
    {
        strcat(v->str, a->cell[i]->str);
    }

    lval_del(a);
    return v;
}

lval_t *builtin_heads(lenv_t *e, lval_t *a)
{
    KLASSERT_NUM("head.s", a, 1);
    KLASSERT_TYPE("head.s", a, 0, LVAL_STR);

    KLASSERT(a, strlen(a->cell[0]->str) > 0, "Empty string passed to function 'head.s'.");

    lval_t *v = lval_take(a, 0);
    realloc(v->str, 2);
    v->str[1] = '\0';

    return v;
}

lval_t *builtin_tails(lenv_t *e, lval_t *a)
{
    KLASSERT_NUM("tail.s", a, 1);
    KLASSERT_TYPE("tail.s", a, 0, LVAL_STR);

    KLASSERT(a, strlen(a->cell[0]->str) > 0, "Empty string passed to function 'tail.s'.");

    lval_t *v = lval_take(a, 0);
    int len = strlen(v->str);

    memmove(v->str, v->str + 1, len - 1);
    v->str = realloc(v->str, len);
    v->str[len - 1] = '\0';

    return v;
}

lval_t *builtin_read(lenv_t *e, lval_t *a)
{
    KLASSERT_NUM("read", a, 1);
    KLASSERT_TYPE("read", a, 0, LVAL_STR);

    lval_t *v = lval_qexpr();
    lval_t *s = lval_take(a, 0);

    for (int i = 0; i < strlen(s->str); ++i)
    {
        char *a = malloc(2);
        a[0] = s->str[i];
        a[1] = '\0';

        lval_add(v, lval_str(a));

        free(a);
    }

    lval_del(s);
    return v;
}

lval_t *builtin_show(lenv_t *e, lval_t *a)
{
    KLASSERT_NUM("show", a, 1);
    KLASSERT_TYPE("show", a, 0, LVAL_STR);

    lval_t *v = lval_take(a, 0);
    printf("%s", v->str);

    lval_del(v);
    return lval_sexpr();
}

lval_t *builtin_readfile(lenv_t *e, lval_t *a)
{
    KLASSERT_NUM("readfile", a, 1);
    KLASSERT_TYPE("readfile", a, 0, LVAL_STR);

    lval_t *s = lval_take(a, 0);

    FILE *f = fopen(s->sym, "rb");
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *contents = malloc(fsize + 1);
    fread(contents, 1, fsize, f);
    fclose(f);

    contents[fsize] = '\0';

    lval_del(s);
    lval_t *x = lval_str(contents);
    free(contents);
    return x;
}

lval_t *builtin_init(lenv_t *e, lval_t *a)
{
    KLARGS(a, 1, "Too many arugments passed to function 'init'.");
    KLASSERT(a, a->cell[0]->type == LVAL_QEXPR, "Incorrect type passed to function 'init'.");
    KLEMPTY(a->cell[0], "Empty Q-expression passed to function 'init'.");

    lval_t *v = lval_take(a, 0);

    lval_del(lval_pop(v, v->count - 1));
    return v;
}

lval_t *builtin_len(lenv_t *e, lval_t *a)
{
    KLARGS(a, 1, "Wrong number of arguments passed to function 'len'.");
    KLASSERT(a, a->cell[0]->type == LVAL_QEXPR, "Incorrect type passed to function 'len'.");

    return lval_num(a->cell[0]->count);
}

lval_t *builtin_ord(lenv_t *e, lval_t *a, char *op)
{
    KLASSERT_NUM(op, a, 2);
    KLASSERT_TYPE(op, a, 0, LVAL_NUM);
    KLASSERT_TYPE(op, a, 1, LVAL_NUM);

    int r;
    if (strcmp(op, ">") == 0)
    {
        r = (a->cell[0]->num > a->cell[1]->num);
    }
    if (strcmp(op, "<") == 0)
    {
        r = (a->cell[0]->num < a->cell[1]->num);
    }
    if (strcmp(op, ">=") == 0)
    {
        r = (a->cell[0]->num >= a->cell[1]->num);
    }
    if (strcmp(op, "<=") == 0)
    {
        r = (a->cell[0]->num <= a->cell[1]->num);
    }
    lval_del(a);
    return lval_num(r);
}

lval_t *builtin_lt(lenv_t *e, lval_t *a)
{
    return builtin_ord(e, a, "<");
}

lval_t *builtin_le(lenv_t *e, lval_t *a)
{
    return builtin_ord(e, a, "<=");
}

lval_t *builtin_gt(lenv_t *e, lval_t *a)
{
    return builtin_ord(e, a, ">");
}

lval_t *builtin_ge(lenv_t *e, lval_t *a)
{
    return builtin_ord(e, a, ">=");
}

lval_t *builtin_cons(lenv_t *e, lval_t *a)
{
    KLARGS(a, 2, "Wrong number of arguments passed to function 'cons'.");
    KLASSERT(a, a->cell[0]->type == LVAL_NUM, "Incorrect type passed to function 'cons'.");
    KLASSERT(a, a->cell[1]->type == LVAL_QEXPR, "Incorrect type passed to function 'cons'.");

    lval_t *x = lval_pop(a, 0);
    long num = x->num;
    lval_del(x);
    x = lval_qexpr();
    x = lval_add(x, lval_num(num));

    while (a->count)
    {
        x = lval_join(x, lval_pop(a, 0));
    }

    lval_del(a);
    return x;
}

int lval_eq(lval_t *a, lval_t *b)
{
    if (a->type != b->type)
    {
        return 0;
    }

    switch (a->type)
    {
    case LVAL_NUM:
        return a->num == b->num;

    case LVAL_SYM:
    case LVAL_ERR:
        return strcmp(a->err, b->err) == 0;

    case LVAL_SEXPR:
    case LVAL_QEXPR:
        if (a->count != b->count)
        {
            return 0;
        }
        for (int i = 0; i < a->count; ++i)
        {
            if (!lval_eq(a->cell[i], b->cell[i]))
                return 0;
        }
        return 1;

    case LVAL_FUN:
        return lval_eq(a->formals, b->formals) && lval_eq(a->body, b->body);
    case LVAL_STR:
        return strcmp(a->str, b->str) == 0;

    default:
        return 0;
    }
}

lval_t *builtin_eq(lenv_t *e, lval_t *a)
{
    KLASSERT_NUM("==", a, 2);

    lval_t *arg1 = lval_pop(a, 0);
    lval_t *arg2 = lval_take(a, 0);

    return lval_num(lval_eq(arg1, arg2));
}

lval_t *builtin_ne(lenv_t *e, lval_t *a)
{
    KLASSERT_NUM("!=", a, 2);

    lval_t *arg1 = lval_pop(a, 0);
    lval_t *arg2 = lval_take(a, 0);

    return lval_num(!lval_eq(arg1, arg2));
}

lval_t *builtin_if(lenv_t *e, lval_t *a)
{
    KLASSERT(a, a->count == 3 || a->count == 2, "Function 'if' needs either 2 or 3 arguments. "
                                                "Found %i.",
             a->count);

    KLASSERT_TYPE("if", a, 0, LVAL_NUM);
    KLASSERT_TYPE("if", a, 1, LVAL_QEXPR);

    a->cell[1]->type = LVAL_SEXPR;
    if (a->count == 3)
    {
        KLASSERT_TYPE("if", a, 2, LVAL_QEXPR);
        a->cell[2]->type = LVAL_SEXPR;
    }

    lval_t *result;

    if (a->cell[0]->num == 1)
        result = a->cell[1];
    else if (a->count == 3)
        result = a->cell[2];
    else
        result = lval_sexpr();

    result = lval_eval(e, result);
    lval_del(a);
    return result;
}

lval_t *builtin_op(lenv_t *e, lval_t *a, char *op)
{
    // Make sure argument are numbers
    for (int i = 0; i < a->count; ++i)
    {
        if (a->cell[i]->type != LVAL_NUM)
        {
            lval_del(a);
            return lval_err("Cannot operate on non-numbers!");
        }
    }
    // First arugment
    lval_t *x = lval_pop(a, 0);

    // This is a unary operator.
    if ((strcmp(op, "-") == 0) && a->count == 0)
    {
        x->num = -x->num;
    }

    while (a->count > 0)
    {
        // Next element
        lval_t *y = lval_pop(a, 0);

        if (strcmp(op, "+") == 0)
        {
            x->num += y->num;
        }
        if (strcmp(op, "-") == 0)
        {
            x->num -= y->num;
        }
        if (strcmp(op, "*") == 0)
        {
            x->num *= y->num;
        }
        if (strcmp(op, "/") == 0)
        {
            if (y->num == 0)
            {
                lval_del(x);
                lval_del(y);
                x = lval_err("Cannot divide by zero!");
                break;
            }
            x->num /= y->num;
        }
        lval_del(y);
    }

    lval_del(a);
    return x;
}

lval_t *lval_lambda(lval_t *formals, lval_t *body)
{
    lval_t *v = malloc(sizeof(lval_t));
    v->type = LVAL_FUN;

    v->builtin = NULL;

    v->env = lenv_new();

    v->formals = formals;
    v->body = body;
    return v;
}

lval_t *lval_eval_sexpr(lenv_t *e, lval_t *v)
{
    // evaluate children of s expression
    for (int i = 0; i < v->count; ++i)
    {
        v->cell[i] = lval_eval(e, v->cell[i]);
    }

    // check if there are any errors in children
    for (int i = 0; i < v->count; ++i)
    {
        if (v->cell[i]->type == LVAL_ERR)
        {
            return lval_take(v, i);
        }
    }

    // Empty expression
    if (v->count == 0)
    {
        return v;
    }

    // Single expression
    if (v->count == 1)
    {
        return lval_take(v, 0);
    }

    // Make sure first element is symbol (a.k.a polish notation)
    lval_t *f = lval_pop(v, 0);
    if (f->type != LVAL_FUN)
    {
        lval_t *err = lval_err(
            "S-Expression starts with incorrect type. "
            "Got %s. Expected %s.",
            ltype_name(f->type), ltype_name(LVAL_FUN));
        lval_del(f);
        lval_del(v); // Yeet the whole thing
        return err;
    }

    lval_t *result = lval_call(e, f, v);
    lval_del(f);
    return result;
}

void lval_print(lval_t *v)
{
    switch (v->type)
    {
    case LVAL_NUM:
        printf("%li", v->num);
        break;
    case LVAL_ERR:
        printf("Error: %s", v->err);
        break;
    case LVAL_STR:
        lval_print_str(v);
        break;
    case LVAL_SYM:
        printf("%s", v->sym);
        break;
    case LVAL_FUN:
        if (v->builtin)
        {
            printf("<function>");
        }
        else
        {
            printf("(\\ ");
            lval_print(v->formals);
            putchar(' ');
            lval_print(v->body);
            putchar(')');
        }
        break;
    case LVAL_SEXPR:
        lval_expr_print(v, '(', ')');
        break;
    case LVAL_QEXPR:
        lval_expr_print(v, '{', '}');
        break;
    }
}

void lval_print_str(lval_t *v)
{
    char *escape = malloc(strlen(v->str) + 1);
    strcpy(escape, v->str);

    escape = mpcf_escape(escape);
    printf("\"%s\"", escape);

    free(escape);
}

void lval_println(lval_t *v)
{
    lval_print(v);
    putchar('\n');
}

lval_t *lval_read(mpc_ast_t *t)
{
    if (strstr(t->tag, "number"))
    {
        return lval_read_num(t);
    }
    if (strstr(t->tag, "string"))
    {
        return lval_read_str(t);
    }
    if (strstr(t->tag, "symbol"))
    {
        return lval_sym(t->contents);
    }

    /* Root (>) or S-Expression then create empty dynamic list. */
    lval_t *x = NULL;
    if (strcmp(t->tag, ">") == 0)
    {
        x = lval_sexpr();
    }
    if (strstr(t->tag, "sexpr"))
    {
        x = lval_sexpr();
    }
    if (strstr(t->tag, "qexpr"))
    {
        x = lval_qexpr();
    }

    for (int i = 0; i < t->children_num; ++i)
    {
        // Start filling the S-expression / root expression with actual children
        if (strcmp(t->children[i]->contents, "(") == 0)
        {
            continue;
        }
        if (strcmp(t->children[i]->contents, ")") == 0)
        {
            continue;
        }
        if (strcmp(t->children[i]->contents, "{") == 0)
        {
            continue;
        }
        if (strcmp(t->children[i]->contents, "}") == 0)
        {
            continue;
        }
        if (strcmp(t->children[i]->tag, "regex") == 0)
        {
            continue;
        }
        if (strstr(t->children[i]->tag, "comment"))
        {
            continue;
        }
        x = lval_add(x, lval_read(t->children[i]));
    }

    return x;
}

lval_t *builtin_or(lenv_t *e, lval_t *a)
{
    KLASSERT_NUM("||", a, 2);
    KLASSERT_TYPE("||", a, 0, LVAL_NUM);
    KLASSERT_TYPE("||", a, 1, LVAL_NUM);

    lval_t *result = lval_num(a->cell[0]->num || a->cell[1]->num);

    lval_del(a);
    return result;
}

lval_t *builtin_and(lenv_t *e, lval_t *a)
{
    KLASSERT_NUM("&&", a, 2);
    KLASSERT_TYPE("&&", a, 0, LVAL_NUM);
    KLASSERT_TYPE("&&", a, 1, LVAL_NUM);

    lval_t *result = lval_num(a->cell[0]->num && a->cell[1]->num);

    lval_del(a);
    return result;
}

lval_t *builtin_not(lenv_t *e, lval_t *a)
{
    KLASSERT_NUM("!", a, 1);
    KLASSERT_TYPE("!", a, 0, LVAL_NUM);

    lval_t *result = lval_num(!a->cell[0]->num);

    lval_del(a);
    return result;
}

char *ltype_name(lval_type_t t)
{
    switch (t)
    {
    case LVAL_FUN:
        return "Function";
    case LVAL_STR:
        return "String";
    case LVAL_NUM:
        return "Number";
    case LVAL_ERR:
        return "Error";
    case LVAL_SYM:
        return "Symbol";
    case LVAL_SEXPR:
        return "S-Expression";
    case LVAL_QEXPR:
        return "Q-Expression";
    default:
        return "Unknown";
    }
}

int main(int argc, char **argv)
{
    number = mpc_new("number");
    symbol = mpc_new("symbol");
    comment = mpc_new("comment");
    string = mpc_new("string");
    expr = mpc_new("expr");
    sexpr = mpc_new("sexpr");
    qexpr = mpc_new("qexpr");
    program = mpc_new("program");

    mpca_lang(MPCA_LANG_DEFAULT,
              "                                                                                 \
        number          : /-?[0-9]+(,[0-9]+)*(\\.[0-9]+)?(e[0-9]+)?/ ;                          \
        symbol          : /[a-zA-Z0-9_+\\-*\\/\\\\=<>!&|\\.]+/;                                 \
        comment         : /;[^\\r\\n]*/ ;                                                       \
        string          : /\"(\\\\.|[^\"])*\"/ ;                                                \
        expr            : <number> | <symbol> | <sexpr> | <qexpr> | <string> | <comment> ;      \
        sexpr           : '(' <expr>* ')' ;                                                     \
        qexpr           : '{' <expr>* '}' ;                                                     \
        program         : /^/ <expr>* /$/ ;                                                     \
        ",
              number, symbol, comment, string, expr, sexpr, qexpr, program);

    lenv_t *e = lenv_new();
    lenv_add_builtins(e);

    if (argc >= 2)
    {
        /* loop over each supplied filename (starting from 1) */
        for (int i = 1; i < argc; i++)
        {
            /* Argument list with a single argument, the filename */
            lval_t *args = lval_add(lval_sexpr(), lval_str(argv[i]));

            /* Pass to builtin load and get the result */
            lval_t *x = builtin_load(e, args);

            /* If the result is an error be sure to print it */
            if (x->type == LVAL_ERR)
            {
                lval_println(x);
            }
            lval_del(x);
        }
    }
    // Invoke interpreter
    else
    {
        puts("kl Version 0.1");
        puts("Press Ctrl+C to Exit.");

        for (;;)
        {
            char *input = readline("kl> ");

            if (strcmp(input, "clear") == 0 || strcmp(input, "cls") == 0)
            {
                system("cls");
                continue;
            }

            mpc_result_t r;
            if (mpc_parse("<stdin>", input, program, &r))
            {
                lval_t *expr = lval_read(r.output);
#ifdef DEBUG
                lval_println(expr);
                mpc_ast_print(r.output);
#endif
                lval_t *result = lval_eval(e, expr);
                lval_println(result);
                lval_del(result);
                mpc_ast_delete(r.output);
                result = NULL;
                r.output = NULL;
            }
            else
            {
                mpc_err_print(r.error);
                mpc_err_delete(r.error);
                r.error = NULL;
            }

            free(input);
        }
    }

    mpc_cleanup(8, number, symbol, comment, string, expr, sexpr, qexpr, program);

    return 0;
}