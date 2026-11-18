/* scale30 C adapter — ২টা library, PREREG §3 contract (PREREG_newlangs)।
 * ব্যবহার: ./run.sh <cases.json> <outdir> [impl ...]
 * load(case) → key (stage=keyload); verify(token, key, algs) → claims (stage=verify)।
 * config = README-র নিরাপদ স্বাভাবিক ব্যবহার। truth.json কখনো পড়া হয় না।
 *
 * libjwt: jwt_checker_setkey(alg=allowed_algs[0], JWK) + jwt_checker_verify — pin[0]।
 *   claim library শুধু checker callback-এ দেখায় (parse-এর পরে, verify-এর আগে); verify 0 ফেরত দিলে
 *   সেই claim-ই application-এর belief। keyload = jwks_create (JWK parse)।
 * cjose: JWS-স্তরের library — cjose_jws_import + cjose_jws_verify(jws, JWK); alg allow-list আর
 *   exp যাচাই নেই। plaintext JSON object হলে সেটাই claims। */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <jansson.h>
#include <jwt.h>
#include <cjose/cjose.h>

#ifndef LIBJWT_VER
#error "LIBJWT_VER must come from pkg-config at build time (run.sh)"
#endif

typedef struct {
	int accepted;
	json_t *claims;   /* owned */
	char error[201];
	const char *stage;
} rec_t;

static long long now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void set_err(rec_t *r, const char *stage, const char *type, const char *msg)
{
	r->stage = stage;
	snprintf(r->error, sizeof r->error, "%s: %s", type, msg ? msg : "(no message)");
}

/* ── libjwt ── */
typedef struct { jwk_set_t *jwks; } libjwt_key;

static void *libjwt_load(json_t *c, rec_t *r)
{
	char *s = json_dumps(json_object_get(json_object_get(c, "key"), "jwk"), JSON_COMPACT);
	jwk_set_t *jwks = jwks_create(s);
	free(s);
	if (jwks == NULL) { set_err(r, "keyload", "jwks_create", "NULL"); return NULL; }
	if (jwks_error(jwks)) { set_err(r, "keyload", "jwks_error", jwks_error_msg(jwks)); jwks_free(jwks); return NULL; }
	const jwk_item_t *it = jwks_item_get(jwks, 0);
	if (it == NULL || jwks_item_error(it)) {
		set_err(r, "keyload", "jwks_item_error", it ? jwks_item_error_msg(it) : "no item");
		jwks_free(jwks); return NULL;
	}
	libjwt_key *k = malloc(sizeof *k);
	k->jwks = jwks;
	return k;
}

static int libjwt_cb(jwt_t *jwt, jwt_config_t *cfg)
{
	jwt_value_t v;
	jwt_set_GET_JSON(&v, NULL);                 /* NULL name = পুরো claims object */
	if (jwt_claim_get(jwt, &v) == JWT_VALUE_ERR_NONE && v.json_val) {
		char **out = cfg->ctx;
		*out = (char *)v.json_val;
	}
	return 0;
}

static void libjwt_verify(const char *tok, void *key, json_t *algs, rec_t *r)
{
	libjwt_key *k = key;
	char *claims_json = NULL;
	const char *alg0 = json_string_value(json_array_get(algs, 0));
	jwt_checker_t *ch = jwt_checker_new();
	if (ch == NULL) { set_err(r, "verify", "jwt_checker_new", "NULL"); return; }
	if (jwt_checker_setkey(ch, jwt_str_alg(alg0), jwks_item_get(k->jwks, 0))) {
		set_err(r, "verify", "jwt_checker_setkey", jwt_checker_error_msg(ch));
		jwt_checker_free(ch); return;
	}
	jwt_checker_setcb(ch, libjwt_cb, &claims_json);
	if (jwt_checker_verify(ch, tok) == 0) {
		json_error_t je;
		json_t *cl = claims_json ? json_loads(claims_json, 0, &je) : NULL;
		if (json_is_object(cl)) { r->accepted = 1; r->claims = cl; r->stage = "verify"; }
		else { json_decref(cl); set_err(r, "claims", "claims", "no claims object exposed"); }
	} else {
		set_err(r, "verify", "jwt_checker_verify", jwt_checker_error_msg(ch));
	}
	free(claims_json);
	jwt_checker_free(ch);
}

static void libjwt_free(void *key) { libjwt_key *k = key; jwks_free(k->jwks); free(k); }

/* ── cjose ── */
static void *cjose_load(json_t *c, rec_t *r)
{
	cjose_err err;
	char *s = json_dumps(json_object_get(json_object_get(c, "key"), "jwk"), JSON_COMPACT);
	cjose_jwk_t *jwk = cjose_jwk_import(s, strlen(s), &err);
	free(s);
	if (jwk == NULL) set_err(r, "keyload", "cjose_jwk_import", err.message);
	return jwk;
}

static void cjose_verify_(const char *tok, void *key, json_t *algs, rec_t *r)
{
	(void)algs;                                 /* allow-list API নেই */
	cjose_err err;
	cjose_jws_t *jws = cjose_jws_import(tok, strlen(tok), &err);
	if (jws == NULL) { set_err(r, "verify", "cjose_jws_import", err.message); return; }
	if (!cjose_jws_verify(jws, key, &err)) {
		set_err(r, "verify", "cjose_jws_verify", err.message);
		cjose_jws_release(jws); return;
	}
	uint8_t *pt = NULL; size_t n = 0;
	if (!cjose_jws_get_plaintext(jws, &pt, &n, &err)) {
		set_err(r, "claims", "cjose_jws_get_plaintext", err.message);
		cjose_jws_release(jws); return;
	}
	json_error_t je;
	json_t *cl = json_loadb((const char *)pt, n, 0, &je);   /* pt jws-এর মালিকানায় */
	if (json_is_object(cl)) { r->accepted = 1; r->claims = cl; r->stage = "verify"; }
	else { json_decref(cl); set_err(r, "claims", "json", "payload is not a JSON object"); }
	cjose_jws_release(jws);
}

static void cjose_free_(void *key) { cjose_jwk_release(key); }

typedef struct {
	const char *name, *backend;
	const char *(*version)(void);
	void *(*load)(json_t *, rec_t *);
	void (*verify)(const char *, void *, json_t *, rec_t *);
	void (*free_key)(void *);
} impl_t;

static const char *libjwt_version(void) { return LIBJWT_VER; }

static const impl_t IMPLS[] = {
	{ "libjwt", "openssl", libjwt_version, libjwt_load, libjwt_verify, libjwt_free },
	{ "cjose", "openssl", cjose_version, cjose_load, cjose_verify_, cjose_free_ },
};
#define N_IMPLS (sizeof IMPLS / sizeof IMPLS[0])

static void run_one(const impl_t *im, json_t *cases, const char *outdir)
{
	char path[4096];
	snprintf(path, sizeof path, "%s/c__%s.jsonl", outdir, im->name);
	FILE *f = fopen(path, "w");
	if (f == NULL) { perror(path); exit(1); }
	char impl[64];
	snprintf(impl, sizeof impl, "c/%s", im->name);
	size_t i; json_t *c;
	json_array_foreach(cases, i, c) {
		rec_t r = { 0, NULL, "", "" };
		long long ns = 0;
		const char *tok = json_string_value(json_object_get(c, "token"));
		json_t *algs = json_object_get(c, "allowed_algs");
		void *k = im->load(c, &r);
		if (k != NULL) {
			long long t0 = now_ns();
			im->verify(tok, k, algs, &r);
			ns = now_ns() - t0;
			if (i == 0) {                       /* প্রথম call-এ lazy init — আবার মাপা */
				rec_t r2 = { 0, NULL, "", "" };
				t0 = now_ns();
				im->verify(tok, k, algs, &r2);
				ns = now_ns() - t0;
				json_decref(r2.claims);
			}
			im->free_key(k);
		}
		json_t *o = json_pack("{s:s, s:s, s:s, s:s, s:O, s:b, s:o, s:s, s:s, s:I}",
			"impl", impl, "version", im->version(), "lang", "c", "backend", im->backend,
			"case", json_object_get(c, "id"), "accepted", r.accepted,
			"claims", r.claims ? r.claims : json_object(), "error", r.error,
			"stage", r.stage, "ns", (json_int_t)ns);
		char *line = json_dumps(o, JSON_COMPACT);
		fprintf(f, "%s\n", line);
		free(line);
		json_decref(o);
	}
	fclose(f);
	fprintf(stderr, "done %s\n", im->name);
}

int main(int argc, char **argv)
{
	if (argc < 3) { fprintf(stderr, "usage: %s <cases.json> <outdir> [impl ...]\n", argv[0]); return 2; }
	json_error_t je;
	json_t *root = json_load_file(argv[1], 0, &je);
	if (root == NULL) { fprintf(stderr, "%s: %s\n", argv[1], je.text); return 1; }
	json_t *cases = json_object_get(root, "cases");
	for (size_t j = 0; j < N_IMPLS; j++) {
		int want = argc == 3;
		for (int a = 3; a < argc; a++) if (strcmp(argv[a], IMPLS[j].name) == 0) want = 1;
		if (want) run_one(&IMPLS[j], cases, argv[2]);
	}
	json_decref(root);
	return 0;
}
